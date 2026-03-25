#!/usr/bin/env python3
"""
IRIS-VE — Script di migrazione file da LocalStorage a S3/MinIO
==============================================================
Uso:
    python migrate_to_s3.py [--dry-run] [--delete-local] [--workers 4]

Opzioni:
    --dry-run       Simula senza caricare nulla
    --delete-local  Elimina i file locali dopo upload confermato
    --workers N     Parallelismo (default: 4)

Variabili d'ambiente richieste (stesso file 'env' del progetto):
    DATABASE_URL, S3_ENDPOINT_URL, S3_BUCKET, S3_ACCESS_KEY, S3_SECRET_KEY

Esempio:
    # Prima testa senza modificare nulla:
    python migrate_to_s3.py --dry-run

    # Migra tutto mantenendo anche i file locali:
    python migrate_to_s3.py

    # Migra ed elimina i file locali:
    python migrate_to_s3.py --delete-local
"""

import os
import sys
import csv
import argparse
import datetime
import concurrent.futures
from pathlib import Path

# Carica .env prima di tutto
from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).parent / 'env')

# Imports
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("❌ boto3 non installato. Esegui: pip install boto3")
    sys.exit(1)

try:
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
except ImportError:
    print("❌ sqlalchemy non installato. Esegui: pip install sqlalchemy")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    # tqdm opzionale — fallback senza barra di progresso
    def tqdm(iterable, **kwargs):
        return iterable

# ─── Configurazione ───────────────────────────────────────────────────────────

DATABASE_URL   = os.environ.get('DATABASE_URL', 'mysql+pymysql://root:root@localhost/iris_ve')
UPLOAD_FOLDER  = os.path.join(os.path.dirname(__file__), 'uploads')
S3_ENDPOINT    = os.environ.get('S3_ENDPOINT_URL')
S3_BUCKET      = os.environ.get('S3_BUCKET', 'iris-ve')
S3_ACCESS_KEY  = os.environ.get('S3_ACCESS_KEY')
S3_SECRET_KEY  = os.environ.get('S3_SECRET_KEY')
S3_REGION      = os.environ.get('S3_REGION', 'us-east-1')


def get_s3_client():
    kwargs = dict(
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        region_name=S3_REGION,
    )
    if S3_ENDPOINT:
        kwargs['endpoint_url'] = S3_ENDPOINT
    return boto3.client('s3', **kwargs)


def ensure_bucket(s3):
    try:
        s3.head_bucket(Bucket=S3_BUCKET)
        print(f"✅ Bucket '{S3_BUCKET}' esiste")
    except ClientError as e:
        code = e.response['Error']['Code']
        if code in ('404', 'NoSuchBucket'):
            s3.create_bucket(Bucket=S3_BUCKET)
            print(f"✅ Bucket '{S3_BUCKET}' creato")
        else:
            print(f"❌ Errore bucket: {e}")
            sys.exit(1)


def get_active_upload_folder(engine):
    """Legge StorageConfig dal DB per ottenere il path attivo."""
    with engine.connect() as conn:
        try:
            row = conn.execute(text(
                "SELECT active_disk_path FROM storage_config LIMIT 1"
            )).fetchone()
            if row and row[0] and os.path.isdir(row[0]):
                return row[0]
        except Exception:
            pass
    return UPLOAD_FOLDER


def get_all_files(engine):
    """Restituisce lista di (id, original_name, file_path) da DB."""
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT id, original_name, file_path FROM files ORDER BY id"
        )).fetchall()
    return rows


def upload_file(args):
    """Worker function per il pool di thread."""
    s3, file_id, original_name, object_key, local_path, dry_run, delete_local = args
    result = {
        'id': file_id,
        'name': original_name or object_key,
        'object_key': object_key,
        'status': None,
        'error': None,
        'size_bytes': 0,
    }

    if not os.path.exists(local_path):
        result['status'] = 'MISSING'
        result['error'] = f'File non trovato: {local_path}'
        return result

    result['size_bytes'] = os.path.getsize(local_path)

    if dry_run:
        result['status'] = 'DRY_RUN'
        return result

    # Verifica se già caricato
    try:
        s3.head_object(Bucket=S3_BUCKET, Key=object_key)
        result['status'] = 'SKIP_EXISTS'
        if delete_local and os.path.exists(local_path):
            os.remove(local_path)
            result['status'] = 'SKIP_EXISTS+DELETED'
        return result
    except ClientError as e:
        if e.response['Error']['Code'] not in ('404', 'NoSuchKey'):
            result['status'] = 'ERROR'
            result['error'] = str(e)
            return result

    # Upload
    try:
        with open(local_path, 'rb') as f:
            s3.upload_fileobj(f, S3_BUCKET, object_key)
        result['status'] = 'OK'

        if delete_local:
            os.remove(local_path)
            result['status'] = 'OK+DELETED'

    except Exception as e:
        result['status'] = 'ERROR'
        result['error'] = str(e)

    return result


def main():
    parser = argparse.ArgumentParser(description='IRIS-VE: Migra file da LocalStorage a S3/MinIO')
    parser.add_argument('--dry-run', action='store_true',
                        help='Simula senza caricare nulla')
    parser.add_argument('--delete-local', action='store_true',
                        help='Elimina file locali dopo upload riuscito')
    parser.add_argument('--workers', type=int, default=4,
                        help='Thread paralleli (default: 4)')
    args = parser.parse_args()

    print("=" * 60)
    print("  IRIS-VE — Migrazione a S3/MinIO")
    print("=" * 60)
    print(f"  Endpoint: {S3_ENDPOINT or 'AWS S3 standard'}")
    print(f"  Bucket:   {S3_BUCKET}")
    print(f"  Dry run:  {args.dry_run}")
    print(f"  Elimina:  {args.delete_local}")
    print(f"  Workers:  {args.workers}")
    print("=" * 60)

    if not S3_ACCESS_KEY or not S3_SECRET_KEY:
        print("❌ S3_ACCESS_KEY e S3_SECRET_KEY devono essere impostate nel file 'env'")
        sys.exit(1)

    # Connessione DB
    engine = create_engine(DATABASE_URL)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("✅ Connessione al database OK")
    except Exception as e:
        print(f"❌ Errore connessione DB: {e}")
        sys.exit(1)

    # Client S3
    s3 = get_s3_client()
    try:
        s3.list_buckets()
        print("✅ Connessione a S3/MinIO OK")
    except Exception as e:
        print(f"❌ Errore connessione S3: {e}")
        sys.exit(1)

    if not args.dry_run:
        ensure_bucket(s3)

    # Path attivo
    upload_dir = get_active_upload_folder(engine)
    print(f"📁 Upload folder: {upload_dir}")

    # File da migrare
    files = get_all_files(engine)
    total = len(files)
    print(f"📦 File nel database: {total}")

    if total == 0:
        print("ℹ️  Nessun file da migrare.")
        return

    # Prepara tasks
    tasks = []
    for file_id, original_name, object_key in files:
        local_path = os.path.join(upload_dir, object_key)
        tasks.append((s3, file_id, original_name, object_key, local_path,
                      args.dry_run, args.delete_local))

    # Migrazione parallela
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = list(tqdm(
            executor.map(upload_file, tasks),
            total=total,
            desc="Migrazione",
            unit="file"
        ))
        results = futures

    # Report
    stats = {'OK': 0, 'OK+DELETED': 0, 'SKIP_EXISTS': 0, 'SKIP_EXISTS+DELETED': 0,
             'MISSING': 0, 'ERROR': 0, 'DRY_RUN': 0}
    total_bytes = 0
    errors = []

    for r in results:
        status = r['status']
        stats[status] = stats.get(status, 0) + 1
        total_bytes += r.get('size_bytes', 0)
        if status == 'ERROR':
            errors.append(r)

    # Salva log CSV
    log_file = f"migrate_s3_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(log_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['id', 'name', 'object_key', 'status', 'error', 'size_bytes'])
        writer.writeheader()
        writer.writerows(results)

    # Stampa sommario
    total_mb = total_bytes / (1024 * 1024)
    print("\n" + "=" * 60)
    print("  SOMMARIO")
    print("=" * 60)
    print(f"  ✅ Caricati:            {stats.get('OK', 0) + stats.get('OK+DELETED', 0)}")
    print(f"  ⏭️  Già presenti:        {stats.get('SKIP_EXISTS', 0) + stats.get('SKIP_EXISTS+DELETED', 0)}")
    print(f"  ❌ Errori:              {stats.get('ERROR', 0)}")
    print(f"  🔍 File mancanti:       {stats.get('MISSING', 0)}")
    print(f"  🧪 Dry run (simulati):  {stats.get('DRY_RUN', 0)}")
    print(f"  📊 Totale dati:         {total_mb:.1f} MB")
    print(f"  📝 Log salvato in:      {log_file}")
    print("=" * 60)

    if errors:
        print(f"\n⚠️  Primi {min(5, len(errors))} errori:")
        for e in errors[:5]:
            print(f"   [{e['id']}] {e['name']}: {e['error']}")

    if not args.dry_run and stats.get('ERROR', 0) == 0:
        print("\n✅ Migrazione completata!")
        print("   Ora puoi impostare STORAGE_BACKEND=minio nel file 'env' e riavviare.")
    elif args.dry_run:
        print("\nℹ️  Dry run completato. Rimuovi --dry-run per eseguire la migrazione.")


if __name__ == '__main__':
    main()

