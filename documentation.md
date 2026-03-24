# IRIS-VE v2.0 — Documentazione Tecnica

**Sistema di cloud storage personale con cifratura end-to-end, progettato con estetica glassmorphism e architettura enterprise.**

---

## Indice

1. [Panoramica del sistema](#1-panoramica-del-sistema)
2. [Requisiti](#2-requisiti)
3. [Installazione](#3-installazione)
4. [Configurazione](#4-configurazione)
5. [Avvio dell'applicazione](#5-avvio-dellapplicazione)
6. [Guida all'utilizzo](#6-guida-allutilizzo)
7. [API Reference](#7-api-reference)
8. [Sicurezza](#8-sicurezza)
9. [Monitoraggio e analytics](#9-monitoraggio-e-analytics)
10. [Manutenzione](#10-manutenzione)
11. [Troubleshooting](#11-troubleshooting)
12. [Aggiornamenti](#12-aggiornamenti)
13. [Licenza](#13-licenza)

---

## 1. Panoramica del sistema

IRIS-VE v2.0 è una soluzione di cloud storage personale self-hosted che combina semplicità d'uso, sicurezza di livello enterprise e un'interfaccia moderna in stile glassmorphism. Il sistema supporta cartelle normali e cartelle cifrate con crittografia AES-256.

### Funzionalità principali

**Sicurezza**
- Cifratura AES-256-CFB per cartelle protette
- Derivazione chiave PBKDF2 con SHA-256 e 150.000 iterazioni
- Rate limiting per endpoint sensibili
- Audit logging completo di tutte le operazioni
- Validazione file con blocco estensioni pericolose

**Prestazioni**
- Sistema di caching multi-livello
- Connection pooling per il database
- Task in background per la manutenzione automatica
- Deduplicazione file tramite hash SHA-256

**Interfaccia**
- Design system glassmorphism dark/light
- Layout responsive per tutti i dispositivi
- Drag & drop per l'upload
- Ricerca in tempo reale
- Animazioni fluide con curve di Bézier

**Analytics**
- Dashboard statistiche in tempo reale
- Health check endpoint
- Metriche di utilizzo e accesso
- Retention automatica di log e statistiche

---

## 2. Requisiti

### Software

| Componente | Versione minima | Consigliata |
|---|---|---|
| Python | 3.8 | 3.11+ |
| MySQL | 8.0 | 8.0+ |
| MariaDB (alternativa) | 10.5 | 10.11+ |
| wkhtmltopdf | qualsiasi | ultima stabile |

### Hardware

**Installazione base**

| Risorsa | Minimo |
|---|---|
| CPU | 2 core / 2,4 GHz |
| RAM | 4 GB |
| Disco | 10 GB SSD |
| Rete | 100 Mbps |

**Installazione enterprise**

| Risorsa | Consigliato |
|---|---|
| CPU | 4+ core / 3,0 GHz |
| RAM | 8 GB+ |
| Disco | 50 GB+ SSD NVMe |
| Rete | 1 Gbps |

---

## 3. Installazione

### Installazione automatica (consigliata)

```bash
# 1. Entra nella directory del progetto
cd iris-ve

# 2. Esegui lo script di setup
chmod +x setup.sh
./setup.sh

# 3. Configura la stringa di connessione al database in app.py (riga 28)

# 4. Inizializza il database
mysql -u root -p python < database_setup.sql

# 5. Avvia l'applicazione
python app.py
```

### Installazione manuale

```bash
# 1. Crea e attiva l'ambiente virtuale Python
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows

# 2. Installa le dipendenze
pip install --upgrade pip
pip install -r requirements.txt

# 3. Crea il database MySQL
mysql -u root -p
```
```sql
CREATE DATABASE python CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
EXIT;
```
```bash
# 4. Applica lo schema del database
mysql -u root -p python < database_setup.sql

# 5. Crea le directory necessarie
mkdir -p uploads backups logs
chmod 755 uploads backups logs

# 6. Verifica la disponibilità di wkhtmltopdf (necessario per la generazione PDF)
which wkhtmltopdf

# Se non è installato:
# Ubuntu/Debian:  sudo apt-get install wkhtmltopdf
# macOS:          brew install wkhtmltopdf
# CentOS/RHEL:    sudo yum install wkhtmltopdf
```

---

## 4. Configurazione

### Connessione al database

Modifica la riga della stringa di connessione in `app.py`:

```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://utente:password@host:porta/database'
```

### Variabili d'ambiente

Crea un file `.env` nella root del progetto per sovrascrivere i valori predefiniti:

```bash
DATABASE_URL=mysql://user:password@localhost/python
SECRET_KEY=chiave-segreta-casuale-e-lunga
FLASK_ENV=production
MAX_CONTENT_LENGTH=524288000   # 500 MB
LOG_LEVEL=INFO
BACKUP_RETENTION_DAYS=30
```

### Parametri avanzati

Per ambienti enterprise, i parametri principali si trovano in `app.py`:

```python
# Pool di connessioni al database
'pool_size': 20,          # connessioni simultanee mantenute nel pool
'pool_timeout': 20,       # secondi di attesa prima del timeout
'pool_recycle': -1,       # -1 = nessun riciclo automatico

# Rate limiting
"200 per day"             # limite globale giornaliero
"50 per hour"             # limite globale orario

# Cache
'CACHE_DEFAULT_TIMEOUT': 300   # TTL della cache in secondi
```

---

## 5. Avvio dell'applicazione

### Sviluppo

```bash
source venv/bin/activate
python app.py
```

L'applicazione è raggiungibile su `http://localhost:5000`.

### Produzione con Gunicorn

```bash
pip install gunicorn

gunicorn \
  --workers 4 \
  --worker-class gevent \
  --worker-connections 1000 \
  --max-requests 10000 \
  --max-requests-jitter 1000 \
  --preload \
  --bind 0.0.0.0:5000 \
  --timeout 300 \
  --keep-alive 5 \
  app:app
```

### Configurazione Nginx (reverse proxy)

```nginx
server {
    listen 80;
    server_name tuo-dominio.com;
    client_max_body_size 500M;

    # Header di sicurezza
    add_header X-Content-Type-Options  nosniff;
    add_header X-Frame-Options         DENY;
    add_header X-XSS-Protection        "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000";

    location / {
        proxy_pass              http://127.0.0.1:5000;
        proxy_set_header Host   $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeout estesi per upload di grandi dimensioni
        proxy_connect_timeout   60s;
        proxy_send_timeout      300s;
        proxy_read_timeout      300s;
    }

    location /static/ {
        alias   /percorso/iris-ve/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

---

## 6. Guida all'utilizzo

### Cartelle normali

**Creazione**
1. Clicca **Nuova cartella** nella dashboard o nella barra laterale.
2. Inserisci nome (obbligatorio, max 100 caratteri) e descrizione opzionale.
3. Lascia il toggle **Cartella cifrata** disattivato.
4. Conferma con **Crea cartella**.

**Gestione file**
- **Upload**: trascina i file nell'area apposita oppure clicca per selezionarli. Supporta selezione multipla.
- **Download**: clicca sul pulsante di download nella riga del file.
- **Modifica**: editor integrato per file di testo (`.txt`, `.md`, `.json`, ecc.).
- **Eliminazione**: clicca sull'icona cestino nella riga del file e conferma.

### Cartelle cifrate

**Creazione**
1. Clicca **Nuova cartella**.
2. Attiva il toggle **Cartella cifrata**.
3. Inserisci una password sicura (minimo 8 caratteri).
4. (Opzionale) Aggiungi un suggerimento e il contenuto iniziale da cifrare.
5. Conferma con **Crea cartella**.

**Accesso**
1. Clicca sulla cartella cifrata nella dashboard.
2. Inserisci la password nel modal di autenticazione.
3. L'applicazione verifica la chiave e mostra il contenuto decifrato.

**Caratteristiche tecniche della cifratura**

| Parametro | Valore |
|---|---|
| Algoritmo | AES-256-CFB |
| Derivazione chiave | PBKDF2-SHA256 |
| Iterazioni | 150.000 |
| Salt | 16 byte casuali per cartella |
| IV | 16 byte casuali per messaggio |
| Memorizzazione password | Mai (zero-knowledge) |

### Ricerca e navigazione

- **Ricerca in tempo reale**: filtra le cartelle per nome digitando nella barra di ricerca.
- **Ordinamento**: per data di creazione, nome o dimensione.
- **Breadcrumb**: navigazione contestuale sempre visibile nella topbar.

---

## 7. API Reference

### Endpoints di sistema

```
GET  /health                    Health check dell'applicazione
GET  /api/stats                 Statistiche complete del sistema
GET  /disk-space                Informazioni sull'utilizzo del disco
GET  /documentation             Pagina di documentazione web
GET  /download_documentation    Download PDF della documentazione
```

### Gestione cartelle

```
GET  /                          Dashboard con lista cartelle
GET  /api/folders               Lista cartelle (JSON)
POST /create_folder             Crea una cartella normale
POST /create_encrypted_folder   Crea una cartella cifrata
GET  /search_folders            Ricerca cartelle per nome
GET  /folder/<id>               Visualizza contenuto cartella
GET  /api/folders/recent        Cartelle accedute di recente (JSON)
```

### Gestione file

```
POST /upload                    Upload file in una cartella
GET  /download/<filename>       Download file per nome
GET  /get-file-content/<id>     Contenuto file (per editor)
POST /save-file/<id>            Salva modifiche a un file testuale
POST /delete-file/<id>          Elimina un file
POST /api/files/duplicate-check Verifica file duplicati
```

### Cartelle cifrate

```
POST /verify_encrypted_folder/<id>    Verifica password e ottieni accesso
GET  /view_encrypted_folder/<id>      Visualizza contenuto decifrato
POST /upload_encrypted_file/<id>      Upload file cifrato
POST /delete-encrypted-file/<id>      Elimina file da cartella cifrata
```

### Backup e manutenzione

```
GET  /backup/create             Crea un backup del database
```

### Rate limiting

| Endpoint | Limite |
|---|---|
| Generale | 200/giorno, 50/ora |
| Creazione cartelle | 10/minuto |
| Upload file | 30/minuto |
| Accesso cartelle cifrate | 5/minuto |
| Verifica password | 10/minuto |
| Ricerca | 30/minuto |
| Backup database | 1/ora |

---

## 8. Sicurezza

### Architettura

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Client    │    │   Flask Server   │    │   MySQL DB      │
│                 │    │                  │    │                 │
│  HTTPS only     │◄──►│  Rate limiting   │◄──►│  Connessioni    │
│  CSP headers    │    │  Input validation│    │  cifrate        │
│  XSS protect    │    │  Audit logging   │    │  User isolation │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Implementazione della cifratura

```python
# Derivazione chiave
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,           # chiave a 256 bit
        salt=salt,           # salt univoco per cartella
        iterations=150000,   # protezione contro brute force
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Cifratura AES-256-CFB
def encrypt(message: str, password: str) -> tuple:
    salt = os.urandom(16)        # salt casuale
    key  = derive_key(password, salt)
    iv   = os.urandom(16)        # initialization vector casuale
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    # ... logica di cifratura
```

### Validazione file

```python
# Estensioni bloccate per sicurezza
DANGEROUS_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.com', '.pif',
    '.scr', '.vbs', '.js', '.msi', '.dll'
]
```

### Checklist di hardening

- Hashing password con PBKDF2 e salt
- Cookie `Secure` e `HttpOnly`
- Sanitizzazione rigorosa degli input
- Query parametrizzate (prevenzione SQL injection)
- Content Security Policy (prevenzione XSS)
- Validazione CSRF token
- Validazione tipo e dimensione file in upload
- Rate limiting per prevenzione brute force
- Audit logging per conformità
- Error handling senza information disclosure

---

## 9. Monitoraggio e analytics

### Metriche disponibili

Endpoint: `GET /api/stats`

```json
{
  "overview": {
    "total_folders": 25,
    "total_encrypted_folders": 8,
    "total_files": 143,
    "total_size_bytes": 2457600
  },
  "recent_activity": [...]
}
```

### Health check

```bash
curl http://localhost:5000/health
```

Risposta attesa:

```json
{
  "status": "healthy",
  "database": "connected",
  "timestamp": "2025-09-22T00:00:00.000000",
  "version": "2.0"
}
```

### Audit logging

Ogni azione viene registrata con:

| Campo | Descrizione |
|---|---|
| `user_ip` | Indirizzo IP della richiesta |
| `timestamp` | Data e ora precise |
| `action` | Tipo di operazione |
| `resource` | Risorsa coinvolta |
| `details` | Informazioni aggiuntive |

I log vengono conservati per 30 giorni e rimossi automaticamente.

---

## 10. Manutenzione

### Backup

```bash
# Backup tramite endpoint HTTP
curl http://localhost:5000/backup/create

# Automazione con cron (ogni giorno alle 02:00)
0 2 * * * curl -s http://localhost:5000/backup/create

# Backup manuale con lo script incluso
chmod +x backup.sh
./backup.sh
```

### Pulizia automatica

Il sistema esegue le seguenti operazioni in background:

| Operazione | Frequenza |
|---|---|
| Rimozione log > 30 giorni | Ogni ora |
| Rimozione statistiche > 1 anno | Giornaliera |
| Pulizia file temporanei | Settimanale |
| Ottimizzazione tabelle database | Mensile |

### Monitoraggio spazio disco

```bash
# Controlla lo spazio disponibile
df -h /percorso/iris-ve

# Monitoraggio continuo (aggiornamento ogni 60s)
watch -n 60 'df -h | grep iris-ve'
```

### Performance tuning MySQL

```sql
-- Parametri consigliati
SET GLOBAL innodb_buffer_pool_size = 512M;
SET GLOBAL query_cache_size        = 128M;
SET GLOBAL max_connections         = 200;
SET GLOBAL innodb_log_file_size    = 256M;

-- Indici personalizzati (se necessario)
CREATE INDEX idx_file_upload_date ON file(uploaded_at DESC);
CREATE INDEX idx_audit_user_action ON audit_logs(user_ip, action);
```

---

## 11. Troubleshooting

### Errore di connessione al database

```bash
# Verifica che il servizio MySQL sia attivo
systemctl status mysql
sudo systemctl start mysql

# Test della connessione
mysql -u root -p python -e "SELECT 1;"

# Controlla la stringa di connessione in app.py
grep SQLALCHEMY_DATABASE_URI app.py
```

### Errori di permessi

```bash
# Correggi i permessi delle directory
sudo chown -R www-data:www-data /percorso/iris-ve
chmod 755 uploads backups logs
chmod 644 app.py requirements.txt

# Se SELinux è attivo
sudo setsebool -P httpd_can_network_connect 1
```

### Problemi di memoria

```bash
# Monitora l'utilizzo delle risorse
htop
free -h

# Ottimizzazioni Python
export PYTHONUNBUFFERED=1
export MALLOC_ARENA_MAX=2

# Riduzione dei worker Gunicorn
gunicorn --max-requests 1000 --max-requests-jitter 100
```

### Certificati SSL/TLS

```bash
# Generazione certificato con Certbot
sudo certbot --nginx -d tuo-dominio.com

# Verifica il certificato
openssl x509 -in /etc/ssl/certs/iris-ve.crt -text -noout

# Test della connessione HTTPS
curl -I https://tuo-dominio.com
```

### Analisi dei log

```bash
# Log dell'applicazione
tail -f logs/iris_ve.log

# Log Nginx
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Log MySQL
tail -f /var/log/mysql/error.log

# Log del servizio systemd
journalctl -u iris-ve -f
```

### Debug mode

```python
# Solo per ambienti di sviluppo — non usare mai in produzione
app.run(debug=True)

# Logging avanzato
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## 12. Aggiornamenti

### Procedura di aggiornamento

```bash
# 1. Crea un backup prima di procedere
cp -r iris-ve iris-ve-backup-$(date +%Y%m%d)

# 2. Scarica e decomprimi la nuova versione in una directory temporanea

# 3. Aggiorna le dipendenze Python
pip install -r requirements.txt --upgrade

# 4. Applica eventuali migrazioni del database fornite con l'aggiornamento

# 5. Testa in un ambiente di staging

# 6. Effettua il deploy in produzione
systemctl stop iris-ve
cp -r iris-ve-new/* iris-ve/
systemctl start iris-ve

# 7. Verifica che il sistema funzioni correttamente
curl http://localhost:5000/health
```

### Procedura di rollback

```bash
systemctl stop iris-ve
rm -rf iris-ve
mv iris-ve-backup-YYYYMMDD iris-ve
systemctl start iris-ve
```

---

## 13. Licenza

IRIS-VE v2.0 è rilasciato sotto licenza MIT.

```
MIT License

Copyright (c) 2025 Riccardo Vincenzi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

*IRIS-VE v2.0 — Ultima revisione: marzo 2026*
