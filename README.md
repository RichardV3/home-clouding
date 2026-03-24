# IRIS-VE v2.0

**Cloud storage personale self-hosted con cifratura AES-256 e interfaccia glassmorphism.**

---

## Caratteristiche

- **Cifratura AES-256-CFB** — cartelle protette con derivazione chiave PBKDF2 a 150.000 iterazioni
- **Design glassmorphism** — interfaccia dark/light moderna, completamente responsive
- **Upload drag & drop** — supporto file fino a 500 MB con barra di avanzamento in tempo reale
- **Analytics integrati** — dashboard statistiche, health check, audit logging completo
- **Rate limiting** — protezione automatica contro abusi e attacchi brute force
- **Accesso FTP** — disponibile sulla porta 2121

---

## Installazione rapida

```bash
# 1. Entra nella directory del progetto
cd iris-ve

# 2. Esegui il setup automatico
chmod +x setup.sh
./setup.sh

# 3. Configura la connessione al database in app.py (riga 28)

# 4. Inizializza il database
mysql -u root -p python < database_setup.sql

# 5. Avvia l'applicazione
source venv/bin/activate
python app.py

# Accedi su http://localhost:5000
```

---

## Requisiti

| Componente | Versione minima |
|---|---|
| Python | 3.8 (consigliato 3.11+) |
| MySQL / MariaDB | 8.0 / 10.5 |
| RAM | 4 GB |
| Disco | 10 GB SSD |

---

## Stack tecnologico

- **Backend**: Python / Flask, SQLAlchemy, Flask-Limiter, Flask-Caching, `cryptography`
- **Frontend**: Jinja2, Bootstrap 5, Bootstrap Icons, IRIS-VE Design System (CSS custom)
- **Database**: MySQL / MariaDB
- **Produzione**: Gunicorn + Nginx

---

## Sicurezza

| Parametro | Valore |
|---|---|
| Algoritmo di cifratura | AES-256-CFB |
| Derivazione chiave | PBKDF2-SHA256 |
| Iterazioni | 150.000 |
| Salt | 16 byte casuali per cartella |
| IV | 16 byte casuali per messaggio |
| Memorizzazione password | Mai (zero-knowledge) |

---

## Monitoraggio

```bash
# Health check
curl http://localhost:5000/health

# Statistiche di sistema
curl http://localhost:5000/api/stats

# Backup database
curl http://localhost:5000/backup/create
```

---

## Documentazione

La documentazione tecnica completa è disponibile in `documentation.md` e accessibile via web all'endpoint `/documentation`.

---

*IRIS-VE v2.0 — Sviluppato da Riccardo Vincenzi*