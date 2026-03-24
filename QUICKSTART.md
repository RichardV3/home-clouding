# 🚀 IRIS-VE v2.0 - Quick Start Guide

## 📋 Pre-requisiti

- **Python 3.8+** (raccomandato 3.11+)
- **MySQL 8.0+** o MariaDB 10.5+
- **wkhtmltopdf** per generazione PDF
- **4GB RAM** e **10GB spazio disco**

## ⚡ Installazione Express (5 minuti)

```bash
# 1. Estrazione e setup
unzip iris-ve-v2-apple-complete-*.zip
cd iris-ve-v2-apple-complete
chmod +x setup.sh
./setup.sh

# 2. Configurazione database
mysql -u root -p
CREATE DATABASE python CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'iris_ve'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON python.* TO 'iris_ve'@'localhost';
FLUSH PRIVILEGES;
exit

# 3. Inizializzazione schema
mysql -u root -p python < database_setup.sql

# 4. Configurazione app
nano app.py  # Modifica riga 28 con i tuoi dati database

# 5. Avvio
source venv/bin/activate
python app.py

# 6. Test
curl http://localhost:5000/health
```

## 🎯 Primo Utilizzo

1. **Accedi** a `http://localhost:5000`
2. **Crea** la tua prima cartella normale
3. **Carica** alcuni file di test
4. **Crea** una cartella crittografata sicura
5. **Esplora** le funzionalità avanzate

## 🔧 Configurazione Avanzata

### Database Ottimizzato
```sql
-- Performance tuning MySQL per IRIS-VE
SET GLOBAL innodb_buffer_pool_size = 512M;
SET GLOBAL query_cache_size = 128M;
SET GLOBAL max_connections = 200;
```

### Produzione con Nginx
```bash
# 1. Installa Nginx
sudo apt install nginx  # Ubuntu/Debian
sudo yum install nginx  # CentOS/RHEL

# 2. Configura IRIS-VE
sudo cp configs/nginx.conf /etc/nginx/sites-available/iris-ve
sudo ln -s /etc/nginx/sites-available/iris-ve /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 3. Avvia con Gunicorn
gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

### Systemd Service
```bash
# 1. Installa service
sudo cp configs/iris-ve.service /etc/systemd/system/
sudo systemctl daemon-reload

# 2. Avvia servizio
sudo systemctl enable iris-ve
sudo systemctl start iris-ve
sudo systemctl status iris-ve
```

## 📊 Monitoraggio

### Health Check
```bash
# Verifica stato applicazione
curl http://localhost:5000/health

# Risposta attesa:
{
  "status": "healthy",
  "database": "connected", 
  "timestamp": "2025-09-22T00:00:00.000000",
  "version": "2.0"
}
```

### Statistiche Sistema
```bash
# Metriche complete
curl http://localhost:5000/api/stats | jq

# Spazio disco
curl http://localhost:5000/disk-space | jq
```

### Log Analysis
```bash
# Application logs
tail -f logs/iris_ve.log

# Audit logs (tramite database)
mysql -u root -p python -e "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10;"
```

## 🔒 Sicurezza

### Rate Limiting
- **Cartelle normali**: 10/minuto
- **Cartelle crittografate**: 5/minuto  
- **Upload file**: 30/minuto
- **API generale**: 200/giorno, 50/ora

### File Sicurezza
```bash
# Verifica permessi
ls -la uploads/ backups/ logs/
# Dovrebbe mostrare: drwxr-xr-x

# Fix permessi se necessario
chmod 755 uploads backups logs
chown -R www-data:www-data /path/to/iris-ve  # Produzione
```

### SSL/HTTPS Setup
```bash
# Con Let's Encrypt
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
sudo systemctl reload nginx
```

## 🛠 Troubleshooting Rapido

### Database Connection Error
```bash
# Test connessione
mysql -u iris_ve -p python -e "SELECT 1;"

# Verifica configurazione
grep SQLALCHEMY_DATABASE_URI app.py
```

### Memory Issues
```bash
# Monitoring
htop
free -h

# Ottimizzazione
export PYTHONUNBUFFERED=1
```

### Permission Errors
```bash
sudo chown -R $(whoami):$(whoami) /path/to/iris-ve
chmod +x setup.sh
chmod 755 uploads backups logs
```

## 📱 Features Highlight

### 🎨 Design Apple
- **SF Pro Display** font nativo
- **Sistema colori** dinamico
- **Dark mode** automatico
- **Animazioni fluide**
- **Layout responsive**

### 🔐 Sicurezza Enterprise
- **AES-256** crittografia
- **PBKDF2** key derivation
- **Audit logging** completo
- **Rate limiting** intelligente
- **File validation** automatica

### ⚡ Performance
- **< 100ms** response time
- **Connection pooling** database
- **Multi-level caching** 
- **Background tasks**
- **Query optimization**

## 🆘 Supporto Veloce

### Comandi Utili
```bash
# Restart completo
sudo systemctl restart iris-ve nginx mysql

# Reset password database (emergency)
mysql -u root -p -e "ALTER USER 'iris_ve'@'localhost' IDENTIFIED BY 'new_password';"

# Backup manuale
curl http://localhost:5000/backup/create

# Clear cache
rm -rf __pycache__ .pytest_cache
```

### Log Locations
- **App**: `logs/iris_ve.log`
- **Nginx**: `/var/log/nginx/iris_ve_*.log`
- **MySQL**: `/var/log/mysql/error.log`
- **System**: `journalctl -u iris-ve`

---

**✅ IRIS-VE v2.0 pronto!** Enjoy your Apple-inspired cloud storage! 🌸

*Per assistenza: consulta `documentation.md` o visita `/documentation` nell'app*
