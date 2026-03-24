#!/bin/bash

# IRIS-VE v2.0 Setup Script - Apple Design Edition
echo "🚀 IRIS-VE v2.0 Setup Script"
echo "=================================="
echo "📱 Con design Apple-inspired"
echo ""

# Colori per output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Funzioni helper
success() {
    echo -e "${GREEN}✅ $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Controllo prerequisiti
info "Verifica prerequisiti sistema..."

# Verifica Python
if ! command -v python3 &> /dev/null; then
    error "Python 3 non trovato. Installare Python 3.8+"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
info "Python versione: $PYTHON_VERSION"

# Verifica pip
if ! command -v pip3 &> /dev/null; then
    error "pip3 non trovato. Installare pip"
    exit 1
fi

# Verifica MySQL
if ! command -v mysql &> /dev/null; then
    warning "MySQL client non trovato. Installare mysql-client per funzionalità complete"
fi

success "Prerequisiti verificati"

# Crea virtual environment
info "📦 Creazione virtual environment..."
if [ -d "venv" ]; then
    warning "Virtual environment esistente trovato"
    read -p "Vuoi ricrearlo? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf venv
        python3 -m venv venv
    fi
else
    python3 -m venv venv
fi

# Attiva virtual environment
info "🔧 Attivazione virtual environment..."
source venv/bin/activate || {
    error "Errore nell'attivazione del virtual environment"
    exit 1
}

success "Virtual environment attivo"

# Upgrade pip
info "📦 Aggiornamento pip..."
pip install --upgrade pip

# Installa dipendenze
info "📦 Installazione dipendenze Python..."
pip install -r requirements.txt || {
    error "Errore nell'installazione delle dipendenze"
    echo "Verifica che requirements.txt sia presente e corretto"
    exit 1
}

success "Dipendenze Python installate"

# Crea directory necessarie
info "📁 Creazione directory sistema..."
mkdir -p uploads backups logs templates static
chmod 755 uploads backups logs
chmod 644 templates/* 2>/dev/null || true

success "Directory create"

# Verifica wkhtmltopdf
info "🔍 Verifica wkhtmltopdf per generazione PDF..."
if ! command -v wkhtmltopdf &> /dev/null; then
    warning "wkhtmltopdf non trovato"
    echo "   Per generazione PDF, installa wkhtmltopdf:"
    echo "   📦 Ubuntu/Debian: sudo apt-get install wkhtmltopdf"
    echo "   📦 CentOS/RHEL: sudo yum install wkhtmltopdf"
    echo "   📦 macOS: brew install wkhtmltopdf"
    echo "   📦 Windows: Scarica da https://wkhtmltopdf.org/downloads.html"
else
    success "wkhtmltopdf installato: $(wkhtmltopdf --version | head -n1)"
fi

# Configurazione database
echo ""
echo "🗄️  CONFIGURAZIONE DATABASE"
echo "=========================="
info "Configura la connessione MySQL in app.py:"
echo "   Riga 28: app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://user:password@host:port/database'"
echo ""
info "Per creare il database:"
echo "   mysql -u root -p"
echo "   CREATE DATABASE python CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
echo "   exit"
echo ""
info "Per inizializzare lo schema:"
echo "   mysql -u root -p python < database_setup.sql"
echo ""

# Configurazione sicurezza
echo "🔐 CONFIGURAZIONE SICUREZZA"
echo "========================="
info "Il sistema include sicurezza avanzata:"
echo "   🛡️  Rate limiting automatico"
echo "   🔒 Crittografia AES-256 per cartelle sicure"
echo "   📝 Audit logging completo"
echo "   🚫 Validazione file per sicurezza"
echo "   🔑 Backup automatico file eliminati"
echo ""

# Test installazione
info "🧪 Test installazione..."
python3 -c "
try:
    import flask, flask_sqlalchemy, flask_limiter, flask_caching
    import cryptography, markdown, pdfkit
    print('✅ Importazioni principali: OK')
except ImportError as e:
    print(f'❌ Errore importazione: {e}')
    exit(1)
"

# Informazioni avvio
echo ""
echo "🎉 INSTALLAZIONE COMPLETATA!"
echo "============================"
echo ""
success "IRIS-VE v2.0 è pronto all'uso!"
echo ""
echo "📋 PROSSIMI PASSI:"
echo "1. 🗄️  Configura database MySQL in app.py"
echo "2. 🔧 Esegui database_setup.sql per inizializzare schema"
echo "3. 🚀 Avvia applicazione:"
echo ""
echo "   ${BLUE}# Modalità sviluppo${NC}"
echo "   source venv/bin/activate"
echo "   python app.py"
echo ""
echo "   ${BLUE}# Modalità produzione${NC}"
echo "   source venv/bin/activate"
echo "   gunicorn -w 4 -b 0.0.0.0:5000 app:app"
echo ""
echo "4. 🌐 Accedi a: http://localhost:5000"
echo ""
echo "📚 CARATTERISTICHE v2.0:"
echo "   🎨 Design Apple-inspired con SF Pro Display"
echo "   🔒 Cartelle crittografate AES-256"
echo "   ⚡ Performance ottimizzate con caching"
echo "   📊 Dashboard statistiche real-time"
echo "   🛡️  Sicurezza enterprise-grade"
echo "   📱 UI responsive per tutti i dispositivi"
echo ""
echo "📖 Per documentazione completa: http://localhost:5000/documentation"
echo ""
info "Buon lavoro con IRIS-VE! 🌸"
