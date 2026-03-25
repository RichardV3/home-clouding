#!/bin/bash
# ============================================================================
# IRIS-VE — Installazione MinIO nativa (senza Docker)
# ============================================================================
# Uso:
#   chmod +x setup_minio.sh
#   ./setup_minio.sh
#
# Questo script:
#   1. Scarica MinIO server
#   2. Crea le cartelle dati
#   3. Crea un servizio systemd (opzionale)
#   4. Avvia MinIO
# ============================================================================

set -e

MINIO_USER="minioadmin"
MINIO_PASS="minioadmin"
MINIO_DATA_DIR="$HOME/minio-data"
MINIO_PORT=9000
MINIO_CONSOLE_PORT=9001
MINIO_BIN="/usr/local/bin/minio"

echo "═══════════════════════════════════════════════════════"
echo "  IRIS-VE — Setup MinIO locale"
echo "═══════════════════════════════════════════════════════"

# ─── Detect OS & Architecture ─────────────────────────────
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

case "$ARCH" in
    x86_64)  ARCH_DL="amd64" ;;
    aarch64) ARCH_DL="arm64" ;;
    armv7l)  ARCH_DL="arm"   ;;
    *)
        echo "❌ Architettura non supportata: $ARCH"
        exit 1
        ;;
esac

DOWNLOAD_URL="https://dl.min.io/server/minio/release/${OS}-${ARCH_DL}/minio"

# ─── Download MinIO ───────────────────────────────────────
if [ -f "$MINIO_BIN" ]; then
    echo "✅ MinIO già installato in $MINIO_BIN"
    $MINIO_BIN --version
else
    echo "📥 Download MinIO da $DOWNLOAD_URL..."
    sudo curl -fsSL "$DOWNLOAD_URL" -o "$MINIO_BIN"
    sudo chmod +x "$MINIO_BIN"
    echo "✅ MinIO installato: $($MINIO_BIN --version)"
fi

# ─── Crea cartella dati ───────────────────────────────────
mkdir -p "$MINIO_DATA_DIR"
echo "📁 Cartella dati: $MINIO_DATA_DIR"

# ─── Verifica porte libere ────────────────────────────────
check_port() {
    if ss -tlnp 2>/dev/null | grep -q ":$1 "; then
        echo "⚠️  Porta $1 già in uso!"
        echo "   Controlla con: sudo lsof -i :$1"
        echo "   Se è il tuo EXTERNAL_PORT di IRIS-VE, cambialo nel file env"
        return 1
    fi
    return 0
}

check_port $MINIO_PORT || true
check_port $MINIO_CONSOLE_PORT || true

# ─── Crea servizio systemd (opzionale) ────────────────────
read -p "Vuoi creare un servizio systemd per avvio automatico? [y/N] " CREATE_SERVICE

if [[ "$CREATE_SERVICE" =~ ^[Yy]$ ]]; then
    SERVICE_FILE="/etc/systemd/system/minio.service"
    sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=MinIO Object Storage
Documentation=https://min.io/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
Environment="MINIO_ROOT_USER=$MINIO_USER"
Environment="MINIO_ROOT_PASSWORD=$MINIO_PASS"
ExecStart=$MINIO_BIN server $MINIO_DATA_DIR --address ":$MINIO_PORT" --console-address ":$MINIO_CONSOLE_PORT"
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable minio
    sudo systemctl start minio
    echo "✅ Servizio minio creato e avviato"
    echo "   Comandi utili:"
    echo "   sudo systemctl status minio     # stato"
    echo "   sudo systemctl restart minio    # riavvia"
    echo "   sudo journalctl -u minio -f     # log in tempo reale"
else
    echo ""
    echo "Per avviare MinIO manualmente:"
    echo ""
    echo "  MINIO_ROOT_USER=$MINIO_USER MINIO_ROOT_PASSWORD=$MINIO_PASS \\"
    echo "    minio server $MINIO_DATA_DIR \\"
    echo "    --address ':$MINIO_PORT' --console-address ':$MINIO_CONSOLE_PORT'"
    echo ""
fi

# ─── Summary ──────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ✅ MinIO pronto!"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  🌐 Console Web:  http://localhost:$MINIO_CONSOLE_PORT"
echo "  🔌 API S3:       http://localhost:$MINIO_PORT"
echo "  👤 Username:     $MINIO_USER"
echo "  🔑 Password:     $MINIO_PASS"
echo "  📁 Dati in:      $MINIO_DATA_DIR"
echo ""
echo "  Prossimi passi per IRIS-VE:"
echo "  1. Copia env_minio come 'env' nella cartella del progetto"
echo "  2. Se hai file esistenti: python migrate_to_s3.py --dry-run"
echo "  3. Poi: python migrate_to_s3.py"
echo "  4. Avvia IRIS-VE: python app.py"
echo ""
echo "═══════════════════════════════════════════════════════"
