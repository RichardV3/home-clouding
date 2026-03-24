FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create necessary directories
RUN mkdir -p uploads backups logs

# Expose port
EXPOSE 5000

# Health check — usa /health che non richiede auth
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run with eventlet worker (richiesto da Flask-SocketIO per WebSocket)
# --timeout 600 per supportare upload fino a 15 GB
# --worker-connections 1000 per gestire connessioni WS concorrenti
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--worker-class", "eventlet", \
     "--workers", "1", \
     "--worker-connections", "1000", \
     "--timeout", "600", \
     "--keep-alive", "5", \
     "--log-level", "warning", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
