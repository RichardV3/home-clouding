# IRIS-VE v2.0 - Cloud Storage Encrypted
# Improved: Security fixes, performance optimizations, FTP server, new endpoints
# Author: Riccardo Vincenzi

from flask import Flask, request, render_template, redirect, url_for, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

from datetime import datetime, timedelta
from functools import wraps
import os
import socket
import requests
import logging
from logging.handlers import RotatingFileHandler
import hashlib
import zipfile
import shutil
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from dotenv import load_dotenv

# Load .env / env file before reading any os.environ variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'env'))

# ============================================================================
# CONFIGURATION
# ============================================================================

app = Flask(__name__, template_folder='templates', static_folder='static')

# Security — SECRET_KEY must be set in environment (min 32 chars)
_secret = os.environ.get('SECRET_KEY')
if not _secret or len(_secret) < 32:
    raise RuntimeError(
        "SECRET_KEY non impostato o troppo corto (minimo 32 caratteri). "
        "Generane uno con: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.config['SECRET_KEY'] = _secret

# Admin credentials (read from env at startup)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'changeme_insecure_default'))

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'mysql+pymysql://root:root@localhost/iris_ve'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 20,
    'pool_timeout': 20,
    'pool_recycle': 3600,   # Recycle connections every 1 hour (was -1 → stale connections)
    'pool_pre_ping': True
}

# File Upload — 15 GB limit, all extensions allowed
app.config['MAX_CONTENT_LENGTH'] = 15 * 1024 * 1024 * 1024  # 15 GB
app.config['MAX_FORM_MEMORY_SIZE'] = 0  # Never buffer uploads in RAM — always stream to disk

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
BACKUP_FOLDER = os.path.join(os.path.dirname(__file__), 'backups')
LOG_FOLDER = os.path.join(os.path.dirname(__file__), 'logs')
STATIC_FOLDER = os.path.join(os.path.dirname(__file__), 'static')

# Cache
app.config['CACHE_TYPE'] = 'simple'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300

# Session
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Create folders
for folder in [UPLOAD_FOLDER, BACKUP_FOLDER, LOG_FOLDER, STATIC_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# ProxyFix for external access
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Extensions
db = SQLAlchemy(app)
cache = Cache(app)
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
limiter.init_app(app)

# ============================================================================
# LOGGING
# ============================================================================

if not app.debug:
    file_handler = RotatingFileHandler(
        os.path.join(LOG_FOLDER, 'iris_ve.log'),
        maxBytes=10 * 1024 * 1024,
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

logger = logging.getLogger(__name__)


# ============================================================================
# DATABASE MODELS
# ============================================================================

class Folder(db.Model):
    __tablename__ = 'folders'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    icon = db.Column(db.String(64), nullable=True, default='bi-folder-fill')
    is_encrypted = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(255), nullable=True)
    salt = db.Column(db.String(255), nullable=True)  # kept for schema compatibility
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    files = db.relationship('File', backref='folder', lazy=True, cascade='all, delete-orphan')
    logs = db.relationship('ActionLog', backref='folder', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        """Hash password using werkzeug PBKDF2-SHA256"""
        self.password_hash = generate_password_hash(password)
        # salt column no longer used — werkzeug stores salt inside the hash string

    def check_password(self, password):
        """Verify password"""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def to_dict_base(self):
        """Base dict without files_count (avoids N+1 — count passed separately)"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'icon': self.icon or 'bi-folder-fill',
            'is_encrypted': self.is_encrypted,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }

    def to_dict(self):
        """Full dict with files_count via subquery"""
        from sqlalchemy import func
        files_count = db.session.query(func.count(File.id)).filter(
            File.folder_id == self.id
        ).scalar()
        d = self.to_dict_base()
        d['files_count'] = files_count
        return d


class File(db.Model):
    __tablename__ = 'files'
    __table_args__ = (
        db.Index('ix_files_folder_id', 'folder_id'),
    )

    id = db.Column(db.Integer, primary_key=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=True)
    size = db.Column(db.BigInteger, nullable=False)
    mime_type = db.Column(db.String(100), nullable=True)
    file_path = db.Column(db.String(512), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_encrypted = db.Column(db.Boolean, default=False)
    logs = db.relationship('ActionLog', backref='file', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.original_name or self.name,
            'size': self.size,
            'mime_type': self.mime_type,
            'created_at': self.created_at.isoformat(),
            'is_encrypted': self.is_encrypted
        }


class ActionLog(db.Model):
    __tablename__ = 'action_logs'
    __table_args__ = (
        db.Index('ix_action_logs_timestamp', 'timestamp'),
        db.Index('ix_action_logs_folder_id', 'folder_id'),
    )

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(50), nullable=False)
    resource_type = db.Column(db.String(50), nullable=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'resource_type': self.resource_type,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_file_icon(filename):
    """Get Bootstrap icon class for file"""
    ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''

    icon_map = {
        ('txt', 'doc', 'docx', 'pdf'): 'bi-file-text',
        ('jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp'): 'bi-file-image',
        ('mp4', 'avi', 'mkv', 'mov', 'wmv'): 'bi-file-play',
        ('mp3', 'wav', 'flac', 'aac', 'm4a'): 'bi-file-music',
        ('zip', 'rar', '7z', 'tar', 'gz'): 'bi-file-zip',
        ('csv', 'xlsx', 'xls'): 'bi-file-spreadsheet',
        ('py', 'js', 'html', 'css', 'json', 'xml'): 'bi-file-code'
    }

    for exts, icon in icon_map.items():
        if ext in exts:
            return icon
    return 'bi-file-earmark'


def get_file_icon_class(filename):
    """Get CSS class for file icon color"""
    ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
    if ext in ('txt', 'doc', 'docx', 'pdf', 'md'):
        return 'file-icon-doc'
    if ext in ('jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp'):
        return 'file-icon-img'
    if ext in ('mp4', 'avi', 'mkv', 'mov', 'wmv'):
        return 'file-icon-video'
    if ext in ('mp3', 'wav', 'flac', 'aac', 'm4a'):
        return 'file-icon-audio'
    if ext in ('zip', 'rar', '7z', 'tar', 'gz'):
        return 'file-icon-archive'
    if ext in ('py', 'js', 'ts', 'html', 'css', 'json', 'xml', 'java', 'cpp', 'c', 'sh'):
        return 'file-icon-code'
    return 'file-icon-default'


def format_bytes(size_bytes):
    """Format bytes to human-readable string"""
    if not size_bytes:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            # Show integer for bytes, 1 decimal for larger units
            return f"{size_bytes:.0f} {unit}" if unit == 'B' else f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# Register helper functions as Jinja2 template globals
app.jinja_env.globals.update(
    get_file_icon=get_file_icon,
    get_file_icon_class=get_file_icon_class,
    format_bytes=format_bytes,
)


def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_public_ip():
    """Get public IP address"""
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        return response.json()['ip']
    except Exception:
        try:
            response = requests.get('https://checkip.amazonaws.com', timeout=5)
            return response.text.strip()
        except Exception:
            return "IP pubblico non rilevato"


def log_action(action, resource_type=None, resource_id=None, details=None):
    """Log user action"""
    try:
        log = ActionLog(
            action=action,
            resource_type=resource_type,
            folder_id=resource_id if resource_type == 'folder' else None,
            file_id=resource_id if resource_type == 'file' else None,
            details=details,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Error logging action: {e}")


def allowed_file(_filename):
    """Allow all file types — no extension restriction"""
    return True


def sanitize_name(name: str, max_len: int = 255) -> str:
    """Sanitize folder/file names: strip whitespace and limit length.
    XSS prevention is handled by Jinja2 auto-escaping (server-side)
    and escapeHtml() (client-side) — do NOT store HTML entities in the DB.
    """
    return name.strip()[:max_len]


def encrypt_data(data, password):
    """Encrypt data with password"""
    try:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return base64.b64encode(salt + iv + encrypted_data).decode('utf-8')
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return None


def decrypt_data(encrypted_data, password):
    """Decrypt data with password"""
    try:
        data = base64.b64decode(encrypted_data)
        salt = data[:16]
        iv = data[16:32]
        encrypted = data[32:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(encrypted) + decryptor.finalize()

        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return None


# ============================================================================
# AUTHENTICATION & DECORATORS
# ============================================================================

def login_required(f):
    """Redirect to login page if not authenticated (for page routes)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def api_login_required(f):
    """Return 401 JSON if not authenticated (for API routes)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Non autenticato'}), 401
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# ROUTES - MAIN
# ============================================================================

@app.route('/')
def index():
    """Home page / Login page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """Login with username and password"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['user_id'] = 1
            session.permanent = True
            return redirect(url_for('dashboard'))
        return render_template('index.html', login_error='Credenziali non valide')
    return render_template('index.html')


@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard with folders"""
    try:
        folders = Folder.query.all()
        return render_template('folder.html', folders=folders)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('500.html'), 500


@app.route('/folder/<int:folder_id>')
@login_required
def view_folder(folder_id):
    """View folder contents"""
    try:
        folder = Folder.query.get_or_404(folder_id)

        if folder.is_encrypted:
            locked = not session.get(f'folder_{folder_id}_unlocked', False)
            files = [] if locked else File.query.filter_by(folder_id=folder_id).all()
            return render_template('view_encrypted_folder.html',
                                   folder=folder, files=files,
                                   content='', locked=locked)

        files = File.query.filter_by(folder_id=folder_id).all()
        return render_template('folder.html', folder=folder, files=files)
    except Exception as e:
        logger.error(f"View folder error: {e}")
        return render_template('500.html'), 500


@app.route('/documentation')
@login_required
def documentation():
    """View documentation"""
    try:
        doc_path = os.path.join(os.path.dirname(__file__), 'documentation.md')
        if os.path.exists(doc_path):
            with open(doc_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return render_template('documentation.html', content=content)
        return render_template('documentation.html', content='Documentazione non disponibile')
    except Exception as e:
        logger.error(f"Documentation error: {e}")
        return render_template('500.html'), 500


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/folders', methods=['GET'])
@api_login_required
@cache.cached(timeout=30, key_prefix='all_folders')
def api_get_folders():
    """Get all folders with file count via single JOIN query (no N+1)"""
    try:
        from sqlalchemy import func
        results = db.session.query(
            Folder,
            func.count(File.id).label('files_count')
        ).outerjoin(File, File.folder_id == Folder.id).group_by(Folder.id).all()

        folders_data = []
        for folder, count in results:
            d = folder.to_dict_base()
            d['files_count'] = count
            folders_data.append(d)
        return jsonify(folders_data)
    except Exception as e:
        logger.error(f"Get folders error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/folders', methods=['POST'])
@api_login_required
@limiter.limit("10 per minute")
def api_create_folder():
    """Create new folder"""
    try:
        data = request.get_json()
        name = sanitize_name(data.get('name', ''))
        description = sanitize_name(data.get('description', ''), max_len=1000)
        is_encrypted = data.get('is_encrypted', False)
        password = data.get('password', '')

        if not name or len(name) < 1:
            return jsonify({'success': False, 'message': 'Nome cartella non valido'}), 400

        folder = Folder(name=name, description=description, is_encrypted=is_encrypted)

        if is_encrypted and password:
            folder.set_password(password)

        db.session.add(folder)
        db.session.commit()

        cache.delete('all_folders')
        log_action('create_folder', 'folder', folder.id, f'Created: {name}')

        # Newly created folder always has 0 files — no subquery needed
        d = folder.to_dict_base()
        d['files_count'] = 0
        return jsonify({'success': True, 'folder': d}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create folder error: {e}")
        return jsonify({'success': False, 'message': 'Errore creazione'}), 500


@app.route('/api/folders/<int:folder_id>', methods=['PUT'])
@api_login_required
@limiter.limit("10 per minute")
def api_update_folder(folder_id):
    """Update folder"""
    try:
        folder = Folder.query.get_or_404(folder_id)
        data = request.get_json()

        ALLOWED_ICONS = {
            'bi-folder-fill', 'bi-folder-symlink-fill', 'bi-archive-fill',
            'bi-briefcase-fill', 'bi-camera-fill', 'bi-music-note-beamed',
            'bi-code-slash', 'bi-book-fill', 'bi-film', 'bi-image-fill',
            'bi-shield-lock-fill', 'bi-star-fill', 'bi-heart-fill',
            'bi-cloud-fill', 'bi-database-fill', 'bi-gear-fill',
            'bi-person-fill', 'bi-house-fill', 'bi-lock-fill', 'bi-bookmark-fill',
        }
        if 'name' in data:
            folder.name = sanitize_name(data['name'])
        if 'description' in data:
            folder.description = sanitize_name(data['description'], max_len=1000)
        if 'icon' in data and data['icon'] in ALLOWED_ICONS:
            folder.icon = data['icon']

        db.session.commit()

        cache.delete('all_folders')
        log_action('update_folder', 'folder', folder_id, f'Updated: {folder.name}')

        return jsonify({'success': True, 'folder': folder.to_dict()})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update folder error: {e}")
        return jsonify({'success': False, 'message': 'Errore aggiornamento'}), 500


@app.route('/api/folders/<int:folder_id>', methods=['DELETE'])
@api_login_required
@limiter.limit("10 per minute")
def api_delete_folder(folder_id):
    """Delete folder — collect disk paths first, commit DB, then remove files from disk
    so that a DB failure never leaves orphaned records without physical files."""
    try:
        folder = Folder.query.get_or_404(folder_id)
        folder_name = folder.name

        # Collect paths BEFORE deleting anything
        disk_paths = [
            os.path.join(UPLOAD_FOLDER, f.file_path)
            for f in folder.files
        ]

        # Delete from DB (cascade removes File and ActionLog rows)
        db.session.delete(folder)
        db.session.commit()

        # Only after a successful commit, remove physical files
        for path in disk_paths:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError as oe:
                logger.warning(f"Could not remove file from disk: {path} — {oe}")

        cache.delete('all_folders')
        log_action('delete_folder', 'folder', folder_id, f'Deleted: {folder_name}')

        return jsonify({'success': True, 'message': 'Cartella eliminata'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete folder error: {e}")
        return jsonify({'success': False, 'message': 'Errore eliminazione'}), 500


@app.route('/api/folders/<int:folder_id>/files', methods=['GET'])
@api_login_required
def api_get_files(folder_id):
    """Get files in folder with pagination"""
    try:
        Folder.query.get_or_404(folder_id)
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)
        pagination = File.query.filter_by(folder_id=folder_id).paginate(
            page=page, per_page=per_page, error_out=False
        )
        return jsonify({
            'files': [f.to_dict() for f in pagination.items],
            'total': pagination.total,
            'page': page,
            'pages': pagination.pages,
            'per_page': per_page
        })
    except Exception as e:
        logger.error(f"Get files error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/folders/<int:folder_id>/upload', methods=['POST'])
@api_login_required
@limiter.limit("20 per minute")
def api_upload_file(folder_id):
    """Upload file to folder"""
    try:
        folder = Folder.query.get_or_404(folder_id)

        if 'file' not in request.files:
            logger.error(f"Upload error: No file part in request. Files: {list(request.files.keys())}")
            return jsonify({'success': False, 'message': 'Nessun file trovato'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'success': False, 'message': 'Nome file vuoto'}), 400

        if not allowed_file(file.filename):
            return jsonify({'success': False, 'message': f'Tipo file non consentito: {file.filename}'}), 400

        # Generate unique filename with SHA256
        filename = secure_filename(file.filename)
        file_hash = hashlib.sha256(f"{filename}_{datetime.utcnow().timestamp()}".encode()).hexdigest()
        file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'bin'
        file_path = f"{file_hash}.{file_ext}"

        # Save file
        full_path = os.path.join(UPLOAD_FOLDER, file_path)
        try:
            file.save(full_path)
            file_size = os.path.getsize(full_path)
        except Exception as e:
            logger.error(f"Upload error: Failed to save file: {e}")
            return jsonify({'success': False, 'message': f'Errore nel salvataggio: {e}'}), 500

        # Create database record
        db_file = File(
            folder_id=folder_id,
            name=file_hash,
            original_name=filename,
            size=file_size,
            mime_type=file.content_type or 'application/octet-stream',
            file_path=file_path,
            is_encrypted=folder.is_encrypted
        )

        db.session.add(db_file)
        db.session.commit()

        cache.delete('all_folders')
        log_action('upload_file', 'file', db_file.id, f'Uploaded: {filename} ({file_size} bytes)')
        logger.info(f"✅ File uploaded successfully: {filename} -> {file_path} ({file_size} bytes)")

        return jsonify({'success': True, 'file': db_file.to_dict()}), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Upload error: {e}", exc_info=True)
        return jsonify({'success': False, 'message': f'Errore upload: {str(e)}'}), 500


@app.route('/api/files/<int:file_id>/download', methods=['GET'])
@api_login_required
@limiter.limit("30 per minute")
def api_download_file(file_id):
    """Download file"""
    try:
        file = File.query.get_or_404(file_id)
        file_path = os.path.join(UPLOAD_FOLDER, file.file_path)

        if not os.path.exists(file_path):
            logger.error(f"Download error: File not found at {file_path}")
            return jsonify({'success': False, 'message': 'File non trovato'}), 404

        log_action('download_file', 'file', file_id, f'Downloaded: {file.original_name}')
        logger.info(f"✅ File downloaded: {file.original_name}")

        return send_file(
            file_path,
            as_attachment=True,
            download_name=file.original_name or file.name
        )
    except Exception as e:
        logger.error(f"Download error: {e}")
        return jsonify({'success': False, 'message': 'Errore download'}), 500


@app.route('/api/files/<int:file_id>', methods=['DELETE'])
@api_login_required
@limiter.limit("10 per minute")
def api_delete_file(file_id):
    """Delete file"""
    try:
        file = File.query.get_or_404(file_id)
        file_path = os.path.join(UPLOAD_FOLDER, file.file_path)
        file_name = file.original_name

        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"✅ File deleted from disk: {file_path}")

        db.session.delete(file)
        db.session.commit()

        cache.delete('all_folders')
        log_action('delete_file', 'file', file_id, f'Deleted: {file_name}')

        return jsonify({'success': True, 'message': 'File eliminato'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete file error: {e}")
        return jsonify({'success': False, 'message': 'Errore eliminazione'}), 500


@app.route('/api/files/<int:file_id>/preview', methods=['GET'])
@api_login_required
def api_file_preview(file_id):
    """Return preview data for a file (text, image url, zip listing)"""
    try:
        file = File.query.get_or_404(file_id)
        file_path = os.path.join(UPLOAD_FOLDER, file.file_path)
        filename = file.original_name or file.name
        ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''

        if not os.path.exists(file_path):
            return jsonify({'type': 'unsupported', 'message': 'File non trovato su disco'}), 404

        # Image
        if ext in ('jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'avif'):
            return jsonify({'type': 'image', 'url': f'/api/files/{file_id}/preview-inline'})

        # Text / code
        if ext in ('txt', 'md', 'json', 'xml', 'csv', 'py', 'js', 'ts', 'html',
                   'css', 'sh', 'bash', 'yaml', 'yml', 'toml', 'ini', 'log',
                   'java', 'c', 'cpp', 'h', 'rs', 'go', 'rb', 'php', 'sql'):
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read(100000)  # max 100 KB shown
            return jsonify({'type': 'text', 'content': content, 'ext': ext})

        # ZIP
        if ext == 'zip':
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    all_entries = zf.infolist()
                    total = len(all_entries)
                    contents = [
                        {
                            'name': info.filename,
                            'size': format_bytes(info.file_size),
                            'compressed': format_bytes(info.compress_size),
                            'is_dir': info.filename.endswith('/')
                        }
                        for info in all_entries[:300]
                    ]
                return jsonify({'type': 'zip', 'contents': contents, 'total': total})
            except zipfile.BadZipFile:
                return jsonify({'type': 'unsupported', 'message': 'Archivio ZIP non valido'})

        return jsonify({'type': 'unsupported'})
    except Exception as e:
        logger.error(f"Preview error: {e}")
        return jsonify({'success': False, 'message': 'Errore anteprima'}), 500


@app.route('/api/files/<int:file_id>/preview-inline', methods=['GET'])
@api_login_required
def api_file_preview_inline(file_id):
    """Serve file inline for image preview with correct MIME type"""
    try:
        file = File.query.get_or_404(file_id)
        file_path = os.path.join(UPLOAD_FOLDER, file.file_path)
        if not os.path.exists(file_path):
            return jsonify({'success': False, 'message': 'File non trovato'}), 404
        return send_file(
            file_path,
            as_attachment=False,
            download_name=file.original_name or file.name,
            mimetype=file.mime_type or 'application/octet-stream'
        )
    except Exception as e:
        logger.error(f"Preview inline error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/files/<int:file_id>/zip-extract', methods=['GET'])
@api_login_required
def api_zip_extract(file_id):
    """Extract and download a single file from a ZIP archive"""
    try:
        file = File.query.get_or_404(file_id)
        file_path = os.path.join(UPLOAD_FOLDER, file.file_path)
        filename = file.original_name or file.name
        ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''

        if ext != 'zip':
            return jsonify({'success': False, 'message': 'Non è un file ZIP'}), 400

        inner_path = request.args.get('path', '')
        if not inner_path or inner_path.endswith('/'):
            return jsonify({'success': False, 'message': 'Percorso non valido'}), 400

        if not os.path.exists(file_path):
            return jsonify({'success': False, 'message': 'File non trovato'}), 404

        import io, mimetypes
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                try:
                    zf.getinfo(inner_path)
                except KeyError:
                    return jsonify({'success': False, 'message': 'File non trovato nell\'archivio'}), 404
                data = zf.read(inner_path)
        except zipfile.BadZipFile:
            return jsonify({'success': False, 'message': 'Archivio ZIP non valido'}), 400

        basename = os.path.basename(inner_path)
        mime = mimetypes.guess_type(basename)[0] or 'application/octet-stream'
        return send_file(io.BytesIO(data), as_attachment=True,
                         download_name=basename, mimetype=mime)
    except Exception as e:
        logger.error(f"ZIP extract error: {e}")
        return jsonify({'success': False, 'message': 'Errore estrazione'}), 500


@app.route('/api/folders/<int:folder_id>/encrypt', methods=['POST'])
@api_login_required
@limiter.limit("5 per minute")
def api_unlock_encrypted_folder(folder_id):
    """Unlock encrypted folder"""
    try:
        folder = Folder.query.get_or_404(folder_id)

        if not folder.is_encrypted:
            return jsonify({'success': False, 'message': 'Cartella non criptata'}), 400

        data = request.get_json()
        password = data.get('password', '')

        if not folder.check_password(password):
            return jsonify({'success': False, 'message': 'Password errata'}), 401

        session[f'folder_{folder_id}_unlocked'] = True
        log_action('unlock_folder', 'folder', folder_id, 'Unlocked encrypted folder')

        return jsonify({'success': True, 'message': 'Cartella sbloccata'})
    except Exception as e:
        logger.error(f"Unlock folder error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/documentation', methods=['GET'])
@api_login_required
def api_get_documentation():
    """Get documentation content"""
    try:
        doc_path = os.path.join(os.path.dirname(__file__), 'documentation.md')
        if os.path.exists(doc_path):
            with open(doc_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return jsonify({'success': True, 'content': content})
        return jsonify({'success': True, 'content': 'Documentazione non disponibile'})
    except Exception as e:
        logger.error(f"Get documentation error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


# ============================================================================
# UTILITY & MONITORING ENDPOINTS
# ============================================================================

@app.route('/health')
def health_check():
    """Health check endpoint — no auth required for monitoring systems"""
    try:
        db.session.execute(db.text('SELECT 1'))
        db_status = 'ok'
    except Exception:
        db_status = 'error'
    status = 'ok' if db_status == 'ok' else 'degraded'
    return jsonify({
        'status': status,
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat()
    }), 200 if status == 'ok' else 503


@app.route('/api/stats')
@api_login_required
def api_stats():
    """System statistics: folder/file counts, total size"""
    try:
        from sqlalchemy import func
        folder_count = db.session.query(func.count(Folder.id)).scalar() or 0
        file_count = db.session.query(func.count(File.id)).scalar() or 0
        total_size = db.session.query(func.sum(File.size)).scalar() or 0
        return jsonify({
            'folders': folder_count,
            'files': file_count,
            'total_size_bytes': total_size,
            'total_size_human': format_bytes(total_size)
        })
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({'success': False, 'message': 'Errore statistiche'}), 500


@app.route('/api/disk-space')
@api_login_required
def api_disk_space():
    """Disk space usage for the uploads folder"""
    try:
        total, used, free = shutil.disk_usage(UPLOAD_FOLDER)
        return jsonify({
            'total': total,
            'used': used,
            'free': free,
            'total_human': format_bytes(total),
            'used_human': format_bytes(used),
            'free_human': format_bytes(free),
            'percent_used': round((used / total) * 100, 1)
        })
    except Exception as e:
        logger.error(f"Disk space error: {e}")
        return jsonify({'success': False, 'message': 'Errore disco'}), 500


@app.route('/api/network-info')
@api_login_required
@cache.cached(timeout=300, key_prefix='network_info')
def api_network_info():
    """Network information: local IP, public IP, configured ports"""
    try:
        local_ip = get_local_ip()
        public_ip = get_public_ip()
        http_port = int(os.environ.get('EXTERNAL_PORT', 9000))
        ftp_port = int(os.environ.get('FTP_PORT', 2121))
        return jsonify({
            'local_ip': local_ip,
            'public_ip': public_ip,
            'http_port': http_port,
            'ftp_port': ftp_port,
            'local_url': f'http://{local_ip}:{http_port}',
            'public_url': f'http://{public_ip}:{http_port}'
        })
    except Exception as e:
        logger.error(f"Network info error: {e}")
        return jsonify({'success': False, 'message': 'Errore rete'}), 500


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def page_not_found(e):
    try:
        log_action('404_error', details=f'URL: {request.url}')
    except Exception as log_err:
        logger.debug(f"Could not log 404 action: {log_err}")
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 error at {request.url}: {e}")
    try:
        log_action('500_error', details=f'URL: {request.url}')
    except Exception as log_err:
        logger.debug(f"Could not log 500 action: {log_err}")
    return render_template('500.html'), 500


@app.errorhandler(413)
def file_too_large(e):
    logger.error(f"Error 413: File too large")
    return jsonify({'success': False, 'message': 'File troppo grande (max 15 GB)'}), 413


@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Error 429: Rate limit exceeded")
    return jsonify({'success': False, 'message': 'Troppi tentativi, riprova tra poco'}), 429


# ============================================================================
# FTP SERVER (optional — controlled by FTP_ENABLED env var)
# ============================================================================

def start_ftp_server():
    """Start pyftpdlib FTP server — call in a daemon thread or separate process"""
    try:
        from pyftpdlib.handlers import FTPHandler
        from pyftpdlib.servers import FTPServer
        from pyftpdlib.authorizers import DummyAuthorizer

        ftp_user = os.environ.get('FTP_USER', 'iris_ftp')
        ftp_password = os.environ.get('FTP_PASSWORD', 'change_me_ftp_password')
        ftp_port = int(os.environ.get('FTP_PORT', 2121))
        passive_ports_raw = os.environ.get('FTP_PASSIVE_PORTS', '60000-60100')
        p_start, p_end = (int(x) for x in passive_ports_raw.split('-'))

        authorizer = DummyAuthorizer()
        # perm: e=list, l=list, r=read, a=append, d=delete, f=rename, m=mkdir, w=write, M=chmod, T=mtime
        authorizer.add_user(ftp_user, ftp_password, UPLOAD_FOLDER, perm='elradfmwMT')

        handler = FTPHandler
        handler.authorizer = authorizer
        handler.passive_ports = range(p_start, p_end + 1)
        handler.banner = "IRIS-VE FTP Server — Ready"

        server = FTPServer(('0.0.0.0', ftp_port), handler)
        logger.info(f"✅ FTP server avviato su porta {ftp_port} (passive: {p_start}-{p_end})")
        server.serve_forever()
    except ImportError:
        logger.error("pyftpdlib non installato. Esegui: pip install pyftpdlib==1.5.9")
    except Exception as e:
        logger.error(f"FTP server error: {e}")


# ============================================================================
# STARTUP & INFO
# ============================================================================

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            logger.info("✅ Database tables created")
        except Exception as e:
            logger.error(f"❌ Database initialization error: {e}")
            print(f"⚠️  Database error: {e}")
            print(f"📝 Make sure MySQL is running and database 'iris_ve' exists")
            print(f"   Run: mysql -u root -p")
            print(f"        CREATE DATABASE iris_ve;")
            print(f"        EXIT;")

    # Start FTP server in background thread if enabled
    if os.environ.get('FTP_ENABLED', 'False').lower() == 'true':
        import threading
        ftp_thread = threading.Thread(target=start_ftp_server, daemon=True)
        ftp_thread.start()
        logger.info("FTP server thread avviato")

    local_ip = get_local_ip()
    public_ip = get_public_ip()
    http_port = int(os.environ.get('EXTERNAL_PORT', 25565))
    ftp_port = int(os.environ.get('FTP_PORT', 2121))

    print("═" * 80)
    print("🚀 IRIS-VE v2.0 STARTUP")
    print("═" * 80)
    print(f"")
    print(f"📍 Local Access:  http://{local_ip}:5000")
    print(f"🌐 Remote Access: http://{public_ip}:{http_port}")
    print(f"📁 FTP Access:    ftp://{local_ip}:{ftp_port}")
    print(f"")
    print(f"⚙️  NETWORK CONFIGURATION")
    print(f"   Internal Port (Flask):  5000")
    print(f"   External Port (HTTP):   {http_port}")
    print(f"   FTP Port:               {ftp_port}")
    print(f"   Local IP:               {local_ip}")
    print(f"   Public IP:              {public_ip}")
    print(f"")
    print(f"🔧 PORT FORWARDING SETUP (router)")
    print(f"   Porta 80    → {local_ip}:80    (nginx HTTP)")
    print(f"   Porta {http_port} → {local_ip}:5000  (Flask diretto)")
    print(f"   Porta {ftp_port}  → {local_ip}:{ftp_port}  (FTP control)")
    print(f"   Porte 60000-60100 → {local_ip} (FTP passive data)")
    print(f"")
    print(f"✅ Server pronto!")
    print("═" * 80)

    # Start server
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True
    )
