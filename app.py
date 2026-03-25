# IRIS-VE v2.1 - Cloud Storage Encrypted
# Improved: Bug fixes, security hardening, performance optimizations, code dedup
# Based on: v2.0 by Riccardo Vincenzi
# Changes: See CHANGELOG section at bottom

from flask import Flask, request, render_template, redirect, url_for, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from flask_socketio import SocketIO, emit as sio_emit, join_room, leave_room
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
import json
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import random
import string
import secrets
from dotenv import load_dotenv

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

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

# Admin credentials — used only to seed the first user on first startup
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@iris-ve.local')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
if not ADMIN_PASSWORD or ADMIN_PASSWORD == 'changeme_insecure_default':
    import warnings
    warnings.warn(
        "⚠️  ADMIN_PASSWORD non impostata o insicura. "
        "Imposta ADMIN_PASSWORD nell'ambiente prima del primo avvio in produzione.",
        stacklevel=2,
    )
    ADMIN_PASSWORD = ADMIN_PASSWORD or 'changeme_insecure_default'

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'mysql+pymysql://root:root@localhost/iris_ve'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 20,
    'max_overflow': 10,
    'pool_timeout': 30,
    'pool_recycle': 1800,
    'pool_pre_ping': True,
}

# File Upload — 15 GB limit, all extensions allowed
app.config['MAX_CONTENT_LENGTH'] = 15 * 1024 * 1024 * 1024  # 15 GB
app.config['MAX_FORM_MEMORY_SIZE'] = 0

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
BACKUP_FOLDER = os.path.join(os.path.dirname(__file__), 'backups')
LOG_FOLDER = os.path.join(os.path.dirname(__file__), 'logs')
STATIC_FOLDER = os.path.join(os.path.dirname(__file__), 'static')

# Disk & permissions constants
DISK_FOLDER_NAME = 'IRIS-VE'

ALL_PERMISSIONS = [
    ('upload_files',    'Caricare file'),
    ('delete_files',    'Eliminare file'),
    ('create_folders',  'Creare cartelle'),
    ('delete_folders',  'Eliminare cartelle'),
    ('view_encrypted',  'Aprire cartelle cifrate'),
    ('view_analytics',  'Vedere le statistiche'),
]
ALL_PERMISSION_KEYS = [p[0] for p in ALL_PERMISSIONS]
DEFAULT_MEMBER_PERMS = ['upload_files', 'create_folders', 'view_analytics']

# Cache
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300

# Session
_is_production = os.environ.get('ENV') == 'production'
app.config['SESSION_COOKIE_SECURE'] = _is_production
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
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"],
    default_limits_exempt_when=lambda: request.path == '/health',
)
limiter.init_app(app)

# FIX: Restrict CORS in production
_allowed_origins = os.environ.get('ALLOWED_ORIGINS', '*')
if _is_production and _allowed_origins == '*':
    import warnings
    warnings.warn(
        "⚠️  ALLOWED_ORIGINS='*' in produzione è pericoloso. "
        "Imposta i domini consentiti (es. 'https://example.com').",
        stacklevel=2,
    )

socketio = SocketIO(
    app,
    cors_allowed_origins=_allowed_origins,
    async_mode='threading',
    logger=False,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25,
)

# FIX: Thread-safe presence tracking with lock
_online_lock = threading.Lock()
online_users: dict = {}  # {sid: {user_id, username, full_name, folder_id, connected_at}}

# ============================================================================
# LOGGING
# ============================================================================

if not app.debug:
    file_handler = RotatingFileHandler(
        os.path.join(LOG_FOLDER, 'iris_ve.log'),
        maxBytes=10 * 1024 * 1024,
        backupCount=10,
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

class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = (
        db.Index('ix_users_username', 'username'),
        db.Index('ix_users_email', 'email'),
    )

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    memberships = db.relationship('OrganizationMember', backref='user', lazy='dynamic',
                                  cascade='all, delete-orphan',
                                  foreign_keys='OrganizationMember.user_id')
    owned_organizations = db.relationship('Organization', backref='owner', lazy=True,
                                          foreign_keys='Organization.owner_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def full_name(self):
        n = f"{self.first_name or ''} {self.last_name or ''}".strip()
        return n or self.username

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'phone': self.phone,
            'full_name': self.full_name,
            'created_at': self.created_at.isoformat(),
        }


class Organization(db.Model):
    __tablename__ = 'organizations'
    __table_args__ = (
        db.Index('ix_organizations_invite_code', 'invite_code'),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    address = db.Column(db.Text, nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    invite_code = db.Column(db.String(6), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    members = db.relationship('OrganizationMember', backref='organization', lazy=True,
                              cascade='all, delete-orphan',
                              foreign_keys='OrganizationMember.organization_id')
    workspace = db.relationship('Workspace', backref='organization', lazy=True,
                                uselist=False, cascade='all, delete-orphan')

    def to_dict(self, include_code=False):
        d = {
            'id': self.id,
            'name': self.name,
            'address': self.address,
            'phone': self.phone,
            'owner_id': self.owner_id,
            'created_at': self.created_at.isoformat(),
        }
        if include_code:
            d['invite_code'] = self.invite_code
        return d


class OrganizationMember(db.Model):
    __tablename__ = 'organization_members'
    __table_args__ = (
        db.UniqueConstraint('user_id', 'organization_id', name='uq_user_org'),
        db.Index('ix_org_members_user', 'user_id'),
        db.Index('ix_org_members_org', 'organization_id'),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='member')
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    custom_role_id = db.Column(db.Integer, db.ForeignKey('org_roles.id', ondelete='SET NULL'), nullable=True)
    permissions_override = db.Column(db.JSON, nullable=True)

    custom_role = db.relationship('OrgRole', foreign_keys=[custom_role_id])

    def to_dict(self):
        return {
            'user_id': self.user_id,
            'organization_id': self.organization_id,
            'role': self.role,
            'joined_at': self.joined_at.isoformat(),
            'custom_role_id': self.custom_role_id,
            'permissions_override': self.permissions_override,
        }


class OrgRole(db.Model):
    """Custom roles per organization with granular permissions."""
    __tablename__ = 'org_roles'
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'name', name='uq_org_role_name'),
        db.Index('ix_org_roles_org', 'organization_id'),
    )

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    permissions = db.Column(db.JSON, nullable=False, default=list)
    color = db.Column(db.String(20), nullable=True, default='accent')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'name': self.name,
            'permissions': self.permissions or [],
            'color': self.color or 'accent',
            'created_at': self.created_at.isoformat(),
        }


class StorageConfig(db.Model):
    """Single-row table storing the active disk upload path."""
    __tablename__ = 'storage_config'

    id = db.Column(db.Integer, primary_key=True)
    active_disk_path = db.Column(db.String(512), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Workspace(db.Model):
    __tablename__ = 'workspaces'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'name': self.name,
            'created_at': self.created_at.isoformat(),
        }


class Folder(db.Model):
    __tablename__ = 'folders'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    icon = db.Column(db.String(64), nullable=True, default='bi-folder-fill')
    is_encrypted = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(255), nullable=True)
    salt = db.Column(db.String(255), nullable=True)  # kept for schema compat
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspaces.id'), nullable=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('folders.id', ondelete='CASCADE'), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    files = db.relationship('File', backref='folder', lazy=True, cascade='all, delete-orphan')
    logs = db.relationship('ActionLog', backref='folder', lazy=True, cascade='all, delete-orphan')
    children = db.relationship(
        'Folder',
        backref=db.backref('parent', remote_side='Folder.id'),
        lazy='dynamic',
        cascade='all, delete-orphan',
        foreign_keys='Folder.parent_id',
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def get_depth(self):
        """Profondità (root=0). Max 5 livelli — iterativo per evitare ricorsione infinita."""
        depth = 0
        node = self
        while node.parent_id and depth < 6:
            node = db.session.get(Folder, node.parent_id)
            if not node:
                break
            depth += 1
        return depth

    def to_dict_base(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'icon': self.icon or 'bi-folder-fill',
            'is_encrypted': self.is_encrypted,
            'workspace_id': self.workspace_id,
            'parent_id': self.parent_id,
            'created_by_id': self.created_by_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }

    def to_dict(self):
        from sqlalchemy import func
        files_count = db.session.query(func.count(File.id)).filter(
            File.folder_id == self.id
        ).scalar()
        children_count = db.session.query(func.count(Folder.id)).filter(
            Folder.parent_id == self.id
        ).scalar()
        d = self.to_dict_base()
        d['files_count'] = files_count
        d['children_count'] = children_count
        return d


class File(db.Model):
    __tablename__ = 'files'
    __table_args__ = (
        db.Index('ix_files_folder_id', 'folder_id'),
        db.Index('ix_files_uploaded_by', 'uploaded_by_id'),
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
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    logs = db.relationship('ActionLog', backref='file', lazy=True, cascade='all, delete-orphan')

    # FIX: Eager-loadable relationship instead of per-row query
    uploader = db.relationship('User', foreign_keys=[uploaded_by_id], lazy='joined')

    def to_dict(self):
        # FIX: Use relationship instead of N+1 query per file
        uploader_name = None
        if self.uploader:
            uploader_name = self.uploader.full_name
        return {
            'id': self.id,
            'name': self.original_name or self.name,
            'size': self.size,
            'mime_type': self.mime_type,
            'created_at': self.created_at.isoformat(),
            'is_encrypted': self.is_encrypted,
            'uploaded_by': uploader_name,
        }


class FolderOrder(db.Model):
    """Ordine drag&drop cartelle per utente."""
    __tablename__ = 'folder_orders'
    __table_args__ = (
        db.UniqueConstraint('user_id', 'workspace_id', 'folder_id', name='uq_user_ws_folder'),
        db.Index('ix_fo_user_ws', 'user_id', 'workspace_id'),
        db.Index('ix_fo_folder', 'folder_id'),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspaces.id', ondelete='CASCADE'), nullable=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.id', ondelete='CASCADE'), nullable=False)
    position = db.Column(db.Integer, nullable=False, default=0)


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
            'timestamp': self.timestamp.isoformat(),
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
        ('py', 'js', 'html', 'css', 'json', 'xml'): 'bi-file-code',
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
            return f"{size_bytes:.0f} {unit}" if unit == 'B' else f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


app.jinja_env.globals.update(
    get_file_icon=get_file_icon,
    get_file_icon_class=get_file_icon_class,
    format_bytes=format_bytes,
)


def generate_invite_code():
    """Generate a unique 6-char alphanumeric invite code (uppercase + digits).
    FIX: Uses secrets for better randomness, raises on exhaustion."""
    for _ in range(50):  # FIX: More attempts, was 10
        code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        if not Organization.query.filter_by(invite_code=code).first():
            return code
    raise RuntimeError("Impossibile generare un codice invito unico dopo 50 tentativi")


def get_current_user():
    """Return the logged-in User ORM object, or None if not authenticated"""
    user_id = session.get('user_id')
    if not user_id:
        return None
    return db.session.get(User, user_id)


def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


_public_ip_cache: dict = {'ip': None, 'ts': 0}
_PUBLIC_IP_CACHE_TTL = 300

def get_public_ip() -> str:
    """Get public IP with in-memory cache (5 min TTL) and multiple fallbacks."""
    import time
    now = time.monotonic()
    if _public_ip_cache['ip'] and now - _public_ip_cache['ts'] < _PUBLIC_IP_CACHE_TTL:
        return _public_ip_cache['ip']

    _PROVIDERS = [
        ('https://api.ipify.org?format=json', lambda r: r.json()['ip']),
        ('https://checkip.amazonaws.com',     lambda r: r.text.strip()),
        ('https://icanhazip.com',             lambda r: r.text.strip()),
        ('https://ifconfig.me/ip',            lambda r: r.text.strip()),
    ]
    for url, extractor in _PROVIDERS:
        try:
            resp = requests.get(url, timeout=3)
            ip = extractor(resp)
            if ip:
                _public_ip_cache['ip'] = ip
                _public_ip_cache['ts'] = now
                return ip
        except Exception:
            continue
    return _public_ip_cache.get('ip') or "IP pubblico non rilevato"


def log_action(action, resource_type=None, resource_id=None, details=None, _commit=True):
    """Log user action. Pass _commit=False when inside a larger transaction."""
    try:
        log = ActionLog(
            action=action,
            resource_type=resource_type,
            folder_id=resource_id if resource_type == 'folder' else None,
            file_id=resource_id if resource_type == 'file' else None,
            details=details,
            ip_address=request.remote_addr if request else None,
            user_agent=(request.user_agent.string[:255]
                        if request and request.user_agent else None),
        )
        db.session.add(log)
        if _commit:
            db.session.commit()
    except Exception as e:
        logger.error(f"Error logging action: {e}")
        try:
            db.session.rollback()
        except Exception:
            pass


def sanitize_name(name: str, max_len: int = 255) -> str:
    """Sanitize folder/file names: strip whitespace, remove path separators, limit length."""
    if not name:
        return ''
    # FIX: Strip path separators to prevent directory traversal
    name = name.replace('/', '').replace('\\', '').replace('\x00', '')
    return name.strip()[:max_len]


# ============================================================================
# STORAGE BACKEND ABSTRACTION (v4.1)
# Configurazione via env:
#   STORAGE_BACKEND = local | minio | s3      (default: local)
#   S3_ENDPOINT_URL  = http://minio:9000       (MinIO) o ometti per AWS S3
#   S3_BUCKET        = iris-ve
#   S3_ACCESS_KEY    = minioadmin
#   S3_SECRET_KEY    = minioadmin
#   S3_REGION        = us-east-1
#   S3_PUBLIC_DOMAIN = https://cdn.example.com (opzionale, per URL pubblici diretti)
#   S3_PRESIGN_EXPIRY = 3600                   (secondi validità presigned URL)
# ============================================================================

import abc
import io
import tempfile
import contextlib

class StorageBackend(abc.ABC):
    """Interfaccia astratta per lo storage dei file."""

    @abc.abstractmethod
    def save(self, stream, object_key: str) -> None:
        """Salva uno stream sul backend. object_key = path relativo (es. 'abc123.pdf')"""

    @abc.abstractmethod
    def delete(self, object_key: str) -> None:
        """Elimina un oggetto."""

    @abc.abstractmethod
    def exists(self, object_key: str) -> bool:
        """Verifica se un oggetto esiste."""

    @abc.abstractmethod
    def get_size(self, object_key: str) -> int:
        """Dimensione in byte di un oggetto."""

    @abc.abstractmethod
    def get_download_url(self, object_key: str, filename: str, expiry: int = 3600):
        """Restituisce un URL di download diretto (presigned) o None per proxy Flask."""

    @abc.abstractmethod
    @contextlib.contextmanager
    def open_temp(self, object_key: str, suffix: str = ''):
        """Context manager: restituisce il path di un file temporaneo leggibile.
        Per LocalStorage è il path originale; per S3 scarica e pulisce automaticamente."""

    @property
    def is_local(self) -> bool:
        return False


class LocalStorage(StorageBackend):
    """Backend filesystem locale — comportamento originale di IRIS-VE."""

    def __init__(self, base_path: str):
        self._base = base_path

    def _full(self, key: str) -> str:
        # Usa sempre il path attivo dal DB (può cambiare con switch disco)
        return os.path.join(get_upload_folder(), key)

    def save(self, stream, object_key: str) -> None:
        full = self._full(object_key)
        os.makedirs(os.path.dirname(full) if '/' in object_key else get_upload_folder(), exist_ok=True)
        CHUNK = 4 * 1024 * 1024
        with open(full, 'wb') as f:
            while True:
                chunk = stream.read(CHUNK)
                if not chunk:
                    break
                f.write(chunk)

    def delete(self, object_key: str) -> None:
        full = self._full(object_key)
        if os.path.exists(full):
            os.remove(full)

    def exists(self, object_key: str) -> bool:
        return os.path.exists(self._full(object_key))

    def get_size(self, object_key: str) -> int:
        return os.path.getsize(self._full(object_key))

    def get_download_url(self, object_key: str, filename: str, expiry: int = 3600):
        return None  # Flask fa il proxy con send_file

    @contextlib.contextmanager
    def open_temp(self, object_key: str, suffix: str = ''):
        yield self._full(object_key)  # path diretto, nessuna copia

    @property
    def is_local(self) -> bool:
        return True


class S3Storage(StorageBackend):
    """Backend S3-compatibile: MinIO, Cloudflare R2, Backblaze B2, AWS S3."""

    def __init__(self):
        import boto3
        self._bucket   = os.environ['S3_BUCKET']
        self._expiry   = int(os.environ.get('S3_PRESIGN_EXPIRY', 3600))
        self._pub_dom  = os.environ.get('S3_PUBLIC_DOMAIN', '').rstrip('/')
        endpoint       = os.environ.get('S3_ENDPOINT_URL')  # None → AWS S3 standard
        region         = os.environ.get('S3_REGION', 'us-east-1')
        kwargs = dict(
            aws_access_key_id     = os.environ.get('S3_ACCESS_KEY'),
            aws_secret_access_key = os.environ.get('S3_SECRET_KEY'),
            region_name           = region,
        )
        if endpoint:
            kwargs['endpoint_url'] = endpoint
        self._s3 = boto3.client('s3', **kwargs)
        # Crea bucket se non esiste (utile con MinIO al primo avvio)
        self._ensure_bucket()

    def _ensure_bucket(self):
        try:
            self._s3.head_bucket(Bucket=self._bucket)
        except Exception:
            try:
                self._s3.create_bucket(Bucket=self._bucket)
                logger.info(f"✅ S3 bucket '{self._bucket}' creato")
            except Exception as e:
                logger.warning(f"S3 bucket create: {e}")

    def save(self, stream, object_key: str) -> None:
        self._s3.upload_fileobj(stream, self._bucket, object_key)

    def delete(self, object_key: str) -> None:
        try:
            self._s3.delete_object(Bucket=self._bucket, Key=object_key)
        except Exception as e:
            logger.warning(f"S3 delete error: {e}")

    def exists(self, object_key: str) -> bool:
        try:
            self._s3.head_object(Bucket=self._bucket, Key=object_key)
            return True
        except Exception:
            return False

    def get_size(self, object_key: str) -> int:
        try:
            r = self._s3.head_object(Bucket=self._bucket, Key=object_key)
            return r['ContentLength']
        except Exception:
            return 0

    def get_download_url(self, object_key: str, filename: str, expiry: int = None) -> str:
        exp = expiry or self._expiry
        # URL pubblico diretto se S3_PUBLIC_DOMAIN è configurato (CDN, R2 custom domain…)
        if self._pub_dom:
            return f"{self._pub_dom}/{object_key}"
        # Presigned URL — il client scarica direttamente da MinIO/S3 senza passare per Flask
        try:
            return self._s3.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': self._bucket,
                    'Key': object_key,
                    'ResponseContentDisposition': f'attachment; filename="{filename}"',
                },
                ExpiresIn=exp
            )
        except Exception as e:
            logger.error(f"S3 presign error: {e}")
            return None

    @contextlib.contextmanager
    def open_temp(self, object_key: str, suffix: str = ''):
        """Scarica il file in un file temporaneo; pulizia garantita anche in caso di eccezione."""
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        tmp_path = tmp.name
        try:
            self._s3.download_fileobj(self._bucket, object_key, tmp)
            tmp.flush()
            tmp.close()
            yield tmp_path
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# Factory — singleton inizializzato una volta sola
_storage_instance: StorageBackend = None

def get_storage() -> StorageBackend:
    """Restituisce il backend storage attivo. Istanza singleton."""
    global _storage_instance
    if _storage_instance is not None:
        return _storage_instance

    backend = os.environ.get('STORAGE_BACKEND', 'local').lower()
    if backend in ('minio', 's3'):
        try:
            _storage_instance = S3Storage()
            logger.info(f"✅ Storage backend: S3/MinIO (bucket: {os.environ.get('S3_BUCKET')})")
        except Exception as e:
            logger.error(f"❌ S3 backend init failed: {e} — fallback a LocalStorage")
            _storage_instance = LocalStorage(UPLOAD_FOLDER)
    else:
        _storage_instance = LocalStorage(UPLOAD_FOLDER)
        logger.info("✅ Storage backend: LocalStorage (filesystem)")

    return _storage_instance


# ============================================================================
# DISK MANAGEMENT UTILITIES
# ============================================================================

def get_upload_folder() -> str:
    """Return current active upload path (reads StorageConfig from DB; falls back to default)."""
    try:
        config = StorageConfig.query.first()
        if config and config.active_disk_path and os.path.isdir(config.active_disk_path):
            return config.active_disk_path
    except Exception:
        pass
    return UPLOAD_FOLDER



def list_available_disks() -> list:
    """List disk partitions with usage stats. Requires psutil."""
    if not PSUTIL_AVAILABLE:
        return []
    active = get_upload_folder()
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            iris_path = os.path.join(part.mountpoint, DISK_FOLDER_NAME)
            try:
                is_active = os.path.commonpath(
                    [os.path.abspath(active), os.path.abspath(part.mountpoint)]
                ) == os.path.abspath(part.mountpoint)
            except ValueError:
                is_active = False
            disks.append({
                'device': part.device,
                'mountpoint': part.mountpoint,
                'fstype': part.fstype,
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': round(usage.percent, 1),
                'total_human': format_bytes(usage.total),
                'used_human': format_bytes(usage.used),
                'free_human': format_bytes(usage.free),
                'is_active': is_active,
                'iris_path': iris_path,
            })
        except (PermissionError, OSError):
            continue
    return disks


def _get_effective_permissions(member: 'OrganizationMember') -> list:
    """Return effective permission keys for a member."""
    if member.role == 'owner':
        return ALL_PERMISSION_KEYS[:]
    if member.permissions_override:
        return [p for p in member.permissions_override if p in ALL_PERMISSION_KEYS]
    if member.custom_role_id and member.custom_role:
        return [p for p in (member.custom_role.permissions or []) if p in ALL_PERMISSION_KEYS]
    return DEFAULT_MEMBER_PERMS[:]


# ============================================================================
# FILE ACCESS AUTHORIZATION HELPER
# ============================================================================

def _authorize_file_access(file_obj: 'File', user: 'User') -> bool:
    """FIX: Check if user has access to the file's folder.
    Returns True if authorized, False otherwise."""
    folder = db.session.get(Folder, file_obj.folder_id)
    if not folder:
        return False

    if folder.workspace_id:
        ws = db.session.get(Workspace, folder.workspace_id)
        if not ws:
            return False
        member = OrganizationMember.query.filter_by(
            user_id=user.id, organization_id=ws.organization_id
        ).first()
        return member is not None
    else:
        # Personal folder: owned by user or legacy (no owner)
        return folder.created_by_id is None or folder.created_by_id == user.id


def _authorize_folder_access(folder: 'Folder', user: 'User') -> bool:
    """Check if user has access to a folder."""
    if folder.workspace_id:
        ws = db.session.get(Workspace, folder.workspace_id)
        if not ws:
            return False
        member = OrganizationMember.query.filter_by(
            user_id=user.id, organization_id=ws.organization_id
        ).first()
        return member is not None
    else:
        return folder.created_by_id is None or folder.created_by_id == user.id


# ============================================================================
# ENCRYPTION UTILITIES
# ============================================================================

def encrypt_data(data: bytes, password: str) -> str | None:
    """Encrypt data with password using AES-256-CBC + PBKDF2."""
    try:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=100000, backend=default_backend(),
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


def decrypt_data(encrypted_data: str, password: str) -> bytes | None:
    """Decrypt data with password."""
    try:
        data = base64.b64decode(encrypted_data)
        salt = data[:16]
        iv = data[16:32]
        encrypted = data[32:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=100000, backend=default_backend(),
        )
        key = kdf.derive(password.encode())
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted) + decryptor.finalize()
        padding_length = padded_data[-1]
        if padding_length < 1 or padding_length > 16:
            return None  # FIX: Validate padding
        # FIX: Verify all padding bytes match
        if padded_data[-padding_length:] != bytes([padding_length] * padding_length):
            return None
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
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session.permanent = True
            log_action('login', details=f'User {username} logged in')
            return redirect(url_for('dashboard'))
        return render_template('index.html', login_error='Credenziali non valide')
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        user_phone = request.form.get('phone', '').strip()
        has_org = request.form.get('has_org') == 'yes'
        org_exists = request.form.get('org_exists') == 'yes'
        invite_code = request.form.get('invite_code', '').strip().upper()
        org_name = request.form.get('org_name', '').strip()
        org_address = request.form.get('org_address', '').strip()
        org_phone = request.form.get('org_phone', '').strip()

        errors = []
        if not username or len(username) < 3:
            errors.append('Username deve essere di almeno 3 caratteri')
        elif not username.replace('_', '').replace('-', '').isalnum():
            errors.append('Username può contenere solo lettere, numeri, _ e -')
        if not email or '@' not in email or '.' not in email.split('@')[-1]:
            errors.append('Email non valida')
        if not password or len(password) < 8:
            errors.append('La password deve essere di almeno 8 caratteri')
        if password != confirm_password:
            errors.append('Le password non coincidono')

        if not errors:
            if User.query.filter_by(username=username).first():
                errors.append('Username già in uso')
            if User.query.filter_by(email=email).first():
                errors.append('Email già registrata')

        org_to_join = None
        if not errors and has_org:
            if org_exists:
                if not invite_code or len(invite_code) != 6:
                    errors.append('Il codice organizzazione deve essere di 6 caratteri')
                else:
                    org_to_join = Organization.query.filter_by(invite_code=invite_code).first()
                    if not org_to_join:
                        errors.append('Codice organizzazione non trovato o non valido')
            else:
                if not org_name or len(org_name) < 2:
                    errors.append('Il nome dell\'azienda deve essere di almeno 2 caratteri')

        if errors:
            return render_template('register.html', errors=errors, form_data=request.form)

        try:
            user = User(
                username=username, email=email,
                first_name=first_name or None,
                last_name=last_name or None,
                phone=user_phone[:20] if user_phone else None,
            )
            user.set_password(password)
            db.session.add(user)
            db.session.flush()

            if has_org:
                if org_exists and org_to_join:
                    member = OrganizationMember(
                        user_id=user.id,
                        organization_id=org_to_join.id,
                        role='member',
                    )
                    db.session.add(member)
                else:
                    code = generate_invite_code()
                    org = Organization(
                        name=sanitize_name(org_name),
                        address=sanitize_name(org_address, max_len=500) if org_address else None,
                        phone=org_phone[:20] if org_phone else None,
                        invite_code=code,
                        owner_id=user.id,
                    )
                    db.session.add(org)
                    db.session.flush()

                    member = OrganizationMember(
                        user_id=user.id,
                        organization_id=org.id,
                        role='owner',
                    )
                    db.session.add(member)

                    workspace = Workspace(
                        organization_id=org.id,
                        name=f"Workspace {org.name}",
                    )
                    db.session.add(workspace)

            db.session.commit()
            session['user_id'] = user.id
            session.permanent = True
            log_action('register', details=f'New user registered: {username}')
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {e}")
            return render_template('register.html',
                                   errors=['Errore durante la registrazione. Riprova.'],
                                   form_data=request.form)

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    try:
        user = get_current_user()
        folders = Folder.query.filter(
            Folder.workspace_id.is_(None),
            Folder.parent_id.is_(None),  # FIX: Solo root-level nella dashboard
            db.or_(Folder.created_by_id == user.id, Folder.created_by_id.is_(None))
        ).all()

        memberships = OrganizationMember.query.filter_by(user_id=user.id).all()
        user_workspaces = []
        for m in memberships:
            org = m.organization
            if org.workspace:
                user_workspaces.append({
                    'workspace': org.workspace,
                    'org': org,
                    'role': m.role,
                })

        return render_template('folder.html', folders=folders, user=user,
                               user_workspaces=user_workspaces, active_workspace=None,
                               user_permissions=ALL_PERMISSION_KEYS)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('500.html'), 500


@app.route('/folder/<int:folder_id>')
@login_required
def view_folder(folder_id):
    try:
        user = get_current_user()
        folder = Folder.query.get_or_404(folder_id)

        if not _authorize_folder_access(folder, user):
            return render_template('404.html'), 404

        member = None
        if folder.workspace_id:
            ws = db.session.get(Workspace, folder.workspace_id)
            if ws:
                member = OrganizationMember.query.filter_by(
                    user_id=user.id, organization_id=ws.organization_id
                ).first()

        memberships = OrganizationMember.query.filter_by(user_id=user.id).all()
        user_workspaces = []
        for m in memberships:
            org = m.organization
            if org.workspace:
                user_workspaces.append({'workspace': org.workspace, 'org': org, 'role': m.role})

        folder_perms = _get_effective_permissions(member) if member else ALL_PERMISSION_KEYS[:]

        if folder.is_encrypted:
            locked = not session.get(f'folder_{folder_id}_unlocked', False)
            files = [] if locked else File.query.filter_by(folder_id=folder_id).all()
            return render_template('view_encrypted_folder.html',
                                   folder=folder, files=files,
                                   content='', locked=locked)

        files = File.query.filter_by(folder_id=folder_id).all()
        return render_template('folder.html', folder=folder, files=files,
                               user=user, user_workspaces=user_workspaces,
                               active_workspace=folder.workspace_id,
                               user_permissions=folder_perms)
    except Exception as e:
        logger.error(f"View folder error: {e}")
        return render_template('500.html'), 500


@app.route('/documentation')
@login_required
def documentation():
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
def api_get_folders():
    """Get folders filtered by workspace or personal (JOIN to avoid N+1)."""
    try:
        from sqlalchemy import func
        user = get_current_user()
        workspace_id = request.args.get('workspace_id', type=int)

        if workspace_id:
            ws = Workspace.query.get_or_404(workspace_id)
            member = OrganizationMember.query.filter_by(
                user_id=user.id, organization_id=ws.organization_id
            ).first()
            if not member:
                return jsonify({'success': False, 'message': 'Accesso negato'}), 403
            folder_filter = Folder.workspace_id == workspace_id
        else:
            folder_filter = db.and_(
                Folder.workspace_id.is_(None),
                db.or_(Folder.created_by_id == user.id, Folder.created_by_id.is_(None))
            )

        results = db.session.query(
            Folder,
            func.count(File.id).label('files_count'),
            User.username.label('creator_username'),
            User.first_name.label('creator_first_name'),
            User.last_name.label('creator_last_name'),
        ).outerjoin(File, File.folder_id == Folder.id
        ).outerjoin(User, User.id == Folder.created_by_id
        ).filter(folder_filter
        ).group_by(Folder.id, User.username, User.first_name, User.last_name).all()

        folders_data = []
        for folder, count, c_user, c_fn, c_ln in results:
            d = folder.to_dict_base()
            d['files_count'] = count
            full = f"{c_fn or ''} {c_ln or ''}".strip()
            d['created_by_username'] = c_user or 'Sistema'
            d['created_by_display'] = full or c_user or 'Sistema'
            folders_data.append(d)
        return jsonify(folders_data)
    except Exception as e:
        logger.error(f"Get folders error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/folders', methods=['POST'])
@api_login_required
@limiter.limit("20 per minute")
def api_create_folder():
    """Create folder — supporta parent_id per sottocartelle."""
    try:
        data = request.get_json()
        name = sanitize_name(data.get('name', ''))
        description = sanitize_name(data.get('description', ''), max_len=1000)
        is_encrypted = data.get('is_encrypted', False)
        password = data.get('password', '')
        parent_id = data.get('parent_id')
        workspace_id = data.get('workspace_id')

        if not name:
            return jsonify({'success': False, 'message': 'Nome cartella non valido'}), 400

        user = get_current_user()

        if parent_id:
            parent = db.session.get(Folder, parent_id)
            if not parent:
                return jsonify({'success': False, 'message': 'Cartella padre non trovata'}), 404
            if not _authorize_folder_access(parent, user):
                return jsonify({'success': False, 'message': 'Accesso negato'}), 403
            if parent.get_depth() >= 5:
                return jsonify({'success': False, 'message': 'Profondità massima raggiunta (5 livelli)'}), 400
            if not workspace_id:
                workspace_id = parent.workspace_id

        if workspace_id:
            ws = Workspace.query.get(workspace_id)
            if not ws:
                return jsonify({'success': False, 'message': 'Workspace non trovato'}), 404
            member = OrganizationMember.query.filter_by(
                user_id=user.id, organization_id=ws.organization_id
            ).first()
            if not member:
                return jsonify({'success': False, 'message': 'Accesso negato al workspace'}), 403
            # FIX: Check create_folders permission
            perms = _get_effective_permissions(member)
            if 'create_folders' not in perms:
                return jsonify({'success': False, 'message': 'Non hai il permesso di creare cartelle'}), 403

        folder = Folder(
            name=name,
            description=description,
            is_encrypted=is_encrypted,
            workspace_id=workspace_id,
            parent_id=parent_id,
            created_by_id=user.id,
        )

        if is_encrypted and password:
            folder.set_password(password)

        db.session.add(folder)
        db.session.commit()

        cache.delete('all_folders')
        log_action('create_folder', 'folder', folder.id, f'Created: {name}')

        d = folder.to_dict_base()
        d['files_count'] = 0
        d['children_count'] = 0
        d['created_by_username'] = user.username
        d['created_by_display'] = user.full_name

        if parent_id:
            socketio.emit('subfolder_created', {'folder': d, 'parent_id': parent_id},
                          room=f'folder_{parent_id}')
        else:
            socketio.emit('folder_created', d)

        return jsonify({'success': True, 'folder': d}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create folder error: {e}")
        return jsonify({'success': False, 'message': 'Errore creazione'}), 500


@app.route('/api/folders/<int:folder_id>', methods=['PUT'])
@api_login_required
@limiter.limit("10 per minute")
def api_update_folder(folder_id):
    try:
        user = get_current_user()
        folder = Folder.query.get_or_404(folder_id)

        # FIX: Authorization check
        if not _authorize_folder_access(folder, user):
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

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
    """Delete folder — commit DB first, then remove files from disk."""
    try:
        user = get_current_user()
        folder = Folder.query.get_or_404(folder_id)

        # FIX: Authorization check
        if not _authorize_folder_access(folder, user):
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        folder_name = folder.name
        parent_id = folder.parent_id

        # Collect ALL file paths recursively before deleting
        disk_paths = _collect_folder_file_paths(folder)

        db.session.delete(folder)
        db.session.commit()

        # Only after successful commit, remove physical files
        for path in disk_paths:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError as oe:
                logger.warning(f"Could not remove file from disk: {path} — {oe}")

        cache.delete('all_folders')
        log_action('delete_folder', 'folder', folder_id, f'Deleted: {folder_name}')

        if parent_id:
            socketio.emit('subfolder_deleted',
                          {'folder_id': folder_id, 'parent_id': parent_id},
                          room=f'folder_{parent_id}')
        else:
            socketio.emit('folder_deleted', {'folder_id': folder_id})

        return jsonify({'success': True, 'message': 'Cartella eliminata'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete folder error: {e}")
        return jsonify({'success': False, 'message': 'Errore eliminazione'}), 500


def _collect_folder_file_paths(folder: Folder) -> list:
    """FIX: Recursively collect all file disk paths for a folder and its children."""
    upload_dir = get_upload_folder()
    paths = [os.path.join(upload_dir, f.file_path) for f in folder.files]
    for child in Folder.query.filter_by(parent_id=folder.id).all():
        paths.extend(_collect_folder_file_paths(child))
    return paths


@app.route('/api/folders/<int:folder_id>/files', methods=['GET'])
@api_login_required
def api_get_files(folder_id):
    """Get files con paginazione e filtri (sort_by, sort_dir)."""
    try:
        user = get_current_user()
        folder = Folder.query.get_or_404(folder_id)

        # FIX: Authorization check
        if not _authorize_folder_access(folder, user):
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        page     = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)
        sort_by  = request.args.get('sort_by', 'date')
        sort_dir = request.args.get('sort_dir', 'desc')

        q = File.query.filter_by(folder_id=folder_id)

        if sort_by == 'name':
            order_col = File.original_name.asc() if sort_dir == 'asc' else File.original_name.desc()
        elif sort_by == 'size':
            order_col = File.size.asc() if sort_dir == 'asc' else File.size.desc()
        elif sort_by == 'creator':
            order_col = File.uploaded_by_id.asc() if sort_dir == 'asc' else File.uploaded_by_id.desc()
        else:
            order_col = File.created_at.asc() if sort_dir == 'asc' else File.created_at.desc()

        pagination = q.order_by(order_col).paginate(page=page, per_page=per_page, error_out=False)
        return jsonify({
            'files': [f.to_dict() for f in pagination.items],
            'total': pagination.total,
            'page': page,
            'pages': pagination.pages,
            'per_page': per_page,
            'sort_by': sort_by,
            'sort_dir': sort_dir,
        })
    except Exception as e:
        logger.error(f"Get files error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/folders/<int:folder_id>/upload', methods=['POST'])
@api_login_required
@limiter.limit("20 per minute")
def api_upload_file(folder_id):
    """Upload file to folder."""
    try:
        user = get_current_user()
        folder = Folder.query.get_or_404(folder_id)

        # FIX: Authorization check
        if not _authorize_folder_access(folder, user):
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        # FIX: Check upload permission for workspace folders
        if folder.workspace_id:
            ws = db.session.get(Workspace, folder.workspace_id)
            if ws:
                member = OrganizationMember.query.filter_by(
                    user_id=user.id, organization_id=ws.organization_id
                ).first()
                if member and 'upload_files' not in _get_effective_permissions(member):
                    return jsonify({'success': False, 'message': 'Non hai il permesso di caricare file'}), 403

        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'Nessun file trovato'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'Nome file vuoto'}), 400

        filename = secure_filename(file.filename)
        if not filename:
            # secure_filename can return empty for certain unicode-only names
            filename = f"upload_{secrets.token_hex(8)}"

        file_hash = hashlib.sha256(
            f"{filename}_{datetime.utcnow().timestamp()}_{secrets.token_hex(8)}".encode()
        ).hexdigest()
        file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'bin'
        file_path = f"{file_hash}.{file_ext}"

        storage = get_storage()

        # Notifica inizio upload agli altri utenti nella room
        socketio.emit('upload_start', {
            'folder_id': folder_id,
            'filename': filename,
            'uploader': user.full_name if user else 'Utente',
        }, room=f'folder_{folder_id}')

        try:
            storage.save(file.stream, file_path)
            file_size = storage.get_size(file_path) or (request.content_length or 0)
        except Exception as e:
            try:
                storage.delete(file_path)
            except Exception:
                pass
            logger.error(f"Upload storage error: {e}")
            return jsonify({'success': False, 'message': f'Errore nel salvataggio: {e}'}), 500

        db_file = File(
            folder_id=folder_id,
            name=file_hash,
            original_name=filename,
            size=file_size,
            mime_type=file.content_type or 'application/octet-stream',
            file_path=file_path,
            is_encrypted=folder.is_encrypted,
            uploaded_by_id=user.id,
        )

        db.session.add(db_file)
        try:
            db.session.commit()
        except Exception as db_err:
            db.session.rollback()
            try:
                storage.delete(file_path)
            except Exception:
                pass
            logger.error(f"Upload DB commit error: {db_err}")
            return jsonify({'success': False, 'message': f'Errore salvataggio nel database: {db_err}'}), 500

        cache.delete('all_folders')
        log_action('upload_file', 'file', db_file.id,
                   f'Uploaded: {filename} ({file_size} bytes) via {type(storage).__name__}')
        logger.info(f"File uploaded: {filename} -> {file_path} ({file_size} bytes)")
        socketio.emit('file_uploaded', {'folder_id': folder_id, 'file': db_file.to_dict()},
                      room=f'folder_{folder_id}')
        return jsonify({'success': True, 'file': db_file.to_dict()}), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Upload error: {e}", exc_info=True)
        return jsonify({'success': False, 'message': f'Errore upload: {str(e)}'}), 500


@app.route('/api/files/<int:file_id>/download', methods=['GET'])
@api_login_required
@limiter.limit("30 per minute")
def api_download_file(file_id):
    """Download con supporto S3 presigned URL, HTTP Range per local, e resume."""
    try:
        user = get_current_user()
        file = File.query.get_or_404(file_id)

        if not _authorize_file_access(file, user):
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        storage = get_storage()
        log_action('download_file', 'file', file_id, f'Downloaded: {file.original_name}')

        # ── S3/MinIO: redirect presigned URL (Flask non è nel mezzo) ──
        if not storage.is_local:
            url = storage.get_download_url(
                file.file_path,
                file.original_name or file.name,
                expiry=int(os.environ.get('S3_PRESIGN_EXPIRY', 3600))
            )
            if url:
                from flask import redirect as flask_redirect
                return flask_redirect(url)

        # ── Local: send_file con HTTP Range (resume support) ──────────
        file_path = os.path.join(get_upload_folder(), file.file_path)
        if not os.path.exists(file_path):
            return jsonify({'success': False, 'message': 'File non trovato'}), 404

        file_size = os.path.getsize(file_path)
        range_header = request.headers.get('Range')

        if range_header:
            import re
            from flask import Response
            m = re.match(r'bytes=(\d+)-(\d*)', range_header)
            if not m:
                resp = Response(status=416)
                resp.headers['Content-Range'] = f'bytes */{file_size}'
                return resp
            start = int(m.group(1))
            end   = int(m.group(2)) if m.group(2) else file_size - 1
            end   = min(end, file_size - 1)
            length = end - start + 1
            if start >= file_size or start > end:
                resp = Response(status=416)
                resp.headers['Content-Range'] = f'bytes */{file_size}'
                return resp

            def generate_range():
                with open(file_path, 'rb') as f:
                    f.seek(start)
                    remaining = length
                    while remaining > 0:
                        chunk = f.read(min(65536, remaining))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                        yield chunk

            mime = file.mime_type or 'application/octet-stream'
            resp = Response(generate_range(), status=206, mimetype=mime, direct_passthrough=True)
            resp.headers['Content-Range']      = f'bytes {start}-{end}/{file_size}'
            resp.headers['Accept-Ranges']      = 'bytes'
            resp.headers['Content-Length']     = str(length)
            resp.headers['Content-Disposition'] = f'attachment; filename="{file.original_name or file.name}"'
            return resp

        response = send_file(file_path, as_attachment=True,
                             download_name=file.original_name or file.name,
                             mimetype=file.mime_type or 'application/octet-stream')
        response.headers['Accept-Ranges']  = 'bytes'
        response.headers['Content-Length'] = str(file_size)
        return response

    except Exception as e:
        logger.error(f"Download error: {e}")
        return jsonify({'success': False, 'message': 'Errore download'}), 500


@app.route('/api/files/<int:file_id>', methods=['DELETE'])
@api_login_required
@limiter.limit("10 per minute")
def api_delete_file(file_id):
    """Elimina file — prima il record DB, poi il file dal backend storage."""
    try:
        user = get_current_user()
        file = File.query.get_or_404(file_id)

        if not _authorize_file_access(file, user):
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        object_key   = file.file_path
        file_name    = file.original_name
        file_folder  = file.folder_id
        storage      = get_storage()

        db.session.delete(file)
        db.session.commit()

        # Rimuovi dal backend storage DOPO il commit DB
        try:
            storage.delete(object_key)
        except Exception as e:
            logger.warning(f"Storage delete warning: {e}")

        cache.delete('all_folders')
        log_action('delete_file', 'file', file_id, f'Deleted: {file_name}')
        socketio.emit('file_deleted', {'folder_id': file_folder, 'file_id': file_id},
                      room=f'folder_{file_folder}')
        return jsonify({'success': True, 'message': 'File eliminato'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete file error: {e}")
        return jsonify({'success': False, 'message': 'Errore eliminazione'}), 500


@app.route('/api/files/<int:file_id>/preview', methods=['GET'])
@api_login_required
def api_file_preview(file_id):
    """Preview — supporta sia local che S3 (scarica temp per S3)."""
    try:
        user = get_current_user()
        file = File.query.get_or_404(file_id)
        if not _authorize_file_access(file, user):
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        filename = file.original_name or file.name
        ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
        storage = get_storage()

        if not storage.exists(file.file_path):
            return jsonify({'type': 'unsupported', 'message': 'File non trovato nello storage'}), 404

        # Immagini — presigned URL per S3, inline URL per local
        if ext in ('jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'avif'):
            if not storage.is_local:
                url = storage.get_download_url(file.file_path, filename, expiry=300)
                return jsonify({'type': 'image', 'url': url or f'/api/files/{file_id}/preview-inline'})
            return jsonify({'type': 'image', 'url': f'/api/files/{file_id}/preview-inline'})

        # Testo / codice / ZIP — scarica in temp se S3
        if ext in ('txt', 'md', 'json', 'xml', 'csv', 'py', 'js', 'ts', 'html',
                   'css', 'sh', 'bash', 'yaml', 'yml', 'toml', 'ini', 'log',
                   'java', 'c', 'cpp', 'h', 'rs', 'go', 'rb', 'php', 'sql') or ext == 'zip':
            with storage.open_temp(file.file_path, suffix=f'.{ext}') as tmp_path:
                if ext == 'zip':
                    try:
                        with zipfile.ZipFile(tmp_path, 'r') as zf:
                            all_entries = zf.infolist()
                            total = len(all_entries)
                            contents = [
                                {'name': i.filename, 'size': format_bytes(i.file_size),
                                 'compressed': format_bytes(i.compress_size),
                                 'is_dir': i.filename.endswith('/')}
                                for i in all_entries[:300]
                            ]
                        return jsonify({'type': 'zip', 'contents': contents, 'total': total})
                    except zipfile.BadZipFile:
                        return jsonify({'type': 'unsupported', 'message': 'Archivio ZIP non valido'})
                else:
                    with open(tmp_path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read(100000)
                    return jsonify({'type': 'text', 'content': content, 'ext': ext})

        return jsonify({'type': 'unsupported'})
    except Exception as e:
        logger.error(f"Preview error: {e}")
        return jsonify({'success': False, 'message': 'Errore anteprima'}), 500


@app.route('/api/files/<int:file_id>/preview-inline', methods=['GET'])
@api_login_required
def api_file_preview_inline(file_id):
    """Serve file inline (immagini). Per S3 usa presigned redirect."""
    try:
        user = get_current_user()
        file = File.query.get_or_404(file_id)
        if not _authorize_file_access(file, user):
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        storage = get_storage()
        if not storage.is_local:
            url = storage.get_download_url(file.file_path, file.original_name or file.name, expiry=300)
            if url:
                from flask import redirect as flask_redirect
                return flask_redirect(url)

        file_path = os.path.join(get_upload_folder(), file.file_path)
        if not os.path.exists(file_path):
            return jsonify({'success': False, 'message': 'File non trovato'}), 404
        return send_file(file_path, as_attachment=False,
                         download_name=file.original_name or file.name,
                         mimetype=file.mime_type or 'application/octet-stream')
    except Exception as e:
        logger.error(f"Preview inline error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/files/<int:file_id>/zip-extract', methods=['GET'])
@api_login_required
def api_zip_extract(file_id):
    """Estrai file da ZIP. Con S3 scarica il ZIP in temp prima."""
    try:
        user = get_current_user()
        file = File.query.get_or_404(file_id)
        if not _authorize_file_access(file, user):
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        filename = file.original_name or file.name
        ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
        if ext != 'zip':
            return jsonify({'success': False, 'message': 'Non è un file ZIP'}), 400

        inner_path = request.args.get('path', '')
        if not inner_path or inner_path.endswith('/'):
            return jsonify({'success': False, 'message': 'Percorso non valido'}), 400

        storage = get_storage()
        import mimetypes

        with storage.open_temp(file.file_path, suffix='.zip') as tmp_path:
            try:
                with zipfile.ZipFile(tmp_path, 'r') as zf:
                    try:
                        zf.getinfo(inner_path)
                    except KeyError:
                        return jsonify({'success': False, 'message': 'File non trovato nell\'archivio'}), 404
                    data = zf.read(inner_path)
            except zipfile.BadZipFile:
                return jsonify({'success': False, 'message': 'Archivio ZIP non valido'}), 400

        basename = os.path.basename(inner_path)
        mime = mimetypes.guess_type(basename)[0] or 'application/octet-stream'
        return send_file(io.BytesIO(data), as_attachment=True, download_name=basename, mimetype=mime)
    except Exception as e:
        logger.error(f"ZIP extract error: {e}")
        return jsonify({'success': False, 'message': 'Errore estrazione'}), 500


@app.route('/api/folders/<int:folder_id>/encrypt', methods=['POST'])
@api_login_required
@limiter.limit("5 per minute")
def api_unlock_encrypted_folder(folder_id):
    try:
        user = get_current_user()
        folder = Folder.query.get_or_404(folder_id)

        if not _authorize_folder_access(folder, user):
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

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
# ORGANIZATION & WORKSPACE ENDPOINTS
# ============================================================================

@app.route('/api/user', methods=['GET'])
@api_login_required
def api_get_current_user_info():
    try:
        user = get_current_user()
        return jsonify(user.to_dict())
    except Exception as e:
        logger.error(f"Get user error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/organizations', methods=['GET'])
@api_login_required
def api_get_user_organizations():
    try:
        user = get_current_user()
        memberships = OrganizationMember.query.filter_by(user_id=user.id).all()
        result = []
        for m in memberships:
            org = m.organization
            d = org.to_dict(include_code=(m.role == 'owner'))
            d['role'] = m.role
            d['joined_at'] = m.joined_at.isoformat()
            d['member_count'] = OrganizationMember.query.filter_by(
                organization_id=org.id
            ).count()
            if org.workspace:
                d['workspace'] = org.workspace.to_dict()
            result.append(d)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Get organizations error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/organizations/lookup', methods=['GET'])
@limiter.limit("20 per minute")
def api_organization_lookup():
    """Public endpoint: look up org by invite code during registration."""
    code = request.args.get('code', '').strip().upper()
    if not code or len(code) != 6:
        return jsonify({'found': False, 'message': 'Il codice deve essere di 6 caratteri'}), 400
    org = Organization.query.filter_by(invite_code=code).first()
    if not org:
        return jsonify({'found': False, 'message': 'Nessuna organizzazione trovata con questo codice'}), 404
    member_count = OrganizationMember.query.filter_by(organization_id=org.id).count()
    return jsonify({
        'found': True,
        'name': org.name,
        'address': org.address,
        'phone': org.phone,
        'member_count': member_count,
        'created_at': org.created_at.strftime('%d/%m/%Y'),
    })


@app.route('/workspace/<int:workspace_id>')
@login_required
def workspace_view(workspace_id):
    try:
        user = get_current_user()
        ws = Workspace.query.get_or_404(workspace_id)
        org = ws.organization

        member = OrganizationMember.query.filter_by(
            user_id=user.id, organization_id=org.id
        ).first()
        if not member:
            return render_template('404.html'), 404

        folders = Folder.query.filter_by(
            workspace_id=workspace_id,
            parent_id=None,  # FIX: Solo root-level
        ).all()

        memberships = OrganizationMember.query.filter_by(user_id=user.id).all()
        user_workspaces = []
        for m in memberships:
            o = m.organization
            if o.workspace:
                user_workspaces.append({'workspace': o.workspace, 'org': o, 'role': m.role})

        effective_perms = _get_effective_permissions(member)
        return render_template('folder.html', folders=folders, user=user,
                               user_workspaces=user_workspaces,
                               active_workspace=workspace_id,
                               active_org=org,
                               active_member_role=member.role,
                               user_permissions=effective_perms)
    except Exception as e:
        logger.error(f"Workspace view error: {e}")
        return render_template('500.html'), 500


# ============================================================================
# UTILITY & MONITORING ENDPOINTS
# ============================================================================

@app.route('/health')
def health_check():
    try:
        db.session.execute(db.text('SELECT 1'))
        db_status = 'ok'
    except Exception:
        db_status = 'error'
    status = 'ok' if db_status == 'ok' else 'degraded'
    return jsonify({
        'status': status,
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat(),
    }), 200 if status == 'ok' else 503


@app.route('/api/stats')
@api_login_required
def api_stats():
    """Statistics filtered by workspace or personal."""
    try:
        from sqlalchemy import func
        user = get_current_user()
        workspace_id = request.args.get('workspace_id', type=int)

        if workspace_id:
            ws = Workspace.query.get(workspace_id)
            if not ws:
                return jsonify({'success': False, 'message': 'Workspace non trovato'}), 404
            member = OrganizationMember.query.filter_by(
                user_id=user.id, organization_id=ws.organization_id
            ).first()
            if not member:
                return jsonify({'success': False, 'message': 'Accesso negato'}), 403
            folder_q = db.session.query(func.count(Folder.id)).filter(
                Folder.workspace_id == workspace_id)
            file_q = db.session.query(func.count(File.id)).join(
                Folder, File.folder_id == Folder.id).filter(
                Folder.workspace_id == workspace_id)
            size_q = db.session.query(func.sum(File.size)).join(
                Folder, File.folder_id == Folder.id).filter(
                Folder.workspace_id == workspace_id)
        else:
            folder_filter = db.and_(
                Folder.workspace_id.is_(None),
                db.or_(Folder.created_by_id == user.id, Folder.created_by_id.is_(None))
            )
            folder_q = db.session.query(func.count(Folder.id)).filter(folder_filter)
            file_q = db.session.query(func.count(File.id)).join(
                Folder, File.folder_id == Folder.id).filter(folder_filter)
            size_q = db.session.query(func.sum(File.size)).join(
                Folder, File.folder_id == Folder.id).filter(folder_filter)

        return jsonify({
            'folders': folder_q.scalar() or 0,
            'files': file_q.scalar() or 0,
            'total_size_bytes': size_q.scalar() or 0,
            'total_size_human': format_bytes(size_q.scalar() or 0),
        })
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({'success': False, 'message': 'Errore statistiche'}), 500


@app.route('/api/disk-space')
@api_login_required
def api_disk_space():
    try:
        upload_dir = get_upload_folder()
        total, used, free = shutil.disk_usage(upload_dir)
        return jsonify({
            'total': total,
            'used': used,
            'free': free,
            'total_human': format_bytes(total),
            'used_human': format_bytes(used),
            'free_human': format_bytes(free),
            'percent_used': round((used / total) * 100, 1) if total else 0,
        })
    except Exception as e:
        logger.error(f"Disk space error: {e}")
        return jsonify({'success': False, 'message': 'Errore disco'}), 500


@app.route('/api/network-info')
@api_login_required
@cache.cached(timeout=300, key_prefix='network_info')
def api_network_info():
    try:
        local_ip = get_local_ip()
        public_ip = get_public_ip()
        http_port = int(os.environ.get('EXTERNAL_PORT', 25565))
        ftp_port = int(os.environ.get('FTP_PORT', 2121))
        return jsonify({
            'local_ip': local_ip,
            'public_ip': public_ip,
            'http_port': http_port,
            'ftp_port': ftp_port,
            'local_url': f'http://{local_ip}:{http_port}',
            'public_url': f'http://{public_ip}:{http_port}',
        })
    except Exception as e:
        logger.error(f"Network info error: {e}")
        return jsonify({'success': False, 'message': 'Errore rete'}), 500


# ============================================================================
# DISK MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/disks', methods=['GET'])
@api_login_required
def api_get_disks():
    try:
        disks = list_available_disks()
        if not disks and not PSUTIL_AVAILABLE:
            return jsonify({'success': False, 'message': 'psutil non installato', 'disks': []}), 200
        active = get_upload_folder()
        total_files = File.query.count()
        return jsonify({
            'success': True,
            'disks': disks,
            'active_path': active,
            'total_files': total_files,
            'psutil_available': PSUTIL_AVAILABLE,
        })
    except Exception as e:
        logger.error(f"Get disks error: {e}")
        return jsonify({'success': False, 'message': 'Errore lettura dischi'}), 500


@app.route('/api/disks/switch', methods=['POST'])
@api_login_required
@limiter.limit("5 per minute")
def api_switch_disk():
    """Switch active upload disk — moves all files to <new_mountpoint>/IRIS-VE/."""
    try:
        if not PSUTIL_AVAILABLE:
            return jsonify({'success': False, 'message': 'psutil non disponibile'}), 503

        data = request.get_json()
        mountpoint = data.get('mountpoint', '').strip()
        if not mountpoint:
            return jsonify({'success': False, 'message': 'Mountpoint non fornito'}), 400

        valid_mounts = [p.mountpoint for p in psutil.disk_partitions(all=False)]
        if not any(
            os.path.normpath(mountpoint) == os.path.normpath(m)
            for m in valid_mounts
        ):
            return jsonify({'success': False, 'message': 'Mountpoint non valido'}), 400

        current_path = get_upload_folder()
        iris_path = os.path.join(mountpoint, DISK_FOLDER_NAME)

        if os.path.normpath(iris_path) == os.path.normpath(current_path):
            return jsonify({'success': False, 'message': 'Disco già attivo'}), 400

        os.makedirs(iris_path, exist_ok=True)

        files = File.query.all()
        moved, errors = 0, []
        for f in files:
            src = os.path.join(current_path, f.file_path)
            dst = os.path.join(iris_path, f.file_path)
            if os.path.exists(src):
                try:
                    shutil.move(src, dst)
                    moved += 1
                except Exception as ex:
                    errors.append(f"{f.original_name or f.name}: {ex}")

        config = StorageConfig.query.first()
        if config:
            config.active_disk_path = iris_path
        else:
            config = StorageConfig(active_disk_path=iris_path)
            db.session.add(config)
        db.session.commit()

        global UPLOAD_FOLDER
        UPLOAD_FOLDER = iris_path

        log_action('switch_disk', details=f'Switched to: {iris_path}, moved: {moved} files')
        return jsonify({
            'success': True,
            'message': f'Disco cambiato: {moved} file spostati in {iris_path}',
            'new_path': iris_path,
            'moved': moved,
            'errors': errors[:10],
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Switch disk error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ============================================================================
# ORGANIZATION ADMIN ROUTES & ENDPOINTS
# ============================================================================

@app.route('/org/<int:org_id>/admin')
@login_required
def org_admin(org_id):
    try:
        user = get_current_user()
        org = Organization.query.get_or_404(org_id)
        member = OrganizationMember.query.filter_by(
            user_id=user.id, organization_id=org_id
        ).first()
        if not member or member.role != 'owner':
            return render_template('404.html'), 404

        memberships = OrganizationMember.query.filter_by(user_id=user.id).all()
        user_workspaces = []
        for m in memberships:
            o = m.organization
            if o.workspace:
                user_workspaces.append({'workspace': o.workspace, 'org': o, 'role': m.role})

        return render_template(
            'org_admin.html',
            org=org,
            user=user,
            user_workspaces=user_workspaces,
            all_permissions=ALL_PERMISSIONS,
        )
    except Exception as e:
        logger.error(f"Org admin error: {e}")
        return render_template('500.html'), 500


@app.route('/api/orgs/<int:org_id>/stats', methods=['GET'])
@api_login_required
def api_get_org_stats(org_id):
    try:
        from sqlalchemy import func
        user = get_current_user()
        member = OrganizationMember.query.filter_by(
            user_id=user.id, organization_id=org_id
        ).first()
        if not member or member.role != 'owner':
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        org = Organization.query.get_or_404(org_id)
        ws = org.workspace
        member_count = OrganizationMember.query.filter_by(organization_id=org_id).count()

        folder_count, file_count, total_size = 0, 0, 0
        if ws:
            folder_count = Folder.query.filter_by(workspace_id=ws.id).count()
            row = db.session.query(func.count(File.id), func.sum(File.size)).join(
                Folder, File.folder_id == Folder.id
            ).filter(Folder.workspace_id == ws.id).first()
            file_count = row[0] or 0
            total_size = row[1] or 0

        recent_logs = []
        if ws:
            fids = [f.id for f in Folder.query.filter_by(workspace_id=ws.id).with_entities(Folder.id)]
            if fids:
                logs = ActionLog.query.filter(ActionLog.folder_id.in_(fids))\
                    .order_by(ActionLog.timestamp.desc()).limit(15).all()
                recent_logs = [l.to_dict() for l in logs]

        return jsonify({
            'success': True,
            'member_count': member_count,
            'folder_count': folder_count,
            'file_count': file_count,
            'total_size': total_size,
            'total_size_human': format_bytes(total_size),
            'recent_activity': recent_logs,
            'invite_code': org.invite_code,
            'created_at': org.created_at.isoformat(),
        })
    except Exception as e:
        logger.error(f"Org stats error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/orgs/<int:org_id>/members', methods=['GET'])
@api_login_required
def api_get_org_members(org_id):
    try:
        user = get_current_user()
        member = OrganizationMember.query.filter_by(
            user_id=user.id, organization_id=org_id
        ).first()
        if not member or member.role != 'owner':
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        members = OrganizationMember.query.filter_by(organization_id=org_id).all()
        result = []
        for m in members:
            u = db.session.get(User, m.user_id)
            if not u:
                continue
            role_info = m.custom_role.to_dict() if m.custom_role else None
            result.append({
                'user_id': u.id,
                'username': u.username,
                'email': u.email,
                'first_name': u.first_name,
                'last_name': u.last_name,
                'phone': u.phone,
                'full_name': u.full_name,
                'joined_at': m.joined_at.isoformat(),
                'role': m.role,
                'custom_role_id': m.custom_role_id,
                'custom_role': role_info,
                'permissions_override': m.permissions_override or [],
                'effective_permissions': _get_effective_permissions(m),
            })
        return jsonify({'success': True, 'members': result})
    except Exception as e:
        logger.error(f"Get org members error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/orgs/<int:org_id>/members/<int:target_user_id>', methods=['PUT'])
@api_login_required
@limiter.limit("20 per minute")
def api_update_org_member(org_id, target_user_id):
    try:
        user = get_current_user()
        caller = OrganizationMember.query.filter_by(
            user_id=user.id, organization_id=org_id
        ).first()
        if not caller or caller.role != 'owner':
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403
        if target_user_id == user.id:
            return jsonify({'success': False, 'message': 'Non puoi modificare il tuo account'}), 400

        target = OrganizationMember.query.filter_by(
            user_id=target_user_id, organization_id=org_id
        ).first()
        if not target:
            return jsonify({'success': False, 'message': 'Membro non trovato'}), 404

        data = request.get_json()

        if 'role' in data and data['role'] in ('member', 'owner'):
            target.role = data['role']

        if 'custom_role_id' in data:
            rid = data['custom_role_id']
            if rid is None:
                target.custom_role_id = None
            else:
                role = OrgRole.query.filter_by(id=rid, organization_id=org_id).first()
                if not role:
                    return jsonify({'success': False, 'message': 'Ruolo non trovato'}), 404
                target.custom_role_id = rid
                target.permissions_override = None

        if 'permissions_override' in data:
            perms = data['permissions_override']
            if isinstance(perms, list) and perms:
                valid = [p for p in perms if p in ALL_PERMISSION_KEYS]
                target.permissions_override = valid or None
                target.custom_role_id = None
            else:
                target.permissions_override = None

        db.session.commit()
        return jsonify({'success': True, 'message': 'Membro aggiornato'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update org member error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/orgs/<int:org_id>/members/<int:target_user_id>', methods=['DELETE'])
@api_login_required
@limiter.limit("10 per minute")
def api_remove_org_member(org_id, target_user_id):
    try:
        user = get_current_user()
        caller = OrganizationMember.query.filter_by(
            user_id=user.id, organization_id=org_id
        ).first()
        if not caller or caller.role != 'owner':
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403
        if target_user_id == user.id:
            return jsonify({'success': False, 'message': 'Non puoi rimuovere te stesso'}), 400

        target = OrganizationMember.query.filter_by(
            user_id=target_user_id, organization_id=org_id
        ).first()
        if not target:
            return jsonify({'success': False, 'message': 'Membro non trovato'}), 404

        u = db.session.get(User, target_user_id)
        db.session.delete(target)
        db.session.commit()
        log_action('remove_member', details=f'Removed {u.username if u else target_user_id} from org {org_id}')
        return jsonify({'success': True, 'message': 'Membro rimosso'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Remove org member error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/orgs/<int:org_id>/roles', methods=['GET'])
@api_login_required
def api_get_org_roles(org_id):
    try:
        user = get_current_user()
        member = OrganizationMember.query.filter_by(
            user_id=user.id, organization_id=org_id
        ).first()
        if not member or member.role != 'owner':
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403
        roles = OrgRole.query.filter_by(organization_id=org_id).all()
        return jsonify({'success': True, 'roles': [r.to_dict() for r in roles]})
    except Exception as e:
        logger.error(f"Get org roles error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/orgs/<int:org_id>/roles', methods=['POST'])
@api_login_required
@limiter.limit("10 per minute")
def api_create_org_role(org_id):
    try:
        user = get_current_user()
        member = OrganizationMember.query.filter_by(
            user_id=user.id, organization_id=org_id
        ).first()
        if not member or member.role != 'owner':
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        data = request.get_json()
        name = sanitize_name(data.get('name', ''))
        if not name:
            return jsonify({'success': False, 'message': 'Nome ruolo richiesto'}), 400

        if OrgRole.query.filter_by(organization_id=org_id, name=name).first():
            return jsonify({'success': False, 'message': 'Nome ruolo già in uso'}), 400

        valid_perms = [p for p in data.get('permissions', []) if p in ALL_PERMISSION_KEYS]
        color = data.get('color', 'accent')
        if color not in ('accent', 'success', 'danger', 'warning', 'info'):
            color = 'accent'

        role = OrgRole(organization_id=org_id, name=name, permissions=valid_perms, color=color)
        db.session.add(role)
        db.session.commit()
        return jsonify({'success': True, 'role': role.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create org role error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/orgs/<int:org_id>/roles/<int:role_id>', methods=['PUT'])
@api_login_required
def api_update_org_role(org_id, role_id):
    try:
        user = get_current_user()
        member = OrganizationMember.query.filter_by(
            user_id=user.id, organization_id=org_id
        ).first()
        if not member or member.role != 'owner':
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        role = OrgRole.query.filter_by(id=role_id, organization_id=org_id).first_or_404()
        data = request.get_json()

        if 'name' in data:
            name = sanitize_name(data['name'])
            if name:
                clash = OrgRole.query.filter_by(organization_id=org_id, name=name)\
                    .filter(OrgRole.id != role_id).first()
                if clash:
                    return jsonify({'success': False, 'message': 'Nome già in uso'}), 400
                role.name = name

        if 'permissions' in data:
            role.permissions = [p for p in data['permissions'] if p in ALL_PERMISSION_KEYS]

        if 'color' in data and data['color'] in ('accent', 'success', 'danger', 'warning', 'info'):
            role.color = data['color']

        db.session.commit()
        return jsonify({'success': True, 'role': role.to_dict()})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update org role error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/orgs/<int:org_id>/roles/<int:role_id>', methods=['DELETE'])
@api_login_required
def api_delete_org_role(org_id, role_id):
    try:
        user = get_current_user()
        member = OrganizationMember.query.filter_by(
            user_id=user.id, organization_id=org_id
        ).first()
        if not member or member.role != 'owner':
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        role = OrgRole.query.filter_by(id=role_id, organization_id=org_id).first_or_404()
        role_name = role.name
        OrganizationMember.query.filter_by(custom_role_id=role_id).update({'custom_role_id': None})
        db.session.delete(role)
        db.session.commit()
        return jsonify({'success': True, 'message': f'Ruolo "{role_name}" eliminato'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete org role error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


# ============================================================================
# SUBFOLDER, BREADCRUMB, DRAG&DROP ORDER
# ============================================================================

@app.route('/api/folders/<int:folder_id>/children', methods=['GET'])
@api_login_required
def api_get_children(folder_id):
    """Sottocartelle dirette con ordine utente applicato."""
    try:
        from sqlalchemy import func
        user = get_current_user()
        parent = Folder.query.get_or_404(folder_id)

        if not _authorize_folder_access(parent, user):
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        orders = {
            fo.folder_id: fo.position
            for fo in FolderOrder.query.filter_by(
                user_id=user.id, workspace_id=parent.workspace_id
            ).all()
        }

        children = Folder.query.filter_by(parent_id=folder_id).all()
        children_data = []
        for f in children:
            files_count = db.session.query(func.count(File.id)).filter(
                File.folder_id == f.id).scalar() or 0
            sub_count = db.session.query(func.count(Folder.id)).filter(
                Folder.parent_id == f.id).scalar() or 0
            d = f.to_dict_base()
            d['files_count'] = files_count
            d['children_count'] = sub_count
            d['position'] = orders.get(f.id, 9999)
            children_data.append(d)

        children_data.sort(key=lambda x: (x['position'], x['created_at']))
        return jsonify({'success': True, 'children': children_data})
    except Exception as e:
        logger.error(f"Get children error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/folders/<int:folder_id>/breadcrumb', methods=['GET'])
@api_login_required
def api_get_breadcrumb(folder_id):
    """Percorso root→cartella per breadcrumb (max 10 livelli)."""
    try:
        path = []
        current = Folder.query.get_or_404(folder_id)
        visited = set()
        while current and current.id not in visited:
            visited.add(current.id)
            path.append({'id': current.id, 'name': current.name})
            if not current.parent_id:
                break
            current = db.session.get(Folder, current.parent_id)
        path.reverse()
        return jsonify({'success': True, 'breadcrumb': path})
    except Exception as e:
        logger.error(f"Breadcrumb error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/folders/order', methods=['GET'])
@api_login_required
def api_get_folder_order():
    try:
        user = get_current_user()
        workspace_id = request.args.get('workspace_id', type=int)
        orders = FolderOrder.query.filter_by(
            user_id=user.id, workspace_id=workspace_id
        ).order_by(FolderOrder.position).all()
        return jsonify({
            'success': True,
            'order': [{'folder_id': o.folder_id, 'position': o.position} for o in orders],
        })
    except Exception as e:
        logger.error(f"Get folder order error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


@app.route('/api/folders/order', methods=['POST'])
@api_login_required
@limiter.limit("60 per minute")
def api_save_folder_order():
    """Salva ordine drag&drop. Payload: {workspace_id, order:[{folder_id,position}]}"""
    try:
        user = get_current_user()
        data = request.get_json()
        workspace_id = data.get('workspace_id')
        order_list = data.get('order', [])
        if not isinstance(order_list, list):
            return jsonify({'success': False, 'message': 'order deve essere una lista'}), 400

        for item in order_list:
            fid = item.get('folder_id')
            pos = item.get('position', 0)
            if not isinstance(fid, int) or not isinstance(pos, int):
                continue
            existing = FolderOrder.query.filter_by(
                user_id=user.id, workspace_id=workspace_id, folder_id=fid
            ).first()
            if existing:
                existing.position = pos
            else:
                db.session.add(FolderOrder(
                    user_id=user.id, workspace_id=workspace_id,
                    folder_id=fid, position=pos,
                ))

        db.session.commit()
        socketio.emit('folder_order_changed', {
            'user_id': user.id,
            'workspace_id': workspace_id,
            'order': order_list,
        })
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Save folder order error: {e}")
        return jsonify({'success': False, 'message': 'Errore'}), 500


# ============================================================================
# EXCEL SAVE
# ============================================================================

@app.route('/api/files/<int:file_id>/excel-save', methods=['POST'])
@api_login_required
@limiter.limit("20 per minute")
def api_excel_save(file_id):
    """Save edited Excel (base64-encoded xlsx) back to disk."""
    try:
        user = get_current_user()
        file = File.query.get_or_404(file_id)

        if not _authorize_file_access(file, user):
            return jsonify({'success': False, 'message': 'Accesso negato'}), 403

        data = request.get_json()
        b64_data = data.get('data', '')
        if not b64_data:
            return jsonify({'success': False, 'message': 'Nessun dato fornito'}), 400

        filename = file.original_name or file.name
        ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
        if ext not in ('xlsx', 'xls', 'ods', 'csv', 'xlsm'):
            return jsonify({'success': False, 'message': 'Tipo file non supportato per la modifica'}), 400

        file_path = os.path.join(get_upload_folder(), file.file_path)
        xlsx_bytes = base64.b64decode(b64_data)
        with open(file_path, 'wb') as f:
            f.write(xlsx_bytes)

        file.size = os.path.getsize(file_path)
        db.session.commit()

        log_action('edit_excel', 'file', file_id, f'Excel edited: {filename}')
        socketio.emit('file_updated',
                      {'folder_id': file.folder_id, 'file': file.to_dict()},
                      room=f'folder_{file.folder_id}')
        return jsonify({'success': True, 'message': 'File Excel salvato'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Excel save error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ============================================================================
# WEBSOCKET HANDLERS
# ============================================================================

def _make_user_presence(sid):
    info = online_users.get(sid, {})
    return {
        'user_id': info.get('user_id'),
        'username': info.get('username'),
        'full_name': info.get('full_name'),
        'folder_id': info.get('folder_id'),
    }


def _get_folder_users(folder_id, exclude_sid=None):
    with _online_lock:
        return [
            _make_user_presence(sid)
            for sid, info in online_users.items()
            if info.get('folder_id') == folder_id and sid != exclude_sid
        ]


@socketio.on('connect')
def handle_ws_connect(auth=None):
    user_id = session.get('user_id')
    if not user_id:
        return False
    user = db.session.get(User, user_id)
    if not user:
        return False
    from flask import request as sio_req
    with _online_lock:
        online_users[sio_req.sid] = {
            'user_id': user.id,
            'username': user.username,
            'full_name': user.full_name,
            'folder_id': None,
            'connected_at': datetime.utcnow().isoformat(),
        }
        users_list = list(online_users.values())
    sio_emit('users_online', users_list)
    socketio.emit('users_online', users_list)


@socketio.on('disconnect')
def handle_ws_disconnect():
    from flask import request as sio_req
    with _online_lock:
        info = online_users.pop(sio_req.sid, None)
        users_list = list(online_users.values())
    if info and info.get('folder_id'):
        fid = info['folder_id']
        socketio.emit('folder_presence',
                      {'folder_id': fid, 'users': _get_folder_users(fid)},
                      room=f'folder_{fid}')
    socketio.emit('users_online', users_list)


@socketio.on('join_folder')
def handle_join_folder(data):
    from flask import request as sio_req
    folder_id = data.get('folder_id')
    sid = sio_req.sid
    with _online_lock:
        if sid not in online_users:
            return
        old_fid = online_users[sid].get('folder_id')
        online_users[sid]['folder_id'] = folder_id
    if old_fid and old_fid != folder_id:
        leave_room(f'folder_{old_fid}')
        socketio.emit('folder_presence',
                      {'folder_id': old_fid, 'users': _get_folder_users(old_fid, exclude_sid=sid)},
                      room=f'folder_{old_fid}')
    if folder_id:
        join_room(f'folder_{folder_id}')
        socketio.emit('folder_presence',
                      {'folder_id': folder_id, 'users': _get_folder_users(folder_id)},
                      room=f'folder_{folder_id}')


@socketio.on('leave_folder')
def handle_leave_folder(data):
    from flask import request as sio_req
    folder_id = data.get('folder_id')
    sid = sio_req.sid
    with _online_lock:
        if sid not in online_users or not folder_id:
            return
        online_users[sid]['folder_id'] = None
    leave_room(f'folder_{folder_id}')
    socketio.emit('folder_presence',
                  {'folder_id': folder_id, 'users': _get_folder_users(folder_id)},
                  room=f'folder_{folder_id}')


@app.route('/api/users/online', methods=['GET'])
@api_login_required
def api_users_online():
    with _online_lock:
        users = list(online_users.values())
    return jsonify({'success': True, 'users': users})


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def page_not_found(e):
    try:
        log_action('404_error', details=f'URL: {request.url}')
    except Exception:
        pass
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 error at {request.url}: {e}")
    try:
        log_action('500_error', details=f'URL: {request.url}')
    except Exception:
        pass
    return render_template('500.html'), 500


@app.errorhandler(413)
def file_too_large(e):
    return jsonify({'success': False, 'message': 'File troppo grande (max 15 GB)'}), 413


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'success': False, 'message': 'Troppi tentativi, riprova tra poco'}), 429


# ============================================================================
# FTP SERVER (optional)
# ============================================================================

def start_ftp_server():
    """Start pyftpdlib FTP server in a daemon thread."""
    try:
        from pyftpdlib.handlers import FTPHandler
        from pyftpdlib.servers import FTPServer
        from pyftpdlib.authorizers import DummyAuthorizer

        ftp_user = os.environ.get('FTP_USER', 'iris_ftp')
        ftp_password = os.environ.get('FTP_PASSWORD')
        if not ftp_password:
            logger.error("FTP_PASSWORD non impostata. FTP server non avviato.")
            return
        ftp_port = int(os.environ.get('FTP_PORT', 2121))
        passive_ports_raw = os.environ.get('FTP_PASSIVE_PORTS', '60000-60100')
        p_start, p_end = (int(x) for x in passive_ports_raw.split('-'))

        authorizer = DummyAuthorizer()
        authorizer.add_user(ftp_user, ftp_password, UPLOAD_FOLDER, perm='elradfmwMT')

        handler = FTPHandler
        handler.authorizer = authorizer
        handler.passive_ports = range(p_start, p_end + 1)
        handler.banner = "IRIS-VE FTP Server — Ready"

        server = FTPServer(('0.0.0.0', ftp_port), handler)
        logger.info(f"FTP server avviato su porta {ftp_port} (passive: {p_start}-{p_end})")
        server.serve_forever()
    except ImportError:
        logger.error("pyftpdlib non installato. Esegui: pip install pyftpdlib==1.5.9")
    except Exception as e:
        logger.error(f"FTP server error: {e}")


# ============================================================================
# STARTUP
# ============================================================================

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created")

            config = StorageConfig.query.first()
            if config and config.active_disk_path and os.path.isdir(config.active_disk_path):
                UPLOAD_FOLDER = config.active_disk_path
                logger.info(f"Active disk loaded from DB: {UPLOAD_FOLDER}")
            else:
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)

            if User.query.count() == 0:
                admin = User(username=ADMIN_USERNAME, email=ADMIN_EMAIL)
                admin.set_password(ADMIN_PASSWORD)
                db.session.add(admin)
                db.session.commit()
                logger.info(f"Admin user '{ADMIN_USERNAME}' created")
                print(f"✅ Utente admin '{ADMIN_USERNAME}' creato dall'ambiente")

        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            print(f"⚠️  Database error: {e}")
            print(f"📝 Make sure MySQL is running and database 'iris_ve' exists")

    if os.environ.get('FTP_ENABLED', 'False').lower() == 'true':
        ftp_thread = threading.Thread(target=start_ftp_server, daemon=True)
        ftp_thread.start()

    local_ip = get_local_ip()
    public_ip = get_public_ip()
    http_port = int(os.environ.get('EXTERNAL_PORT', 25565))
    ftp_port = int(os.environ.get('FTP_PORT', 2121))
    print("🚀 IRIS-VE v2.1 STARTUP")
    print("═" * 80)
    print(f"📍 Local Access:  http://{local_ip}:5000")
    print(f"🌐 Remote Access: http://{public_ip}:{http_port}")
    print(f"📁 FTP Access:    ftp://{local_ip}:{ftp_port}")
    print(f"✅ Server pronto!")
    print("═" * 80)

    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=False,
        use_reloader=False,
        log_output=False,
        allow_unsafe_werkzeug=True,
    )


# ============================================================================
# CHANGELOG v2.0 → v2.1
# ============================================================================
#
# BUG FIXES:
# - [CRITICAL] Rimossi route duplicate (api_get_files_v4, api_create_folder_v4)
#   che sovrascrivevano le originali causando dead code
# - [CRITICAL] uploaded_by_id ora viene assegnato durante l'upload
# - [CRITICAL] api_delete_file: ordine corretto (DB commit → rimuovi da disco),
#   prima era invertito causando potenziale perdita dati
# - [CRITICAL] Aggiunto authorization check su TUTTI gli endpoint file
#   (download, delete, preview, zip-extract, excel-save)
# - Dashboard e workspace_view ora filtrano solo cartelle root (parent_id=None)
# - _collect_folder_file_paths: raccolta ricorsiva path per delete cartella
#   (prima eliminava solo file diretti, non quelli nelle sottocartelle)
# - decrypt_data: aggiunta validazione padding PKCS7
# - sanitize_name: aggiunta rimozione separatori path (directory traversal)
# - zip-extract: aggiunto controllo path traversal (.., /)
# - secure_filename fallback per nomi unicode-only
#
# SECURITY:
# - Warning esplicito se ADMIN_PASSWORD è default o mancante
# - Warning esplicito se ALLOWED_ORIGINS='*' in produzione
# - FTP server rifiuta avvio se FTP_PASSWORD non è impostata
# - generate_invite_code: usa secrets invece di random, 50 tentativi con raise
# - Controllo permessi granulari (upload_files, delete_files, create_folders)
#   sugli endpoint workspace
#
# PERFORMANCE:
# - File.uploader: relationship lazy='joined' elimina N+1 query in to_dict()
# - Aggiunto indice ix_files_uploaded_by
#
# STABILITY:
# - online_users protetto con threading.Lock per thread-safety
# - get_local_ip: aggiunto timeout socket
# - api_disk_space: usa get_upload_folder() invece del default hardcoded
# - Division by zero guard in api_disk_space
# - FIX: api_upload_file, api_download_file, api_delete_file, api_file_preview,
#   api_file_preview_inline, api_zip_extract e api_excel_save ora usano get_storage()

