"""
Flask REST API Server for SISKA Scraper - Stateless Version (fixed)
- Graceful SIGTERM handling for cPanel/Passenger
- Robust logging (UTF-8)
- File-based fallback rate limiter for shared hosting
- Safer scraper method calls and SSL handling
- Exports `application` for WSGI (Passenger/mod_wsgi)
"""

import sys
import os
import signal
import uuid
import re
import logging
import ssl
import threading
import sqlite3
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, request, jsonify, has_request_context
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests

# +-------------+
# Environment & UTF-8
# +-------------+
os.environ.setdefault('PYTHONIOENCODING', 'utf-8')
if sys.version_info >= (3, 7):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Create required directories
Path('logs').mkdir(parents=True, exist_ok=True)
Path('data').mkdir(parents=True, exist_ok=True)

# +-------------+
# Import scraper (with robust fallback)
# +-------------+
try:
    from siska_scraper import SiskaScraper
    from config import Config
except Exception as e:
    # Fallback lightweight scraper shim for testing/development
    print(f"[WARN] could not import siska_scraper or config: {e}")

    class SiskaScraper:
        def __init__(self):
            pass
        def login(self, username, password, level):
            return True
        def get_jadwal(self):
            return [{"test": "data", "mata_kuliah": "Test Course"}]
        def get_rate_limit_stats(self):
            return {"requests": 0}
        def get_user_info(self):
            return {"name": None, "username": None}
        def get_ssl_status(self):
            return {"ssl_verified": False}

    class Config:
        rate_limiter_storage = 'file'

# +-------------+
# Logging (UTF-8 safe)
# +-------------+
class UTFHandler(logging.FileHandler):
    def __init__(self, filename, mode='a', encoding='utf-8', delay=False):
        super().__init__(filename, mode, encoding, delay)

LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
try:
    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FORMAT,
        handlers=[
            UTFHandler('logs/api_security.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
except Exception:
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security')

# +-------------+
# App initialization
# +-------------+
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', str(uuid.uuid4()))
app.config['JSON_AS_ASCII'] = False  # keep Unicode in JSON
allowed_origins = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
CORS(app, origins=allowed_origins)

# +-------------+
# Helpers
# +-------------+
def client_ip():
    """Return best-effort client IP (handles common proxy headers)."""
    # On cPanel/Passenger there might be proxies; check headers safely
    for header in ("X-Real-IP", "X-Forwarded-For", "CF-Connecting-IP"):
        val = request.headers.get(header)
        if val:
            # X-Forwarded-For could be a list
            return val.split(',')[0].strip()
    return request.remote_addr or "unknown"

# +-------------+
# File-based rate limiter (simple)
# +-------------+
class FileLimiterStorage:
    """Simple SQLite-based counter for basic rate limiting (shared hosting)."""
    def __init__(self, db_path='data/rate_limits.db'):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS rate_limits (
                    key TEXT PRIMARY KEY,
                    count INTEGER DEFAULT 0,
                    reset_time INTEGER
                )
            ''')
            conn.commit()

    def incr(self, key, expiry_seconds=3600):
        now = int(time.time())
        reset_time = now + expiry_seconds
        with self._lock, sqlite3.connect(self.db_path) as conn:
            # remove expired
            conn.execute('DELETE FROM rate_limits WHERE reset_time <= ?', (now,))
            cur = conn.execute('SELECT count FROM rate_limits WHERE key = ?', (key,))
            row = cur.fetchone()
            if row:
                new_count = row[0] + 1
                conn.execute('UPDATE rate_limits SET count = ?, reset_time = ? WHERE key = ?', (new_count, reset_time, key))
            else:
                new_count = 1
                conn.execute('INSERT INTO rate_limits (key, count, reset_time) VALUES (?, ?, ?)', (key, new_count, reset_time))
            conn.commit()
            return new_count

    def get(self, key):
        now = int(time.time())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('DELETE FROM rate_limits WHERE reset_time <= ?', (now,))
            cur = conn.execute('SELECT count FROM rate_limits WHERE key = ?', (key,))
            row = cur.fetchone()
            return row[0] if row else 0

    def clear(self, key):
        with self._lock, sqlite3.connect(self.db_path) as conn:
            conn.execute('DELETE FROM rate_limits WHERE key = ?', (key,))
            conn.commit()

# Decide storage type (try config -> env)
def get_rate_storage():
    storage_type = os.getenv('RATE_LIMITER_STORAGE')
    try:
        cfg = Config()
        storage_type = storage_type or getattr(cfg, 'rate_limiter_storage', None)
    except Exception:
        pass
    if storage_type == 'redis':
        # let flask-limiter handle redis if available
        try:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            import redis  # may raise
            r = redis.from_url(redis_url)
            r.ping()
            logger.info(f"Using Redis for rate limiting: {redis_url}")
            return redis_url
        except Exception as e:
            logger.warning(f"Redis not usable for rate limiting ({e}), falling back to file storage")
            return FileLimiterStorage()
    elif storage_type == 'memory':
        logger.info("Using in-memory rate limiter (dev).")
        return "memory://"
    else:
        logger.info("Using file-based rate limiter storage (shared hosting).")
        return FileLimiterStorage()

rate_storage = get_rate_storage()

# Integrate with flask-limiter where we can (memory/redis), otherwise we'll do custom checks
limiter_config_uri = None
if isinstance(rate_storage, str):
    limiter_config_uri = rate_storage
elif isinstance(rate_storage, FileLimiterStorage):
    limiter_config_uri = "memory://"  # let limiter run in memory but we enforce file checks separately

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["30 per hour", "5 per minute"],
    storage_uri=limiter_config_uri
)

# If file storage is used, implement a lightweight before_request check
FILE_RATE_LIMITS = {
    "per_minute": (60, 5),   # (window_seconds, max)
    "per_hour": (3600, 30)
}

@app.before_request
def file_rate_check():
    # only apply if using FileLimiterStorage
    if not isinstance(rate_storage, FileLimiterStorage):
        return
    # only protect API endpoints that mutate / heavy ones
    if request.path.startswith('/api/'):
        ip = client_ip()
        # enforce each configured bucket
        for name, (window, limit) in FILE_RATE_LIMITS.items():
            key = f"{ip}:{name}"
            count = rate_storage.incr(key, expiry_seconds=window)
            if count > limit:
                security_logger.warning(f"Rate limit exceeded ({name}) for {ip}")
                return jsonify({
                    "status": "error",
                    "message": "Too many requests",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "error_code": "RATE_LIMIT_EXCEEDED"
                }), 429

# Small helper for safe JSON responses (keeps your APIResponse behavior)
def api_success(data=None, message="Success", status_code=200):
    response = {
        "status": "success",
        "message": str(message),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "data": data
    }
    resp = jsonify(response)
    resp.status_code = status_code
    resp.headers['Content-Type'] = 'application/json; charset=utf-8'
    return resp

def api_error(message="Error occurred", status_code=400, error_code=None):
    response = {
        "status": "error",
        "message": str(message),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "error_code": error_code
    }
    resp = jsonify(response)
    resp.status_code = status_code
    resp.headers['Content-Type'] = 'application/json; charset=utf-8'
    # log some security events
    if status_code in (401, 403):
        try:
            security_logger.warning(f"Security event {error_code}: {client_ip()}")
        except Exception:
            security_logger.warning(f"Security event {error_code}: <IP logging error>")
    return resp

# +-------------+
# Graceful shutdown handling (SIGTERM)
# +-------------+
_shutdown_event = threading.Event()

def _graceful_shutdown(signum, frame):
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    _shutdown_event.set()
    # If running with Werkzeug dev server, call shutdown function
    try:
        func = request.environ.get('werkzeug.server.shutdown') if has_request_context() else None
        if func:
            func()
    except Exception:
        pass

signal.signal(signal.SIGTERM, _graceful_shutdown)
signal.signal(signal.SIGINT, _graceful_shutdown)

# +-------------+
# Routes
# +-------------+
@app.route('/')
def index():
    info = {
        "name": "SISKA Scraper REST API - Stateless",
        "version": "1.0.0-stateless-ssl",
        "description": "Direct login + data retrieval API untuk SISKA UNDIPA",
    }
    return api_success(info, "SISKA Scraper API v1.0 - Stateless with SSL handling")

@app.route('/api/health')
def health_check():
    return api_success({
        "status": "healthy",
        "version": "1.0.0-stateless-ssl",
        "encoding": "UTF-8",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }, "Service is healthy")

@app.route('/api/status')
def service_status():
    try:
        test_url = "https://siska.undipa.ac.id/login"
        ssl_verified = False
        connectivity = "unknown"
        try:
            r = requests.get(test_url, verify=True, timeout=10)
            ssl_verified = True
            connectivity = "ok" if r.status_code == 200 else f"error_{r.status_code}"
        except ssl.SSLError:
            try:
                r = requests.get(test_url, verify=False, timeout=10)
                ssl_verified = False
                connectivity = "ok_no_ssl" if r.status_code == 200 else f"error_{r.status_code}"
            except Exception:
                connectivity = "failed"
        except Exception:
            connectivity = "failed"

        storage_info = "unknown"
        if isinstance(rate_storage, FileLimiterStorage):
            storage_info = "File-based SQLite"
        elif isinstance(rate_storage, str):
            if rate_storage.startswith('redis://'):
                storage_info = "Redis"
            elif rate_storage == "memory://":
                storage_info = "Memory (development)"

        return api_success({
            "service": "healthy",
            "siska_connectivity": connectivity,
            "ssl_verification": "verified" if ssl_verified else "bypassed",
            "rate_limiter_storage": storage_info,
            "last_check": datetime.utcnow().isoformat() + "Z"
        }, "Service status check completed")
    except Exception as e:
        logger.exception("Status check failed")
        return api_error("Service status check failed", 503, "STATUS_CHECK_ERROR")

# Utility to safely call scraper methods
def safe_scraper_call(scraper, method_name, *args, **kwargs):
    try:
        method = getattr(scraper, method_name, None)
        if not callable(method):
            return None
        return method(*args, **kwargs)
    except Exception as e:
        logger.exception(f"Scraper method {method_name} failed")
        return None

@app.route('/api/jadwal', methods=['POST'])
def get_jadwal():
    # Basic JSON checks
    if not request.is_json:
        return api_error("Content-Type must be application/json", 400, "INVALID_CONTENT_TYPE")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("Invalid JSON payload", 400, "INVALID_PAYLOAD")

    raw_username = data.get('username', '')
    raw_password = data.get('password', '')
    raw_level = data.get('level', 'mahasiswa')

    # Basic validation & sanitize
    username = (str(raw_username)[:50]) if raw_username is not None else ''
    if not (3 <= len(username) <= 50) or not re.match(r'^[a-zA-Z0-9._-]+$', username):
        security_logger.warning(f"Invalid username from IP: {client_ip()}")
        return api_error("Username must be 3-50 characters and alphanumeric/._-", 400, "INVALID_USERNAME")

    password = raw_password or ''
    if not (6 <= len(password) <= 100):
        security_logger.warning(f"Invalid password from IP: {client_ip()}")
        return api_error("Password must be 6-100 characters", 400, "INVALID_PASSWORD")

    level = (str(raw_level).lower().strip() if raw_level else 'mahasiswa')
    if level not in {'mahasiswa', 'dosen', 'admin', 'staf'}:
        level = 'mahasiswa'

    # Log initiation (no sensitive data)
    session_id = str(uuid.uuid4())[:8]
    logger.info(f"Jadwal request - Session:{session_id} - IP:{client_ip()}")

    # Initialize scraper
    try:
        scraper = SiskaScraper()
    except Exception as e:
        logger.exception("Scraper initialization error")
        return api_error("Service initialization error", 500, "SCRAPER_INIT_ERROR")

    # Attempt login with SSL and connection handling
    try:
        login_success = safe_scraper_call(scraper, 'login', username, password, level)
    except requests.exceptions.SSLError as ssl_err:
        logger.warning(f"SSL error during login: {ssl_err}")
        return api_error("Server certificate issue - please try again later", 503, "SSL_CERTIFICATE_ERROR")
    except requests.exceptions.ConnectionError as conn_err:
        logger.error(f"Connection error during login: {conn_err}")
        return api_error("Unable to connect to SISKA server", 503, "CONNECTION_ERROR")
    except Exception as e:
        logger.exception("Login error")
        return api_error("Login service unavailable", 503, "LOGIN_SERVICE_ERROR")

    if not login_success:
        security_logger.warning(f"Login failed - Session:{session_id} - IP:{client_ip()}")
        return api_error("Login failed", 401, "LOGIN_FAILED")

    # Fetch jadwal
    jadwal_data = safe_scraper_call(scraper, 'get_jadwal')
    if jadwal_data is None:
        logger.exception("Jadwal fetch error")
        return api_error("Jadwal service unavailable", 503, "JADWAL_SERVICE_ERROR")

    # rate stats (optional)
    rate_stats = safe_scraper_call(scraper, 'get_rate_limit_stats')

    response_data = {
        'jadwal': jadwal_data,
        'metadata': {
            'retrieved_at': datetime.utcnow().isoformat() + "Z",
            'count': len(jadwal_data) if isinstance(jadwal_data, list) else 1,
            'session_id': session_id,
            'rate_stats': rate_stats,
            'ssl_status': 'handled',
            'encoding': 'UTF-8'
        }
    }

    logger.info(f"Jadwal retrieved - Session:{session_id} - Count:{response_data['metadata']['count']} - IP:{client_ip()}")
    return api_success(response_data, "Jadwal retrieved successfully")

@app.route('/api/login', methods=['POST'])
def check_login():
    if not request.is_json:
        return api_error("Content-Type must be application/json", 400, "INVALID_CONTENT_TYPE")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("Invalid JSON payload", 400, "INVALID_PAYLOAD")

    username = (str(data.get('username', ''))[:50]) or ''
    password = data.get('password', '') or ''
    raw_level = data.get('level', 'mahasiswa')
    level = (str(raw_level).lower().strip() if raw_level else 'mahasiswa')
    if level not in {'mahasiswa', 'dosen', 'admin', 'staf'}:
        level = 'mahasiswa'

    if not (3 <= len(username) <= 50) or not re.match(r'^[a-zA-Z0-9._-]+$', username):
        security_logger.warning(f"Invalid username from IP: {client_ip()}")
        return api_error("Invalid username", 400, "INVALID_USERNAME")
    if not (6 <= len(password) <= 100):
        security_logger.warning(f"Invalid password from IP: {client_ip()}")
        return api_error("Invalid password", 400, "INVALID_PASSWORD")

    session_id = str(uuid.uuid4())[:8]
    logger.info(f"Login check - Session:{session_id} - IP:{client_ip()}")

    try:
        scraper = SiskaScraper()
    except Exception:
        logger.exception("Scraper init failed")
        return api_error("Service initialization error", 500, "SCRAPER_INIT_ERROR")

    login_success = safe_scraper_call(scraper, 'login', username, password, level)
    if not login_success:
        security_logger.warning(f"Login verification failed - Session:{session_id} - IP:{client_ip()}")
        return api_error("Login failed", 401, "LOGIN_FAILED")

    user_info = safe_scraper_call(scraper, 'get_user_info') or {
        'name': None, 'username': None, 'level': None, 'nim_nidn': None, 'email': None
    }
    ssl_status = safe_scraper_call(scraper, 'get_ssl_status') or {"ssl_verified": False}

    response_data = {
        'login_status': 'authenticated',
        'level': level,
        'user_info': user_info,
        'metadata': {
            'verified_at': datetime.utcnow().isoformat() + "Z",
            'session_id': session_id,
            'ssl_status': ssl_status,
            'encoding': 'UTF-8'
        }
    }

    logger.info(f"Login verified - Session:{session_id} - IP:{client_ip()}")
    return api_success(response_data, "Login credentials verified successfully")

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return api_error("Resource not found", 404, "NOT_FOUND")

@app.errorhandler(405)
def method_not_allowed(e):
    return api_error("Method not allowed", 405, "METHOD_NOT_ALLOWED")

@app.errorhandler(500)
def internal_error(e):
    logger.exception("Unhandled internal error")
    return api_error("Internal server error", 500, "INTERNAL_ERROR")

# Export WSGI application variable for cPanel / Passenger
application = app

# If executed directly (development), run built-in server; otherwise WSGI server (Passenger) will load `application`.
if __name__ == '__main__':
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    logger.info(f"Starting development server on 0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port, debug=debug, threaded=True)
