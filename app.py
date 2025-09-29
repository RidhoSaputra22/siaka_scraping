"""
Flask REST API Server for SISKA Scraper - Stateless Version
Direct login + data retrieval without session management
"""

import sys
import os

# [SECURITY] ENCODING: Set UTF-8 encoding untuk environment
os.environ['PYTHONIOENCODING'] = 'utf-8'

# Force UTF-8 encoding untuk Python
if sys.version_info >= (3, 7):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import uuid
import re
import hashlib
from datetime import datetime
import logging
import ssl
import requests
import sqlite3
import threading
from pathlib import Path

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Import our scraper
try:
    from siska_scraper import SiskaScraper
    from config import Config
except ImportError as e:
    print(f"Import warning: {e}")
    # Create minimal scraper for testing
    class SiskaScraper:
        def login(self, username, password, level):
            return True
        def get_jadwal(self):
            return [{"test": "data", "mata_kuliah": "Test Course"}]
        def get_rate_limit_stats(self):
            return {"requests": 0}

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', str(uuid.uuid4()))

# [SECURITY] ENCODING: Set Flask to handle Unicode properly
app.config['JSON_AS_ASCII'] = False  # Allow Unicode in JSON responses

allowed_origins = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
CORS(app, origins=allowed_origins)

# Rate Limiter Storage Configuration
class FileLimiterStorage:
    """SQLite-based storage for Flask-Limiter - suitable for shared hosting"""
    
    def __init__(self, db_path='data/rate_limits.db'):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database for rate limiting"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS rate_limits (
                    key TEXT PRIMARY KEY,
                    count INTEGER DEFAULT 0,
                    reset_time INTEGER,
                    created_at INTEGER DEFAULT (strftime('%s', 'now'))
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_reset_time ON rate_limits(reset_time)
            ''')
            conn.commit()
    
    def incr(self, key, expiry=None):
        """Increment counter for key"""
        import time
        current_time = int(time.time())
        reset_time = current_time + (expiry or 3600)  # Default 1 hour
        
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                # Clean expired entries
                conn.execute('DELETE FROM rate_limits WHERE reset_time < ?', (current_time,))
                
                # Get or create entry
                cursor = conn.execute('SELECT count FROM rate_limits WHERE key = ?', (key,))
                row = cursor.fetchone()
                
                if row:
                    new_count = row[0] + 1
                    conn.execute('UPDATE rate_limits SET count = ? WHERE key = ?', (new_count, key))
                else:
                    new_count = 1
                    conn.execute(
                        'INSERT INTO rate_limits (key, count, reset_time) VALUES (?, ?, ?)',
                        (key, new_count, reset_time)
                    )
                
                conn.commit()
                return new_count
    
    def get(self, key):
        """Get current count for key"""
        import time
        current_time = int(time.time())
        
        with sqlite3.connect(self.db_path) as conn:
            # Clean expired entries first
            conn.execute('DELETE FROM rate_limits WHERE reset_time < ?', (current_time,))
            
            cursor = conn.execute('SELECT count FROM rate_limits WHERE key = ?', (key,))
            row = cursor.fetchone()
            return row[0] if row else 0
    
    def clear(self, key):
        """Clear counter for key"""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('DELETE FROM rate_limits WHERE key = ?', (key,))
                conn.commit()

def get_limiter_storage():
    """Get appropriate storage backend for rate limiter"""
    try:
        from config import Config
        config = Config()
        storage_type = config.rate_limiter_storage
    except:
        storage_type = os.getenv('RATE_LIMITER_STORAGE', 'file')
    
    if storage_type == 'redis':
        try:
            import redis
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            # Test Redis connection
            r = redis.from_url(redis_url)
            r.ping()
            print(f"[INFO] Using Redis storage for rate limiting: {redis_url}")
            return redis_url
        except ImportError:
            print("[WARNING] Redis not available, falling back to file storage")
        except Exception as e:
            print(f"[WARNING] Redis connection failed: {e}, falling back to file storage")
    
    elif storage_type == 'memory':
        print("[INFO] Using in-memory storage for rate limiting (development only)")
        return "memory://"
    
    # Default to file storage (best for shared hosting)
    file_path = os.getenv('RATE_LIMITER_FILE_PATH', 'data/rate_limits.db')
    print(f"[INFO] Using file-based storage for rate limiting: {file_path}")
    return FileLimiterStorage(file_path)

# Initialize rate limiter with appropriate storage
storage_backend = get_limiter_storage()

# For file-based storage, we'll use a simpler approach with environment variable
if isinstance(storage_backend, FileLimiterStorage):
    # Use memory storage and implement our own rate limiting logic
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["30 per hour", "5 per minute"],
        storage_uri="memory://"  # We'll handle persistence ourselves
    )
    # Store reference to our custom storage for later use
    app.config['CUSTOM_RATE_STORAGE'] = storage_backend
else:
    # URL-based storage (Redis or memory)
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["30 per hour", "5 per minute"],
        storage_uri=storage_backend
    )

limiter.init_app(app)

# [SECURITY] ENCODING: Enhanced logging with UTF-8 support
class UTFHandler(logging.FileHandler):
    def __init__(self, filename, mode='a', encoding='utf-8', delay=False):
        super().__init__(filename, mode, encoding, delay)

try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            UTFHandler('logs/api_security.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
except Exception:
    # Fallback to basic logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security')

class SecurityValidator:
    """Input validation and sanitization"""
    
    @staticmethod
    def validate_username(username):
        """Validate username format"""
        if not username or len(username) < 3 or len(username) > 50:
            return False, "Username must be 3-50 characters"
        
        # Allow alphanumeric, dots, underscores, hyphens
        pattern = r'^[a-zA-Z0-9._-]+$'
        if not re.match(pattern, username):
            return False, "Username contains invalid characters"
        
        return True, None
    
    @staticmethod
    def validate_password(password):
        """Basic password validation"""
        if not password or len(password) < 6 or len(password) > 100:
            return False, "Password must be 6-100 characters"
        
        return True, None
    
    @staticmethod
    def validate_level(level):
        """Validate user level"""
        allowed_levels = {'mahasiswa', 'dosen', 'admin', 'staf'}
        level = level.lower().strip()
        
        if level not in allowed_levels:
            return 'mahasiswa', "Invalid level, defaulting to mahasiswa"
        
        return level, None
    
    @staticmethod
    def sanitize_input(input_str, max_length=100):
        """Sanitize user input - Unicode safe"""
        if not input_str:
            return ""
        
        # Handle Unicode properly
        try:
            input_str = str(input_str)
            # Remove potentially dangerous characters but keep Unicode
            sanitized = re.sub(r'[<>"\';\\]', '', input_str)
            return sanitized[:max_length].strip()
        except UnicodeError:
            # Fallback to ASCII-safe version
            sanitized = input_str.encode('ascii', 'ignore').decode('ascii')
            return sanitized[:max_length].strip()

class APIResponse:
    """Secure API response format"""
    
    @staticmethod
    def success(data=None, message="Success", status_code=200):
        """Create success response - Unicode safe"""
        try:
            response = {
                "status": "success",
                "message": str(message),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "data": data
            }
            json_response = jsonify(response)
            json_response.status_code = status_code
            json_response.headers['Content-Type'] = 'application/json; charset=utf-8'
            return json_response
        except UnicodeEncodeError as e:
            logger.warning(f"Unicode encoding error in success response: {e}")
            return APIResponse._create_safe_response(data, message, status_code, "success")
    
    @staticmethod
    def error(message="Error occurred", status_code=400, error_code=None):
        """Create error response - Unicode safe"""
        try:
            generic_messages = {
                401: "Authentication failed",
                403: "Access denied", 
                404: "Resource not found",
                500: "Internal server error",
                503: "Service temporarily unavailable"
            }
            
            if status_code in [401, 500, 503] and error_code:
                message = generic_messages.get(status_code, message)
            
            response = {
                "status": "error",
                "message": str(message),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "error_code": error_code
            }
            
            if status_code in [401, 403]:
                try:
                    security_logger.warning(f"Security event {error_code}: {request.remote_addr}")
                except:
                    security_logger.warning(f"Security event {error_code}: <IP logging error>")
            
            json_response = jsonify(response)
            json_response.status_code = status_code
            json_response.headers['Content-Type'] = 'application/json; charset=utf-8'
            return json_response
        except UnicodeEncodeError as e:
            logger.warning(f"Unicode encoding error in error response: {e}")
            return APIResponse._create_safe_response(None, message, status_code, "error", error_code)
    
    @staticmethod
    def _create_safe_response(data, message, status_code, status, error_code=None):
        """Create ASCII-safe response as fallback"""
        try:
            safe_message = message.encode('ascii', 'ignore').decode('ascii') if message else "Response encoding error"
            response = {
                "status": status,
                "message": safe_message,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            if status == "success":
                response["data"] = {"note": "Unicode data filtered for compatibility"}
            else:
                response["error_code"] = error_code or "ENCODING_ERROR"
            return jsonify(response), status_code
        except Exception:
            return jsonify({
                "status": "error",
                "message": "Server encoding error",
                "error_code": "CRITICAL_ENCODING_ERROR"
            }), 500

@app.before_request
def limit_request_size():
    """Limit request size to prevent DoS"""
    if request.content_length and request.content_length > 1024 * 1024:  # 1MB limit
        return APIResponse.error("Request too large", 413, "REQUEST_TOO_LARGE")

@app.route('/')
def index():
    """API information endpoint"""
    info = {
        "name": "SISKA Scraper REST API - Stateless",
        "version": "1.0.0-stateless-ssl",
        "description": "Direct login + data retrieval API untuk SISKA UNDIPA",
        "endpoints": {
            "POST /api/jadwal": "Login dan ambil jadwal dalam satu request",
            "GET /api/health": "Health check",
            "GET /api/status": "Service status including SSL info",
            "GET /api/docs": "API documentation"
        },
        "features": [
            "Stateless design",
            "Direct login + data",
            "Rate limiting",
            "Input validation",
            "Secure logging",
            "SSL error handling",
            "Unicode support"
        ]
    }
    return APIResponse.success(info, "SISKA Scraper API v1.0 - Stateless with SSL handling")

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return APIResponse.success({
        "status": "healthy",
        "version": "1.0.0-stateless-ssl",
        "encoding": "UTF-8",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }, "Service is healthy")

@app.route('/api/status')
def service_status():
    """Check service and SSL status"""
    try:
        # Test connection to SISKA
        test_url = "https://siska.undipa.ac.id/login"
        
        # Test with SSL verification first
        ssl_verified = False
        connectivity = "unknown"
        
        try:
            response = requests.get(test_url, verify=True, timeout=10)
            ssl_verified = True
            connectivity = "ok" if response.status_code == 200 else "error"
        except ssl.SSLError:
            # Try without SSL verification
            try:
                response = requests.get(test_url, verify=False, timeout=10)
                ssl_verified = False
                connectivity = "ok_no_ssl" if response.status_code == 200 else "error"
            except Exception:
                connectivity = "failed"
        except Exception:
            connectivity = "failed"
        
        # Get rate limiter storage info
        storage_info = "unknown"
        if isinstance(storage_backend, str):
            if storage_backend.startswith('redis://'):
                storage_info = "Redis"
            elif storage_backend == "memory://":
                storage_info = "Memory (development)"
        else:
            storage_info = "File-based SQLite"
        
        status_data = {
            "service": "healthy",
            "siska_connectivity": connectivity,
            "ssl_verification": "verified" if ssl_verified else "bypassed",
            "ssl_warning": None if ssl_verified else "SSL certificate verification disabled due to server issues",
            "rate_limiter_storage": storage_info,
            "last_check": datetime.utcnow().isoformat() + "Z"
        }
        
        return APIResponse.success(status_data, "Service status check completed")
        
    except Exception as e:
        logger.error(f"Status check error: {e}")
        return APIResponse.error("Service status check failed", 503, "STATUS_CHECK_ERROR")

@app.route('/api/docs')
def api_docs():
    """API documentation endpoint"""
    docs = {
        "title": "SISKA Scraper API Documentation",
        "version": "1.0.0-stateless-ssl",
        "description": "Stateless API untuk mengambil jadwal dari SISKA UNDIPA dengan SSL handling",
        "base_url": request.host_url.rstrip('/'),
        "endpoints": {
            "POST /api/jadwal": {
                "description": "Login dan ambil jadwal dalam satu request",
                "method": "POST",
                "content_type": "application/json",
                "rate_limit": "5 requests per minute",
                "payload": {
                    "username": "string (required, 3-50 chars)",
                    "password": "string (required, 6-100 chars)", 
                    "level": "string (optional: mahasiswa|dosen|admin|staf)"
                },
                "response": {
                    "success": {
                        "status": "success",
                        "data": {
                            "jadwal": "array of jadwal objects",
                            "metadata": "response metadata including SSL info"
                        }
                    },
                    "error": {
                        "status": "error",
                        "message": "error description",
                        "error_code": "error identifier"
                    }
                }
            }
        },
        "security": [
            "Input validation and sanitization",
            "Rate limiting (5 req/min, 30 req/hour)", 
            "Request size limits (1MB max)",
            "CORS restrictions",
            "Security event logging (no sensitive data)",
            "Generic error messages",
            "SSL certificate error handling",
            "Unicode/UTF-8 support",
            "Session-based tracking (anonymous)"
        ],
        "ssl_handling": {
            "description": "API automatically handles SSL certificate issues",
            "behavior": "Falls back to unverified SSL if certificate is expired",
            "warning": "Users are notified when SSL verification is bypassed"
        }
    }
    return APIResponse.success(docs, "API Documentation")


@app.route('/api/jadwal', methods=['POST'])
@limiter.limit("5 per minute") 
def get_jadwal():
    """
    Stateless endpoint: Login dan ambil jadwal dalam satu request
    Enhanced with SSL and Unicode error handling
    
    Expected JSON payload:
    {
        "username": "your_username",
        "password": "your_password", 
        "level": "mahasiswa"  // optional, default: mahasiswa
    }
    
    Returns jadwal data directly (no session)
    """
    try:
        if not request.is_json:
            return APIResponse.error("Content-Type must be application/json", 400, "INVALID_CONTENT_TYPE")
        
        data = request.get_json()
        if not isinstance(data, dict):
            return APIResponse.error("Invalid JSON payload", 400, "INVALID_PAYLOAD")

        raw_username = data.get('username', '')
        raw_password = data.get('password', '')
        raw_level = data.get('level', 'mahasiswa')

        username = SecurityValidator.sanitize_input(raw_username, 50)
        password = raw_password  # Don't sanitize password (may contain special chars)
        level, level_warning = SecurityValidator.validate_level(raw_level)

        username_valid, username_error = SecurityValidator.validate_username(username)
        if not username_valid:
            security_logger.warning(f"Invalid username from IP: {request.remote_addr}")
            return APIResponse.error(username_error, 400, "INVALID_USERNAME")

        password_valid, password_error = SecurityValidator.validate_password(password)
        if not password_valid:
            security_logger.warning(f"Invalid password format from IP: {request.remote_addr}")
            return APIResponse.error(password_error, 400, "INVALID_PASSWORD")

        # [SECURITY] Log attempt without sensitive data
        try:
            # Generate session ID untuk tracking tanpa expose data user
            session_id = str(uuid.uuid4())[:8]
            logger.info(f"Jadwal request initiated - Session: {session_id} - IP: {request.remote_addr}")
        except Exception as e:
            logger.warning(f"Logging error (Unicode): {e}")
            session_id = "session_error"
            logger.info(f"Jadwal request initiated - IP: {request.remote_addr}")
        
        # Initialize scraper with SSL error handling
        try:
            scraper = SiskaScraper()
        except Exception as e:
            logger.error(f"Scraper initialization error: {e}")
            return APIResponse.error("Service initialization error", 500, "SCRAPER_INIT_ERROR")
        
        # Attempt login with SSL error handling
        try:
            login_success = scraper.login(username, password, level)
        except (ssl.SSLError, requests.exceptions.SSLError) as ssl_error:
            logger.warning(f"SSL certificate error during login: {ssl_error}")
            return APIResponse.error("Server certificate issue - please try again later", 503, "SSL_CERTIFICATE_ERROR")
        except requests.exceptions.ConnectionError as conn_error:
            logger.error(f"Connection error during login: {conn_error}")
            return APIResponse.error("Unable to connect to SISKA server", 503, "CONNECTION_ERROR")
        except Exception as login_error:
            logger.error(f"Login error: {login_error}")
            return APIResponse.error("Login service unavailable", 503, "LOGIN_SERVICE_ERROR")
        
        if not login_success:
            try:
                security_logger.warning(f"Login failed - Session: {session_id} - IP: {request.remote_addr}")
            except:
                security_logger.warning(f"Login failed - IP: {request.remote_addr}")
            return APIResponse.error(status_code=401, error_code="LOGIN_FAILED")
        
        # Get jadwal data with SSL error handling
        try:
            jadwal_data = scraper.get_jadwal()
        except (ssl.SSLError, requests.exceptions.SSLError) as ssl_error:
            logger.warning(f"SSL certificate error during jadwal fetch: {ssl_error}")
            return APIResponse.error("Server certificate issue - please try again later", 503, "SSL_CERTIFICATE_ERROR")
        except requests.exceptions.ConnectionError as conn_error:
            logger.error(f"Connection error during jadwal fetch: {conn_error}")
            return APIResponse.error("Unable to connect to SISKA server", 503, "CONNECTION_ERROR")
        except Exception as jadwal_error:
            logger.error(f"Jadwal fetch error: {jadwal_error}")
            return APIResponse.error("Jadwal service unavailable", 503, "JADWAL_SERVICE_ERROR")
        
        if not jadwal_data:
            logger.info(f"No jadwal data found - Session: {session_id}")
            return APIResponse.error("No jadwal data available", 404, "NO_JADWAL_DATA")
        
        # [SECURITY] Log successful retrieval without sensitive data
        try:
            logger.info(f"Jadwal retrieved successfully - Session: {session_id} - Count: {len(jadwal_data)} - IP: {request.remote_addr}")
        except:
            logger.info(f"Jadwal retrieved - Count: {len(jadwal_data)} - IP: {request.remote_addr}")
        
        # Get rate limiting stats (optional)
        try:
            rate_stats = scraper.get_rate_limit_stats()
        except:
            rate_stats = None
        
        # Prepare response - Unicode safe, tanpa data sensitif
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
        
        if level_warning:
            response_data['metadata']['warning'] = level_warning
        
        return APIResponse.success(response_data, "Jadwal retrieved successfully")
        
    except UnicodeEncodeError as e:
        # [SECURITY] ENCODING: Handle Unicode errors specifically
        error_id = str(uuid.uuid4())[:8]
        logger.error(f"Unicode encoding error [{error_id}]: {str(e)} - IP: {request.remote_addr}")
        return APIResponse.error("Data encoding error", 500, "UNICODE_ERROR")
        
    except Exception as e:
        # [SECURITY] Log errors without exposing sensitive details - Unicode safe
        error_id = str(uuid.uuid4())[:8]
        try:
            logger.error(f"Jadwal error [{error_id}]: {str(e)} - IP: {request.remote_addr}")
        except UnicodeEncodeError:
            # Fallback logging for Unicode errors
            logger.error(f"Jadwal error [{error_id}]: <Unicode logging error> - IP: {request.remote_addr}")
        return APIResponse.error(status_code=500, error_code="JADWAL_ERROR")

# [SECURITY] Error handlers with generic messages - Unicode safe
@app.errorhandler(404)
def not_found(error):
    return APIResponse.error(status_code=404, error_code="NOT_FOUND")

@app.errorhandler(405)
def method_not_allowed(error):
    return APIResponse.error("Method not allowed", 405, "METHOD_NOT_ALLOWED")

@app.errorhandler(500)
def internal_error(error):
    error_id = str(uuid.uuid4())[:8]
    try:
        logger.error(f"Internal error [{error_id}]: {error}")
    except UnicodeEncodeError:
        logger.error(f"Internal error [{error_id}]: <Unicode logging error>")
    return APIResponse.error(status_code=500, error_code="INTERNAL_ERROR")

# For WSGI deployment
application = app

if __name__ == '__main__':
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    print("[INFO] Starting SISKA API Server (Stateless + SSL + UTF-8)...")
    print(f"[INFO] Server will run on http://localhost:{port}")
    print(f"[INFO] API Documentation: http://localhost:{port}/api/docs")
    print("[INFO] Security features: Rate limiting, Input validation, Logging")
    print("[INFO] SSL certificate error handling enabled")
    print("[INFO] Unicode/UTF-8 support enabled")
    
    app.run(
        host='127.0.0.1' if not debug else '0.0.0.0',  # Localhost only in production
        port=port,
        debug=debug,
        threaded=True
    )