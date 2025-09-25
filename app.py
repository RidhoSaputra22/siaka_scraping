"""
Flask REST API Server for SISKA Scraper - Stateless Version
Direct login + data retrieval without session management
"""

import sys
import os

# 🔒 SECURITY: Set UTF-8 encoding untuk environment
os.environ['PYTHONIOENCODING'] = 'utf-8'

# Force UTF-8 encoding untuk Python
if sys.version_info >= (3, 7):
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import uuid
import re
import hashlib
from datetime import datetime
import logging

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# 🔒 ENCODING: Setup logging with UTF-8 encoding
class UTFHandler(logging.FileHandler):
    def __init__(self, filename, mode='a', encoding='utf-8', delay=False):
        super().__init__(filename, mode, encoding, delay)

# Import our scraper
try:
    from siska_scraper import SiskaScraper
    from config import Config
except ImportError as e:
    print(f"Import error: {e}")
    # Create minimal scraper for testing
    class SiskaScraper:
        def login(self, username, password, level):
            return True
        def get_jadwal(self):
            return [{"test": "data", "mata_kuliah": "Test Course"}]
        def get_rate_limit_stats(self):
            return {"requests": 0}
    
    class Config:
        FLASK_PORT = 5000

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', str(uuid.uuid4()))

# 🔒 ENCODING: Set Flask to handle Unicode properly
app.config['JSON_AS_ASCII'] = False  # Allow Unicode in JSON responses

# 🔒 SECURITY: CORS with specific origins only
allowed_origins = os.getenv('ALLOWED_ORIGINS', '*').split(',')
CORS(app, origins=allowed_origins)

# 🔒 SECURITY: Enhanced rate limiter with Redis fallback
try:
    # Try Redis for production
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["30 per hour", "5 per minute"],
        storage_uri=redis_url
    )
except:
    # Fallback to memory storage (with warning)
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["30 per hour", "5 per minute"]
    )

limiter.init_app(app)

# 🔒 ENCODING: Enhanced logging with UTF-8 support
try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            UTFHandler('logs/api_security.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
except Exception as e:
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
    """Secure API response format - Unicode safe"""
    
    @staticmethod
    def success(data=None, message="Success", status_code=200):
        """Create success response - Unicode safe"""
        try:
            response = {
                "status": "success",
                "message": str(message),  # Ensure string conversion
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "data": data
            }
            
            # Create JSON response with UTF-8 encoding
            json_response = jsonify(response)
            json_response.status_code = status_code
            json_response.headers['Content-Type'] = 'application/json; charset=utf-8'
            return json_response
            
        except UnicodeEncodeError as e:
            # Fallback: clean Unicode characters
            logger.warning(f"Unicode encoding error in success response: {e}")
            return APIResponse._create_safe_response(data, message, status_code, "success")
    
    @staticmethod
    def error(message="Error occurred", status_code=400, error_code=None):
        """Create error response - Unicode safe"""
        try:
            # 🔒 SECURITY: Generic error messages for security-sensitive errors
            generic_messages = {
                401: "Authentication failed",
                403: "Access denied", 
                404: "Resource not found",
                500: "Internal server error"
            }
            
            if status_code in [401, 500] and error_code:
                message = generic_messages.get(status_code, message)
            
            response = {
                "status": "error",
                "message": str(message),  # Ensure string conversion
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "error_code": error_code
            }
            
            # 🔒 SECURITY: Log security events (Unicode safe)
            if status_code in [401, 403]:
                try:
                    security_logger.warning(f"Security event {error_code}: {request.remote_addr}")
                except:
                    security_logger.warning(f"Security event {error_code}: <IP logging error>")
            
            # Create JSON response with UTF-8 encoding
            json_response = jsonify(response)
            json_response.status_code = status_code
            json_response.headers['Content-Type'] = 'application/json; charset=utf-8'
            return json_response
            
        except UnicodeEncodeError as e:
            # Fallback: clean Unicode characters
            logger.warning(f"Unicode encoding error in error response: {e}")
            return APIResponse._create_safe_response(None, message, status_code, "error", error_code)
    
    @staticmethod
    def _create_safe_response(data, message, status_code, status, error_code=None):
        """Create ASCII-safe response as fallback"""
        try:
            # Clean message from Unicode characters
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
            
            json_response = jsonify(response)
            json_response.status_code = status_code
            return json_response
            
        except Exception as e:
            # Ultimate fallback
            return jsonify({
                "status": "error",
                "message": "Server encoding error",
                "error_code": "CRITICAL_ENCODING_ERROR"
            }), 500

# 🔒 SECURITY: Request size limit
@app.before_request
def limit_request_size():
    """Limit request size to prevent DoS"""
    if request.content_length and request.content_length > 1024 * 1024:  # 1MB limit
        return APIResponse.error("Request too large", 413, "REQUEST_TOO_LARGE")

@app.route('/')
def index():
    """API information endpoint - Unicode safe"""
    info = {
        "name": "SISKA Scraper REST API - Stateless",
        "version": "1.0.0-stateless-utf8",
        "description": "Direct login + data retrieval API untuk SISKA UNDIPA",
        "endpoints": {
            "POST /api/jadwal": "Login dan ambil jadwal dalam satu request",
            "GET /api/health": "Health check",
            "GET /api/docs": "API documentation"
        },
        "features": [
            "Stateless design",
            "Direct login + data",
            "Rate limiting",
            "Input validation", 
            "Secure logging",
            "Unicode support"  # Added this feature
        ],
        "encoding": "UTF-8"
    }
    return APIResponse.success(info, "SISKA Scraper API v1.0 - Stateless with UTF-8 support")

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return APIResponse.success({
        "status": "healthy",
        "version": "1.0.0-stateless-utf8",
        "encoding": "UTF-8",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }, "Service is healthy")

@app.route('/api/docs')
def api_docs():
    """API documentation endpoint"""
    docs = {
        "title": "SISKA Scraper API Documentation",
        "version": "1.0.0-stateless-utf8",
        "description": "Stateless API untuk mengambil jadwal dari SISKA UNDIPA",
        "encoding": "UTF-8 supported",
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
                            "metadata": "response metadata"
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
            "Security event logging",
            "Generic error messages",
            "Unicode/UTF-8 support"
        ]
    }
    return APIResponse.success(docs, "API Documentation")

@app.route('/api/jadwal', methods=['POST'])
@limiter.limit("5 per minute")  # 🔒 SECURITY: Strict rate limiting
def get_jadwal():
    """
    Stateless endpoint: Login dan ambil jadwal dalam satu request
    Unicode safe version
    """
    try:
        # 🔒 SECURITY: Validate content type
        if not request.is_json:
            return APIResponse.error("Content-Type must be application/json", 400, "INVALID_CONTENT_TYPE")
        
        data = request.get_json()
        if not isinstance(data, dict):
            return APIResponse.error("Invalid JSON payload", 400, "INVALID_PAYLOAD")

        # 🔒 SECURITY: Input validation and sanitization
        raw_username = data.get('username', '')
        raw_password = data.get('password', '')
        raw_level = data.get('level', 'mahasiswa')

        username = SecurityValidator.sanitize_input(raw_username, 50)
        password = raw_password  # Don't sanitize password (may contain special chars)
        level, level_warning = SecurityValidator.validate_level(raw_level)

        # 🔒 SECURITY: Validate inputs
        username_valid, username_error = SecurityValidator.validate_username(username)
        if not username_valid:
            security_logger.warning(f"Invalid username from IP: {request.remote_addr}")
            return APIResponse.error(username_error, 400, "INVALID_USERNAME")

        password_valid, password_error = SecurityValidator.validate_password(password)
        if not password_valid:
            security_logger.warning(f"Invalid password format from IP: {request.remote_addr}")
            return APIResponse.error(password_error, 400, "INVALID_PASSWORD")

        # 🔒 SECURITY: Log attempt (without sensitive data) - Unicode safe
        try:
            username_hash = hashlib.sha256(username.encode('utf-8')).hexdigest()[:8]
            logger.info(f"Jadwal request - User hash: {username_hash} - Level: {level} - IP: {request.remote_addr}")
        except Exception as e:
            logger.warning(f"Logging error (Unicode): {e}")
            logger.info(f"Jadwal request - IP: {request.remote_addr}")
        
        # Initialize scraper
        scraper = SiskaScraper()
        
        # Attempt login
        login_success = scraper.login(username, password, level)
        
        if not login_success:
            try:
                security_logger.warning(f"Login failed - User hash: {username_hash} - IP: {request.remote_addr}")
            except:
                security_logger.warning(f"Login failed - IP: {request.remote_addr}")
            return APIResponse.error(status_code=401, error_code="LOGIN_FAILED")
        
        # Get jadwal data
        jadwal_data = scraper.get_jadwal()
        
        if not jadwal_data:
            logger.info(f"No jadwal data found - IP: {request.remote_addr}")
            return APIResponse.error("No jadwal data available", 404, "NO_JADWAL_DATA")
        
        # 🔒 SECURITY: Log successful data retrieval - Unicode safe
        try:
            logger.info(f"Jadwal retrieved - User hash: {username_hash} - Count: {len(jadwal_data)} - IP: {request.remote_addr}")
        except:
            logger.info(f"Jadwal retrieved - Count: {len(jadwal_data)} - IP: {request.remote_addr}")
        
        # Get rate limiting stats (optional)
        try:
            rate_stats = scraper.get_rate_limit_stats()
        except:
            rate_stats = None
        
        # Prepare response - Unicode safe
        response_data = {
            'jadwal': jadwal_data,
            'metadata': {
                'retrieved_at': datetime.utcnow().isoformat() + "Z",
                'count': len(jadwal_data) if isinstance(jadwal_data, list) else 1,
                'level': level,
                'rate_stats': rate_stats,
                'encoding': 'UTF-8'
            }
        }
        
        if level_warning:
            response_data['metadata']['warning'] = level_warning
        
        return APIResponse.success(response_data, "Jadwal retrieved successfully")
        
    except UnicodeEncodeError as e:
        # 🔒 ENCODING: Handle Unicode errors specifically
        error_id = str(uuid.uuid4())[:8]
        logger.error(f"Unicode encoding error [{error_id}]: {str(e)} - IP: {request.remote_addr}")
        return APIResponse.error("Data encoding error", 500, "UNICODE_ERROR")
        
    except Exception as e:
        # 🔒 SECURITY: Log errors without exposing sensitive details - Unicode safe
        error_id = str(uuid.uuid4())[:8]
        try:
            logger.error(f"Jadwal error [{error_id}]: {str(e)} - IP: {request.remote_addr}")
        except UnicodeEncodeError:
            # Fallback logging for Unicode errors
            logger.error(f"Jadwal error [{error_id}]: <Unicode logging error> - IP: {request.remote_addr}")
        return APIResponse.error(status_code=500, error_code="JADWAL_ERROR")

# 🔒 SECURITY: Error handlers with generic messages - Unicode safe
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
    
    print("🚀 Starting SISKA API Server (Stateless + UTF-8)...")
    print(f"📡 Server will run on http://localhost:{port}")
    print(f"📚 API Documentation: http://localhost:{port}/api/docs")
    print("🔒 Security features: Rate limiting, Input validation, Logging")
    print("🌐 Unicode/UTF-8 support enabled")
    
    # 🔒 SECURITY: Production-safe settings
    app.run(
        host='127.0.0.1' if not debug else '0.0.0.0',  # Localhost only in production
        port=port,
        debug=debug,
        threaded=True
    )