"""
Flask REST API Server for SISKA Scraper - Stateless Version
Direct login + data retrieval without session management
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import uuid
import re
import hashlib
from datetime import datetime
import logging

# Import our scraper
from siska_scraper import SiskaScraper
from config import Config

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', str(uuid.uuid4()))

# 🔒 SECURITY: CORS with specific origins only
allowed_origins = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
CORS(app, origins=allowed_origins)

# 🔒 SECURITY: Enhanced rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["30 per hour", "5 per minute"]  # More restrictive
)
limiter.init_app(app)

# 🔒 SECURITY: Enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/api_security.log'),
        logging.StreamHandler()
    ]
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
        """Sanitize user input"""
        if not input_str:
            return ""
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\';\\]', '', str(input_str))
        return sanitized[:max_length].strip()

class APIResponse:
    """Secure API response format"""
    
    @staticmethod
    def success(data=None, message="Success", status_code=200):
        response = {
            "status": "success",
            "message": message,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "data": data
        }
        return jsonify(response), status_code
    
    @staticmethod
    def error(message="Error occurred", status_code=400, error_code=None):
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
            "message": message,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "error_code": error_code
        }
        
        # 🔒 SECURITY: Log security events
        if status_code in [401, 403]:
            security_logger.warning(f"Security event {error_code}: {request.remote_addr}")
        
        return jsonify(response), status_code

# 🔒 SECURITY: Request size limit
@app.before_request
def limit_request_size():
    """Limit request size to prevent DoS"""
    if request.content_length and request.content_length > 1024 * 1024:  # 1MB limit
        return APIResponse.error("Request too large", 413, "REQUEST_TOO_LARGE")


@app.route('/api/jadwal', methods=['POST'])
@limiter.limit("5 per minute")  # 🔒 SECURITY: Strict rate limiting
def get_jadwal():
    """
    Stateless endpoint: Login dan ambil jadwal dalam satu request
    
    Expected JSON payload:
    {
        "username": "your_username",
        "password": "your_password", 
        "level": "mahasiswa"  // optional, default: mahasiswa
    }
    
    Returns jadwal data directly (no session)
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

        # 🔒 SECURITY: Log attempt (without sensitive data)
        username_hash = hashlib.sha256(username.encode()).hexdigest()[:8]
        logger.info(f"Jadwal request - User hash: {username_hash} - Level: {level} - IP: {request.remote_addr}")
        
        # Initialize scraper
        scraper = SiskaScraper()
        
        # Attempt login
        login_success = scraper.login(username, password, level)
        
        if not login_success:
            security_logger.warning(f"Login failed - User hash: {username_hash} - IP: {request.remote_addr}")
            return APIResponse.error(status_code=401, error_code="LOGIN_FAILED")
        
        # Get jadwal data
        jadwal_data = scraper.get_jadwal()
        
        if not jadwal_data:
            logger.info(f"No jadwal data found - User hash: {username_hash}")
            return APIResponse.error("No jadwal data available", 404, "NO_JADWAL_DATA")
        
        # 🔒 SECURITY: Log successful data retrieval
        logger.info(f"Jadwal retrieved - User hash: {username_hash} - Count: {len(jadwal_data)} - IP: {request.remote_addr}")
        
        # Get rate limiting stats (optional)
        try:
            rate_stats = scraper.get_rate_limit_stats()
        except:
            rate_stats = None
        
        # Prepare response
        response_data = {
            'jadwal': jadwal_data,
            'metadata': {
                'retrieved_at': datetime.utcnow().isoformat() + "Z",
                'count': len(jadwal_data) if isinstance(jadwal_data, list) else 1,
                'level': level,
                'rate_stats': rate_stats
            }
        }
        
        if level_warning:
            response_data['metadata']['warning'] = level_warning
        
        return APIResponse.success(response_data, "Jadwal retrieved successfully")
        
    except Exception as e:
        # 🔒 SECURITY: Log errors without exposing sensitive details
        error_id = str(uuid.uuid4())[:8]
        logger.error(f"Jadwal error [{error_id}]: {str(e)} - IP: {request.remote_addr}")
        return APIResponse.error(status_code=500, error_code="JADWAL_ERROR")

# 🔒 SECURITY: Error handlers with generic messages
@app.errorhandler(404)
def not_found(error):
    return APIResponse.error(status_code=404, error_code="NOT_FOUND")

@app.errorhandler(405)
def method_not_allowed(error):
    return APIResponse.error("Method not allowed", 405, "METHOD_NOT_ALLOWED")

@app.errorhandler(500)
def internal_error(error):
    error_id = str(uuid.uuid4())[:8]
    logger.error(f"Internal error [{error_id}]: {error}")
    return APIResponse.error(status_code=500, error_code="INTERNAL_ERROR")

if __name__ == '__main__':
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    print(f"🚀 Starting SISKA API Server (Stateless)...")
    print(f"📡 Server will run on http://localhost:{port}")
    print(f"📚 API Documentation: http://localhost:{port}/api/docs")
    print(f"🔒 Security features: Rate limiting, Input validation, Logging")
    
    # 🔒 SECURITY: Production-safe settings
    app.run(
        host='127.0.0.1' if not debug else '0.0.0.0',  # Localhost only in production
        port=port,
        debug=debug,
        threaded=True
    )