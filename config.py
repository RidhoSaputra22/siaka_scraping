import os
from dotenv import load_dotenv

class Config:
    """Configuration management class"""
    
    def __init__(self, env_file='.env'):
        """Initialize configuration by loading environment variables"""
        load_dotenv(env_file)
        
        # SISKA credentials
        self.username = os.getenv('SISKA_USERNAME')
        self.password = os.getenv('SISKA_PASSWORD') 
        self.level = os.getenv('SISKA_LEVEL', 'mahasiswa')
        
        # URLs
        self.base_url = 'https://siska.undipa.ac.id'
        self.login_url = f'{self.base_url}/login'
        self.jadwal_url = f'{self.base_url}/jadwal'
        
        # Rate Limiting Configuration
        self.request_delay = float(os.getenv('SISKA_REQUEST_DELAY', '2.0'))  # Delay between requests (seconds)
        self.max_retries = int(os.getenv('SISKA_MAX_RETRIES', '3'))  # Maximum retry attempts
        self.retry_delay_base = float(os.getenv('SISKA_RETRY_DELAY_BASE', '5.0'))  # Base delay for retry backoff
        self.request_timeout = int(os.getenv('SISKA_REQUEST_TIMEOUT', '30'))  # Request timeout (seconds)
        self.max_requests_per_minute = int(os.getenv('SISKA_MAX_REQUESTS_PER_MINUTE', '15'))  # Max requests per minute
        
        # Session Configuration
        self.session_keep_alive = bool(os.getenv('SISKA_KEEP_ALIVE', 'True').lower() == 'true')
        self.respect_robots_txt = bool(os.getenv('SISKA_RESPECT_ROBOTS', 'True').lower() == 'true')
        self.user_agent = os.getenv('SISKA_USER_AGENT', 'SiskaScraper/1.0 (+https://github.com/your-repo)')
        
        # Rate Limiter Storage Configuration
        self.rate_limiter_storage = os.getenv('RATE_LIMITER_STORAGE', 'file')  # file, redis, memory
        self.redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        self.rate_limiter_file_path = os.getenv('RATE_LIMITER_FILE_PATH', 'data/rate_limits.db')
        
        # Output settings
        self.output_dir = os.getenv('OUTPUT_DIR', 'data')
        self.default_format = os.getenv('DEFAULT_FORMAT', 'json')
        
        # Create output directory if not exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Create rate limiter directory if using file storage
        if self.rate_limiter_storage == 'file':
            rate_limiter_dir = os.path.dirname(self.rate_limiter_file_path)
            if rate_limiter_dir:
                os.makedirs(rate_limiter_dir, exist_ok=True)
    
    def validate_credentials(self):
        """Validate that required credentials are set"""
        if not self.username or not self.password:
            raise ValueError("Username and password must be set in .env file")
        return True