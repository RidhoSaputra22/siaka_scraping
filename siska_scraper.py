import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
from bs4 import BeautifulSoup
import json
import time
import ssl
import warnings
from datetime import datetime, timedelta
from collections import deque
from config import Config
from utils import (
    save_to_json, save_to_csv, get_timestamp, 
    validate_response, clean_text
)

# Suppress SSL warnings for expired certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class SiskaScraper:
    """SISKA UNDIPA Web Scraper for Jadwal Data"""
    
    def __init__(self, config_file='.env'):
        """Initialize scraper with configuration"""
        self.config = Config(config_file)
        self.session = requests.Session()
        self.is_logged_in = False
        self.ssl_verified = True  # Track SSL verification status
        
        # Rate limiting tracking
        self.request_times = deque()  # Track request timestamps
        self.last_request_time = None
        self.total_requests = 0
        
        # Configure SSL handling first
        self._configure_ssl_session()
        
        # Set default headers with configured user agent
        self.session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive' if self.config.session_keep_alive else 'close',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def _configure_ssl_session(self):
        """Configure session with SSL certificate error handling"""
        try:
            print("🔍 Testing SSL connection to SISKA...")
            # Test SSL connection first
            test_response = self.session.get(f"{self.config.base_url}/login", verify=True, timeout=15)
            self.ssl_verified = True
            print("✅ SSL certificate verified successfully")
        except (requests.exceptions.SSLError, ssl.SSLError) as e:
            print(f"⚠️  SSL certificate error: {e}")
            print("🔧 Disabling SSL verification for this session")
            print("⚠️  WARNING: SSL verification is disabled - connection may not be secure")
            self.ssl_verified = False
            self.session.verify = False
        except Exception as e:
            print(f"⚠️  Connection test failed: {e}")
            print("🔧 Will attempt with SSL disabled")
            self.ssl_verified = False
            self.session.verify = False
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS", "POST"],
            backoff_factor=2,
            respect_retry_after_header=True
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def _wait_for_rate_limit(self):
        """Implement rate limiting by waiting between requests"""
        current_time = datetime.now()
        
        # Clean old request times (older than 1 minute)
        minute_ago = current_time - timedelta(minutes=1)
        while self.request_times and self.request_times[0] < minute_ago:
            self.request_times.popleft()
        
        # Check if we've exceeded max requests per minute
        if len(self.request_times) >= self.config.max_requests_per_minute:
            oldest_request = self.request_times[0]
            wait_time = 60 - (current_time - oldest_request).total_seconds()
            if wait_time > 0:
                print(f"Rate limit reached. Waiting {wait_time:.1f} seconds...")
                time.sleep(wait_time)
        
        # Ensure minimum delay between requests
        if self.last_request_time:
            time_since_last = (current_time - self.last_request_time).total_seconds()
            if time_since_last < self.config.request_delay:
                wait_time = self.config.request_delay - time_since_last
                print(f"Waiting {wait_time:.1f} seconds between requests...")
                time.sleep(wait_time)
        
        # Record this request
        self.request_times.append(datetime.now())
        self.last_request_time = datetime.now()
        self.total_requests += 1
    
    def _make_request(self, method, url, **kwargs):
        """Make HTTP request with rate limiting and retry logic"""
        self._wait_for_rate_limit()
        
        # Set timeout if not specified
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.config.request_timeout
        
        for attempt in range(self.config.max_retries + 1):
            try:
                print(f"Making {method.upper()} request to {url} (attempt {attempt + 1})")
                
                # Set SSL verification based on current state
                if not self.ssl_verified:
                    kwargs['verify'] = False
                
                if method.lower() == 'get':
                    response = self.session.get(url, **kwargs)
                elif method.lower() == 'post':
                    response = self.session.post(url, **kwargs)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                # Check response status
                if response.status_code == 429:  # Too Many Requests
                    retry_after = response.headers.get('Retry-After', self.config.retry_delay_base)
                    wait_time = float(retry_after) if isinstance(retry_after, str) else retry_after
                    print(f"Server returned 429 (Too Many Requests). Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                
                elif response.status_code >= 500:  # Server errors
                    if attempt < self.config.max_retries:
                        wait_time = self.config.retry_delay_base * (2 ** attempt)  # Exponential backoff
                        print(f"Server error ({response.status_code}). Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                        continue
                
                return response
                
            except (requests.exceptions.SSLError, ssl.SSLError) as e:
                print(f"SSL Error on attempt {attempt + 1}: {e}")
                if self.ssl_verified and attempt < self.config.max_retries:
                    # Switch to non-verified SSL and retry
                    print("🔧 Switching to non-verified SSL mode")
                    print("⚠️  WARNING: SSL verification disabled due to certificate error")
                    self.ssl_verified = False
                    self.session.verify = False
                    kwargs['verify'] = False
                    continue
                elif attempt >= self.config.max_retries:
                    raise
                    
            except requests.exceptions.RequestException as e:
                if attempt < self.config.max_retries:
                    wait_time = self.config.retry_delay_base * (2 ** attempt)
                    print(f"Request failed: {e}. Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                else:
                    print(f"Request failed after {self.config.max_retries + 1} attempts: {e}")
                    raise
        
        return response
    
    def get_rate_limit_stats(self):
        """Get current rate limiting statistics"""
        current_time = datetime.now()
        minute_ago = current_time - timedelta(minutes=1)
        
        # Count requests in the last minute
        recent_requests = sum(1 for req_time in self.request_times if req_time >= minute_ago)
        
        return {
            'total_requests': self.total_requests,
            'requests_last_minute': recent_requests,
            'max_requests_per_minute': self.config.max_requests_per_minute,
            'request_delay': self.config.request_delay,
            'last_request_time': self.last_request_time.isoformat() if self.last_request_time else None
        }
    
    def print_rate_limit_stats(self):
        """Print current rate limiting statistics"""
        stats = self.get_rate_limit_stats()
        print(f"\nRate Limit Statistics:")
        print(f"  Total requests: {stats['total_requests']}")
        print(f"  Requests in last minute: {stats['requests_last_minute']}/{stats['max_requests_per_minute']}")
        print(f"  Request delay: {stats['request_delay']}s")
        print(f"  Last request: {stats['last_request_time'] or 'Never'}")
        
        # Calculate estimated remaining capacity
        remaining = stats['max_requests_per_minute'] - stats['requests_last_minute']
        if remaining > 0:
            print(f"  Remaining capacity: {remaining} requests")
        else:
            print(f"  Rate limit reached - requests will be throttled")
    
    def get_ssl_status(self):
        """Get SSL verification status"""
        return {
            'ssl_verified': self.ssl_verified,
            'warning': None if self.ssl_verified else "SSL certificate verification is disabled"
        }
    
    def get_login_form_data(self):
        """Get login form data including CSRF token if present"""
        try:
            response = self._make_request('get', self.config.login_url)
            validate_response(response)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find the login form
            login_form = soup.find('form')
            if not login_form:
                raise Exception("Login form not found")
            
            form_data = {}
            
            # Get all input fields
            for input_field in login_form.find_all('input'):
                name = input_field.get('name')
                value = input_field.get('value', '')
                if name:
                    form_data[name] = value
            
            return form_data, soup
            
        except Exception as e:
            print(f"Error getting login form: {e}")
            raise
    
    def login(self, username=None, password=None, level=None):
        """Login to SISKA system"""
        try:
            # Use provided credentials or config defaults
            username = username or self.config.username
            password = password or self.config.password
            level = level or self.config.level
            
            if not username or not password:
                raise ValueError("Username and password are required")
            
            print("Getting login form...")
            form_data, soup = self.get_login_form_data()
            
            # Update form data with credentials
            # Based on the webpage analysis, the fields seem to be:
            # NIM/NIDN/USERNAME, Password, Level
            
            # Try common field names for username
            username_fields = ['username']
            password_fields = ['pwd']
            level_fields = ['level']
            
            # Find actual field names from the form
            form_inputs = soup.find_all('input')
            
            for input_field in form_inputs:
                input_type = input_field.get('type', '').lower()
                input_name = input_field.get('name', '').lower()
                
                # Username field
                if input_type == 'text' or any(field in input_name for field in username_fields):
                    form_data[input_field.get('name')] = username
                    
                # Password field  
                elif input_type == 'password' or any(field in input_name for field in password_fields):
                    form_data[input_field.get('name')] = password
            
            # Handle level/role selection - map level names to values
            level_mapping = {
                'mahasiswa': '1',
                'dosen': '2', 
                'staf': '3',
                'admin': '3'  # alias for staf
            }
            
            level_value = level_mapping.get(level.lower(), level) if level else '1'
            
            select_fields = soup.find_all('select')
            for select_field in select_fields:
                select_name = select_field.get('name', '').lower()
                if any(field in select_name for field in level_fields):
                    form_data[select_field.get('name')] = level_value
            
            # Add submit button field (required by server)
            form_data['btnLogin'] = 'Sign In'
            
            print("Attempting login...")
            print(f"Username: {username}")
            print(f"Password: {password}")
            print(f"Level: {level}")

            print(f"form-data: {form_data}")

            # Submit login form
            response = self._make_request(
                'post',
                self.config.login_url, 
                data=form_data,
                allow_redirects=True
            )
            
            print(f"response: {response}")
            
            validate_response(response)
            
            # Check if login was successful
            if self._check_login_success(response):
                self.is_logged_in = True
                print("Login successful!")
                return True
            else:
                print("Login failed!")
                print("Response URL:", response.url)
                print("Response text preview:", response.text[:500])
                return False
                
        except Exception as e:
            print(f"Login error: {e}")
            raise
    
    def _check_login_success(self, response):
        """Check if login was successful"""
        # Check if redirected away from login page to main dashboard
        current_url = response.url.lower()
        
        # Success indicators - redirected to main page or dashboard
        if 'login' not in current_url and (
            'dashboard' in current_url or 
            'main' in current_url or 
            'index' in current_url or
            current_url.endswith('/') or
            current_url == self.config.base_url.lower()
        ):
            return True
            
        # Parse page content for success/error indicators
        soup = BeautifulSoup(response.text, 'html.parser')
        page_text = soup.get_text().lower()
        
        # Success indicators in page content
        success_indicators = [
            'dashboard', 'beranda', 'welcome', 'selamat datang', 'logout'
        ]
        
        if any(indicator in page_text for indicator in success_indicators):
            return True
            
        # Error indicators
        error_indicators = [
            'error', 'invalid', 'incorrect', 'failed', 'salah', 
            'username atau password', 'login gagal', 'akses ditolak'
        ]
        
        if any(indicator in page_text for indicator in error_indicators):
            return False
            
        # If we're still on login page with sign in form, login failed
        if soup.find('form') and any(text in page_text for text in ['sign in', 'masuk', 'login']):
            # But make sure it's actually the login form, not a different form
            login_form = soup.find('form', action='') or soup.find('form', action=None)
            if login_form and (
                login_form.find('input', {'name': 'username'}) or 
                login_form.find('input', {'name': 'pwd'})
            ):
                return False
            
        return True
    
    def get_jadwal(self):
        """Scrape jadwal data from SISKA"""
        if not self.is_logged_in:
            raise Exception("Must login first before accessing jadwal")
        
        try:
            print("Fetching jadwal data...")
            response = self._make_request('get', self.config.jadwal_url)
            validate_response(response)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Parse jadwal data based on HTML structure
            jadwal_data = self._parse_jadwal_page(soup)
            
            print(f"Successfully scraped {len(jadwal_data)} jadwal entries")
            return jadwal_data
            
        except Exception as e:
            print(f"Error getting jadwal: {e}")
            raise
    
    def _parse_jadwal_page(self, soup):
        """Parse jadwal page HTML to extract schedule data"""
        jadwal_list = []
        
        print("Analyzing jadwal page structure...")
        
        # Method 1: Look for malformed table with scattered TD elements
        print("Method 1: Searching for scattered TD elements...")
        
        # Find all TD elements that might contain jadwal data
        all_tds = soup.find_all('td')
        
        # Look for patterns of 7 consecutive TDs (kode, mata kuliah, kelas, hari, jam, ruang, dosen)
        expected_columns = ['Kode', 'Mata Kuliah', 'Kelas', 'Hari', 'Jam', 'Ruang', 'Dosen']
        
        # Group TDs into potential rows
        i = 0
        while i < len(all_tds):
            # Look for a sequence that might be a jadwal row
            potential_row = []
            
            # Check if this TD starts a new row (contains kode pattern)
            first_td_text = clean_text(all_tds[i].get_text())
            
            # Kode mata kuliah pattern: Letter(s) + Numbers + optional Letter + "-T"
            import re
            kode_pattern = r'^[A-Z]\d{4}-[A-Z]$'
            
            if re.match(kode_pattern, first_td_text):
                # This looks like a kode, collect next 6 TDs
                for j in range(7):  # 7 columns expected
                    if i + j < len(all_tds):
                        cell_text = clean_text(all_tds[i + j].get_text())
                        potential_row.append(cell_text)
                    else:
                        break
                
                # If we have all 7 columns, it's likely a complete row
                if len(potential_row) == 7:
                    row_data = {}
                    for col_idx, value in enumerate(potential_row):
                        row_data[expected_columns[col_idx]] = value
                    
                    row_data['table_index'] = 1
                    row_data['row_index'] = len(jadwal_list) + 1
                    row_data['row_type'] = 'data'
                    
                    jadwal_list.append(row_data)
                    print(f"Found jadwal row: {potential_row}")
                    
                    i += 7  # Skip the TDs we just processed
                    continue
            
            i += 1  # Move to next TD
        
        # Method 2: Traditional table parsing (fallback)
        if not jadwal_list:
            print("Method 2: Traditional table parsing...")
            tables = soup.find_all('table')
            
            for table_idx, table in enumerate(tables):
                rows = table.find_all('tr')
                print(f"Table {table_idx + 1} has {len(rows)} rows")
                
                if len(rows) > 1:
                    # Get headers
                    headers = []
                    header_row = rows[0]
                    for th in header_row.find_all(['th', 'td']):
                        header_text = clean_text(th.get_text())
                        if header_text:
                            headers.append(header_text)
                    
                    print(f"Headers: {headers}")
                    
                    # Process data rows
                    for row_idx, row in enumerate(rows[1:], 1):
                        cells = row.find_all(['td', 'th'])
                        if len(cells) >= 3:  # At least some meaningful data
                            row_data = {}
                            
                            for i, cell in enumerate(cells):
                                cell_text = clean_text(cell.get_text())
                                header_name = headers[i] if i < len(headers) else f"Column_{i+1}"
                                row_data[header_name] = cell_text
                            
                            # Skip empty or summary rows
                            non_empty_values = [v for v in row_data.values() if v and v.strip()]
                            
                            if non_empty_values and not any(
                                keyword in ' '.join(non_empty_values).lower() 
                                for keyword in ['total sks', 'jumlah sks']
                            ):
                                row_data['table_index'] = table_idx + 1
                                row_data['row_index'] = row_idx
                                row_data['row_type'] = 'data'
                                jadwal_list.append(row_data)
        
        # Method 3: Pattern-based extraction from raw text
        if not jadwal_list:
            print("Method 3: Pattern-based text extraction...")
            
            page_text = soup.get_text()
            
            # Look for jadwal patterns in text
            lines = page_text.split('\n')
            
            for line in lines:
                line = line.strip()
                if len(line) > 10:  # Skip short lines
                    # Check if line contains jadwal-like patterns
                    if any(day in line.upper() for day in ['SENIN', 'SELASA', 'RABU', 'KAMIS', 'JUMAT', 'SABTU']):
                        if any(time_pattern in line for time_pattern in ['.', ':']):  # Time indicators
                            jadwal_list.append({
                                'type': 'text_pattern',
                                'content': line,
                                'row_type': 'extracted'
                            })
        
        print(f"Total extracted entries: {len(jadwal_list)}")
        
        # Debug output
        for i, entry in enumerate(jadwal_list[:3]):
            print(f"Entry {i+1}: {entry}")
        
        return jadwal_list
    
    def save_jadwal(self, jadwal_data, filename=None, format='json'):
        """Save jadwal data to file"""
        if not filename:
            timestamp = get_timestamp()
            filename = f"jadwal_{timestamp}"
        
        if format.lower() == 'json':
            if not filename.endswith('.json'):
                filename += '.json'
            return save_to_json(jadwal_data, filename, self.config.output_dir)
        
        elif format.lower() == 'csv':
            if not filename.endswith('.csv'):
                filename += '.csv'
            return save_to_csv(jadwal_data, filename, self.config.output_dir)
        
        else:
            raise ValueError("Supported formats: json, csv")
    
    def run_full_scraping(self):
        """Run complete scraping process"""
        try:
            print("=== SISKA Jadwal Scraper ===")
            
            # Login
            if self.login():
                # Get jadwal data
                jadwal_data = self.get_jadwal()
                
                # Save data
                json_file = self.save_jadwal(jadwal_data, format='json')
                csv_file = self.save_jadwal(jadwal_data, format='csv')
                
                print(f"\n✓ Scraping completed successfully!")
                print(f"  JSON: {json_file}")
                print(f"  CSV: {csv_file}")
                
                return jadwal_data
            else:
                print("✗ Failed to login. Please check credentials.")
                return None
                
        except Exception as e:
            print(f"✗ Scraping failed: {e}")
            raise

# Example usage
if __name__ == "__main__":
    scraper = SiskaScraper()
    
    # Option 1: Use credentials from .env file
    # scraper.run_full_scraping()
    
    # Option 2: Provide credentials manually
    # scraper.login(username="your_username", password="your_password", level="mahasiswa")
    # jadwal_data = scraper.get_jadwal()
    # scraper.save_jadwal(jadwal_data)
    
    print("Scraper initialized. Use login() method to start scraping.")