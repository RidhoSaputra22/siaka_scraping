"""
WSGI configuration for SISKA Scraper API
Production deployment entry point
"""

import sys
import os

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

# Import the Flask application
from app import app

# WSGI application object (this is what Passenger is looking for)
application = app

if __name__ == "__main__":
    application.run()