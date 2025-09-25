#!/usr/bin/env python3
"""
Flask server runner with configuration
"""

import os
import sys
from app import app, logger

def main():
    """Main function to run Flask server"""
    
    # Load environment variables
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    
    print("🚀 SISKA Scraper REST API Server")
    print("=" * 50)
    print(f"📡 Server URL: http://localhost:{port}")
    print(f"📚 API Docs: http://localhost:{port}/api/docs")
    print(f"💡 Health Check: http://localhost:{port}/api/health")
    print(f"🔧 Debug Mode: {'ON' if debug else 'OFF'}")
    print("=" * 50)
    
    # Log startup
    logger.info(f"Starting Flask server on {host}:{port}, debug={debug}")
    
    try:
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True,
            use_reloader=debug
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
        logger.info("Server stopped by user")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        logger.error(f"Server error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()