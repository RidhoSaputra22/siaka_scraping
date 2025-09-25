"""
Test deployment configuration
"""

import sys
import os

print("Testing deployment configuration...")
print(f"Python path: {sys.path}")
print(f"Current directory: {os.getcwd()}")
print(f"Files in directory: {os.listdir('.')}")

# Test imports
try:
    print("Testing Flask import...")
    from flask import Flask
    print("✅ Flask imported successfully")
    
    print("Testing app import...")
    from app import app
    print("✅ App imported successfully")
    
    print("Testing WSGI application...")
    from app import application
    print("✅ WSGI application available")
    
    print("Testing wsgi module...")
    import wsgi
    print(f"✅ WSGI module: {wsgi}")
    print(f"✅ WSGI application: {wsgi.application}")
    
    print("\n🎉 All imports successful!")
    print("✅ Deployment configuration is correct!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()