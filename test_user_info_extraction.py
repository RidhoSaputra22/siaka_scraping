#!/usr/bin/env python3
"""
Test script untuk fitur user info extraction pada endpoint /api/login
"""
import requests
import json
import time

# Test endpoint
BASE_URL = "http://localhost:5000"
LOGIN_ENDPOINT = f"{BASE_URL}/api/login"

def test_user_info_extraction():
    """Test ekstraksi informasi user setelah login"""
    
    print("=== Testing User Info Extraction ===\n")
    
    # Test dengan kredensial yang benar (sesuaikan dengan kredensial valid)
    print("Test: Login dengan kredensial valid untuk ekstraksi user info")
    headers = {"Content-Type": "application/json"}
    
    # Note: Ganti dengan kredensial yang valid untuk testing
    test_credentials = [
        {
            "username": "your_real_username",  # Ganti dengan username valid
            "password": "your_real_password",  # Ganti dengan password valid
            "level": "mahasiswa"
        }
    ]
    
    for i, creds in enumerate(test_credentials, 1):
        print(f"\nTest {i}: Testing with credentials set {i}")
        print(f"Username: {creds['username'][:3]}*** (hidden for security)")
        
        try:
            response = requests.post(LOGIN_ENDPOINT, headers=headers, json=creds, timeout=30)
            
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print("✓ Login successful!")
                print(f"Response structure: {json.dumps(result, indent=2)}")
                
                # Check if user_info is present
                if 'data' in result and 'user_info' in result['data']:
                    user_info = result['data']['user_info']
                    print("\n--- User Information Extracted ---")
                    print(f"Name: {user_info.get('name', 'Not found')}")
                    print(f"Username: {user_info.get('username', 'Not found')}")
                    print(f"Level: {user_info.get('level', 'Not found')}")
                    print(f"NIM/NIDN: {user_info.get('nim_nidn', 'Not found')}")
                    print(f"Email: {user_info.get('email', 'Not found')}")
                    
                    if user_info.get('found_on_page'):
                        print(f"Found on page: {user_info['found_on_page']}")
                    
                    if user_info.get('extraction_error'):
                        print(f"Extraction error: {user_info['extraction_error']}")
                    
                    # Validate extraction success
                    if user_info.get('name') or user_info.get('username'):
                        print("✓ User info extraction SUCCESSFUL")
                    else:
                        print("⚠ User info extraction failed - no name or username found")
                else:
                    print("✗ No user_info found in response")
                    
            elif response.status_code == 401:
                print("✗ Authentication failed - check credentials")
                result = response.json()
                print(f"Error: {result.get('message', 'Unknown error')}")
                
            elif response.status_code == 429:
                print("⚠ Rate limited - waiting and retrying...")
                time.sleep(60)  # Wait 1 minute for rate limit reset
                continue
                
            else:
                print(f"✗ Unexpected status code: {response.status_code}")
                try:
                    result = response.json()
                    print(f"Error: {result.get('message', 'Unknown error')}")
                except:
                    print(f"Raw response: {response.text[:200]}...")
                    
        except requests.exceptions.Timeout:
            print("✗ Request timeout - server might be slow")
        except requests.exceptions.ConnectionError:
            print("✗ Connection error - make sure server is running")
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
    
    print("\n" + "="*50)

def test_api_documentation_update():
    """Test apakah dokumentasi API sudah terupdate"""
    
    print("=== Testing API Documentation Update ===\n")
    
    try:
        response = requests.get(f"{BASE_URL}/api/docs")
        
        if response.status_code == 200:
            docs = response.json()
            
            # Check if login endpoint docs are updated
            if 'data' in docs and 'endpoints' in docs['data']:
                login_docs = docs['data']['endpoints'].get('POST /api/login')
                
                if login_docs and isinstance(login_docs, dict):
                    print("✓ Login endpoint documentation found")
                    print(f"Description: {login_docs.get('description', 'N/A')}")
                    
                    # Check if user_info is mentioned in response structure
                    if 'response' in login_docs and 'success' in login_docs['response']:
                        success_response = login_docs['response']['success']
                        if 'user_info' in str(success_response):
                            print("✓ User info documentation updated")
                        else:
                            print("⚠ User info not found in documentation")
                    else:
                        print("⚠ Response structure not documented")
                else:
                    print("⚠ Login endpoint documentation incomplete")
            else:
                print("✗ Documentation structure invalid")
        else:
            print(f"✗ Failed to get documentation: {response.status_code}")
            
    except Exception as e:
        print(f"✗ Error checking documentation: {e}")

def test_with_mock_credentials():
    """Test dengan kredensial mock untuk melihat behavior error handling"""
    
    print("=== Testing Error Handling ===\n")
    
    headers = {"Content-Type": "application/json"}
    
    # Test dengan kredensial yang salah
    mock_creds = {
        "username": "testuser123",
        "password": "wrongpassword123",
        "level": "mahasiswa"
    }
    
    print("Testing with invalid credentials...")
    try:
        response = requests.post(LOGIN_ENDPOINT, headers=headers, json=mock_creds, timeout=30)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 401:
            print("✓ Correct error handling for invalid credentials")
            result = response.json()
            print(f"Error message: {result.get('message', 'N/A')}")
        else:
            print(f"⚠ Unexpected status for invalid credentials: {response.status_code}")
            
    except Exception as e:
        print(f"✗ Error during test: {e}")

if __name__ == "__main__":
    print("🧪 SISKA User Info Extraction Tests")
    print("="*50)
    
    try:
        # Test API documentation
        test_api_documentation_update()
        print()
        
        # Test error handling first (doesn't require real credentials)
        test_with_mock_credentials()
        print()
        
        # Main test (requires real credentials)
        print("📋 IMPORTANT: To test user info extraction, you need to:")
        print("1. Edit this script and add real SISKA credentials")
        print("2. Make sure the Flask app is running")
        print("3. Run this script again")
        print()
        
        # Uncomment and modify this when you have real credentials
        # test_user_info_extraction()
        
        print("✓ Testing completed!")
        print("\n💡 Next steps:")
        print("- Add real credentials to test user info extraction")
        print("- Monitor server logs for detailed extraction process")
        print("- Check different user types (mahasiswa, dosen, staf)")
        
    except KeyboardInterrupt:
        print("\n⚠ Testing interrupted by user")
    except Exception as e:
        print(f"\n✗ Test suite error: {e}")