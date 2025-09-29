"""
Test script to verify the rate limiter storage implementation
"""
import requests
import time
import json

def test_rate_limiter():
    """Test rate limiter functionality"""
    base_url = "http://localhost:5000"
    
    print("🧪 Testing Rate Limiter Implementation")
    print("=" * 50)
    
    # Test health endpoint
    try:
        response = requests.get(f"{base_url}/api/health")
        if response.status_code == 200:
            print("✅ Health endpoint working")
            data = response.json()
            print(f"   Response: {data['message']}")
        else:
            print(f"❌ Health endpoint failed: {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Connection error: {e}")
        print("   Make sure the Flask app is running with: python app.py")
        return
    
    # Test service status (includes rate limiter info)
    try:
        response = requests.get(f"{base_url}/api/status")
        if response.status_code == 200:
            print("✅ Status endpoint working")
            data = response.json()
            storage_info = data['data'].get('rate_limiter_storage', 'unknown')
            print(f"   Rate limiter storage: {storage_info}")
        else:
            print(f"❌ Status endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Status check error: {e}")
    
    # Test rate limiting by making multiple rapid requests
    print("\n🔄 Testing Rate Limiting (making 6 rapid requests)...")
    
    for i in range(6):
        try:
            start_time = time.time()
            response = requests.get(f"{base_url}/api/health")
            end_time = time.time()
            
            if response.status_code == 200:
                print(f"   Request {i+1}: ✅ Success ({end_time - start_time:.2f}s)")
            elif response.status_code == 429:  # Too Many Requests
                print(f"   Request {i+1}: ⚠️  Rate limited (HTTP 429)")
                break
            else:
                print(f"   Request {i+1}: ❌ Error {response.status_code}")
            
            time.sleep(0.1)  # Small delay between requests
            
        except Exception as e:
            print(f"   Request {i+1}: ❌ Error: {e}")
    
    print("\n📊 Rate Limiter Test Complete")
    print("   If you see rate limiting (HTTP 429), the implementation is working!")
    print("   File-based storage should persist between app restarts.")

if __name__ == "__main__":
    test_rate_limiter()