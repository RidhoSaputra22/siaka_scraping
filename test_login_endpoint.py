#!/usr/bin/env python3
"""
Test script untuk endpoint /api/login
"""
import requests
import json

# Test endpoint
BASE_URL = "http://localhost:5000"
LOGIN_ENDPOINT = f"{BASE_URL}/api/login"

def test_login_endpoint():
    """Test login endpoint dengan berbagai skenario"""
    
    print("=== Testing /api/login endpoint ===\n")
    
    # Test 1: Missing Content-Type
    print("Test 1: Missing Content-Type")
    response = requests.post(LOGIN_ENDPOINT, data="test")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print()
    
    # Test 2: Invalid JSON
    print("Test 2: Invalid JSON")
    headers = {"Content-Type": "application/json"}
    response = requests.post(LOGIN_ENDPOINT, headers=headers, data="invalid json")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print()
    
    # Test 3: Missing username
    print("Test 3: Missing username")
    data = {"password": "testpass"}
    response = requests.post(LOGIN_ENDPOINT, headers=headers, json=data)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print()
    
    # Test 4: Invalid username format
    print("Test 4: Invalid username format")
    data = {"username": "ab", "password": "testpass123"}
    response = requests.post(LOGIN_ENDPOINT, headers=headers, json=data)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print()
    
    # Test 5: Invalid password format  
    print("Test 5: Invalid password format")
    data = {"username": "testuser", "password": "12345"}
    response = requests.post(LOGIN_ENDPOINT, headers=headers, json=data)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print()
    
    # Test 6: Valid format but wrong credentials (expected to fail)
    print("Test 6: Valid format but wrong credentials")
    data = {
        "username": "testuser123",
        "password": "wrongpassword123",
        "level": "mahasiswa"
    }
    response = requests.post(LOGIN_ENDPOINT, headers=headers, json=data)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print()
    
    # Test 7: Test rate limiting (make multiple quick requests)
    print("Test 7: Rate limiting test (6 quick requests)")
    for i in range(6):
        data = {"username": f"user{i}", "password": "password123"}
        response = requests.post(LOGIN_ENDPOINT, headers=headers, json=data)
        print(f"Request {i+1}: Status {response.status_code}")
        if response.status_code == 429:
            print("Rate limited as expected!")
            break
    print()

def test_api_docs():
    """Test documentation endpoint untuk melihat info endpoint baru"""
    
    print("=== Testing API Documentation ===\n")
    response = requests.get(f"{BASE_URL}/api/docs")
    
    if response.status_code == 200:
        docs = response.json()
        print("Available endpoints:")
        for endpoint, info in docs['data']['endpoints'].items():
            print(f"  {endpoint}: {info.get('description', info)}")
        print()
    else:
        print(f"Failed to get docs: {response.status_code}")

if __name__ == "__main__":
    try:
        test_api_docs()
        test_login_endpoint()
        print("✓ Testing completed!")
    except requests.exceptions.ConnectionError:
        print("✗ Could not connect to server. Make sure the Flask app is running on localhost:5000")
    except Exception as e:
        print(f"✗ Test error: {e}")