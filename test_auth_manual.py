#!/usr/bin/env python3
"""
Manual test script for authentication system
"""
import asyncio
import httpx
import json

BASE_URL = "http://localhost:8000"

async def test_auth_flow():
    """Test the complete authentication flow"""
    async with httpx.AsyncClient() as client:
        print("🔐 Testing KeyHaven Pro Authentication System")
        print("=" * 50)
        
        # Test health check
        print("\n1. Testing health check...")
        response = await client.get(f"{BASE_URL}/health")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
        
        # Test user registration
        print("\n2. Testing user registration...")
        register_data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "full_name": "Test User"
        }
        
        response = await client.post(f"{BASE_URL}/api/v1/auth/register", json=register_data)
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 201:
            data = response.json()
            token = data["access_token"]
            print(f"   ✅ Registration successful!")
            print(f"   User ID: {data['user']['id']}")
            print(f"   Email: {data['user']['email']}")
            print(f"   Token: {token[:20]}...")
            
            # Test authenticated endpoint
            print("\n3. Testing authenticated endpoint...")
            headers = {"Authorization": f"Bearer {token}"}
            response = await client.get(f"{BASE_URL}/api/v1/auth/me", headers=headers)
            print(f"   Status: {response.status_code}")
            
            if response.status_code == 200:
                user_data = response.json()
                print(f"   ✅ Authentication successful!")
                print(f"   User: {user_data['full_name']} ({user_data['email']})")
                print(f"   Subscription: {user_data['subscription_tier']}")
                
                # Test team creation
                print("\n4. Testing team creation...")
                team_data = {
                    "name": "Test Team",
                    "description": "A test team for authentication testing"
                }
                
                response = await client.post(f"{BASE_URL}/api/v1/teams/", json=team_data, headers=headers)
                print(f"   Status: {response.status_code}")
                
                if response.status_code == 201:
                    team = response.json()
                    print(f"   ✅ Team creation successful!")
                    print(f"   Team ID: {team['id']}")
                    print(f"   Team Name: {team['name']}")
                    
                    # Test getting user teams
                    print("\n5. Testing get user teams...")
                    response = await client.get(f"{BASE_URL}/api/v1/teams/", headers=headers)
                    print(f"   Status: {response.status_code}")
                    
                    if response.status_code == 200:
                        teams = response.json()
                        print(f"   ✅ Teams retrieved successfully!")
                        print(f"   Number of teams: {len(teams)}")
                        for team in teams:
                            print(f"   - {team['name']} (ID: {team['id']})")
                    else:
                        print(f"   ❌ Failed to get teams: {response.text}")
                else:
                    print(f"   ❌ Team creation failed: {response.text}")
            else:
                print(f"   ❌ Authentication failed: {response.text}")
        else:
            print(f"   ❌ Registration failed: {response.text}")
        
        print("\n" + "=" * 50)
        print("🎉 Authentication system test completed!")

if __name__ == "__main__":
    print("Note: Make sure to start the server first with: uvicorn app.main:app --reload")
    print("This script will test the authentication endpoints.")
    print()
    
    try:
        asyncio.run(test_auth_flow())
    except Exception as e:
        print(f"❌ Test failed: {e}")
        print("Make sure the server is running on http://localhost:8000")