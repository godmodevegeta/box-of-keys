"""
Tests for authentication system
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
import uuid

from app.main import app
from app.core.auth import create_access_token, verify_password, get_password_hash
from app.services.user_service import UserService
from app.schemas.user import UserCreate


class TestAuthUtils:
    """Test authentication utilities"""
    
    def test_password_hashing(self):
        """Test password hashing and verification"""
        password = "TestPassword123!"
        hashed = get_password_hash(password)
        
        # Verify correct password
        assert verify_password(password, hashed) is True
        
        # Verify incorrect password
        assert verify_password("WrongPassword", hashed) is False
    
    def test_jwt_token_creation_and_verification(self):
        """Test JWT token creation and verification"""
        user_data = {"sub": str(uuid.uuid4()), "email": "test@example.com"}
        
        # Create token
        token = create_access_token(user_data)
        assert token is not None
        assert isinstance(token, str)
        
        # Create token with custom expiration
        expires_delta = timedelta(minutes=60)
        token_with_expiry = create_access_token(user_data, expires_delta)
        assert token_with_expiry is not None
        assert isinstance(token_with_expiry, str)
    
    def test_token_expiration(self):
        """Test token expiration"""
        user_data = {"sub": str(uuid.uuid4()), "email": "test@example.com"}
        
        # Create expired token
        expires_delta = timedelta(seconds=-1)  # Already expired
        expired_token = create_access_token(user_data, expires_delta)
        
        # Verification should fail for expired token
        from app.core.auth import verify_token
        from fastapi import HTTPException
        
        with pytest.raises(HTTPException) as exc_info:
            verify_token(expired_token)
        assert exc_info.value.status_code == 401


@pytest.mark.asyncio
class TestUserService:
    """Test user service operations"""
    
    async def test_create_user(self, db_session: AsyncSession):
        """Test user creation"""
        user_service = UserService(db_session)
        
        user_data = UserCreate(
            email="test@example.com",
            password="TestPassword123!",
            full_name="Test User"
        )
        
        user = await user_service.create_user(user_data)
        
        assert user.email == "test@example.com"
        assert user.full_name == "Test User"
        assert user.hashed_password is not None
        assert user.is_active is True
        assert user.is_verified is False
        assert user.subscription_tier == "free"
    
    async def test_create_duplicate_user(self, db_session: AsyncSession):
        """Test creating user with duplicate email"""
        user_service = UserService(db_session)
        
        user_data = UserCreate(
            email="duplicate@example.com",
            password="TestPassword123!"
        )
        
        # Create first user
        await user_service.create_user(user_data)
        
        # Try to create duplicate
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await user_service.create_user(user_data)
        assert exc_info.value.status_code == 400
    
    async def test_authenticate_user(self, db_session: AsyncSession):
        """Test user authentication"""
        user_service = UserService(db_session)
        
        # Create user
        user_data = UserCreate(
            email="auth@example.com",
            password="TestPassword123!"
        )
        created_user = await user_service.create_user(user_data)
        
        # Test successful authentication
        authenticated_user = await user_service.authenticate_user(
            "auth@example.com", "TestPassword123!"
        )
        assert authenticated_user is not None
        assert authenticated_user.id == created_user.id
        assert authenticated_user.last_login is not None
        
        # Test failed authentication - wrong password
        failed_auth = await user_service.authenticate_user(
            "auth@example.com", "WrongPassword"
        )
        assert failed_auth is None
        
        # Test failed authentication - wrong email
        failed_auth = await user_service.authenticate_user(
            "wrong@example.com", "TestPassword123!"
        )
        assert failed_auth is None
    
    async def test_create_oauth_user(self, db_session: AsyncSession):
        """Test OAuth user creation"""
        user_service = UserService(db_session)
        
        user = await user_service.create_oauth_user(
            email="oauth@example.com",
            github_id="12345",
            github_username="testuser",
            full_name="OAuth User",
            avatar_url="https://example.com/avatar.jpg"
        )
        
        assert user.email == "oauth@example.com"
        assert user.github_id == "12345"
        assert user.github_username == "testuser"
        assert user.full_name == "OAuth User"
        assert user.avatar_url == "https://example.com/avatar.jpg"
        assert user.is_verified is True
        assert user.hashed_password is None
        assert user.last_login is not None
    
    async def test_get_user_by_email(self, db_session: AsyncSession):
        """Test getting user by email"""
        user_service = UserService(db_session)
        
        # Create user
        user_data = UserCreate(
            email="findme@example.com",
            password="TestPassword123!"
        )
        created_user = await user_service.create_user(user_data)
        
        # Find user
        found_user = await user_service.get_user_by_email("findme@example.com")
        assert found_user is not None
        assert found_user.id == created_user.id
        
        # Try to find non-existent user
        not_found = await user_service.get_user_by_email("notfound@example.com")
        assert not_found is None


class TestAuthEndpoints:
    """Test authentication endpoints"""
    
    def test_register_endpoint(self, client: TestClient):
        """Test user registration endpoint"""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "register@example.com",
                "password": "TestPassword123!",
                "full_name": "Register User"
            }
        )
        
        assert response.status_code == 201
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
        assert data["user"]["email"] == "register@example.com"
        assert data["user"]["full_name"] == "Register User"
    
    def test_register_invalid_password(self, client: TestClient):
        """Test registration with invalid password"""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "weak@example.com",
                "password": "weak",  # Too weak
                "full_name": "Weak Password User"
            }
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_register_invalid_email(self, client: TestClient):
        """Test registration with invalid email"""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "invalid-email",  # Invalid format
                "password": "TestPassword123!",
                "full_name": "Invalid Email User"
            }
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_login_endpoint(self, client: TestClient):
        """Test user login endpoint"""
        # First register a user
        client.post(
            "/api/v1/auth/register",
            json={
                "email": "login@example.com",
                "password": "TestPassword123!",
                "full_name": "Login User"
            }
        )
        
        # Then login
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "login@example.com",
                "password": "TestPassword123!"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
        assert data["user"]["email"] == "login@example.com"
    
    def test_login_invalid_credentials(self, client: TestClient):
        """Test login with invalid credentials"""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "nonexistent@example.com",
                "password": "WrongPassword"
            }
        )
        
        assert response.status_code == 401
    
    def test_get_current_user(self, client: TestClient):
        """Test getting current user info"""
        # Register and get token
        register_response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "current@example.com",
                "password": "TestPassword123!",
                "full_name": "Current User"
            }
        )
        token = register_response.json()["access_token"]
        
        # Get current user info
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "current@example.com"
        assert data["full_name"] == "Current User"
    
    def test_get_current_user_unauthorized(self, client: TestClient):
        """Test getting current user without token"""
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 403  # No authorization header
    
    def test_get_current_user_invalid_token(self, client: TestClient):
        """Test getting current user with invalid token"""
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401
    
    def test_refresh_token(self, client: TestClient):
        """Test token refresh"""
        # Register and get token
        register_response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "refresh@example.com",
                "password": "TestPassword123!",
                "full_name": "Refresh User"
            }
        )
        token = register_response.json()["access_token"]
        
        # Refresh token
        response = client.post(
            "/api/v1/auth/refresh",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
    
    def test_logout(self, client: TestClient):
        """Test logout endpoint"""
        # Register and get token
        register_response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "logout@example.com",
                "password": "TestPassword123!",
                "full_name": "Logout User"
            }
        )
        token = register_response.json()["access_token"]
        
        # Logout
        response = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data


class TestPasswordValidation:
    """Test password validation"""
    
    def test_valid_passwords(self):
        """Test valid password formats"""
        valid_passwords = [
            "TestPassword123!",
            "MySecure123",
            "Complex1Pass",
            "StrongP@ss1"
        ]
        
        for password in valid_passwords:
            user_data = UserCreate(
                email="test@example.com",
                password=password
            )
            # Should not raise validation error
            assert user_data.password == password
    
    def test_invalid_passwords(self):
        """Test invalid password formats"""
        invalid_passwords = [
            "short",  # Too short
            "nouppercase123",  # No uppercase
            "NOLOWERCASE123",  # No lowercase
            "NoNumbers!",  # No digits
            "toolong" * 20,  # Too long
        ]
        
        for password in invalid_passwords:
            with pytest.raises(ValueError):
                UserCreate(
                    email="test@example.com",
                    password=password
                )