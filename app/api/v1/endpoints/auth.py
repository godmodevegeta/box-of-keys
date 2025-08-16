"""
Authentication endpoints
"""
from datetime import timedelta
from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
import json

from app.core.database import get_db
from app.core.auth import create_access_token, AuthUtils
from app.core.config import settings
from app.core.dependencies import get_current_user, get_optional_current_user
from app.services.user_service import UserService
from app.services.oauth_service import OAuthService
from app.schemas.user import (
    UserCreate, UserLogin, UserResponse, Token, 
    GitHubOAuthRequest, PasswordReset, PasswordResetConfirm
)
from app.models.user import User

router = APIRouter()


@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Register a new user"""
    user_service = UserService(db)
    
    try:
        # Create user
        user = await user_service.create_user(user_data)
        
        # Create access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user.id), "email": user.email},
            expires_delta=access_token_expires
        )
        
        # Parse preferences JSON if exists
        preferences = None
        if user.preferences:
            try:
                preferences = json.loads(user.preferences)
            except json.JSONDecodeError:
                preferences = None
        
        # Create user response
        user_response = UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            github_id=user.github_id,
            github_username=user.github_username,
            avatar_url=user.avatar_url,
            is_active=user.is_active,
            is_verified=user.is_verified,
            subscription_tier=user.subscription_tier,
            preferences=preferences,
            created_at=user.created_at,
            updated_at=user.updated_at,
            last_login=user.last_login
        )
        
        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=user_response
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user account"
        )


@router.post("/login", response_model=Token)
async def login(
    user_data: UserLogin,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Login with email and password"""
    user_service = UserService(db)
    
    # Authenticate user
    user = await user_service.authenticate_user(user_data.email, user_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )
    
    # Refresh user to ensure all attributes are loaded
    await db.refresh(user)
    
    # Create access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email},
        expires_delta=access_token_expires
    )
    
    # Parse preferences JSON if exists
    preferences = None
    if user.preferences:
        try:
            preferences = json.loads(user.preferences)
        except json.JSONDecodeError:
            preferences = None
    
    # Create user response
    user_response = UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        github_id=user.github_id,
        github_username=user.github_username,
        avatar_url=user.avatar_url,
        is_active=user.is_active,
        is_verified=user.is_verified,
        subscription_tier=user.subscription_tier,
        preferences=preferences,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login=user.last_login
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user_response
    )


@router.post("/login/form", response_model=Token)
async def login_form(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Login with OAuth2 password form (for compatibility)"""
    user_service = UserService(db)
    
    # Authenticate user
    user = await user_service.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )
    
    # Refresh user to ensure all attributes are loaded
    await db.refresh(user)
    
    # Create access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email},
        expires_delta=access_token_expires
    )
    
    # Parse preferences JSON if exists
    preferences = None
    if user.preferences:
        try:
            preferences = json.loads(user.preferences)
        except json.JSONDecodeError:
            preferences = None
    
    # Create user response
    user_response = UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        github_id=user.github_id,
        github_username=user.github_username,
        avatar_url=user.avatar_url,
        is_active=user.is_active,
        is_verified=user.is_verified,
        subscription_tier=user.subscription_tier,
        preferences=preferences,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login=user.last_login
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user_response
    )


@router.get("/github/authorize")
async def github_authorize() -> Dict[str, str]:
    """Get GitHub OAuth authorization URL"""
    oauth_service = OAuthService()
    return oauth_service.get_github_auth_url()


@router.post("/github/callback", response_model=Token)
async def github_callback(
    oauth_data: GitHubOAuthRequest,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Handle GitHub OAuth callback"""
    oauth_service = OAuthService()
    user_service = UserService(db)
    
    try:
        # Get user info from GitHub
        github_user = await oauth_service.authenticate_github(oauth_data.code, oauth_data.state)
        
        # Create or update user
        user = await user_service.create_oauth_user(
            email=github_user["email"],
            github_id=github_user["github_id"],
            github_username=github_user["username"],
            full_name=github_user.get("name"),
            avatar_url=github_user.get("avatar_url")
        )
        
        # Refresh user to ensure all attributes are loaded
        await db.refresh(user)
        
        # Create access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user.id), "email": user.email},
            expires_delta=access_token_expires
        )
        
        # Parse preferences JSON if exists
        preferences = None
        if user.preferences:
            try:
                preferences = json.loads(user.preferences)
            except json.JSONDecodeError:
                preferences = None
        
        # Create user response
        user_response = UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            github_id=user.github_id,
            github_username=user.github_username,
            avatar_url=user.avatar_url,
            is_active=user.is_active,
            is_verified=user.is_verified,
            subscription_tier=user.subscription_tier,
            preferences=preferences,
            created_at=user.created_at,
            updated_at=user.updated_at,
            last_login=user.last_login
        )
        
        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=user_response
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to authenticate with GitHub"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
) -> Any:
    """Get current user information"""
    # Parse preferences JSON if exists
    preferences = None
    if current_user.preferences:
        try:
            preferences = json.loads(current_user.preferences)
        except json.JSONDecodeError:
            preferences = None
    
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        github_id=current_user.github_id,
        github_username=current_user.github_username,
        avatar_url=current_user.avatar_url,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        subscription_tier=current_user.subscription_tier,
        preferences=preferences,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at,
        last_login=current_user.last_login
    )


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user)
) -> Dict[str, str]:
    """Logout user (client should discard token)"""
    return {"message": "Successfully logged out"}


@router.post("/refresh", response_model=Token)
async def refresh_token(
    current_user: User = Depends(get_current_user)
) -> Any:
    """Refresh access token"""
    # Create new access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(current_user.id), "email": current_user.email},
        expires_delta=access_token_expires
    )
    
    # Parse preferences JSON if exists
    preferences = None
    if current_user.preferences:
        try:
            preferences = json.loads(current_user.preferences)
        except json.JSONDecodeError:
            preferences = None
    
    # Create user response
    user_response = UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        github_id=current_user.github_id,
        github_username=current_user.github_username,
        avatar_url=current_user.avatar_url,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        subscription_tier=current_user.subscription_tier,
        preferences=preferences,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at,
        last_login=current_user.last_login
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user_response
    )