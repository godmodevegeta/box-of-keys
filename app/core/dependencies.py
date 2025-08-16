"""
FastAPI dependencies for authentication and authorization
"""
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
import uuid

from app.core.database import get_db
from app.core.auth import verify_token
from app.services.user_service import UserService
from app.models.user import User
from app.schemas.user import TokenData

# HTTP Bearer token scheme
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get current authenticated user"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Verify token
        payload = verify_token(credentials.credentials)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        
        # Get user from database
        user_service = UserService(db)
        user = await user_service.get_user_by_id(uuid.UUID(user_id))
        if user is None:
            raise credentials_exception
        
        # Check if user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated"
            )
        
        return user
        
    except ValueError:
        # Invalid UUID
        raise credentials_exception
    except Exception:
        raise credentials_exception


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user (alias for get_current_user since we already check is_active)"""
    return current_user


async def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Get current user if authenticated, otherwise return None"""
    if not credentials:
        return None
    
    try:
        # Verify token
        payload = verify_token(credentials.credentials)
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
        
        # Get user from database
        user_service = UserService(db)
        user = await user_service.get_user_by_id(uuid.UUID(user_id))
        if user is None or not user.is_active:
            return None
        
        return user
        
    except Exception:
        return None


class RequireRole:
    """Dependency class to require specific team role"""
    
    def __init__(self, required_role: str):
        self.required_role = required_role
    
    def __call__(self, current_user: User = Depends(get_current_user)):
        # This is a placeholder for role-based access control
        # In a real implementation, you would check the user's role in the specific team context
        # For now, we'll just return the user
        return current_user


class RequirePermission:
    """Dependency class to require specific permission"""
    
    def __init__(self, required_permission: str):
        self.required_permission = required_permission
    
    def __call__(self, current_user: User = Depends(get_current_user)):
        # This is a placeholder for permission-based access control
        # In a real implementation, you would check the user's permissions
        # For now, we'll just return the user
        return current_user


# Convenience dependencies
require_admin = RequireRole("admin")
require_editor = RequireRole("editor")
require_viewer = RequireRole("viewer")