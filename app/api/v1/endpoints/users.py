"""
User management endpoints
"""
from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
import json

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.services.user_service import UserService
from app.schemas.user import UserResponse, UserUpdate
from app.models.user import User

router = APIRouter()


@router.get("/profile", response_model=UserResponse)
async def get_user_profile(
    current_user: User = Depends(get_current_user)
) -> Any:
    """Get current user profile"""
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


@router.put("/profile", response_model=UserResponse)
async def update_user_profile(
    user_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Update current user profile"""
    user_service = UserService(db)
    
    updated_user = await user_service.update_user(current_user.id, user_data)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Parse preferences JSON if exists
    preferences = None
    if updated_user.preferences:
        try:
            preferences = json.loads(updated_user.preferences)
        except json.JSONDecodeError:
            preferences = None
    
    return UserResponse(
        id=updated_user.id,
        email=updated_user.email,
        full_name=updated_user.full_name,
        github_id=updated_user.github_id,
        github_username=updated_user.github_username,
        avatar_url=updated_user.avatar_url,
        is_active=updated_user.is_active,
        is_verified=updated_user.is_verified,
        subscription_tier=updated_user.subscription_tier,
        preferences=preferences,
        created_at=updated_user.created_at,
        updated_at=updated_user.updated_at,
        last_login=updated_user.last_login
    )


@router.delete("/profile")
async def delete_user_account(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Delete current user account"""
    user_service = UserService(db)
    
    success = await user_service.delete_user(current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {"message": "User account deleted successfully"}


@router.post("/deactivate")
async def deactivate_user_account(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Deactivate current user account"""
    user_service = UserService(db)
    
    success = await user_service.deactivate_user(current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {"message": "User account deactivated successfully"}