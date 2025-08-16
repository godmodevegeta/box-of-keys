"""
User and Team Pydantic schemas for request/response validation
"""
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import uuid


class SubscriptionTier(str, Enum):
    """Subscription tier enumeration"""
    FREE = "free"
    PRO = "pro"
    TEAM = "team"


class TeamRole(str, Enum):
    """Team role enumeration"""
    VIEWER = "viewer"
    EDITOR = "editor"
    ADMIN = "admin"


# User schemas
class UserBase(BaseModel):
    """Base user schema with common fields"""
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool = True


class UserCreate(UserBase):
    """Schema for user creation"""
    password: str = Field(..., min_length=8, max_length=100)
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserLogin(BaseModel):
    """Schema for user login"""
    email: EmailStr
    password: str


class UserUpdate(BaseModel):
    """Schema for user updates"""
    full_name: Optional[str] = None
    preferences: Optional[Dict[str, Any]] = None


class UserResponse(UserBase):
    """Schema for user response"""
    id: uuid.UUID
    github_id: Optional[str] = None
    github_username: Optional[str] = None
    avatar_url: Optional[str] = None
    is_verified: bool
    subscription_tier: SubscriptionTier
    preferences: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


class UserInDB(UserResponse):
    """Schema for user in database (includes sensitive fields)"""
    hashed_password: Optional[str] = None


# Team schemas
class TeamBase(BaseModel):
    """Base team schema"""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class TeamCreate(TeamBase):
    """Schema for team creation"""
    pass


class TeamUpdate(BaseModel):
    """Schema for team updates"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    max_members: Optional[int] = Field(None, ge=1, le=100)


class TeamMemberResponse(BaseModel):
    """Schema for team member response"""
    user_id: uuid.UUID
    email: str
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    role: TeamRole
    permissions: Optional[List[str]] = None
    joined_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class TeamResponse(TeamBase):
    """Schema for team response"""
    id: uuid.UUID
    owner_id: uuid.UUID
    is_active: bool
    max_members: int
    created_at: datetime
    updated_at: datetime
    members: Optional[List[TeamMemberResponse]] = None
    
    model_config = ConfigDict(from_attributes=True)


class TeamInvite(BaseModel):
    """Schema for team invitation"""
    email: EmailStr
    role: TeamRole = TeamRole.VIEWER
    permissions: Optional[List[str]] = None


# Authentication schemas
class Token(BaseModel):
    """Schema for JWT token response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class TokenData(BaseModel):
    """Schema for token data"""
    user_id: Optional[str] = None
    email: Optional[str] = None


class GitHubOAuthRequest(BaseModel):
    """Schema for GitHub OAuth request"""
    code: str
    state: Optional[str] = None


class PasswordReset(BaseModel):
    """Schema for password reset request"""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Schema for password reset confirmation"""
    token: str
    new_password: str = Field(..., min_length=8, max_length=100)
    
    @field_validator('new_password')
    @classmethod
    def validate_password(cls, v):
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v