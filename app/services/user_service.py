"""
User service for database operations
"""
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.orm import selectinload
from datetime import datetime, timezone
import json
import uuid

from app.models.user import User, Team, team_members
from app.schemas.user import UserCreate, UserUpdate, TeamCreate, TeamUpdate, TeamRole
from app.core.auth import get_password_hash, verify_password
from fastapi import HTTPException, status


class UserService:
    """Service class for user operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_user(self, user_data: UserCreate) -> User:
        """Create a new user"""
        # Check if user already exists
        existing_user = await self.get_user_by_email(user_data.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists"
            )
        
        # Create new user
        hashed_password = get_password_hash(user_data.password)
        db_user = User(
            email=user_data.email,
            hashed_password=hashed_password,
            full_name=user_data.full_name,
            is_active=user_data.is_active
        )
        
        self.db.add(db_user)
        await self.db.commit()
        await self.db.refresh(db_user)
        return db_user
    
    async def create_oauth_user(self, email: str, github_id: str, github_username: str, 
                               full_name: Optional[str] = None, avatar_url: Optional[str] = None) -> User:
        """Create a new user from OAuth (GitHub)"""
        # Check if user already exists by email or GitHub ID
        existing_user = await self.get_user_by_email(email)
        if existing_user:
            # Update GitHub info if user exists
            existing_user.github_id = github_id
            existing_user.github_username = github_username
            if avatar_url:
                existing_user.avatar_url = avatar_url
            existing_user.is_verified = True
            existing_user.last_login = datetime.now(timezone.utc)
            await self.db.commit()
            await self.db.refresh(existing_user)
            return existing_user
        
        existing_github_user = await self.get_user_by_github_id(github_id)
        if existing_github_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this GitHub account already exists"
            )
        
        # Create new OAuth user
        db_user = User(
            email=email,
            github_id=github_id,
            github_username=github_username,
            full_name=full_name,
            avatar_url=avatar_url,
            is_verified=True,
            last_login=datetime.now(timezone.utc)
        )
        
        self.db.add(db_user)
        await self.db.commit()
        await self.db.refresh(db_user)
        return db_user
    
    async def authenticate_user(self, email: str, password: str) -> Optional[User]:
        """Authenticate user with email and password"""
        user = await self.get_user_by_email(email)
        if not user:
            return None
        if not user.hashed_password:
            return None  # OAuth user without password
        if not verify_password(password, user.hashed_password):
            return None
        
        # Update last login
        user.last_login = datetime.now(timezone.utc)
        await self.db.commit()
        return user
    
    async def get_user_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        """Get user by ID"""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        result = await self.db.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()
    
    async def get_user_by_github_id(self, github_id: str) -> Optional[User]:
        """Get user by GitHub ID"""
        result = await self.db.execute(
            select(User).where(User.github_id == github_id)
        )
        return result.scalar_one_or_none()
    
    async def update_user(self, user_id: uuid.UUID, user_data: UserUpdate) -> Optional[User]:
        """Update user information"""
        user = await self.get_user_by_id(user_id)
        if not user:
            return None
        
        update_data = user_data.dict(exclude_unset=True)
        
        # Handle preferences JSON serialization
        if 'preferences' in update_data and update_data['preferences'] is not None:
            update_data['preferences'] = json.dumps(update_data['preferences'])
        
        for field, value in update_data.items():
            setattr(user, field, value)
        
        user.updated_at = datetime.now(timezone.utc)
        await self.db.commit()
        await self.db.refresh(user)
        return user
    
    async def deactivate_user(self, user_id: uuid.UUID) -> bool:
        """Deactivate user account"""
        result = await self.db.execute(
            update(User)
            .where(User.id == user_id)
            .values(is_active=False, updated_at=datetime.now(timezone.utc))
        )
        await self.db.commit()
        return result.rowcount > 0
    
    async def delete_user(self, user_id: uuid.UUID) -> bool:
        """Delete user account (hard delete)"""
        result = await self.db.execute(
            delete(User).where(User.id == user_id)
        )
        await self.db.commit()
        return result.rowcount > 0


class TeamService:
    """Service class for team operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_team(self, team_data: TeamCreate, owner_id: uuid.UUID) -> Team:
        """Create a new team"""
        db_team = Team(
            name=team_data.name,
            description=team_data.description,
            owner_id=owner_id
        )
        
        self.db.add(db_team)
        await self.db.commit()
        await self.db.refresh(db_team)
        return db_team
    
    async def get_team_by_id(self, team_id: uuid.UUID) -> Optional[Team]:
        """Get team by ID with members"""
        result = await self.db.execute(
            select(Team)
            .options(selectinload(Team.members))
            .where(Team.id == team_id)
        )
        return result.scalar_one_or_none()
    
    async def get_user_teams(self, user_id: uuid.UUID) -> List[Team]:
        """Get all teams for a user (owned and member)"""
        result = await self.db.execute(
            select(Team)
            .options(selectinload(Team.members))
            .where(
                (Team.owner_id == user_id) | 
                (Team.members.any(User.id == user_id))
            )
        )
        return result.scalars().all()
    
    async def add_team_member(self, team_id: uuid.UUID, user_id: uuid.UUID, 
                             role: TeamRole = TeamRole.VIEWER, 
                             permissions: Optional[List[str]] = None) -> bool:
        """Add member to team"""
        # Check if team exists and user exists
        team = await self.get_team_by_id(team_id)
        if not team:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Team not found"
            )
        
        user_service = UserService(self.db)
        user = await user_service.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Check if user is already a member
        existing_member = await self.db.execute(
            select(team_members).where(
                (team_members.c.team_id == team_id) & 
                (team_members.c.user_id == user_id)
            )
        )
        if existing_member.first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is already a team member"
            )
        
        # Add member
        permissions_json = json.dumps(permissions) if permissions else None
        await self.db.execute(
            team_members.insert().values(
                team_id=team_id,
                user_id=user_id,
                role=role.value,
                permissions=permissions_json
            )
        )
        await self.db.commit()
        return True
    
    async def remove_team_member(self, team_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Remove member from team"""
        result = await self.db.execute(
            delete(team_members).where(
                (team_members.c.team_id == team_id) & 
                (team_members.c.user_id == user_id)
            )
        )
        await self.db.commit()
        return result.rowcount > 0
    
    async def update_team_member_role(self, team_id: uuid.UUID, user_id: uuid.UUID, 
                                     role: TeamRole, permissions: Optional[List[str]] = None) -> bool:
        """Update team member role and permissions"""
        permissions_json = json.dumps(permissions) if permissions else None
        result = await self.db.execute(
            update(team_members)
            .where(
                (team_members.c.team_id == team_id) & 
                (team_members.c.user_id == user_id)
            )
            .values(role=role.value, permissions=permissions_json)
        )
        await self.db.commit()
        return result.rowcount > 0
    
    async def delete_team(self, team_id: uuid.UUID, owner_id: uuid.UUID) -> bool:
        """Delete team (only by owner)"""
        result = await self.db.execute(
            delete(Team).where(
                (Team.id == team_id) & (Team.owner_id == owner_id)
            )
        )
        await self.db.commit()
        return result.rowcount > 0