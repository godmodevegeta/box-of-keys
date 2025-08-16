"""
User and Team database models
"""
from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Table, Text, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import uuid

from app.core.database import Base

# Association table for team members
team_members = Table(
    'team_members',
    Base.metadata,
    Column('team_id', UUID(as_uuid=True), ForeignKey('teams.id'), primary_key=True),
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id'), primary_key=True),
    Column('role', String(50), nullable=False, default='viewer'),
    Column('permissions', Text, nullable=True),  # JSON string for permissions
    Column('joined_at', DateTime(timezone=True), server_default=func.now())
)


class User(Base):
    """User model for authentication and authorization"""
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=True)  # Nullable for OAuth users
    github_id = Column(String(100), unique=True, nullable=True, index=True)
    github_username = Column(String(100), nullable=True)
    full_name = Column(String(255), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    
    # Account status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    
    # Subscription
    subscription_tier = Column(String(50), default='free', nullable=False)
    
    # Preferences stored as JSON string
    preferences = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    owned_teams = relationship("Team", back_populates="owner", cascade="all, delete-orphan")
    teams = relationship("Team", secondary=team_members, back_populates="members")
    
    def __repr__(self):
        return f"<User(id={self.id}, email={self.email})>"


class Team(Base):
    """Team model for collaboration"""
    __tablename__ = "teams"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    owner_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    
    # Team settings
    is_active = Column(Boolean, default=True, nullable=False)
    max_members = Column(Integer, default=10, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    owner = relationship("User", back_populates="owned_teams")
    members = relationship("User", secondary=team_members, back_populates="teams")
    
    def __repr__(self):
        return f"<Team(id={self.id}, name={self.name})>"