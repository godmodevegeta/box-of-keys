"""
Team management endpoints
"""
from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
import uuid

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.services.user_service import TeamService, UserService
from app.schemas.user import (
    TeamCreate, TeamUpdate, TeamResponse, TeamInvite, 
    TeamMemberResponse, TeamRole
)
from app.models.user import User

router = APIRouter()


@router.post("/", response_model=TeamResponse, status_code=status.HTTP_201_CREATED)
async def create_team(
    team_data: TeamCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Create a new team"""
    team_service = TeamService(db)
    
    team = await team_service.create_team(team_data, current_user.id)
    
    return TeamResponse(
        id=team.id,
        name=team.name,
        description=team.description,
        owner_id=team.owner_id,
        is_active=team.is_active,
        max_members=team.max_members,
        created_at=team.created_at,
        updated_at=team.updated_at
    )


@router.get("/", response_model=List[TeamResponse])
async def get_user_teams(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Get all teams for current user"""
    team_service = TeamService(db)
    
    teams = await team_service.get_user_teams(current_user.id)
    
    return [
        TeamResponse(
            id=team.id,
            name=team.name,
            description=team.description,
            owner_id=team.owner_id,
            is_active=team.is_active,
            max_members=team.max_members,
            created_at=team.created_at,
            updated_at=team.updated_at
        )
        for team in teams
    ]


@router.get("/{team_id}", response_model=TeamResponse)
async def get_team(
    team_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Get team by ID"""
    team_service = TeamService(db)
    
    team = await team_service.get_team_by_id(team_id)
    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found"
        )
    
    # Check if user has access to this team
    user_teams = await team_service.get_user_teams(current_user.id)
    if team.id not in [t.id for t in user_teams]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this team"
        )
    
    # Get team members with details
    members = []
    if team.members:
        for member in team.members:
            # This is a simplified version - in a real implementation,
            # you'd need to join with the team_members table to get role info
            members.append(TeamMemberResponse(
                user_id=member.id,
                email=member.email,
                full_name=member.full_name,
                avatar_url=member.avatar_url,
                role=TeamRole.VIEWER,  # Default - would need proper query
                joined_at=member.created_at  # Placeholder
            ))
    
    return TeamResponse(
        id=team.id,
        name=team.name,
        description=team.description,
        owner_id=team.owner_id,
        is_active=team.is_active,
        max_members=team.max_members,
        created_at=team.created_at,
        updated_at=team.updated_at,
        members=members
    )


@router.post("/{team_id}/members", status_code=status.HTTP_201_CREATED)
async def add_team_member(
    team_id: uuid.UUID,
    invite_data: TeamInvite,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Add member to team"""
    team_service = TeamService(db)
    user_service = UserService(db)
    
    # Check if current user is team owner or admin
    team = await team_service.get_team_by_id(team_id)
    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found"
        )
    
    if team.owner_id != current_user.id:
        # In a real implementation, you'd also check for admin role
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only team owners can add members"
        )
    
    # Find user by email
    user_to_add = await user_service.get_user_by_email(invite_data.email)
    if not user_to_add:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Add member to team
    success = await team_service.add_team_member(
        team_id, 
        user_to_add.id, 
        invite_data.role, 
        invite_data.permissions
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to add team member"
        )
    
    return {"message": "Team member added successfully"}


@router.delete("/{team_id}/members/{user_id}")
async def remove_team_member(
    team_id: uuid.UUID,
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Remove member from team"""
    team_service = TeamService(db)
    
    # Check if current user is team owner or admin
    team = await team_service.get_team_by_id(team_id)
    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found"
        )
    
    if team.owner_id != current_user.id and current_user.id != user_id:
        # Users can remove themselves, owners can remove anyone
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    success = await team_service.remove_team_member(team_id, user_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team member not found"
        )
    
    return {"message": "Team member removed successfully"}


@router.put("/{team_id}/members/{user_id}/role")
async def update_team_member_role(
    team_id: uuid.UUID,
    user_id: uuid.UUID,
    role_data: dict,  # {"role": "admin", "permissions": ["read", "write"]}
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Update team member role"""
    team_service = TeamService(db)
    
    # Check if current user is team owner or admin
    team = await team_service.get_team_by_id(team_id)
    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found"
        )
    
    if team.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only team owners can update member roles"
        )
    
    try:
        role = TeamRole(role_data.get("role", "viewer"))
        permissions = role_data.get("permissions", [])
        
        success = await team_service.update_team_member_role(
            team_id, user_id, role, permissions
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Team member not found"
            )
        
        return {"message": "Team member role updated successfully"}
        
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role specified"
        )


@router.delete("/{team_id}")
async def delete_team(
    team_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """Delete team"""
    team_service = TeamService(db)
    
    success = await team_service.delete_team(team_id, current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found or access denied"
        )
    
    return {"message": "Team deleted successfully"}