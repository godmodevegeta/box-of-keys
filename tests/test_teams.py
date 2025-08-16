"""
Tests for team management system
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
import uuid

from app.services.user_service import TeamService, UserService
from app.schemas.user import UserCreate, TeamCreate, TeamRole


@pytest.mark.asyncio
class TestTeamService:
    """Test team service operations"""
    
    async def test_create_team(self, db_session: AsyncSession):
        """Test team creation"""
        user_service = UserService(db_session)
        team_service = TeamService(db_session)
        
        # Create owner user
        user_data = UserCreate(
            email="owner@example.com",
            password="TestPassword123!"
        )
        owner = await user_service.create_user(user_data)
        
        # Create team
        team_data = TeamCreate(
            name="Test Team",
            description="A test team"
        )
        team = await team_service.create_team(team_data, owner.id)
        
        assert team.name == "Test Team"
        assert team.description == "A test team"
        assert team.owner_id == owner.id
        assert team.is_active is True
        assert team.max_members == 10
    
    async def test_get_team_by_id(self, db_session: AsyncSession):
        """Test getting team by ID"""
        user_service = UserService(db_session)
        team_service = TeamService(db_session)
        
        # Create owner user
        user_data = UserCreate(
            email="owner2@example.com",
            password="TestPassword123!"
        )
        owner = await user_service.create_user(user_data)
        
        # Create team
        team_data = TeamCreate(name="Find Me Team")
        created_team = await team_service.create_team(team_data, owner.id)
        
        # Find team
        found_team = await team_service.get_team_by_id(created_team.id)
        assert found_team is not None
        assert found_team.id == created_team.id
        assert found_team.name == "Find Me Team"
        
        # Try to find non-existent team
        not_found = await team_service.get_team_by_id(uuid.uuid4())
        assert not_found is None
    
    async def test_add_team_member(self, db_session: AsyncSession):
        """Test adding member to team"""
        user_service = UserService(db_session)
        team_service = TeamService(db_session)
        
        # Create owner and member users
        owner_data = UserCreate(
            email="teamowner@example.com",
            password="TestPassword123!"
        )
        owner = await user_service.create_user(owner_data)
        
        member_data = UserCreate(
            email="teammember@example.com",
            password="TestPassword123!"
        )
        member = await user_service.create_user(member_data)
        
        # Create team
        team_data = TeamCreate(name="Member Test Team")
        team = await team_service.create_team(team_data, owner.id)
        
        # Add member
        success = await team_service.add_team_member(
            team.id, member.id, TeamRole.EDITOR, ["read", "write"]
        )
        assert success is True
        
        # Try to add same member again (should fail)
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await team_service.add_team_member(team.id, member.id, TeamRole.VIEWER)
        assert exc_info.value.status_code == 400
    
    async def test_remove_team_member(self, db_session: AsyncSession):
        """Test removing member from team"""
        user_service = UserService(db_session)
        team_service = TeamService(db_session)
        
        # Create users
        owner_data = UserCreate(
            email="removeowner@example.com",
            password="TestPassword123!"
        )
        owner = await user_service.create_user(owner_data)
        
        member_data = UserCreate(
            email="removemember@example.com",
            password="TestPassword123!"
        )
        member = await user_service.create_user(member_data)
        
        # Create team and add member
        team_data = TeamCreate(name="Remove Test Team")
        team = await team_service.create_team(team_data, owner.id)
        await team_service.add_team_member(team.id, member.id, TeamRole.VIEWER)
        
        # Remove member
        success = await team_service.remove_team_member(team.id, member.id)
        assert success is True
        
        # Try to remove non-existent member
        success = await team_service.remove_team_member(team.id, uuid.uuid4())
        assert success is False
    
    async def test_update_team_member_role(self, db_session: AsyncSession):
        """Test updating team member role"""
        user_service = UserService(db_session)
        team_service = TeamService(db_session)
        
        # Create users
        owner_data = UserCreate(
            email="roleowner@example.com",
            password="TestPassword123!"
        )
        owner = await user_service.create_user(owner_data)
        
        member_data = UserCreate(
            email="rolemember@example.com",
            password="TestPassword123!"
        )
        member = await user_service.create_user(member_data)
        
        # Create team and add member
        team_data = TeamCreate(name="Role Test Team")
        team = await team_service.create_team(team_data, owner.id)
        await team_service.add_team_member(team.id, member.id, TeamRole.VIEWER)
        
        # Update role
        success = await team_service.update_team_member_role(
            team.id, member.id, TeamRole.ADMIN, ["read", "write", "admin"]
        )
        assert success is True
        
        # Try to update non-existent member
        success = await team_service.update_team_member_role(
            team.id, uuid.uuid4(), TeamRole.EDITOR
        )
        assert success is False
    
    async def test_delete_team(self, db_session: AsyncSession):
        """Test deleting team"""
        user_service = UserService(db_session)
        team_service = TeamService(db_session)
        
        # Create owner
        owner_data = UserCreate(
            email="deleteowner@example.com",
            password="TestPassword123!"
        )
        owner = await user_service.create_user(owner_data)
        
        # Create team
        team_data = TeamCreate(name="Delete Test Team")
        team = await team_service.create_team(team_data, owner.id)
        
        # Delete team
        success = await team_service.delete_team(team.id, owner.id)
        assert success is True
        
        # Try to delete non-existent team
        success = await team_service.delete_team(uuid.uuid4(), owner.id)
        assert success is False
        
        # Try to delete team with wrong owner
        team2_data = TeamCreate(name="Another Team")
        team2 = await team_service.create_team(team2_data, owner.id)
        
        other_user_data = UserCreate(
            email="other@example.com",
            password="TestPassword123!"
        )
        other_user = await user_service.create_user(other_user_data)
        
        success = await team_service.delete_team(team2.id, other_user.id)
        assert success is False


class TestTeamEndpoints:
    """Test team management endpoints"""
    
    def test_create_team_endpoint(self, client: TestClient):
        """Test team creation endpoint"""
        # Register user and get token
        register_response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "teamcreator@example.com",
                "password": "TestPassword123!",
                "full_name": "Team Creator"
            }
        )
        token = register_response.json()["access_token"]
        
        # Create team
        response = client.post(
            "/api/v1/teams/",
            json={
                "name": "API Test Team",
                "description": "Created via API"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "API Test Team"
        assert data["description"] == "Created via API"
        assert "id" in data
        assert "owner_id" in data
    
    def test_create_team_unauthorized(self, client: TestClient):
        """Test team creation without authentication"""
        response = client.post(
            "/api/v1/teams/",
            json={
                "name": "Unauthorized Team",
                "description": "Should fail"
            }
        )
        assert response.status_code == 403
    
    def test_get_user_teams(self, client: TestClient):
        """Test getting user's teams"""
        # Register user and get token
        register_response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "teamlister@example.com",
                "password": "TestPassword123!",
                "full_name": "Team Lister"
            }
        )
        token = register_response.json()["access_token"]
        
        # Create a team
        client.post(
            "/api/v1/teams/",
            json={
                "name": "Listed Team",
                "description": "Should appear in list"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Get teams
        response = client.get(
            "/api/v1/teams/",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert any(team["name"] == "Listed Team" for team in data)
    
    def test_get_team_by_id(self, client: TestClient):
        """Test getting specific team"""
        # Register user and get token
        register_response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "teamgetter@example.com",
                "password": "TestPassword123!",
                "full_name": "Team Getter"
            }
        )
        token = register_response.json()["access_token"]
        
        # Create team
        create_response = client.post(
            "/api/v1/teams/",
            json={
                "name": "Specific Team",
                "description": "Get this team"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        team_id = create_response.json()["id"]
        
        # Get specific team
        response = client.get(
            f"/api/v1/teams/{team_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == team_id
        assert data["name"] == "Specific Team"
    
    def test_get_team_not_found(self, client: TestClient):
        """Test getting non-existent team"""
        # Register user and get token
        register_response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "teamnotfound@example.com",
                "password": "TestPassword123!",
                "full_name": "Team Not Found"
            }
        )
        token = register_response.json()["access_token"]
        
        # Try to get non-existent team
        fake_id = str(uuid.uuid4())
        response = client.get(
            f"/api/v1/teams/{fake_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 404
    
    def test_add_team_member_endpoint(self, client: TestClient):
        """Test adding team member via API"""
        # Register owner
        owner_response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "memberowner@example.com",
                "password": "TestPassword123!",
                "full_name": "Member Owner"
            }
        )
        owner_token = owner_response.json()["access_token"]
        
        # Register member
        client.post(
            "/api/v1/auth/register",
            json={
                "email": "newmember@example.com",
                "password": "TestPassword123!",
                "full_name": "New Member"
            }
        )
        
        # Create team
        team_response = client.post(
            "/api/v1/teams/",
            json={
                "name": "Member Addition Team",
                "description": "For testing member addition"
            },
            headers={"Authorization": f"Bearer {owner_token}"}
        )
        team_id = team_response.json()["id"]
        
        # Add member
        response = client.post(
            f"/api/v1/teams/{team_id}/members",
            json={
                "email": "newmember@example.com",
                "role": "editor",
                "permissions": ["read", "write"]
            },
            headers={"Authorization": f"Bearer {owner_token}"}
        )
        
        assert response.status_code == 201
        data = response.json()
        assert "message" in data
    
    def test_delete_team_endpoint(self, client: TestClient):
        """Test deleting team via API"""
        # Register user and get token
        register_response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "teamdeleter@example.com",
                "password": "TestPassword123!",
                "full_name": "Team Deleter"
            }
        )
        token = register_response.json()["access_token"]
        
        # Create team
        create_response = client.post(
            "/api/v1/teams/",
            json={
                "name": "Team to Delete",
                "description": "Will be deleted"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        team_id = create_response.json()["id"]
        
        # Delete team
        response = client.delete(
            f"/api/v1/teams/{team_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data


class TestTeamRoleValidation:
    """Test team role validation"""
    
    def test_valid_team_roles(self):
        """Test valid team role values"""
        valid_roles = ["viewer", "editor", "admin"]
        
        for role in valid_roles:
            team_role = TeamRole(role)
            assert team_role.value == role
    
    def test_invalid_team_roles(self):
        """Test invalid team role values"""
        invalid_roles = ["owner", "superuser", "guest", "invalid"]
        
        for role in invalid_roles:
            with pytest.raises(ValueError):
                TeamRole(role)