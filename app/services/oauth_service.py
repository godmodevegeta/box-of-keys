"""
OAuth service for GitHub integration
"""
import httpx
from typing import Optional, Dict, Any
from fastapi import HTTPException, status
import secrets

from app.core.config import settings


class GitHubOAuthService:
    """GitHub OAuth service"""
    
    def __init__(self):
        self.client_id = settings.GITHUB_CLIENT_ID
        self.client_secret = settings.GITHUB_CLIENT_SECRET
        self.redirect_uri = "http://localhost:8000/api/v1/auth/github/callback"  # TODO: Make configurable
        
        if not self.client_id or not self.client_secret:
            raise ValueError("GitHub OAuth credentials not configured")
    
    def get_authorization_url(self, state: Optional[str] = None) -> Dict[str, str]:
        """Generate GitHub OAuth authorization URL"""
        if not state:
            state = secrets.token_urlsafe(32)
        
        auth_url = (
            f"https://github.com/login/oauth/authorize"
            f"?client_id={self.client_id}"
            f"&redirect_uri={self.redirect_uri}"
            f"&scope=user:email"
            f"&state={state}"
        )
        
        return {
            "authorization_url": auth_url,
            "state": state
        }
    
    async def exchange_code_for_token(self, code: str) -> str:
        """Exchange authorization code for access token"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                },
                headers={"Accept": "application/json"}
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to exchange code for token"
                )
            
            data = response.json()
            
            if "error" in data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"GitHub OAuth error: {data.get('error_description', data['error'])}"
                )
            
            return data["access_token"]
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from GitHub"""
        async with httpx.AsyncClient() as client:
            # Get user profile
            user_response = await client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"token {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            
            if user_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to get user information from GitHub"
                )
            
            user_data = user_response.json()
            
            # Get user emails
            emails_response = await client.get(
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"token {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            
            primary_email = None
            if emails_response.status_code == 200:
                emails = emails_response.json()
                # Find primary email
                for email in emails:
                    if email.get("primary", False):
                        primary_email = email["email"]
                        break
                # Fallback to first verified email
                if not primary_email:
                    for email in emails:
                        if email.get("verified", False):
                            primary_email = email["email"]
                            break
            
            # Use public email if no primary email found
            if not primary_email:
                primary_email = user_data.get("email")
            
            if not primary_email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No email address found in GitHub account"
                )
            
            return {
                "github_id": str(user_data["id"]),
                "username": user_data["login"],
                "email": primary_email,
                "name": user_data.get("name"),
                "avatar_url": user_data.get("avatar_url"),
                "bio": user_data.get("bio"),
                "company": user_data.get("company"),
                "location": user_data.get("location"),
                "blog": user_data.get("blog"),
                "public_repos": user_data.get("public_repos", 0),
                "followers": user_data.get("followers", 0),
                "following": user_data.get("following", 0),
            }


class OAuthService:
    """General OAuth service"""
    
    def __init__(self):
        self.github = GitHubOAuthService()
    
    async def authenticate_github(self, code: str, state: Optional[str] = None) -> Dict[str, Any]:
        """Authenticate user with GitHub OAuth"""
        # Exchange code for access token
        access_token = await self.github.exchange_code_for_token(code)
        
        # Get user information
        user_info = await self.github.get_user_info(access_token)
        
        return user_info
    
    def get_github_auth_url(self, state: Optional[str] = None) -> Dict[str, str]:
        """Get GitHub authorization URL"""
        return self.github.get_authorization_url(state)