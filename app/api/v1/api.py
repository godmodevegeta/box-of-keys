"""
API v1 router configuration
"""
from fastapi import APIRouter

from app.api.v1.endpoints import auth, users, teams

api_router = APIRouter()

# Include endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(teams.router, prefix="/teams", tags=["teams"])

# Health check endpoint for API v1
@api_router.get("/health")
async def api_health():
    """API v1 health check"""
    return {
        "status": "healthy",
        "api_version": "v1",
        "service": "KeyHaven Pro API"
    }