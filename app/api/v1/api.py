"""
API v1 router configuration
"""
from fastapi import APIRouter

api_router = APIRouter()

# Health check endpoint for API v1
@api_router.get("/health")
async def api_health():
    """API v1 health check"""
    return {
        "status": "healthy",
        "api_version": "v1",
        "service": "KeyHaven Pro API"
    }