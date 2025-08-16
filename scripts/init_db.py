#!/usr/bin/env python3
"""
Initialize database with Alembic migrations
"""
import asyncio
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from alembic.config import Config
from alembic import command
from app.core.database import engine, Base


async def init_database():
    """Initialize database and run migrations"""
    print("🗄️ Initializing database...")
    
    try:
        # Create all tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        print("✅ Database tables created successfully")
        
        # Initialize Alembic
        alembic_cfg = Config("alembic.ini")
        
        # Stamp the database with the current revision
        command.stamp(alembic_cfg, "head")
        print("✅ Alembic initialized and stamped")
        
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        sys.exit(1)
    
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(init_database())