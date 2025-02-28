# backend/database.py
# Manages database initialization and session handling

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
import logging
from .config import config
from .models import Base

logger = logging.getLogger("ECOBOT.DB")

# Database engine
engine = create_engine(
    config.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in config.DATABASE_URL else {},
    echo=config.DEBUG
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Initialize the database by creating all tables."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

def get_db() -> Session:
    """Dependency to provide a database session."""
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()

def test_db_connection():
    """Test the database connection."""
    try:
        with engine.connect() as connection:
            connection.execute("SELECT 1")
        logger.info("Database connection test successful")
        return True
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        return False

# Future: Add migration support with Alembic
def run_migrations():
    """Placeholder for future Alembic migrations."""
    logger.info("Migration placeholder - not implemented")
    # Implement with: alembic revision, alembic upgrade
    pass
