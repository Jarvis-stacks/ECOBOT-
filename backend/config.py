# backend/config.py
# Centralizes configuration settings for ECOBOT backend

import os
from typing import Optional
from dotenv import load_dotenv
from enum import Enum

# Load environment variables
load_dotenv()

class Environment(Enum):
    """Enumeration for application environments."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"

class Config:
    """Base configuration class."""
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", Environment.DEVELOPMENT.value)
    
    # API Keys
    HF_TOKEN: str = os.getenv("HF_TOKEN", "")
    SERP_API_KEY: str = os.getenv("SERP_API_KEY", "")
    GROK_API_TOKEN: str = os.getenv("GROK_API_TOKEN", "")  # Placeholder for future
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./eco_bot.db")
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "default-secret-key-for-dev")  # Should be overridden in production
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    SESSION_TIMEOUT_SECONDS: int = 3600  # 1 hour
    
    # Application Limits
    MAX_MESSAGE_LENGTH: int = 1000
    MAX_HISTORY_ITEMS: int = 50
    
    # Rate Limits
    RATE_LIMIT_LOGIN: str = "10/minute"
    RATE_LIMIT_CONVERSE: str = "50/hour"
    RATE_LIMIT_BRAINSTORM: str = "20/hour"
    RATE_LIMIT_THINK: str = "15/hour"
    RATE_LIMIT_SEARCH: str = "25/hour"
    RATE_LIMIT_HISTORY: str = "30/hour"
    RATE_LIMIT_PROFILE: str = "50/hour"
    RATE_LIMIT_HEALTH: str = "100/hour"
    RATE_LIMIT_DEFAULT: str = "200/hour"
    
    # Caching (future Redis integration)
    CACHE_ENABLED: bool = os.getenv("CACHE_ENABLED", "false").lower() == "true"
    CACHE_TTL: int = 3600  # 1 hour in seconds
    
    # Notifications (future email/SMS)
    NOTIFICATION_ENABLED: bool = os.getenv("NOTIFICATION_ENABLED", "false").lower() == "true"
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")

class DevelopmentConfig(Config):
    """Development-specific configuration."""
    DEBUG: bool = True
    DATABASE_URL: str = "sqlite:///./eco_bot_dev.db"  # Separate dev database

class TestingConfig(Config):
    """Testing-specific configuration."""
    DEBUG: bool = True
    DATABASE_URL: str = "sqlite:///:memory:"  # In-memory for tests
    SECRET_KEY: str = "test-secret-key"

class ProductionConfig(Config):
    """Production-specific configuration."""
    DEBUG: bool = False
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/ecobot")

def get_config(env: Optional[str] = None) -> Config:
    """Return the appropriate config based on environment."""
    env = env or Config.ENVIRONMENT
    if env == Environment.DEVELOPMENT.value:
        return DevelopmentConfig()
    elif env == Environment.TESTING.value:
        return TestingConfig()
    elif env == Environment.PRODUCTION.value:
        return ProductionConfig()
    else:
        raise ValueError(f"Unknown environment: {env}")

# Current configuration instance
config = get_config()

# Future extension: Add methods to reload config dynamically
def reload_config():
    """Reload configuration from environment (future feature)."""
    global config
    config = get_config()
    # Placeholder for dynamic reload logic
    pass
