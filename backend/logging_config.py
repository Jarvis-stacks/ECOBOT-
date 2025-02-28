# backend/logging_config.py
# Configures advanced logging

import logging
import os
from logging.handlers import RotatingFileHandler
from .config import config

def setup_logging():
    """Setup logging configuration."""
    logger = logging.getLogger("ECOBOT")
    logger.setLevel(logging.INFO if not config.DEBUG else logging.DEBUG)
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        "ecobot.log",
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    
    # Console handler for development
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info("Logging setup complete")

# Future: Add JSON logging or remote logging (e.g., to ELK stack)
