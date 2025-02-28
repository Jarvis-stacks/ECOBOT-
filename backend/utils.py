# backend/utils.py
# General utility functions

import re
from datetime import datetime
import uuid
import hashlib
import logging

logger = logging.getLogger("ECOBOT.Utils")

def sanitize_input(text: str) -> str:
    """Remove potentially harmful characters."""
    try:
        return re.sub(r'[<>;]', '', text.strip())
    except Exception as e:
        logger.error(f"Sanitize input error: {e}")
        return text

def truncate_text(text: str, max_length: int = 1000) -> str:
    """Truncate text to a maximum length."""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."

def format_timestamp(dt: datetime) -> str:
    """Format a datetime to ISO string."""
    return dt.isoformat()

def generate_session_id() -> str:
    """Generate a unique session ID."""
    return str(uuid.uuid4())

def hash_string(value: str) -> str:
    """Generate a SHA-256 hash."""
    return hashlib.sha256(value.encode()).hexdigest()

def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

# Future: Add utilities like data compression or encryption
