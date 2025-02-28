# backend/validators.py
# Input validation functions

from .exceptions import ValidationError
from .config import config
import logging

logger = logging.getLogger("ECOBOT.Validators")

def validate_message(message: str) -> None:
    """Validate a conversation message."""
    if not message.strip():
        raise ValidationError("Message cannot be empty")
    if len(message) > config.MAX_MESSAGE_LENGTH:
        raise ValidationError(f"Message exceeds {config.MAX_MESSAGE_LENGTH} characters")

def validate_query(query: str) -> None:
    """Validate a search or brainstorm query."""
    if not query.strip():
        raise ValidationError("Query cannot be empty")
    if len(query) > 500:
        raise ValidationError("Query exceeds 500 characters")

def validate_user_input(username: str, email: str, password: str, full_name: str) -> None:
    """Validate user registration input."""
    if not all([username, email, password, full_name]):
        raise ValidationError("All fields are required")
    if len(username) < 3 or len(username) > 50:
        raise ValidationError("Username must be 3-50 characters")
    if not validate_email(email):
        raise ValidationError("Invalid email format")
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters")
    if len(full_name) < 2 or len(full_name) > 100:
        raise ValidationError("Full name must be 2-100 characters")

from .utils import validate_email  # Imported for reuse

# Future: Add regex patterns or custom validators
