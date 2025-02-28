# backend/exceptions.py
# Custom exception classes and handlers

from fastapi import HTTPException, Request
import logging

logger = logging.getLogger("ECOBOT.Exceptions")

class APIError(HTTPException):
    """Base exception for API errors."""
    def __init__(self, status_code: int, detail: str):
        super().__init__(status_code=status_code, detail=detail)
        logger.error(f"APIError: {status_code} - {detail}")

class ValidationError(APIError):
    """Exception for input validation failures."""
    def __init__(self, detail: str):
        super().__init__(status_code=400, detail=detail)

class AuthError(APIError):
    """Exception for authentication failures."""
    def __init__(self, detail: str = "Authentication failed"):
        super().__init__(status_code=401, detail=detail)

class RateLimitError(APIError):
    """Exception for rate limit exceeded."""
    def __init__(self, detail: str = "Rate limit exceeded"):
        super().__init__(status_code=429, detail=detail)

async def api_exception_handler(request: Request, exc: APIError):
    """Custom handler for API exceptions."""
    return {"status_code": exc.status_code, "detail": exc.detail}

# Future: Add more specific exceptions (e.g., DatabaseError, ServiceError)
