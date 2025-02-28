# backend/middleware.py
# Custom middleware for request/response processing

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import logging
import time
from .config import config

logger = logging.getLogger("ECOBOT.Middleware")

class LoggingMiddleware(BaseHTTPMiddleware):
    """Log all incoming requests and responses."""
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        logger.info(f"Request: {request.method} {request.url}")
        response = await call_next(request)
        duration = time.time() - start_time
        logger.info(f"Response: {response.status_code} - Duration: {duration:.3f}s")
        return response

class PerformanceMiddleware(BaseHTTPMiddleware):
    """Add performance headers to responses."""
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        response.headers["X-Response-Time"] = f"{duration:.3f}"
        return response

# Future: Add IP banning or request validation middleware
class SecurityMiddleware(BaseHTTPMiddleware):
    """Placeholder for future security checks."""
    async def dispatch(self, request: Request, call_next):
        # Example: Ban specific IPs
        # if request.client.host in config.BANNED_IPS:
        #     raise HTTPException(status_code=403, detail="Access denied")
        return await call_next(request)
