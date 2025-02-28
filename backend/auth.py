# backend/auth.py
# Handles authentication and authorization logic

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from .config import config
from .models import User
from .database import get_db
import logging

logger = logging.getLogger("ECOBOT.Auth")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    """Create a JWT access token."""
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, config.SECRET_KEY, algorithm=config.ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"Token creation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create token")

def verify_token(token: str) -> dict:
    """Verify a JWT token and return its payload."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            logger.warning("Token missing 'sub' claim")
            raise credentials_exception
        return payload
    except JWTError as e:
        logger.warning(f"JWT decode error: {e}")
        raise credentials_exception

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Get the current authenticated user."""
    payload = verify_token(token)
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        logger.warning(f"User not found for token: {username}")
        raise HTTPException(status_code=401, detail="User not found")
    if user.disabled:
        logger.warning(f"Disabled user attempted access: {username}")
        raise HTTPException(status_code=403, detail="Account disabled")
    return user

def is_admin_user(user: User) -> bool:
    """Check if a user has admin privileges."""
    # Placeholder: Extend with role-based logic
    return user.username in ["johndoe"]  # Temporary admin check

def get_admin_user(user: User = Depends(get_current_user)) -> User:
    """Ensure the user is an admin."""
    if not is_admin_user(user):
        logger.warning(f"Unauthorized admin access by {user.username}")
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# Future: Add refresh tokens
def create_refresh_token(data: dict) -> str:
    """Placeholder for refresh token creation."""
    # Implement with longer expiry for token refresh
    pass
