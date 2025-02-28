# ECOBOT Backend - A comprehensive, AI-powered chatbot backend
# Built with FastAPI, this backend supports authentication, conversations,
# web search, brainstorming, and more, with rate limiting and error handling.

# --- Imports ---
from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import secrets
import requests
import json
import os
import time
import logging
import sqlite3
from typing import List, Dict, Optional, Union, Any
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv
from enum import Enum
from threading import Lock
from collections import defaultdict
import re
import hashlib
import uuid

# --- Initial Setup ---

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ecobot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ECOBOT")

# Initialize FastAPI app
app = FastAPI(
    title="ECOBOT Backend",
    description="A feature-rich, scalable backend for an AI-powered chatbot.",
    version="1.0.0"
)

# Add CORS middleware for frontend compatibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "*"],  # Adjust for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Rate Limiting Setup ---
limiter = Limiter(key_func=get_remote_address, default_limits=["100/hour"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- Configuration Constants ---
SECRET_KEY = secrets.token_urlsafe(32)  # Secure key for JWT
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
SESSION_TIMEOUT_SECONDS = 3600  # 1 hour session timeout
MAX_MESSAGE_LENGTH = 1000  # Maximum characters per message
MAX_HISTORY_ITEMS = 50  # Maximum history items per user

# API Keys from environment
HF_TOKEN = os.getenv("HF_TOKEN", "")
SERP_API_KEY = os.getenv("SERP_API_KEY", "")
GROK_API_TOKEN = os.getenv("GROK_API_TOKEN", "")  # Placeholder for future use

# Rate Limit Definitions
RATE_LIMIT_LOGIN = "10/minute"
RATE_LIMIT_CONVERSE = "50/hour"
RATE_LIMIT_BRAINSTORM = "20/hour"
RATE_LIMIT_THINK = "15/hour"
RATE_LIMIT_SEARCH = "25/hour"
RATE_LIMIT_HISTORY = "30/hour"
RATE_LIMIT_PROFILE = "50/hour"
RATE_LIMIT_HEALTH = "100/hour"
RATE_LIMIT_DEFAULT = "200/hour"

# --- Database Setup ---
DATABASE_URL = "sqlite:///./eco_bot.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    disabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

class Conversation(Base):
    __tablename__ = "conversations"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    role = Column(String, nullable=False)  # 'user', 'assistant', 'system'
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    metadata = Column(String, nullable=True)  # JSON string for extra info

class Session(Base):
    __tablename__ = "sessions"
    id = Column(String, primary_key=True, index=True)  # UUID
    user_id = Column(Integer, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow)

# Create tables
Base.metadata.create_all(bind=engine)

# --- Dependency Injection ---
def get_db():
    """Provide a database session."""
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Database session failure")
    finally:
        db.close()

# --- Authentication Setup ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- In-memory caches for performance ---
user_sessions = defaultdict(dict)  # {user_id: {session_id: session_data}}
rate_limit_lock = Lock()  # Thread safety for rate limiting

# --- Helper Functions ---

def hash_string(value: str) -> str:
    """Generate a hash for a given string."""
    return hashlib.sha256(value.encode()).hexdigest()

def sanitize_input(text: str) -> str:
    """Remove potentially harmful characters from input."""
    return re.sub(r'[<>;]', '', text.strip())

def validate_email(email: str) -> bool:
    """Basic email validation."""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

def generate_session_id() -> str:
    """Generate a unique session ID."""
    return str(uuid.uuid4())

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed one."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Password verification failed: {e}")
        return False

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Retrieve a user by username from the database."""
    try:
        return db.query(User).filter(User.username == username).first()
    except Exception as e:
        logger.error(f"Error fetching user {username}: {e}")
        return None

def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Authenticate a user with username and password."""
    user = get_user_by_username(db, username)
    if not user:
        logger.warning(f"Authentication failed - User not found: {username}")
        return None
    if not verify_password(password, user.hashed_password):
        logger.warning(f"Authentication failed - Invalid password for {username}")
        return None
    if user.disabled:
        logger.warning(f"Authentication failed - User disabled: {username}")
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"Token creation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create access token")

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Dependency to get the current authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            logger.warning("Token missing username/sub claim")
            raise credentials_exception
    except JWTError as e:
        logger.warning(f"JWT decode error: {e}")
        raise credentials_exception
    user = get_user_by_username(db, username)
    if not user:
        logger.warning(f"User not found for token: {username}")
        raise credentials_exception
    return user

def create_session(db: Session, user: User) -> Session:
    """Create a new session for a user."""
    try:
        session_id = generate_session_id()
        expires_at = datetime.utcnow() + timedelta(seconds=SESSION_TIMEOUT_SECONDS)
        session = Session(
            id=session_id,
            user_id=user.id,
            expires_at=expires_at
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        logger.info(f"Session created for user {user.username}: {session_id}")
        return session
    except Exception as e:
        logger.error(f"Session creation error for {user.username}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create session")

def get_session(db: Session, session_id: str) -> Optional[Session]:
    """Retrieve a session by ID."""
    try:
        session = db.query(Session).filter(Session.id == session_id).first()
        if session and session.expires_at < datetime.utcnow():
            db.delete(session)
            db.commit()
            logger.info(f"Expired session deleted: {session_id}")
            return None
        return session
    except Exception as e:
        logger.error(f"Session retrieval error: {e}")
        return None

# --- API Integration Functions ---

def get_huggingface_response(prompt: str) -> str:
    """Fetch a response from Hugging Face API."""
    if not HF_TOKEN:
        logger.error("Hugging Face API token not set")
        return "Configuration error: Hugging Face API token missing"
    url = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3"
    headers = {
        "Authorization": f"Bearer {HF_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "inputs": prompt,
        "parameters": {
            "max_length": 200,
            "temperature": 0.7,
            "top_p": 0.9,
            "do_sample": True,
            "return_full_text": False
        }
    }
    try:
        start_time = time.time()
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, list) or not result:
            logger.error("Invalid response format from Hugging Face")
            return "Error: Invalid response from AI service"
        generated_text = result[0].get("generated_text", "").strip()
        if not generated_text:
            logger.warning("Empty response from Hugging Face")
            return "No response generated"
        elapsed = time.time() - start_time
        logger.info(f"Hugging Face response generated in {elapsed:.2f}s")
        return generated_text
    except requests.Timeout:
        logger.error("Hugging Face API request timed out")
        return "Error: AI service timed out"
    except requests.RequestException as e:
        logger.error(f"Hugging Face API error: {e}")
        return f"Error: AI service request failed - {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error in Hugging Face call: {e}")
        return "Error: Unexpected issue with AI service"

def get_serpapi_results(query: str) -> List[Dict]:
    """Fetch web search results from SerpAPI."""
    if not SERP_API_KEY:
        logger.error("SerpAPI key not set")
        return []
    url = "https://serpapi.com/search"
    params = {
        "q": sanitize_input(query),
        "api_key": SERP_API_KEY,
        "num": 5,
        "output": "json"
    }
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        results = data.get("organic_results", [])
        if not results:
            logger.info(f"No search results for query: {query}")
            return []
        logger.info(f"Retrieved {len(results)} search results for: {query}")
        return results
    except requests.Timeout:
        logger.error(f"SerpAPI timeout for query: {query}")
        return []
    except requests.RequestException as e:
        logger.error(f"SerpAPI error: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected SerpAPI error: {e}")
        return []

def get_grok_response(prompt: str) -> str:
    """Placeholder for Grok API integration (future)."""
    if not GROK_API_TOKEN:
        return "Grok API not configured (placeholder)"
    # Example implementation (uncomment when ready)
    # url = "https://api.grok.ai/v1/chat"
    # headers = {"Authorization": f"Bearer {GROK_API_TOKEN}"}
    # payload = {"prompt": prompt}
    # try:
    #     response = requests.post(url, headers=headers, json=payload, timeout=10)
    #     response.raise_for_status()
    #     return response.json().get("response", "No response from Grok")
    # except Exception as e:
    #     logger.error(f"Grok API error: {e}")
    #     return f"Error contacting Grok: {str(e)}"
    return "Grok integration not yet implemented"

# --- Utility Functions ---

def format_conversation_history(history: List[Conversation]) -> str:
    """Format conversation history into a prompt string."""
    return "\n".join([f"{msg.role}: {msg.content}" for msg in history]) + "\nassistant:"

def truncate_text(text: str, max_length: int = MAX_MESSAGE_LENGTH) -> str:
    """Truncate text to a maximum length."""
    if len(text) <= max_length:
        return text
    truncated = text[:max_length - 3] + "..."
    logger.info(f"Text truncated from {len(text)} to {max_length} characters")
    return truncated

def save_conversation(db: Session, user_id: int, role: str, content: str, metadata: Optional[str] = None) -> Conversation:
    """Save a conversation entry to the database."""
    try:
        conversation = Conversation(
            user_id=user_id,
            role=role,
            content=truncate_text(sanitize_input(content)),
            metadata=metadata
        )
        db.add(conversation)
        db.commit()
        db.refresh(conversation)
        return conversation
    except Exception as e:
        logger.error(f"Failed to save conversation: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to save conversation")

def cleanup_old_sessions(db: Session):
    """Background task to remove expired sessions."""
    try:
        expired = db.query(Session).filter(Session.expires_at < datetime.utcnow()).all()
        for session in expired:
            db.delete(session)
        db.commit()
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")
    except Exception as e:
        logger.error(f"Session cleanup error: {e}")
        db.rollback()

# --- API Endpoints ---

@app.on_event("startup")
def startup_event():
    """Initialize the application."""
    logger.info("ECOBOT Backend starting up...")
    with SessionLocal() as db:
        # Seed initial users if database is empty
        if not db.query(User).first():
            initial_users = [
                User(
                    username="johndoe",
                    email="johndoe@example.com",
                    full_name="John Doe",
                    hashed_password=pwd_context.hash("secret"),
                    disabled=False
                ),
                User(
                    username="janedoe",
                    email="janedoe@example.com",
                    full_name="Jane Doe",
                    hashed_password=pwd_context.hash("password123"),
                    disabled=False
                )
            ]
            db.add_all(initial_users)
            db.commit()
            logger.info("Seeded initial users into database")

@app.on_event("shutdown")
def shutdown_event():
    """Clean up on shutdown."""
    logger.info("ECOBOT Backend shutting down...")

@app.post("/token", summary="Login to obtain a JWT token")
@limiter.limit(RATE_LIMIT_LOGIN)
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Authenticate a user and return a JWT token with session."""
    try:
        user = authenticate_user(db, form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        session = create_session(db, user)
        user.last_login = datetime.utcnow()
        db.commit()
        background_tasks.add_task(cleanup_old_sessions, db)
        logger.info(f"User {user.username} logged in with session {session.id}")
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "session_id": session.id
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error during login")

@app.post("/register", summary="Register a new user")
@limiter.limit("5/hour")  # Prevent excessive registrations
async def register_user(
    request: Request,
    username: str,
    email: str,
    password: str,
    full_name: str,
    db: Session = Depends(get_db)
):
    """Register a new user account."""
    try:
        if not all([username, email, password, full_name]):
            raise HTTPException(status_code=400, detail="All fields are required")
        if not validate_email(email):
            raise HTTPException(status_code=400, detail="Invalid email format")
        if len(password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
        if db.query(User).filter(User.username == username).first():
            raise HTTPException(status_code=409, detail="Username already exists")
        if db.query(User).filter(User.email == email).first():
            raise HTTPException(status_code=409, detail="Email already registered")
        
        hashed_password = pwd_context.hash(password)
        user = User(
            username=sanitize_input(username),
            email=sanitize_input(email),
            full_name=sanitize_input(full_name),
            hashed_password=hashed_password,
            disabled=False
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info(f"New user registered: {username}")
        return {"message": f"User {username} registered successfully", "user_id": user.id}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Registration error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Unexpected error during registration")

@app.post("/converse", summary="Engage in a multi-turn conversation")
@limiter.limit(RATE_LIMIT_CONVERSE)
async def converse_with_ai(
    request: Request,
    message: str,
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Handle a conversation turn with context."""
    try:
        if not message.strip():
            raise HTTPException(status_code=400, detail="Message cannot be empty")
        session = get_session(db, session_id)
        if not session or session.user_id != current_user.id:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        
        # Save user message
        user_msg = save_conversation(db, current_user.id, "user", message)
        
        # Fetch conversation history
        history = db.query(Conversation).filter(
            Conversation.user_id == current_user.id
        ).order_by(Conversation.timestamp.desc()).limit(MAX_HISTORY_ITEMS).all()[::-1]  # Reverse to chronological
        
        prompt = format_conversation_history(history)
        response = get_huggingface_response(prompt)
        if "Error" in response:
            raise HTTPException(status_code=502, detail=response)
        
        assistant_msg = save_conversation(db, current_user.id, "assistant", response)
        session.last_activity = datetime.utcnow()
        db.commit()
        
        logger.info(f"Conversation turn for {current_user.username}: {message[:50]}...")
        return {
            "response": response,
            "message_id": assistant_msg.id,
            "timestamp": assistant_msg.timestamp.isoformat()
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Conversation error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Unexpected error during conversation")

@app.post("/brainstorm", summary="Generate brainstorming ideas")
@limiter.limit(RATE_LIMIT_BRAINSTORM)
async def brainstorm(
    request: Request,
    query: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate creative ideas based on a query and web search."""
    try:
        if not query.strip():
            raise HTTPException(status_code=400, detail="Query cannot be empty")
        
        # Fetch search results
        search_results = get_serpapi_results(query)
        if not search_results:
            response = get_huggingface_response(
                f"Generate brainstorming ideas for '{query}' without external data."
            )
        else:
            search_summary = "\n".join(
                [f"{r['title']}: {r['snippet']}" for r in search_results[:3]]
            )
            prompt = f"Based on this info, generate creative ideas for '{query}':\n\n{search_summary}"
            response = get_huggingface_response(prompt)
        
        if "Error" in response:
            raise HTTPException(status_code=502, detail=response)
        
        metadata = json.dumps({"query": query, "search_used": bool(search_results)})
        save_conversation(db, current_user.id, "system", f"Brainstorm request: {query}", metadata)
        save_conversation(db, current_user.id, "assistant", response)
        
        logger.info(f"Brainstorming completed for {current_user.username}: {query}")
        return {"ideas": response}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Brainstorming error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Unexpected error during brainstorming")

@app.post("/think", summary="Generate a thoughtful response")
@limiter.limit(RATE_LIMIT_THINK)
async def think_about_topic(
    request: Request,
    topic: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Provide a detailed analysis on a topic."""
    try:
        if not topic.strip():
            raise HTTPException(status_code=400, detail="Topic cannot be empty")
        
        prompt = f"Provide a detailed, thoughtful analysis on '{topic}'. Include insights, considerations, and implications."
        response = get_huggingface_response(prompt)
        if "Error" in response:
            raise HTTPException(status_code=502, detail=response)
        
        metadata = json.dumps({"topic": topic})
        save_conversation(db, current_user.id, "system", f"Thought request: {topic}", metadata)
        save_conversation(db, current_user.id, "assistant", response)
        
        logger.info(f"Thought generated for {current_user.username}: {topic}")
        return {"thought": response}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Thinking error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Unexpected error during thinking")

@app.post("/search", summary="Search the web")
@limiter.limit(RATE_LIMIT_SEARCH)
async def search_web(
    request: Request,
    query: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Fetch web search results."""
    try:
        if not query.strip():
            raise HTTPException(status_code=400, detail="Query cannot be empty")
        
        results = get_serpapi_results(query)
        if not results:
            return {"results": [], "message": "No results found or search API unavailable"}
        
        formatted_results = [
            {"title": r["title"], "link": r["link"], "snippet": r["snippet"]}
            for r in results[:5]
        ]
        metadata = json.dumps({"query": query, "result_count": len(results)})
        save_conversation(db, current_user.id, "system", f"Search request: {query}", metadata)
        
        logger.info(f"Search completed for {current_user.username}: {query}")
        return {"results": formatted_results}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Search error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Unexpected error during search")

@app.get("/history", summary="Retrieve conversation history")
@limiter.limit(RATE_LIMIT_HISTORY)
async def get_history(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Fetch the user's conversation history."""
    try:
        history = db.query(Conversation).filter(
            Conversation.user_id == current_user.id
        ).order_by(Conversation.timestamp).all()
        
        formatted_history = [
            {
                "role": msg.role,
                "content": msg.content,
                "timestamp": msg.timestamp.isoformat(),
                "metadata": json.loads(msg.metadata) if msg.metadata else None
            }
            for msg in history
        ]
        logger.info(f"History retrieved for {current_user.username}: {len(history)} items")
        return {"history": formatted_history}
    except Exception as e:
        logger.error(f"History retrieval error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error retrieving history")

@app.get("/profile", summary="Get user profile")
@limiter.limit(RATE_LIMIT_PROFILE)
async def get_user_profile(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Retrieve the current user's profile information."""
    try:
        profile = {
            "username": current_user.username,
            "email": current_user.email,
            "full_name": current_user.full_name,
            "disabled": current_user.disabled,
            "created_at": current_user.created_at.isoformat(),
            "last_login": current_user.last_login.isoformat() if current_user.last_login else None
        }
        logger.info(f"Profile retrieved for {current_user.username}")
        return profile
    except Exception as e:
        logger.error(f"Profile retrieval error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error retrieving profile")

@app.post("/logout", summary="Log out and invalidate session")
@limiter.limit("20/hour")
async def logout(
    request: Request,
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Invalidate a user's session."""
    try:
        session = get_session(db, session_id)
        if not session or session.user_id != current_user.id:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        db.delete(session)
        db.commit()
        logger.info(f"User {current_user.username} logged out, session {session_id} invalidated")
        return {"message": "Successfully logged out"}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Logout error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Unexpected error during logout")

@app.get("/health", summary="Check backend health")
@limiter.limit(RATE_LIMIT_HEALTH)
async def health_check(request: Request, db: Session = Depends(get_db)):
    """Check the health of the backend services."""
    try:
        # Check database connectivity
        db.execute("SELECT 1")
        db_status = "OK"
        
        # Check API configurations
        hf_status = "OK" if HF_TOKEN else "Hugging Face token missing"
        serp_status = "OK" if SERP_API_KEY else "SerpAPI key missing"
        grok_status = "Not implemented" if not GROK_API_TOKEN else "OK"
        
        # Check response times (optional test call)
        start_time = time.time()
        test_response = get_huggingface_response("Test prompt")
        ai_latency = time.time() - start_time
        ai_status = "OK" if "Error" not in test_response else test_response
        
        status = "healthy" if all([
            db_status == "OK",
            hf_status == "OK",
            serp_status == "OK"
        ]) else "unhealthy"
        
        health_info = {
            "status": status,
            "database": db_status,
            "hugging_face": {"status": hf_status, "latency": f"{ai_latency:.2f}s"},
            "serp_api": serp_status,
            "grok_api": grok_status,
            "timestamp": datetime.utcnow().isoformat(),
            "uptime": f"{time.time() - app.startup_time:.2f}s" if hasattr(app, 'startup_time') else "N/A"
        }
        logger.info("Health check completed")
        return health_info
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

@app.get("/", summary="Root endpoint")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def read_root(request: Request):
    """Welcome message for the ECOBOT backend."""
    try:
        welcome_message = {
            "message": "Welcome to ECOBOT Backend - Your AI-powered assistant!",
            "version": app.version,
            "timestamp": datetime.utcnow().isoformat()
        }
        logger.info("Root endpoint accessed")
        return welcome_message
    except Exception as e:
        logger.error(f"Root endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error at root endpoint")

# --- Admin Endpoints (Restricted Access) ---

def is_admin_user(user: User) -> bool:
    """Check if a user has admin privileges."""
    # For simplicity, assume 'johndoe' is admin; extend with roles in production
    return user.username == "johndoe"

async def get_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to ensure the user is an admin."""
    if not is_admin_user(current_user):
        logger.warning(f"Unauthorized admin access attempt by {current_user.username}")
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

@app.get("/admin/users", summary="List all users (admin only)")
@limiter.limit("10/hour")
async def list_users(
    request: Request,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Retrieve a list of all registered users."""
    try:
        users = db.query(User).all()
        user_list = [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "full_name": u.full_name,
                "disabled": u.disabled,
                "created_at": u.created_at.isoformat()
            }
            for u in users
        ]
        logger.info(f"Admin {admin_user.username} retrieved user list")
        return {"users": user_list, "count": len(user_list)}
    except Exception as e:
        logger.error(f"User list retrieval error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error retrieving users")

@app.post("/admin/disable_user", summary="Disable a user (admin only)")
@limiter.limit("5/hour")
async def disable_user(
    request: Request,
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Disable a user account."""
    try:
        target_user = db.query(User).filter(User.id == user_id).first()
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")
        if target_user.username == admin_user.username:
            raise HTTPException(status_code=400, detail="Cannot disable self")
        target_user.disabled = True
        db.commit()
        logger.info(f"Admin {admin_user.username} disabled user {target_user.username}")
        return {"message": f"User {target_user.username} disabled successfully"}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"User disable error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Unexpected error disabling user")

# --- Background Tasks ---

def log_system_metrics():
    """Log system metrics periodically (e.g., memory usage)."""
    try:
        import psutil
        process = psutil.Process(os.getpid())
        memory = process.memory_info().rss / 1024 / 1024  # MB
        logger.info(f"System metrics - Memory usage: {memory:.2f} MB")
    except ImportError:
        logger.warning("psutil not installed; system metrics unavailable")
    except Exception as e:
        logger.error(f"Error logging system metrics: {e}")

@app.post("/schedule_metrics", summary="Schedule a metrics log")
@limiter.limit("10/hour")
async def schedule_metrics(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """Schedule a background task to log system metrics."""
    background_tasks.add_task(log_system_metrics)
    logger.info(f"Metrics logging scheduled by {current_user.username}")
    return {"message": "Metrics logging scheduled"}

# --- Custom Error Handlers ---

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    """Custom handler for HTTP exceptions."""
    logger.error(f"HTTP error: {exc.status_code} - {exc.detail}")
    return {
        "status_code": exc.status_code,
        "detail": exc.detail,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.exception_handler(Exception)
async def custom_general_exception_handler(request: Request, exc: Exception):
    """Custom handler for uncaught exceptions."""
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return {
        "status_code": 500,
        "detail": "An unexpected error occurred",
        "timestamp": datetime.utcnow().isoformat()
    }

# --- Startup Time Tracking ---
app.startup_time = time.time()

# --- Main Execution ---
if __name__ == "__main__":
    import uvicorn
    logger.info("Starting ECOBOT backend server...")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

# --- Additional Utility Functions (for future expansion) ---

def validate_session_timeout(session: Session) -> bool:
    """Check if a session has timed out based on last activity."""
    try:
        timeout = timedelta(seconds=SESSION_TIMEOUT_SECONDS)
        return (datetime.utcnow() - session.last_activity) < timeout
    except Exception as e:
        logger.error(f"Session timeout validation error: {e}")
        return False

def refresh_session(db: Session, session: Session) -> Session:
    """Refresh a session’s expiration time."""
    try:
        session.expires_at = datetime.utcnow() + timedelta(seconds=SESSION_TIMEOUT_SECONDS)
        session.last_activity = datetime.utcnow()
        db.commit()
        db.refresh(session)
        logger.info(f"Session refreshed: {session.id}")
        return session
    except Exception as e:
        logger.error(f"Session refresh error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to refresh session")

def archive_conversation(db: Session, user_id: int) -> bool:
    """Archive old conversations for a user."""
    try:
        old_threshold = datetime.utcnow() - timedelta(days=30)  # Archive after 30 days
        old_convos = db.query(Conversation).filter(
            Conversation.user_id == user_id,
            Conversation.timestamp < old_threshold
        ).all()
        for convo in old_convos:
            convo.content = f"[ARCHIVED] {convo.content}"
        db.commit()
        logger.info(f"Archived {len(old_convos)} conversations for user {user_id}")
        return True
    except Exception as e:
        logger.error(f"Conversation archive error: {e}")
        db.rollback()
        return False

def export_user_data(db: Session, user_id: int) -> Dict[str, Any]:
    """Export all user data for GDPR compliance or backup."""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"error": "User not found"}
        conversations = db.query(Conversation).filter(Conversation.user_id == user_id).all()
        sessions = db.query(Session).filter(Session.user_id == user_id).all()
        data = {
            "user": {
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "created_at": user.created_at.isoformat()
            },
            "conversations": [
                {"role": c.role, "content": c.content, "timestamp": c.timestamp.isoformat()}
                for c in conversations
            ],
            "sessions": [
                {"id": s.id, "created_at": s.created_at.isoformat(), "expires_at": s.expires_at.isoformat()}
                for s in sessions
            ]
        }
        logger.info(f"Exported data for user {user_id}")
        return data
    except Exception as e:
        logger.error(f"Data export error: {e}")
        return {"error": str(e)}

# --- Extended Admin Functions ---

def get_user_stats(db: Session, user_id: int) -> Dict[str, Any]:
    """Get detailed statistics for a user."""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"error": "User not found"}
        convo_count = db.query(Conversation).filter(Conversation.user_id == user_id).count()
        active_sessions = db.query(Session).filter(
            Session.user_id == user_id,
            Session.expires_at > datetime.utcnow()
        ).count()
        stats = {
            "username": user.username,
            "conversation_count": convo_count,
            "active_sessions": active_sessions,
            "last_login": user.last_login.isoformat() if user.last_login else "Never"
        }
        logger.info(f"Stats retrieved for user {user_id}")
        return stats
    except Exception as e:
        logger.error(f"User stats error: {e}")
        return {"error": str(e)}

# --- Placeholder for Additional Features ---

def process_image_url(url: str) -> str:
    """Placeholder for future image processing (e.g., OCR or analysis)."""
    logger.info(f"Image processing placeholder called with URL: {url}")
    return "Image processing not yet implemented"

def analyze_sentiment(text: str) -> Dict[str, float]:
    """Placeholder for sentiment analysis integration."""
    logger.info(f"Sentiment analysis placeholder called for text: {text[:50]}...")
    return {"positive": 0.5, "negative": 0.3, "neutral": 0.2}

# --- Extended Endpoints for Future Use ---

@app.post("/upload_image", summary="Upload an image for processing (future)")
@limiter.limit("10/hour")
async def upload_image(
    request: Request,
    image_url: str,
    current_user: User = Depends(get_current_user)
):
    """Process an image URL (placeholder for future feature)."""
    try:
        if not image_url.startswith("http"):
            raise HTTPException(status_code=400, detail="Invalid image URL")
        response = process_image_url(image_url)
        logger.info(f"Image upload processed for {current_user.username}: {image_url}")
        return {"result": response}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Image upload error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error processing image")

@app.post("/analyze_text", summary="Analyze text sentiment (future)")
@limiter.limit("20/hour")
async def analyze_text(
    request: Request,
    text: str,
    current_user: User = Depends(get_current_user)
):
    """Analyze the sentiment of text (placeholder for future feature)."""
    try:
        if not text.strip():
            raise HTTPException(status_code=400, detail="Text cannot be empty")
        sentiment = analyze_sentiment(text)
        logger.info(f"Text analysis completed for {current_user.username}")
        return {"sentiment": sentiment}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Text analysis error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error analyzing text")

# --- End of File ---
# This backend is designed to be fully functional and extensible.
# Add more endpoints or integrations as needed below this line.

