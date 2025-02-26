from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import secrets
import requests
from typing import List, Dict, Optional
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
from dotenv import load_dotenv
import logging
import time

# Load environment variables from .env file
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ECOBOT")

# Initialize FastAPI app
app = FastAPI(title="ECOBOT Backend", description="A scalable backend with rate limiting for an AI-powered chatbot.")

# --- Rate Limiting Setup ---
limiter = Limiter(key_func=get_remote_address, default_limits=["100/hour"])  # Default: 100 requests per hour per IP
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- Configuration ---
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# API Keys
HF_TOKEN = os.getenv("HF_TOKEN")
SERP_API_KEY = os.getenv("SERP_API_KEY")

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- In-memory user database ---
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": pwd_context.hash("secret"),
        "disabled": False,
    },
    "janedoe": {
        "username": "janedoe",
        "full_name": "Jane Doe",
        "email": "janedoe@example.com",
        "hashed_password": pwd_context.hash("password123"),
        "disabled": False,
    }
}

# --- Database Setup ---
DATABASE_URL = "sqlite:///./eco_bot.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Conversation(Base):
    __tablename__ = "conversations"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    role = Column(String)
    content = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Helper Functions ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during password verification")

def get_user(db: dict, username: str) -> Optional[dict]:
    try:
        return db.get(username)
    except Exception as e:
        logger.error(f"User retrieval error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error retrieving user")

def authenticate_user(fake_db: dict, username: str, password: str) -> Optional[dict]:
    try:
        user = get_user(fake_db, username)
        if not user:
            logger.warning(f"User not found: {username}")
            return None
        if not verify_password(password, user["hashed_password"]):
            logger.warning(f"Invalid password for user: {username}")
            return None
        return user
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during authentication")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    except Exception as e:
        logger.error(f"Token creation error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error creating access token")

# --- Authentication Endpoints ---
@app.post("/token", summary="Login to get an access token")
@limiter.limit("10/minute")  # 10 login attempts per minute per IP
def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        user = authenticate_user(fake_users_db, form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["username"]}, expires_delta=access_token_expires
        )
        logger.info(f"User {user['username']} logged in successfully")
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error during login")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            logger.warning("Token missing username")
            raise credentials_exception
    except JWTError as e:
        logger.warning(f"JWT decode error: {e}")
        raise credentials_exception
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error validating token")
    user = get_user(fake_users_db, username)
    if user is None:
        logger.warning(f"User not found for token: {username}")
        raise credentials_exception
    if user["disabled"]:
        logger.warning(f"Disabled user attempted access: {username}")
        raise HTTPException(status_code=403, detail="User account is disabled")
    return user

# --- Web Search Functionality ---
def get_search_results(query: str) -> List[Dict]:
    if not SERP_API_KEY:
        logger.error("SerpAPI key not configured")
        return []
    params = {
        "q": query,
        "api_key": SERP_API_KEY,
        "num": 5
    }
    try:
        response = requests.get("https://serpapi.com/search", params=params, timeout=10)
        response.raise_for_status()
        results = response.json().get("organic_results", [])
        logger.info(f"Search successful for query: {query}")
        return results
    except requests.Timeout:
        logger.error(f"Search timeout for query: {query}")
        return []
    except requests.RequestException as e:
        logger.error(f"Search error for query {query}: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected search error: {e}")
        return []

# --- AI Response Functionality ---
def get_ai_response(prompt: str) -> str:
    if not HF_TOKEN:
        logger.error("Hugging Face API token not configured")
        return "Hugging Face API token not configured."
    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    payload = {
        "inputs": prompt,
        "parameters": {
            "max_length": 200,
            "temperature": 0.7,
            "top_p": 0.9,
            "do_sample": True
        }
    }
    try:
        start_time = time.time()
        response = requests.post(
            "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3",
            headers=headers,
            json=payload,
            timeout=15
        )
        response.raise_for_status()
        elapsed_time = time.time() - start_time
        text = response.json()[0]["generated_text"]
        logger.info(f"AI response generated in {elapsed_time:.2f}s")
        return text
    except requests.Timeout:
        logger.error("AI request timed out")
        return "AI request timed out."
    except requests.RequestException as e:
        logger.error(f"AI request error: {e}")
        return f"AI response error: {str(e)}"
    except (IndexError, KeyError) as e:
        logger.error(f"AI response parsing error: {e}")
        return "Error parsing AI response."
    except Exception as e:
        logger.error(f"Unexpected AI error: {e}")
        return "Unexpected error contacting AI service."

# --- Brainstorming Endpoint ---
@app.post("/brainstorm", summary="Generate brainstorming ideas")
@limiter.limit("20/hour")  # 20 brainstorming requests per hour per IP
def brainstorm(request: Request, query: str, current_user: dict = Depends(get_current_user)):
    try:
        if not query.strip():
            logger.warning("Empty query received for brainstorming")
            raise HTTPException(status_code=400, detail="Query cannot be empty")
        search_results = get_search_results(query)
        if not search_results:
            return {"ideas": "No search results found to base ideas on."}
        search_summary = "\n".join([f"{result['title']}: {result['snippet']}" for result in search_results[:3]])
        prompt = f"Based on the following information, generate creative brainstorming ideas for '{query}':\n\n{search_summary}"
        ideas = get_ai_response(prompt)
        logger.info(f"Brainstorming completed for user {current_user['username']}")
        return {"ideas": ideas}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Brainstorming error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error during brainstorming")

# --- Conversation Endpoint ---
@app.post("/converse", summary="Engage in multi-turn conversation")
@limiter.limit("50/hour")  # 50 messages per hour per IP
def converse_with_ai(request: Request, message: str, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        if not message.strip():
            logger.warning("Empty message received for conversation")
            raise HTTPException(status_code=400, detail="Message cannot be empty")
        user_message = Conversation(username=current_user["username"], role="user", content=message)
        db.add(user_message)
        db.commit()
        history = db.query(Conversation).filter(Conversation.username == current_user["username"]).order_by(Conversation.timestamp).all()
        input_text = "\n".join([f"{msg.role}: {msg.content}" for msg in history[-10:]]) + "\nassistant:"
        generated_text = get_ai_response(input_text).strip()
        assistant_response = generated_text.split("assistant:")[-1].strip()
        assistant_message = Conversation(username=current_user["username"], role="assistant", content=assistant_response)
        db.add(assistant_message)
        db.commit()
        logger.info(f"Conversation message processed for {current_user['username']}")
        return {"response": assistant_response}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Conversation error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Unexpected error during conversation")

# --- History Endpoint ---
@app.get("/history", summary="Retrieve conversation history")
@limiter.limit("30/hour")  # 30 history requests per hour per IP
def get_history(request: Request, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        history = db.query(Conversation).filter(Conversation.username == current_user["username"]).order_by(Conversation.timestamp).all()
        logger.info(f"History retrieved for {current_user['username']}")
        return {"history": [{"role": msg.role, "content": msg.content, "timestamp": msg.timestamp} for msg in history]}
    except Exception as e:
        logger.error(f"History retrieval error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error retrieving history")

# --- Thinking Endpoint ---
@app.post("/think", summary="Generate a thoughtful response")
@limiter.limit("15/hour")  # 15 thinking requests per hour per IP
def think_about_topic(request: Request, topic: str, current_user: dict = Depends(get_current_user)):
    try:
        if not topic.strip():
            logger.warning("Empty topic received for thinking")
            raise HTTPException(status_code=400, detail="Topic cannot be empty")
        prompt = f"Provide a detailed, thoughtful analysis or response on the topic: '{topic}'. Include insights, considerations, and potential implications."
        response = get_ai_response(prompt)
        logger.info(f"Thought generated for {current_user['username']} on topic: {topic}")
        return {"thought": response}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Thinking error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error during thinking")

# --- Web Search Endpoint ---
@app.post("/search", summary="Search the web")
@limiter.limit("25/hour")  # 25 search requests per hour per IP
def search_web(request: Request, query: str, current_user: dict = Depends(get_current_user)):
    try:
        if not query.strip():
            logger.warning("Empty query received for search")
            raise HTTPException(status_code=400, detail="Query cannot be empty")
        results = get_search_results(query)
        if not results:
            return {"results": "No results found or search API unavailable."}
        formatted_results = [{"title": r["title"], "link": r["link"], "snippet": r["snippet"]} for r in results[:5]]
        logger.info(f"Search completed for {current_user['username']}")
        return {"results": formatted_results}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Search error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error during search")

# --- User Profile Endpoint ---
@app.get("/profile", summary="Get user profile")
@limiter.limit("50/hour")  # 50 profile requests per hour per IP
def get_user_profile(request: Request, current_user: dict = Depends(get_current_user)):
    try:
        logger.info(f"Profile retrieved for {current_user['username']}")
        return {
            "username": current_user["username"],
            "full_name": current_user["full_name"],
            "email": current_user["email"],
            "disabled": current_user["disabled"]
        }
    except Exception as e:
        logger.error(f"Profile retrieval error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error retrieving profile")

# --- Health Check Endpoint ---
@app.get("/health", summary="Check backend health")
@limiter.limit("100/hour")  # 100 health checks per hour per IP
def health_check(request: Request):
    try:
        hf_status = "OK" if HF_TOKEN else "Hugging Face token missing"
        serp_status = "OK" if SERP_API_KEY else "SerpAPI key missing"
        db_status = "OK"
        try:
            with SessionLocal() as db:
                db.execute("SELECT 1")
        except Exception as e:
            db_status = f"Database error: {e}"
        logger.info("Health check completed")
        return {
            "status": "healthy" if all([hf_status == "OK", serp_status == "OK", db_status == "OK"]) else "unhealthy",
            "hugging_face_api": hf_status,
            "serp_api": serp_status,
            "database": db_status,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error during health check")

# --- Root Endpoint ---
@app.get("/", summary="Root endpoint")
@limiter.limit("200/hour")  # 200 root requests per hour per IP
def read_root(request: Request):
    try:
        logger.info("Root endpoint accessed")
        return {"message": "Welcome to ECOBOT Backend - Your AI-powered assistant!"}
    except Exception as e:
        logger.error(f"Root endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Unexpected error at root endpoint")

# --- Run the Application ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
