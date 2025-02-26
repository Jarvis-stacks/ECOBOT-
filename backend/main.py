from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
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

# Load environment variables from .env file
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="ECOBOT Backend", description="A scalable backend for an AI-powered chatbot with web search and more.")

# --- Configuration ---
SECRET_KEY = secrets.token_urlsafe(32)  # Generate a secure key for JWT
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# API Keys (load from environment variables)
HF_TOKEN = os.getenv("HF_TOKEN")  # Hugging Face API token for AI responses
SERP_API_KEY = os.getenv("SERP_API_KEY")  # SerpAPI key for web search

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- In-memory user database (replace with a real database like PostgreSQL in production) ---
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

# --- Database Setup (SQLite for simplicity, scalable to other databases) ---
DATABASE_URL = "sqlite:///./eco_bot.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Define the Conversation table
class Conversation(Base):
    __tablename__ = "conversations"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    role = Column(String)  # 'user' or 'assistant'
    content = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

# Create the database tables
Base.metadata.create_all(bind=engine)

# Dependency to get a database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Helper Functions ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db: dict, username: str) -> Optional[dict]:
    """Retrieve a user from the database by username."""
    return db.get(username)

def authenticate_user(fake_db: dict, username: str, password: str) -> Optional[dict]:
    """Authenticate a user with username and password."""
    user = get_user(fake_db, username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- Authentication Endpoints ---
@app.post("/token", summary="Login to get an access token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate user and return a JWT token."""
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
    return {"access_token": access_token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Dependency to get the current authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username)
    if user is None:
        raise credentials_exception
    return user

# --- Web Search Functionality ---
def get_search_results(query: str) -> List[Dict]:
    """
    Fetch search results from SerpAPI.

    Args:
        query (str): The search query.

    Returns:
        list: A list of search results or empty list if failed.
    """
    if not SERP_API_KEY:
        return []
    params = {
        "q": query,
        "api_key": SERP_API_KEY,
        "num": 5  # Limit to 5 results for efficiency
    }
    try:
        response = requests.get("https://serpapi.com/search", params=params, timeout=10)
        response.raise_for_status()
        return response.json().get("organic_results", [])
    except requests.RequestException as e:
        print(f"Search error: {e}")
        return []

# --- AI Response Functionality ---
def get_ai_response(prompt: str) -> str:
    """
    Get a response from Hugging Face Inference API (Mistral-7B model).

    Args:
        prompt (str): The input prompt for the model.

    Returns:
        str: The generated response or an error message.
    """
    if not HF_TOKEN:
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
        response = requests.post(
            "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3",
            headers=headers,
            json=payload,
            timeout=15
        )
        response.raise_for_status()
        return response.json()[0]["generated_text"]
    except Exception as e:
        return f"AI response error: {str(e)}"

# --- Brainstorming Endpoint ---
@app.post("/brainstorm", summary="Generate brainstorming ideas based on a query")
def brainstorm(query: str, current_user: dict = Depends(get_current_user)):
    """
    Generate brainstorming ideas using web search results and AI.

    Args:
        query (str): The user's query for brainstorming.

    Returns:
        dict: A dictionary with brainstorming ideas.
    """
    search_results = get_search_results(query)
    if not search_results:
        return {"ideas": "No search results found to base ideas on."}

    # Summarize top 3 search results
    search_summary = "\n".join([f"{result['title']}: {result['snippet']}" for result in search_results[:3]])
    prompt = f"Based on the following information, generate creative brainstorming ideas for '{query}':\n\n{search_summary}"
    
    # Generate AI-powered ideas
    ideas = get_ai_response(prompt)
    return {"ideas": ideas}

# --- Conversation Endpoint ---
@app.post("/converse", summary="Engage in a multi-turn conversation")
def converse_with_ai(message: str, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Handle multi-turn conversations with context from history.

    Args:
        message (str): The user's message.

    Returns:
        dict: A dictionary with the AI's response.
    """
    # Save user's message to database
    user_message = Conversation(username=current_user["username"], role="user", content=message)
    db.add(user_message)
    db.commit()

    # Retrieve conversation history for context
    history = db.query(Conversation).filter(Conversation.username == current_user["username"]).order_by(Conversation.timestamp).all()
    input_text = "\n".join([f"{msg.role}: {msg.content}" for msg in history[-10:]]) + "\nassistant:"  # Limit to last 10 messages

    # Generate AI response
    try:
        generated_text = get_ai_response(input_text).strip()
        assistant_response = generated_text.split("assistant:")[-1].strip()
        
        # Save assistant's response
        assistant_message = Conversation(username=current_user["username"], role="assistant", content=assistant_response)
        db.add(assistant_message)
        db.commit()
        return {"response": assistant_response}
    except Exception as e:
        return {"response": f"Error during conversation: {str(e)}"}

# --- History Endpoint ---
@app.get("/history", summary="Retrieve conversation history")
def get_history(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Retrieve the user's conversation history.

    Returns:
        dict: A dictionary with the conversation history.
    """
    history = db.query(Conversation).filter(Conversation.username == current_user["username"]).order_by(Conversation.timestamp).all()
    return {"history": [{"role": msg.role, "content": msg.content, "timestamp": msg.timestamp} for msg in history]}

# --- Thinking Endpoint ---
@app.post("/think", summary="Generate a thoughtful response on a topic")
def think_about_topic(topic: str, current_user: dict = Depends(get_current_user)):
    """
    Provide a detailed analysis or thoughtful response on a topic.

    Args:
        topic (str): The topic to analyze or think about.

    Returns:
        dict: A dictionary with the thoughtful response.
    """
    prompt = f"Provide a detailed, thoughtful analysis or response on the topic: '{topic}'. Include insights, considerations, and potential implications."
    try:
        response = get_ai_response(prompt)
        return {"thought": response}
    except Exception as e:
        return {"thought": f"Error generating thought: {str(e)}"}

# --- Web Search Endpoint ---
@app.post("/search", summary="Search the web for information")
def search_web(query: str, current_user: dict = Depends(get_current_user)):
    """
    Fetch web search results for a given query.

    Args:
        query (str): The search query.

    Returns:
        dict: A dictionary with search results.
    """
    results = get_search_results(query)
    if not results:
        return {"results": "No results found or search API unavailable."}
    formatted_results = [{"title": r["title"], "link": r["link"], "snippet": r["snippet"]} for r in results[:5]]
    return {"results": formatted_results}

# --- User Profile Endpoint ---
@app.get("/profile", summary="Get user profile information")
def get_user_profile(current_user: dict = Depends(get_current_user)):
    """
    Retrieve the current user's profile information.

    Returns:
        dict: A dictionary with user details.
    """
    return {
        "username": current_user["username"],
        "full_name": current_user["full_name"],
        "email": current_user["email"],
        "disabled": current_user["disabled"]
    }

# --- Future API Integration Placeholder ---
# Placeholder for integrating Grok's API or a custom API
# def get_grok_response(prompt: str) -> str:
#     """Placeholder for Grok API integration."""
#     grok_api_url = "https://api.grok.ai/endpoint"  # Replace with actual URL
#     headers = {"Authorization": "Bearer YOUR_GROK_TOKEN"}
#     payload = {"text": prompt}
#     try:
#         response = requests.post(grok_api_url, headers=headers, json=payload)
#         response.raise_for_status()
#         return response.json()["response"]
#     except Exception as e:
#         return f"Grok API error: {str(e)}"

# --- Health Check Endpoint ---
@app.get("/health", summary="Check backend health")
def health_check():
    """Check if the backend is running and APIs are accessible."""
    hf_status = "OK" if HF_TOKEN else "Hugging Face token missing"
    serp_status = "OK" if SERP_API_KEY else "SerpAPI key missing"
    return {
        "status": "healthy",
        "hugging_face_api": hf_status,
        "serp_api": serp_status,
        "timestamp": datetime.utcnow().isoformat()
    }

# --- Root Endpoint ---
@app.get("/", summary="Root endpoint")
def read_root():
    """Welcome message for the ECOBOT backend."""
    return {"message": "Welcome to ECOBOT Backend - Your AI-powered assistant!"}

# --- Run the Application ---
# To run: uvicorn main:app --reload
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
