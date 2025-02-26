from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import requests
from dotenv import load_dotenv
import os

# Initialize FastAPI app
app = FastAPI()
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import secrets
import requests

# Secret key for JWT (generate a secure key for production)
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# In-memory user database (replace with a real database in production)
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": pwd_context.hash("secret"),
        "disabled": False,
    }
}

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        return db[username]

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
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

async def get_current_user(token: str = Depends(oauth2_scheme)):
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

# Store conversation history for multi-turn support
conversation_history = []

@app.post("/converse")
def converse_with_ai(message: str):
    """
    API endpoint to handle multi-turn conversations with context.
    
    Args:
        message (str): The user's message for this turn.
    
    Returns:
        dict: A dictionary containing the AI's response.
    """
    # Append user's message to conversation history
    conversation_history.append({"role": "user", "content": message})
    
    # Prepare input prompt with conversation history
    input_text = "\n".join([f"{turn['role']}: {turn['content']}" for turn in conversation_history])
    input_text += "\nassistant:"

    # Configure Hugging Face API request with adjusted parameters for conversation
    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    payload = {
        "inputs": input_text,
        "parameters": {"max_length": 150, "temperature": 0.7, "top_p": 0.9}
    }
    try:
        response = requests.post(
            "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3",
            headers=headers,
            json=payload
        )
        response.raise_for_status()
        generated_text = response.json()[0]["generated_text"].strip()
        # Extract the assistant's response
        assistant_response = generated_text.split("assistant:")[-1].strip()
        # Append assistant's response to conversation history
        conversation_history.append({"role": "assistant", "content": assistant_response})
        return {"response": assistant_response}
    except (requests.RequestException, IndexError, KeyError):
        return {"response": "I apologize, but I encountered an error while processing your message. Please try again."}

# Update the existing /process endpoint with better error handling
@app.get("/process")
def process_query(query: str):
    """
    API endpoint to process a user query by fetching search results and generating ideas.
    
    Args:
        query (str): The query string provided by the user.
    
    Returns:
        dict: A dictionary containing the processed result.
    """
    search_results = get_search_results(query)
    if not search_results:
        return {"result": "No search results found for your query."}
    
    processed_result = process_with_hf(search_results, query)
    if processed_result == "Failed to generate ideas due to an API error.":
        return {"result": "Failed to generate ideas due to an API error. Please try again later."}
    return {"result": processed_result}

# Updated /converse endpoint with authentication
@app.post("/converse")
def converse_with_ai(message: str, current_user: dict = Depends(get_current_user)):
    conversation_history.append({"role": "user", "content": message})
    input_text = "\n".join([f"{turn['role']}: {turn['content']}" for turn in conversation_history])
    input_text += "\nassistant:"

    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    payload = {
        "inputs": input_text,
        "parameters": {"max_length": 150, "temperature": 0.7, "top_p": 0.9}
    }
    try:
        response = requests.post(
            "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3",
            headers=headers,
            json=payload
        )
        response.raise_for_status()
        generated_text = response.json()[0]["generated_text"].strip()
        assistant_response = generated_text.split("assistant:")[-1].strip()
        conversation_history.append({"role": "assistant", "content": assistant_response})
        return {"response": assistant_response}
    except (requests.RequestException, IndexError, KeyError):
        return {"response": "I apologize, but I encountered an error. Please try again."}

# Enable CORS to allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Adjust this for your frontend URL
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load environment variables from .env file
load_dotenv()
SERP_API_KEY = os.getenv('SERP_API_KEY')
HF_TOKEN = os.getenv('HF_TOKEN')

def get_search_results(query: str):
    """
    Fetch search results from SerpAPI based on the user's query.
    
    Args:
        query (str): The search query string.
    
    Returns:
        list: A list of search result dictionaries or an empty list if the request fails.
    """
    params = {
        "q": query,
        "api_key": SERP_API_KEY
    }
    try:
        response = requests.get("https://serpapi.com/search", params=params)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json().get("organic_results", [])
    except requests.RequestException:
        return []

def process_with_hf(search_results: list, query: str):
    """
    Process search results using the Hugging Face Inference API to generate brainstorming ideas.
    
    Args:
        search_results (list): List of search result dictionaries.
        query (str): The original user query.
    
    Returns:
        str: The generated brainstorming text or an error message.
    """
    # Prepare input prompt for the model
    input_text = f"Based on the following search results, generate some ideas or suggestions for '{query}':\n\n"
    input_text += "\n".join([f"{result['title']}: {result['snippet']}" for result in search_results[:3]])

    # Configure Hugging Face API request
    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    payload = {
        "inputs": input_text,
        "parameters": {"max_length": 100}
    }
    try:
        response = requests.post(
            "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3",
            headers=headers,
            json=payload
        )
        response.raise_for_status()
        return response.json()[0]["generated_text"]
    except (requests.RequestException, IndexError, KeyError):
        return "Failed to generate ideas due to an API error."

@app.get("/process")
def process_query(query: str):
    """
    API endpoint to process a user query by fetching search results and generating ideas.
    
    Args:
        query (str): The query string provided by the user.
    
    Returns:
        dict: A dictionary containing the processed result.
    """
    search_results = get_search_results(query)
    if not search_results:
        return {"result": "No search results found."}
    
    processed_result = process_with_hf(search_results, query)
    return {"result": processed_result}

# To run: uvicorn main:app --reload
