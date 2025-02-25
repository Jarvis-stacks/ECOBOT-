from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import requests
from dotenv import load_dotenv
import os

# Initialize FastAPI app
app = FastAPI()

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
