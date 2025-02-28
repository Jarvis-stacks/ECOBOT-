# backend/api_clients.py
# Manages external API integrations

import requests
from typing import List, Dict, Any
from .config import config
import logging
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger("ECOBOT.API")

class HuggingFaceClient:
    """Client for interacting with Hugging Face Inference API."""
    BASE_URL = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.3"
    
    def __init__(self, token: str = config.HF_TOKEN):
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    def get_response(self, prompt: str) -> str:
        """Fetch a response from Hugging Face."""
        if not self.token:
            logger.error("Hugging Face token missing")
            return "Configuration error: No API token"
        payload = {
            "inputs": prompt,
            "parameters": {"max_length": 200, "temperature": 0.7, "top_p": 0.9}
        }
        try:
            response = requests.post(self.BASE_URL, headers=self.headers, json=payload, timeout=15)
            response.raise_for_status()
            result = response.json()[0]["generated_text"]
            logger.info("Hugging Face response retrieved")
            return result
        except Exception as e:
            logger.error(f"Hugging Face API error: {e}")
            raise

class SerpAPIClient:
    """Client for SerpAPI web search."""
    BASE_URL = "https://serpapi.com/search"
    
    def __init__(self, api_key: str = config.SERP_API_KEY):
        self.api_key = api_key
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    def search(self, query: str) -> List[Dict[str, Any]]:
        """Perform a web search."""
        if not self.api_key:
            logger.error("SerpAPI key missing")
            return []
        params = {"q": query, "api_key": self.api_key, "num": 5}
        try:
            response = requests.get(self.BASE_URL, params=params, timeout=10)
            response.raise_for_status()
            results = response.json().get("organic_results", [])
            logger.info(f"SerpAPI search completed: {query}")
            return results
        except Exception as e:
            logger.error(f"SerpAPI error: {e}")
            raise

class GrokClient:
    """Placeholder client for future Grok API integration."""
    BASE_URL = "https://api.grok.ai/v1/chat"  # Hypothetical
    
    def __init__(self, token: str = config.GROK_API_TOKEN):
        self.token = token
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def get_response(self, prompt: str) -> str:
        """Placeholder for Grok response."""
        if not self.token:
            return "Grok API not configured"
        # Future implementation
        logger.info("Grok API placeholder called")
        return "Grok integration pending"

# Instances for use
hf_client = HuggingFaceClient()
serp_client = SerpAPIClient()
grok_client = GrokClient()
