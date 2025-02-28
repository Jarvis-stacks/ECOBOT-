# backend/services.py
# Contains business logic for ECOBOT features

from sqlalchemy.orm import Session
from .models import Conversation, User
from .api_clients import hf_client, serp_client
from .utils import sanitize_input, truncate_text
import logging
import json

logger = logging.getLogger("ECOBOT.Services")

class ChatService:
    """Service for conversation-related operations."""
    def __init__(self, db: Session):
        self.db = db
    
    def save_message(self, user_id: int, role: str, content: str, metadata: dict = None) -> Conversation:
        """Save a message to the conversation history."""
        try:
            conversation = Conversation(
                user_id=user_id,
                role=role,
                content=truncate_text(sanitize_input(content)),
                metadata=json.dumps(metadata) if metadata else None
            )
            self.db.add(conversation)
            self.db.commit()
            self.db.refresh(conversation)
            return conversation
        except Exception as e:
            logger.error(f"Save message error: {e}")
            self.db.rollback()
            raise
    
    def get_conversation_history(self, user_id: int, limit: int = 50) -> List[Conversation]:
        """Retrieve conversation history for a user."""
        return self.db.query(Conversation).filter(
            Conversation.user_id == user_id
        ).order_by(Conversation.timestamp.desc()).limit(limit).all()[::-1]
    
    def process_conversation(self, user_id: int, message: str, session_id: str) -> str:
        """Process a conversation turn."""
        self.save_message(user_id, "user", message, {"session_id": session_id})
        history = self.get_conversation_history(user_id)
        prompt = "\n".join([f"{msg.role}: {msg.content}" for msg in history]) + "\nassistant:"
        response = hf_client.get_response(prompt)
        self.save_message(user_id, "assistant", response)
        return response

class BrainstormService:
    """Service for brainstorming feature."""
    def __init__(self, db: Session):
        self.db = db
    
    def generate_ideas(self, user_id: int, query: str) -> str:
        """Generate brainstorming ideas."""
        search_results = serp_client.search(query)
        if not search_results:
            prompt = f"Generate brainstorming ideas for '{query}' without external data."
        else:
            summary = "\n".join([f"{r['title']}: {r['snippet']}" for r in search_results[:3]])
            prompt = f"Based on this info, generate creative ideas for '{query}':\n\n{summary}"
        response = hf_client.get_response(prompt)
        self.db.add(Conversation(
            user_id=user_id,
            role="system",
            content=f"Brainstorm request: {query}",
            metadata=json.dumps({"query": query, "search_used": bool(search_results)})
        ))
        self.db.add(Conversation(user_id=user_id, role="assistant", content=response))
        self.db.commit()
        return response

class ThinkService:
    """Service for thoughtful analysis."""
    def __init__(self, db: Session):
        self.db = db
    
    def analyze_topic(self, user_id: int, topic: str) -> str:
        """Provide a thoughtful analysis."""
        prompt = f"Provide a detailed analysis on '{topic}'. Include insights and implications."
        response = hf_client.get_response(prompt)
        self.db.add(Conversation(
            user_id=user_id,
            role="system",
            content=f"Thought request: {topic}",
            metadata=json.dumps({"topic": topic})
        ))
        self.db.add(Conversation(user_id=user_id, role="assistant", content=response))
        self.db.commit()
        return response

# Future: Add more services (e.g., SentimentService, ImageService)
