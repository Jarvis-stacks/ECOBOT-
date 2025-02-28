# backend/analytics.py
# Tracks usage metrics and analytics

from sqlalchemy.orm import Session
from .models import Conversation, User, Log
from datetime import datetime, timedelta
import logging

logger = logging.getLogger("ECOBOT.Analytics")

class AnalyticsService:
    """Service for tracking and retrieving analytics."""
    def __init__(self, db: Session):
        self.db = db
    
    def log_action(self, user_id: int, action: str, details: str = None):
        """Log a user action."""
        try:
            log_entry = Log(user_id=user_id, action=action, details=details)
            self.db.add(log_entry)
            self.db.commit()
        except Exception as e:
            logger.error(f"Log action error: {e}")
            self.db.rollback()
    
    def get_user_stats(self, user_id: int) -> dict:
        """Get usage statistics for a user."""
        try:
            convo_count = self.db.query(Conversation).filter(Conversation.user_id == user_id).count()
            logs = self.db.query(Log).filter(Log.user_id == user_id).all()
            last_week = datetime.utcnow() - timedelta(days=7)
            recent_convos = self.db.query(Conversation).filter(
                Conversation.user_id == user_id,
                Conversation.timestamp >= last_week
            ).count()
            return {
                "total_conversations": convo_count,
                "recent_conversations": recent_convos,
                "actions_logged": len(logs)
            }
        except Exception as e:
            logger.error(f"User stats error: {e}")
            return {"error": str(e)}

    def get_system_stats(self) -> dict:
        """Get system-wide statistics."""
        try:
            user_count = self.db.query(User).count()
            convo_count = self.db.query(Conversation).count()
            return {
                "total_users": user_count,
                "total_conversations": convo_count
            }
        except Exception as e:
            logger.error(f"System stats error: {e}")
            return {"error": str(e)}

# Future: Export to CSV or integrate with analytics platform
