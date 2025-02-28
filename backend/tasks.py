# backend/tasks.py
# Manages background tasks and scheduled jobs

from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import Session as SessionModel
from datetime import datetime, timedelta
import logging

logger = logging.getLogger("ECOBOT.Tasks")

def cleanup_old_sessions():
    """Remove expired sessions from the database."""
    db = SessionLocal()
    try:
        expired = db.query(SessionModel).filter(SessionModel.expires_at < datetime.utcnow()).all()
        for session in expired:
            db.delete(session)
        db.commit()
        logger.info(f"Cleaned up {len(expired)} expired sessions")
    except Exception as e:
        logger.error(f"Session cleanup error: {e}")
        db.rollback()
    finally:
        db.close()

def archive_conversations():
    """Archive old conversations."""
    db = SessionLocal()
    try:
        threshold = datetime.utcnow() - timedelta(days=30)
        old_convos = db.query(Conversation).filter(Conversation.timestamp < threshold).all()
        for convo in old_convos:
            convo.content = f"[ARCHIVED] {convo.content}"
        db.commit()
        logger.info(f"Archived {len(old_convos)} conversations")
    except Exception as e:
        logger.error(f"Conversation archive error: {e}")
        db.rollback()
    finally:
        db.close()

# Future: Integrate with Celery for task queuing
# from celery import Celery
# celery_app = Celery('ecobot', broker='redis://localhost:6379/0')
# @celery_app.task
# def async_task_example():
#     logger.info("Example async task executed")
