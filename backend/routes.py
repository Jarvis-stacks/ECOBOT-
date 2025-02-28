# backend/routes.py
# Defines API routes separately from main app

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from .auth import get_current_user, get_admin_user
from .services import ChatService, BrainstormService, ThinkService
from .database import get_db
from .models import User
from .config import config
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

chat_router = APIRouter(prefix="/chat", tags=["conversation"])
auth_router = APIRouter(prefix="/auth", tags=["authentication"])
admin_router = APIRouter(prefix="/admin", tags=["admin"])

@auth_router.post("/token")
@limiter.limit(config.RATE_LIMIT_LOGIN)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Implementation moved to main.py or auth service
    pass

@chat_router.post("/converse")
@limiter.limit(config.RATE_LIMIT_CONVERSE)
async def converse(
    request: Request,
    message: str,
    session_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    chat_service = ChatService(db)
    response = chat_service.process_conversation(user.id, message, session_id)
    return {"response": response}

@chat_router.post("/brainstorm")
@limiter.limit(config.RATE_LIMIT_BRAINSTORM)
async def brainstorm(
    request: Request,
    query: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    brainstorm_service = BrainstormService(db)
    ideas = brainstorm_service.generate_ideas(user.id, query)
    return {"ideas": ideas}

@chat_router.post("/think")
@limiter.limit(config.RATE_LIMIT_THINK)
async def think(
    request: Request,
    topic: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    think_service = ThinkService(db)
    thought = think_service.analyze_topic(user.id, topic)
    return {"thought": thought}

@admin_router.get("/users")
@limiter.limit("10/hour")
async def list_users(
    request: Request,
    admin: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    users = db.query(User).all()
    return {"users": [u.username for u in users]}

# Future: Add more routers (e.g., /search, /profile)
