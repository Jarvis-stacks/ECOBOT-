# backend/setup.py
# Manages initial setup and seeding

from sqlalchemy.orm import Session
from .database import SessionLocal, init_db
from .models import User
from passlib.context import CryptContext
import logging

logger = logging.getLogger("ECOBOT.Setup")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def seed_users(db: Session):
    """Seed initial users into the database."""
    initial_users = [
        {
            "username": "johndoe",
            "email": "johndoe@example.com",
            "full_name": "John Doe",
            "password": "secret"
        },
        {
            "username": "janedoe",
            "email": "janedoe@example.com",
            "full_name": "Jane Doe",
            "password": "password123"
        }
    ]
    try:
        for user_data in initial_users:
            if not db.query(User).filter(User.username == user_data["username"]).first():
                hashed_password = pwd_context.hash(user_data["password"])
                user = User(
                    username=user_data["username"],
                    email=user_data["email"],
                    full_name=user_data["full_name"],
                    hashed_password=hashed_password,
                    disabled=False
                )
                db.add(user)
        db.commit()
        logger.info("Initial users seeded successfully")
    except Exception as e:
        logger.error(f"Seeding error: {e}")
        db.rollback()

def setup():
    """Perform initial setup."""
    db = SessionLocal()
    try:
        init_db()
        seed_users(db)
    finally:
        db.close()

if __name__ == "__main__":
    setup()

# Future: Add role seeding or configuration import
