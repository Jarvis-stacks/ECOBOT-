# backend/notifications.py
# Handles user notifications

import smtplib
from email.mime.text import MIMEText
from .config import config
import logging

logger = logging.getLogger("ECOBOT.Notifications")

class NotificationService:
    """Service for sending notifications."""
    def __init__(self):
        self.enabled = config.NOTIFICATION_ENABLED
    
    def send_email(self, to_email: str, subject: str, body: str):
        """Send an email notification."""
        if not self.enabled:
            logger.info("Notifications disabled; skipping email")
            return
        try:
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = config.SMTP_USER
            msg['To'] = to_email
            
            with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
                server.starttls()
                server.login(config.SMTP_USER, config.SMTP_PASSWORD)
                server.send_message(msg)
            logger.info(f"Email sent to {to_email}: {subject}")
        except Exception as e:
            logger.error(f"Email send error: {e}")

    def notify_session_expiry(self, email: str, username: str):
        """Notify user of session expiry."""
        subject = "ECOBOT Session Expiry"
        body = f"Dear {username},\n\nYour session has expired. Please log in again.\n\nBest,\nECOBOT Team"
        self.send_email(email, subject, body)

# Future: Add SMS or in-app notifications
