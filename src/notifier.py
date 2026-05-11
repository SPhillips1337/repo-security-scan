"""
Notification Module

Provides interfaces for alerting the user when security findings are detected.
Supports email notifications via SMTP.
"""

import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class EmailNotifier:
    """Handles sending email alerts for security findings."""

    def __init__(
        self,
        smtp_server: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        sender_email: Optional[str] = None,
        recipient_email: Optional[str] = None,
        smtp_secure: Optional[str] = None,
    ):
        # Prefer environment variables if not explicitly provided
        self.smtp_server = smtp_server or os.environ.get("SMTP_SERVER")
        self.smtp_port = smtp_port or int(os.environ.get("SMTP_PORT", "587"))
        self.smtp_user = smtp_user or os.environ.get("SMTP_USER")
        self.smtp_password = smtp_password or os.environ.get("SMTP_PASSWORD")
        self.sender_email = sender_email or os.environ.get("SENDER_EMAIL")
        self.recipient_email = recipient_email or os.environ.get("RECIPIENT_EMAIL")
        self.smtp_secure = smtp_secure or os.environ.get("SMTP_SECURE", "").lower()

    def is_configured(self) -> bool:
        """Check if all necessary SMTP settings are present."""
        return all([
            self.smtp_server,
            self.smtp_user,
            self.smtp_password,
            self.sender_email,
            self.recipient_email
        ])

    def send_alert(self, subject: str, body: str) -> bool:
        """Send an email alert.

        Returns:
            True if successful, False otherwise.
        """
        if not self.is_configured():
            print("Warning: Email notifier is not fully configured. Set SMTP environment variables.")
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = self.sender_email
            msg["To"] = self.recipient_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            if self.smtp_secure == "ssl":
                # Use SMTP_SSL for port 465
                with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                    server.login(self.smtp_user, self.smtp_password)
                    server.send_message(msg)
            else:
                # Use standard SMTP with STARTTLS for port 587
                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_password)
                    server.send_message(msg)
            
            return True
        except Exception as exc:
            print(f"Error sending email alert: {exc}")
            return False


def format_findings_email(repo_name: str, findings: List) -> str:
    """Format a list of findings into a readable email body."""
    body = f"Security Scan Alert for Repository: {repo_name}\n"
    body += "=" * 50 + "\n\n"
    body += f"Critical findings were detected in the latest scan.\n\n"
    
    for finding in findings:
        body += f"[{finding.matched_secret_type}] {finding.file_path}:{finding.line_number}\n"
        body += f"  Matched: ...{finding.matched_text}...\n\n"
    
    body += "\nPlease review and rotate these secrets immediately."
    return body
