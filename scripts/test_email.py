#!/usr/bin/env python3
"""
Test Email Script
Verifies SMTP configuration by sending a test alert.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from src.notifier import EmailNotifier

def main():
    print("Testing SMTP configuration...")
    notifier = EmailNotifier()
    
    if not notifier.is_configured():
        print("Error: SMTP is not fully configured in .env")
        sys.exit(1)
        
    print(f"Server: {notifier.smtp_server}:{notifier.smtp_port}")
    print(f"User: {notifier.smtp_user}")
    print(f"Secure: {notifier.smtp_secure}")
    print(f"Recipient: {notifier.recipient_email}")
    
    subject = "Security Scanner - Test Alert"
    body = "This is a test email from the Repo Security Scanner to verify your SMTP settings."
    
    print("\nSending test email...")
    success = notifier.send_alert(subject, body)
    
    if success:
        print("Success! Test email sent.")
    else:
        print("Failed to send test email. Check your .env settings and network connection.")

if __name__ == "__main__":
    main()
