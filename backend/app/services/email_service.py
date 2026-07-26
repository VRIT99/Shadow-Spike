from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from pydantic import EmailStr
from app.config import settings

conf = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM or "noreply@shadowspike.com",
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_STARTTLS=settings.MAIL_STARTTLS,
    MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
    USE_CREDENTIALS=bool(settings.MAIL_USERNAME and settings.MAIL_PASSWORD),
    VALIDATE_CERTS=True
)

async def send_password_reset_email(email: str, reset_link: str):
    """
    Sends a password reset email using fastapi-mail.
    If credentials are missing, we gracefully skip sending to prevent crashes during dev.
    """
    if not settings.MAIL_USERNAME or not settings.MAIL_PASSWORD:
        print("\n[WARNING] Email credentials not set in .env. Skipping real email dispatch.")
        return

    html = f"""
    <html>
        <body style="background-color: #010204; color: #e2e8f0; font-family: monospace; padding: 20px;">
            <div style="border: 1px solid #1e2a3a; padding: 20px; max-width: 500px; margin: 0 auto; background: rgba(255,255,255,0.02);">
                <h2 style="color: #4facfe; text-align: center; letter-spacing: 3px;">SHADOW SPIKE</h2>
                <h3 style="color: #fff; font-weight: 300;">SECURE RECOVERY PROTOCOL</h3>
                <p>Hello Operative,</p>
                <p>A request to override your encryption key (password reset) was initiated for this sector.</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" style="background-color: #00f2fe; color: #010204; padding: 12px 24px; text-decoration: none; font-weight: bold; letter-spacing: 1px;">
                        INITIATE OVERRIDE
                    </a>
                </div>
                <p style="color: rgba(255,255,255,0.6); font-size: 12px;">If you did not request this, ignore this transmission.</p>
                <hr style="border-color: rgba(255,255,255,0.1); margin-top: 30px;" />
                <p style="text-align: center; color: rgba(255,255,255,0.3); font-size: 10px;">CLASSIFIED ACCESS ONLY</p>
            </div>
        </body>
    </html>
    """
    
    try:
        # Validate email format
        valid_email = EmailStr(email)
    except Exception:
        # If the email isn't perfectly compliant (like .local), we just proceed without validation errors if possible
        # but pydantic EmailStr might fail. Let's send anyway.
        pass

    message = MessageSchema(
        subject="[Shadow Spike] Action Required: Password Reset Override",
        recipients=[email],
        body=html,
        subtype=MessageType.html
    )

    fm = FastMail(conf)
    try:
        await fm.send_message(message)
        print(f"\n[INFO] Real email dispatched to {email}")
    except Exception as e:
        print(f"\n[ERROR] Failed to send email to {email}. Error: {e}")
