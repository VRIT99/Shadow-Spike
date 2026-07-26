from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import jwt, JWTError
import bcrypt
import pyotp, qrcode, io, base64, uuid, secrets

from app.models.user import User, UserSession, UserRole, AuditLog
from app.config import settings

# pwd_context removed to fix compatibility issues

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def hash_password(password: str) -> str:
    # bcrypt requires bytes
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


def create_access_token(data: dict, expires_delta=None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh", "jti": str(uuid.uuid4())})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_temp_token(user_id: str) -> str:
    data = {
        "sub": user_id,
        "type": "2fa_pending",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
    }
    return jwt.encode(data, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_password_reset_token(user_id: str) -> str:
    data = {
        "sub": user_id,
        "type": "password_reset",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15)
    }
    return jwt.encode(data, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


# ─── TOTP / Google Authenticator ────────────────────────
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str) -> str:
    totp = pyotp.TOTP(
        secret,
        digits=settings.TOTP_DIGITS,
        interval=settings.TOTP_INTERVAL
    )
    return totp.provisioning_uri(
        name=email,
        issuer_name=settings.TOTP_ISSUER
    )


def generate_qr_base64(uri: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=8, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(
        secret,
        digits=settings.TOTP_DIGITS,
        interval=settings.TOTP_INTERVAL
    )
    return totp.verify(code, valid_window=1)


# ─── DB Operations ──────────────────────────────────────
async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id) -> Optional[User]:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def get_user_by_username(db: AsyncSession, username: str) -> Optional[User]:
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def create_user(
    db: AsyncSession,
    email: str,
    username: str,
    password: str,
    full_name: str = None,
    role: UserRole = UserRole.USER
) -> User:
    user = User(
        email=email,
        username=username,
        full_name=full_name,
        hashed_password=hash_password(password),
        role=role,
        is_active=True,
        is_verified=False,
        totp_enabled=False,
        totp_verified=False,
    )
    db.add(user)
    await db.flush()
    return user


async def is_account_locked(user: User) -> bool:
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        return True
    return False


async def handle_failed_login(db: AsyncSession, user: User):
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
    await db.flush()


async def reset_failed_attempts(db: AsyncSession, user: User):
    user.failed_login_attempts = 0
    user.locked_until = None
    await db.flush()


async def create_user_session(
    db: AsyncSession,
    user_id,
    ip_address: str,
    device_info: str,
    refresh_token: str
) -> UserSession:
    session = UserSession(
        user_id=user_id,
        refresh_token=refresh_token,
        ip_address=ip_address,
        device_info=device_info,
        is_active=True,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(session)
    await db.flush()
    return session


async def log_audit(
    db: AsyncSession,
    action: str,
    user_id=None,
    resource: str = None,
    details: str = None,
    ip: str = None,
    ua: str = None,
    status: str = "success"
):
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        details=details,
        ip_address=ip,
        user_agent=ua,
        status=status,
    )
    db.add(log)
    await db.flush()