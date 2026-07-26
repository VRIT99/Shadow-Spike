from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError

from app.database import get_db
from app.services.auth_service import decode_token, get_user_by_id
from app.models.user import User, UserRole

bearer_scheme = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(credentials.credentials)
        if payload.get("type") != "access":
            raise credentials_exception
        user_id = payload.get("sub")
        if not user_id:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await get_user_by_id(db, user_id)
    if not user:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")
    if user.is_banned:
        raise HTTPException(
            status_code=403,
            detail=f"ACCESS REVOKED: {user.ban_reason or 'Protocol violation'}. Permanent termination in effect."
        )
    if user.is_suspended:
        raise HTTPException(
            status_code=403,
            detail=f"SUSPENDED: {user.suspension_reason or 'Security review'}. Your account is temporarily frozen. Please wait for clearance."
        )
    if not user.totp_verified:
        raise HTTPException(
            status_code=403,
            detail="2FA setup required. Please complete Google Authenticator setup."
        )
    return user


async def get_current_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Admin access required"
        )
    return current_user