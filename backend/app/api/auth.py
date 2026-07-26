from fastapi import APIRouter, Depends, HTTPException, Request, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone

from app.database import get_db
from app.schemas.auth import (
    RegisterRequest, LoginRequest, TOTPSetupResponse, TOTPVerifyRequest,
    LoginStep1Response, LoginStep2Request, TokenResponse, RefreshRequest, UserResponse,
    ForgotPasswordRequest, ResetPasswordRequest
)
from app.services.auth_service import (
    get_user_by_email, get_user_by_username, create_user,
    verify_password, create_access_token, create_refresh_token, create_temp_token,
    decode_token, generate_totp_secret, get_totp_uri, generate_qr_base64,
    verify_totp_code, create_user_session, log_audit,
    is_account_locked, handle_failed_login, reset_failed_attempts,
    create_password_reset_token, hash_password
)
from app.services.email_service import send_password_reset_email
from app.middleware.auth_middleware import get_current_user
from app.models.user import User
from jose import JWTError

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", status_code=201)
async def register(
    data: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    if await get_user_by_email(db, data.email):
        raise HTTPException(400, "Email already registered")
    if await get_user_by_username(db, data.username):
        raise HTTPException(400, "Username already taken")

    user = await create_user(
        db, data.email, data.username,
        data.password, data.full_name
    )
    await log_audit(
        db, "user_registered", user.id,
        "auth", f"New user: {data.username}",
        request.client.host
    )
    return {
        "message": "Registration successful. Please login and setup Google Authenticator 2FA.",
        "user_id": str(user.id)
    }


@router.post("/forgot-password")
async def forgot_password(
    data: ForgotPasswordRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_email(db, data.email)
    if not user:
        # Prevent email enumeration by returning a generic success message
        return {"message": "If an account exists, a password reset link has been generated."}

    token = create_password_reset_token(str(user.id))
    reset_link = f"http://localhost:5173/reset-password?token={token}"

    # Use real email service instead of just printing
    background_tasks.add_task(send_password_reset_email, user.email, reset_link)

    await log_audit(
        db, "password_reset_requested", user.id,
        "auth", f"Token generated and email dispatched",
        request.client.host
    )

    return {
        "message": "If an account exists, a password reset link has been generated."
    }


@router.post("/reset-password")
async def reset_password(
    data: ResetPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    try:
        payload = decode_token(data.token)
        if payload.get("type") != "password_reset":
            raise HTTPException(400, "Invalid token type")
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(400, "Invalid or expired reset token")

    from app.services.auth_service import get_user_by_id
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(404, "User not found")

    user.hashed_password = hash_password(data.new_password)
    
    # Invalidate existing sessions
    from sqlalchemy import update
    from app.models.user import UserSession
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id)
        .values(is_active=False)
    )

    await db.flush()
    await log_audit(
        db, "password_reset_completed", user.id,
        "auth", "Password updated",
        request.client.host
    )

    return {"message": "Password successfully reset. You can now login with your new password."}


@router.post("/login", response_model=LoginStep1Response)
async def login_step1(
    data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_email(db, data.email)
    ip = request.client.host

    if not user or not verify_password(data.password, user.hashed_password):
        if user:
            await handle_failed_login(db, user)
            await log_audit(db, "login_failed", user.id, "auth",
                          "Wrong password", ip, status="failed")
        raise HTTPException(401, "Invalid credentials")

    if user.is_banned:
        reason = user.ban_reason or "Protocol violation"
        raise HTTPException(
            403,
            f"ACCESS REVOKED: {reason}. This account has been permanently terminated."
        )

    if user.is_suspended:
        reason = user.suspension_reason or "Security review"
        raise HTTPException(
            403,
            f"SUSPENDED: {reason}. Your account is temporarily frozen. Please wait for official clearance."
        )

    if await is_account_locked(user):
        raise HTTPException(
            423,
            "Account locked due to multiple failed attempts. Try again in 15 minutes."
        )

    await reset_failed_attempts(db, user)

    if not user.totp_verified:
        temp_token = create_temp_token(str(user.id))
        return LoginStep1Response(
            message="Password verified. Please setup Google Authenticator first.",
            requires_2fa=False,
            temp_token=temp_token
        )

    temp_token = create_temp_token(str(user.id))
    await log_audit(db, "login_step1_success", user.id, "auth",
                   "Password verified", ip)
    return LoginStep1Response(
        message="Password verified. Enter your Google Authenticator code.",
        requires_2fa=True,
        temp_token=temp_token
    )


@router.post("/2fa/setup", response_model=TOTPSetupResponse)
async def setup_2fa(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else None

    if not token:
        raise HTTPException(401, "Token required")

    try:
        payload = decode_token(token)
        if payload.get("type") not in ("2fa_pending", "access"):
            raise HTTPException(401, "Invalid token type")
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(401, "Invalid or expired token")

    from app.services.auth_service import get_user_by_id
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(404, "User not found")

    secret = generate_totp_secret()
    uri = get_totp_uri(secret, user.email)
    qr = generate_qr_base64(uri)

    user.totp_secret = secret
    user.totp_enabled = False
    user.totp_verified = False
    await db.flush()

    return TOTPSetupResponse(
        secret=secret,
        qr_code_url=qr,
        provisioning_uri=uri
    )


@router.post("/2fa/verify-setup")
async def verify_2fa_setup(
    data: TOTPVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else None
    if not token:
        raise HTTPException(401, "Token required")

    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(401, "Invalid token")

    from app.services.auth_service import get_user_by_id
    user = await get_user_by_id(db, user_id)
    if not user or not user.totp_secret:
        raise HTTPException(400, "2FA not initialized. Call /2fa/setup first.")

    if not verify_totp_code(user.totp_secret, data.totp_code):
        raise HTTPException(
            400,
            "Invalid TOTP code. Make sure your phone clock is synced."
        )

    user.totp_enabled = True
    user.totp_verified = True
    await db.flush()
    await log_audit(db, "2fa_setup_complete", user.id, "auth",
                   None, request.client.host)
    return {"message": "Google Authenticator 2FA activated successfully!"}


@router.post("/2fa/login", response_model=TokenResponse)
async def login_step2(
    data: LoginStep2Request,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    try:
        payload = decode_token(data.temp_token)
        if payload.get("type") != "2fa_pending":
            raise HTTPException(401, "Invalid token type")
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(401, "Temp token expired or invalid")

    from app.services.auth_service import get_user_by_id
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(404, "User not found")

    if not verify_totp_code(user.totp_secret, data.totp_code):
        await handle_failed_login(db, user)
        await log_audit(db, "2fa_failed", user.id, "auth",
                       "Wrong TOTP code", request.client.host, status="failed")
        raise HTTPException(401, "Invalid 2FA code")

    await reset_failed_attempts(db, user)
    user.last_login = datetime.now(timezone.utc)
    user.last_login_ip = request.client.host
    await db.flush()

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token = create_refresh_token({"sub": str(user.id)})
    ua = request.headers.get("User-Agent", "unknown")
    await create_user_session(db, user.id, request.client.host, ua, refresh_token)
    await log_audit(db, "login_success", user.id, "auth",
                   "Full login complete", request.client.host)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=30 * 60
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    data: RefreshRequest,
    db: AsyncSession = Depends(get_db)
):
    try:
        payload = decode_token(data.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(401, "Invalid token type")
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(401, "Invalid refresh token")

    from sqlalchemy import select
    from app.models.user import UserSession
    result = await db.execute(
        select(UserSession).where(
            UserSession.refresh_token == data.refresh_token,
            UserSession.is_active == True
        )
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(401, "Session not found or expired")

    from app.services.auth_service import get_user_by_id
    user = await get_user_by_id(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(401, "User not found")

    new_access = create_access_token({"sub": str(user.id), "role": user.role})
    new_refresh = create_refresh_token({"sub": str(user.id)})
    session.refresh_token = new_refresh
    session.last_used = datetime.now(timezone.utc)
    await db.flush()

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=30 * 60
    )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    from sqlalchemy import update
    from app.models.user import UserSession
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == current_user.id)
        .values(is_active=False)
    )
    await log_audit(db, "logout", current_user.id, "auth",
                   None, request.client.host)
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user