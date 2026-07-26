from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from datetime import datetime
from uuid import UUID
import re


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    password: str

    @field_validator("username")
    @classmethod
    def username_valid(cls, v):
        if not re.match(r"^[a-zA-Z0-9_]{3,30}$", v):
            raise ValueError("Username must be 3-30 chars, only letters/numbers/underscore")
        return v.lower()

    @field_validator("password")
    @classmethod
    def password_strong(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("Password must contain at least one special character")
        return v


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_strong(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("Password must contain at least one special character")
        return v


class LoginRequest(BaseModel):
    email: str  # str instead of EmailStr to allow .local domains
    password: str


class TOTPSetupResponse(BaseModel):
    secret: str
    qr_code_url: str
    provisioning_uri: str


class TOTPVerifyRequest(BaseModel):
    totp_code: str

    @field_validator("totp_code")
    @classmethod
    def code_digits(cls, v):
        v = v.strip()
        if not re.match(r"^\d{6}$", v):
            raise ValueError("TOTP code must be exactly 6 digits")
        return v


class LoginStep1Response(BaseModel):
    message: str
    requires_2fa: bool
    temp_token: str


class LoginStep2Request(BaseModel):
    temp_token: str
    totp_code: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: UUID
    email: str
    username: str
    full_name: Optional[str]
    role: str
    is_active: bool
    is_banned: bool
    is_suspended: bool
    totp_enabled: bool
    totp_verified: bool
    last_login: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class AdminUserListItem(BaseModel):
    id: UUID
    email: str
    username: str
    full_name: Optional[str]
    role: str
    is_active: bool
    is_banned: bool
    ban_reason: Optional[str]
    is_suspended: bool
    suspension_reason: Optional[str]
    totp_enabled: bool
    totp_verified: bool
    last_login: Optional[datetime]
    last_login_ip: Optional[str]
    failed_login_attempts: int
    created_at: datetime

    class Config:
        from_attributes = True


class BanUserRequest(BaseModel):
    reason: str

class SuspendUserRequest(BaseModel):
    reason: str


class UpdateRoleRequest(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def role_valid(cls, v):
        if v not in ("admin", "user"):
            raise ValueError("Role must be admin or user")
        return v


class AdminStatsResponse(BaseModel):
    total_users: int
    active_users: int
    banned_users: int
    admin_count: int
    total_scans: int
    scans_today: int
    pending_scans: int
