from sqlalchemy import Column, String, Boolean, DateTime, Enum, Text, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import uuid
import enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)

    # Account status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_banned = Column(Boolean, default=False, nullable=False)
    ban_reason = Column(Text, nullable=True)
    is_suspended = Column(Boolean, default=False, nullable=False)
    suspension_reason = Column(Text, nullable=True)

    # 2FA - MANDATORY (Google Authenticator TOTP)
    totp_secret = Column(String(64), nullable=True)
    totp_enabled = Column(Boolean, default=False, nullable=False)
    totp_verified = Column(Boolean, default=False, nullable=False)

    # Login tracking
    last_login = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    scan_results = relationship("ScanResult", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    captured_requests = relationship("CapturedRequest", back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    refresh_token = Column(Text, nullable=False, unique=True)
    device_info = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="sessions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(100), nullable=False)
    resource = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    status = Column(String(20), default="success")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="audit_logs")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    scan_type = Column(String(50), nullable=False)
    target = Column(String(255), nullable=False)
    status = Column(String(20), default="pending")
    result_data = Column(Text, nullable=True)
    risk_level = Column(String(10), nullable=True)
    result_summary = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="scan_results")


class CapturedRequest(Base):
    __tablename__ = "captured_requests"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    method = Column(String(10), nullable=False)
    url = Column(Text, nullable=False)
    host = Column(String(255), nullable=True)
    status_code = Column(Integer, nullable=True)
    
    request_headers = Column(Text, nullable=True)  # JSON string
    request_body = Column(Text, nullable=True)
    
    response_headers = Column(Text, nullable=True)  # JSON string
    response_body = Column(Text, nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="captured_requests")