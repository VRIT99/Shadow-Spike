from pydantic import BaseModel, field_validator
from typing import Optional, List
from datetime import datetime
from uuid import UUID
import re


class PortScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"  # quick, standard, full, custom
    ports: Optional[str] = None  # e.g. "80,443,8080" or "1-1024"

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        # Block obvious bad inputs
        if any(c in v for c in [";", "&", "|", "`", "$", "(", ")"]):
            raise ValueError("Invalid characters in target")
        return v

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v):
        allowed = ["quick", "standard", "full", "custom"]
        if v not in allowed:
            raise ValueError(f"scan_type must be one of: {', '.join(allowed)}")
        return v

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v):
        if v is None:
            return v
        v = v.strip()
        # Allow comma-separated ports and ranges like "80,443,8000-8100"
        if not re.match(r'^[\d,\-\s]+$', v):
            raise ValueError("Invalid port format. Use: 80,443 or 1-1024")
        return v


class PortInfo(BaseModel):
    port: int
    state: str
    service: str = "unknown"
    version: str = ""


class ScanResultResponse(BaseModel):
    id: UUID
    target: str
    scan_type: str
    status: str
    risk_level: Optional[str]
    ports: List[PortInfo] = []
    total_open: int = 0
    total_closed: int = 0
    total_filtered: int = 0
    scan_duration: Optional[float] = None
    created_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class ScanListItem(BaseModel):
    id: UUID
    target: str
    scan_type: str
    status: str
    risk_level: Optional[str]
    total_open: int = 0
    created_at: datetime
    completed_at: Optional[datetime]


class ScanListResponse(BaseModel):
    scans: List[ScanListItem]
    total: int
