from pydantic import BaseModel, field_validator
from typing import Optional, List
from datetime import datetime
from uuid import UUID


class SubdomainScanRequest(BaseModel):
    domain: str
    scan_type: str = "quick"  # quick, standard, deep
    use_crtsh: bool = True  # also query certificate transparency logs

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v):
        v = v.strip().lower()
        if not v:
            raise ValueError("Domain cannot be empty")
        # Remove protocol if pasted
        v = v.replace("https://", "").replace("http://", "").rstrip("/")
        # Basic domain validation
        if any(c in v for c in [" ", ";", "&", "|", "`", "$", "(", ")"]):
            raise ValueError("Invalid characters in domain")
        if "." not in v:
            raise ValueError("Please enter a valid domain (e.g., example.com)")
        return v

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v):
        allowed = ["quick", "standard", "deep"]
        if v not in allowed:
            raise ValueError(f"scan_type must be one of: {', '.join(allowed)}")
        return v


class SubdomainInfo(BaseModel):
    subdomain: str
    ip: Optional[str] = None
    status_code: Optional[int] = None
    server: Optional[str] = None
    source: str = "bruteforce"  # bruteforce, crtsh


class SubdomainResultResponse(BaseModel):
    id: UUID
    domain: str
    scan_type: str
    status: str
    subdomains: List[SubdomainInfo] = []
    total_found: int = 0
    scan_duration: Optional[float] = None
    created_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class SubdomainListItem(BaseModel):
    id: UUID
    domain: str
    scan_type: str
    status: str
    total_found: int = 0
    created_at: datetime
    completed_at: Optional[datetime]


class SubdomainListResponse(BaseModel):
    scans: List[SubdomainListItem]
    total: int
