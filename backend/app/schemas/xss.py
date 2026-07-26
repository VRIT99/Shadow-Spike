from pydantic import BaseModel, field_validator
from typing import Optional, List
from datetime import datetime
from uuid import UUID


class XSSScanRequest(BaseModel):
    target: str
    scan_mode: str = "quick"  # quick | deep

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        if any(c in v for c in [";", "|", "`", "$", "&&"]):
            raise ValueError("Invalid characters in target")
        return v

    @field_validator("scan_mode")
    @classmethod
    def validate_mode(cls, v):
        if v not in ["quick", "deep"]:
            raise ValueError("scan_mode must be 'quick' or 'deep'")
        return v


class XSSVulnerability(BaseModel):
    endpoint: str
    parameter: str
    field_label: Optional[str] = None
    location_summary: Optional[str] = None
    vulnerable_url: Optional[str] = None
    method: str
    context_type: Optional[str] = None
    payload: str
    confidence: str
    severity: str
    evidence: Optional[str] = None
    impact: Optional[str] = None
    xss_type: Optional[str] = None  # reflected | stored | dom | header | blind
    point_type: Optional[str] = None
    form_fields: Optional[dict] = None


class XSSScanResultResponse(BaseModel):
    id: UUID
    target: str
    scan_mode: str
    status: str
    risk_level: Optional[str]
    vulnerabilities: List[XSSVulnerability] = []
    total_vulnerable: int = 0
    critical_count: int = 0
    medium_count: int = 0
    payloads_tested: int = 0
    scan_duration: Optional[float] = None
    waf_detected: bool = False
    waf_name: Optional[str] = None
    params_discovered: int = 0
    header_vulns: int = 0
    blind_vulns: int = 0
    dom_vulns: int = 0
    created_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class XSSScanListItem(BaseModel):
    id: UUID
    target: str
    scan_mode: str
    status: str
    risk_level: Optional[str]
    total_vulnerable: int = 0
    waf_detected: bool = False
    created_at: datetime
    completed_at: Optional[datetime]


class XSSScanListResponse(BaseModel):
    scans: List[XSSScanListItem]
    total: int
