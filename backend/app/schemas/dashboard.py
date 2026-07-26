from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from uuid import UUID

class DashboardStatsResponse(BaseModel):
    total: int
    done: int
    running: int
    high_risk: int

class ActivityLogItem(BaseModel):
    id: UUID
    type: str # 'scan', 'auth', etc
    action: str
    target: Optional[str] = None
    status: str
    result_summary: Optional[str] = None
    created_at: datetime
