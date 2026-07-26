from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, or_
from app.database import get_db
from app.middleware.auth_middleware import get_current_user
from app.models.user import User, ScanResult, AuditLog
from app.schemas.dashboard import DashboardStatsResponse, ActivityLogItem
from typing import List, Optional

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Count total scans for this user
    total = (await db.execute(
        select(func.count(ScanResult.id)).where(ScanResult.user_id == current_user.id)
    )).scalar() or 0
    
    # Completed scans
    done = (await db.execute(
        select(func.count(ScanResult.id)).where(
            ScanResult.user_id == current_user.id,
            ScanResult.status == "completed"
        )
    )).scalar() or 0
    
    # Running scans
    running = (await db.execute(
        select(func.count(ScanResult.id)).where(
            ScanResult.user_id == current_user.id,
            ScanResult.status == "running"
        )
    )).scalar() or 0
    
    # High risk findings
    high_risk = (await db.execute(
        select(func.count(ScanResult.id)).where(
            ScanResult.user_id == current_user.id,
            ScanResult.risk_level == "high"
        )
    )).scalar() or 0
    
    return DashboardStatsResponse(
        total=total,
        done=done,
        running=running,
        high_risk=high_risk
    )

@router.get("/activity", response_model=List[ActivityLogItem])
async def get_recent_activity(
    activity_filter: Optional[str] = "total",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Fetch latest 10 activities based on filter
    q = select(ScanResult).where(ScanResult.user_id == current_user.id)
    
    if activity_filter == "done":
        q = q.where(ScanResult.status == "completed")
    elif activity_filter == "running":
        q = q.where(ScanResult.status == "running")
    elif activity_filter == "high_risk":
        q = q.where(ScanResult.risk_level == "high")
        
    q = q.order_by(desc(ScanResult.created_at)).limit(10)
    results = (await db.execute(q)).scalars().all()
    
    activities = []
    for s in results:
        activities.append(ActivityLogItem(
            id=s.id,
            type="scan",
            action=f"{s.scan_type.replace('_', ' ').title()}",
            target=s.target,
            status=s.status,
            result_summary=s.result_summary or (f"Risk: {s.risk_level}" if s.risk_level else "In progress"),
            created_at=s.created_at
        ))
    
    return activities
