from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update, delete
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from app.database import get_db
from app.middleware.auth_middleware import get_current_admin
from app.models.user import User, UserRole, AuditLog, ScanResult
from app.schemas.auth import (
    AdminUserListItem, BanUserRequest, SuspendUserRequest,
    UpdateRoleRequest, AdminStatsResponse
)

router = APIRouter(prefix="/admin", tags=["Admin Panel"])


@router.get("/stats", response_model=AdminStatsResponse)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_admin)
):
    total_users = (await db.execute(
        select(func.count(User.id)))).scalar()
    active_users = (await db.execute(
        select(func.count(User.id)).where(
            User.is_active == True, User.is_banned == False
        ))).scalar()
    banned_users = (await db.execute(
        select(func.count(User.id)).where(
            User.is_banned == True
        ))).scalar()
    admin_count = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.ADMIN
        ))).scalar()
    total_scans = (await db.execute(
        select(func.count(ScanResult.id)))).scalar()
    today = datetime.now(timezone.utc).date()
    scans_today = (await db.execute(
        select(func.count(ScanResult.id)).where(
            func.date(ScanResult.created_at) == today
        ))).scalar()
    pending_scans = (await db.execute(
        select(func.count(ScanResult.id)).where(
            ScanResult.status.in_(["pending", "running"])
        ))).scalar()

    return AdminStatsResponse(
        total_users=total_users,
        active_users=active_users,
        banned_users=banned_users,
        admin_count=admin_count,
        total_scans=total_scans,
        scans_today=scans_today,
        pending_scans=pending_scans
    )


@router.get("/users")
async def list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    role: Optional[str] = None,
    is_banned: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_admin)
):
    query = select(User)
    if search:
        query = query.where(
            User.username.ilike(f"%{search}%") |
            User.email.ilike(f"%{search}%")
        )
    if role:
        query = query.where(User.role == role)
    if is_banned is not None:
        query = query.where(User.is_banned == is_banned)

    total = (await db.execute(
        select(func.count()).select_from(query.subquery())
    )).scalar()

    query = query.offset(
        (page - 1) * per_page
    ).limit(per_page).order_by(User.created_at.desc())

    users = (await db.execute(query)).scalars().all()

    return {
        "users": [AdminUserListItem.model_validate(u) for u in users],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    }


@router.get("/users/{user_id}")
async def get_user_detail(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_admin)
):
    user = (await db.execute(
        select(User).where(User.id == user_id)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    return AdminUserListItem.model_validate(user)


@router.post("/users/{user_id}/ban")
async def ban_user(
    user_id: UUID,
    data: BanUserRequest,
    db: AsyncSession = Depends(get_db),
    admin=Depends(get_current_admin)
):
    user = (await db.execute(
        select(User).where(User.id == user_id)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == admin.id:
        raise HTTPException(400, "Cannot ban yourself")
    user.is_banned = True
    user.ban_reason = data.reason
    
    # Invalidate all active sessions for this user
    from app.models.user import UserSession
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id)
        .values(is_active=False)
    )
    
    await db.flush()
    return {"message": f"User {user.username} banned successfully"}


@router.post("/users/{user_id}/unban")
async def unban_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_admin)
):
    user = (await db.execute(
        select(User).where(User.id == user_id)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    user.is_banned = False
    user.ban_reason = None
    await db.flush()
    return {"message": f"User {user.username} unbanned"}

@router.post("/users/{user_id}/suspend")
async def suspend_user(
    user_id: UUID,
    data: SuspendUserRequest,
    db: AsyncSession = Depends(get_db),
    admin=Depends(get_current_admin)
):
    user = (await db.execute(
        select(User).where(User.id == user_id)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == admin.id:
        raise HTTPException(400, "Cannot suspend yourself")
    user.is_suspended = True
    user.suspension_reason = data.reason

    # Invalidate all active sessions for this user
    from app.models.user import UserSession
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id)
        .values(is_active=False)
    )

    await db.flush()
    return {"message": f"User {user.username} suspended successfully"}


@router.post("/users/{user_id}/unsuspend")
async def unsuspend_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_admin)
):
    user = (await db.execute(
        select(User).where(User.id == user_id)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    user.is_suspended = False
    user.suspension_reason = None
    await db.flush()
    return {"message": f"User {user.username} unsuspended"}



@router.post("/users/{user_id}/toggle-active")
async def toggle_active(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    admin=Depends(get_current_admin)
):
    user = (await db.execute(
        select(User).where(User.id == user_id)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == admin.id:
        raise HTTPException(400, "Cannot deactivate yourself")
    user.is_active = not user.is_active
    await db.flush()
    return {
        "message": f"User {user.username} "
                   f"{'activated' if user.is_active else 'deactivated'}"
    }


@router.patch("/users/{user_id}/role")
async def update_role(
    user_id: UUID,
    data: UpdateRoleRequest,
    db: AsyncSession = Depends(get_db),
    admin=Depends(get_current_admin)
):
    user = (await db.execute(
        select(User).where(User.id == user_id)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == admin.id:
        raise HTTPException(400, "Cannot change your own role")
    user.role = data.role
    await db.flush()
    return {"message": f"Role updated to {data.role} for {user.username}"}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    admin=Depends(get_current_admin)
):
    user = (await db.execute(
        select(User).where(User.id == user_id)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == admin.id:
        raise HTTPException(400, "Cannot delete yourself")
    await db.delete(user)
    await db.flush()
    return {"message": f"User {user.username} deleted permanently"}


@router.get("/audit-logs")
async def get_audit_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    action: Optional[str] = None,
    user_id: Optional[UUID] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_admin)
):
    query = select(AuditLog).order_by(AuditLog.created_at.desc())
    if action:
        query = query.where(AuditLog.action.ilike(f"%{action}%"))
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if status:
        query = query.where(AuditLog.status == status)

    total = (await db.execute(
        select(func.count()).select_from(query.subquery())
    )).scalar()
    logs = (await db.execute(
        query.offset((page - 1) * per_page).limit(per_page)
    )).scalars().all()

    return {
        "logs": [
            {
                "id": str(l.id),
                "user_id": str(l.user_id) if l.user_id else None,
                "action": l.action,
                "resource": l.resource,
                "details": l.details,
                "ip_address": l.ip_address,
                "status": l.status,
                "created_at": l.created_at.isoformat()
            } for l in logs
        ],
        "total": total,
        "page": page,
        "per_page": per_page
    }


@router.get("/scan-results")
async def get_all_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    scan_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_admin)
):
    query = select(ScanResult).order_by(ScanResult.created_at.desc())
    if scan_type:
        query = query.where(ScanResult.scan_type == scan_type)
    if risk_level:
        query = query.where(ScanResult.risk_level == risk_level)

    total = (await db.execute(
        select(func.count()).select_from(query.subquery())
    )).scalar()
    scans = (await db.execute(
        query.offset((page - 1) * per_page).limit(per_page)
    )).scalars().all()

    return {
        "scans": [
            {
                "id": str(s.id),
                "user_id": str(s.user_id),
                "scan_type": s.scan_type,
                "target": s.target,
                "status": s.status,
                "risk_level": s.risk_level,
                "created_at": s.created_at.isoformat()
            } for s in scans
        ],
        "total": total,
        "page": page,
        "per_page": per_page
    }