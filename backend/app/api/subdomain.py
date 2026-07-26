from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from datetime import datetime, timezone
import json

from app.database import get_db
from app.middleware.auth_middleware import get_current_user
from app.models.user import User, ScanResult
from app.schemas.subdomain import (
    SubdomainScanRequest, SubdomainResultResponse, SubdomainListResponse,
    SubdomainListItem, SubdomainInfo
)
from app.services.subdomain_service import run_subdomain_scan
from app.services.auth_service import log_audit

router = APIRouter(prefix="/subdomain", tags=["Subdomain Enumeration"])


@router.post("/scan", response_model=SubdomainResultResponse)
async def start_subdomain_scan(
    data: SubdomainScanRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Start a subdomain enumeration scan."""
    scan = ScanResult(
        user_id=current_user.id,
        scan_type=f"subdomain_{data.scan_type}",
        target=data.domain,
        status="running",
    )
    db.add(scan)
    await db.flush()
    scan_id = scan.id

    try:
        result = await run_subdomain_scan(
            domain=data.domain,
            scan_type=data.scan_type,
            use_crtsh=data.use_crtsh
        )

        scan.status = "completed"
        scan.result_data = json.dumps(result)
        scan.risk_level = "high" if result["total_found"] > 20 else "medium" if result["total_found"] > 5 else "low"
        scan.completed_at = datetime.now(timezone.utc)
        await db.flush()

        await log_audit(
            db, "subdomain_scan_completed", current_user.id,
            "subdomain", f"Scanned {data.domain}: {result['total_found']} subdomains found",
            request.client.host
        )

        return SubdomainResultResponse(
            id=scan_id,
            domain=data.domain,
            scan_type=data.scan_type,
            status="completed",
            subdomains=[SubdomainInfo(**s) for s in result["subdomains"]],
            total_found=result["total_found"],
            scan_duration=result["scan_duration"],
            created_at=scan.created_at,
            completed_at=scan.completed_at,
        )

    except Exception as e:
        scan.status = "failed"
        scan.result_data = json.dumps({"error": str(e), "subdomains": []})
        await db.flush()
        raise HTTPException(500, f"Scan failed: {str(e)}")


@router.get("/scans", response_model=SubdomainListResponse)
async def list_subdomain_scans(
    page: int = 1,
    per_page: int = 20,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all subdomain scans for the current user."""
    offset = (page - 1) * per_page

    count_q = select(func.count()).select_from(ScanResult).where(
        ScanResult.user_id == current_user.id,
        ScanResult.scan_type.like("subdomain_%")
    )
    total = (await db.execute(count_q)).scalar() or 0

    q = (
        select(ScanResult)
        .where(
            ScanResult.user_id == current_user.id,
            ScanResult.scan_type.like("subdomain_%")
        )
        .order_by(desc(ScanResult.created_at))
        .offset(offset)
        .limit(per_page)
    )
    result = await db.execute(q)
    scans = result.scalars().all()

    items = []
    for s in scans:
        total_found = 0
        if s.result_data:
            try:
                rd = json.loads(s.result_data)
                total_found = rd.get("total_found", 0)
            except:
                pass
        items.append(SubdomainListItem(
            id=s.id,
            domain=s.target,
            scan_type=s.scan_type.replace("subdomain_", ""),
            status=s.status,
            total_found=total_found,
            created_at=s.created_at,
            completed_at=s.completed_at,
        ))

    return SubdomainListResponse(scans=items, total=total)


@router.get("/scans/{scan_id}", response_model=SubdomainResultResponse)
async def get_subdomain_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get details of a specific subdomain scan."""
    q = select(ScanResult).where(
        ScanResult.id == scan_id,
        ScanResult.user_id == current_user.id
    )
    result = await db.execute(q)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(404, "Scan not found")

    subdomains = []
    total_found = 0
    scan_duration = None

    if scan.result_data:
        try:
            rd = json.loads(scan.result_data)
            subdomains = [SubdomainInfo(**s) for s in rd.get("subdomains", [])]
            total_found = rd.get("total_found", 0)
            scan_duration = rd.get("scan_duration")
        except:
            pass

    return SubdomainResultResponse(
        id=scan.id,
        domain=scan.target,
        scan_type=scan.scan_type.replace("subdomain_", ""),
        status=scan.status,
        subdomains=subdomains,
        total_found=total_found,
        scan_duration=scan_duration,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )


@router.delete("/scans/{scan_id}")
async def delete_subdomain_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete a subdomain scan result."""
    q = select(ScanResult).where(
        ScanResult.id == scan_id,
        ScanResult.user_id == current_user.id
    )
    result = await db.execute(q)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(404, "Scan not found")

    await db.delete(scan)
    await db.flush()
    return {"message": "Scan deleted"}


@router.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()
    
    # Authenticate user from the first message
    try:
        data = await websocket.receive_json()
        token = data.get("token")
        domain = data.get("domain")
        scan_type = data.get("scan_type", "quick")
        
        if not token or not domain:
            await websocket.send_json({"error": "Missing token or domain"})
            await websocket.close(code=1008)
            return

        from app.services.auth_service import decode_token, get_user_by_id
        payload = decode_token(token)
        user_id = payload.get("sub")
    except Exception:
        await websocket.send_json({"error": "Invalid token or data format"})
        await websocket.close(code=1008)
        return

    from app.database import AsyncSessionLocal
    import asyncio
    
    async with AsyncSessionLocal() as db:
        user = await get_user_by_id(db, user_id)
        if not user or not user.is_active:
            await websocket.send_json({"error": "Unauthorized"})
            await websocket.close(code=1008)
            return

        # Create pending DB record
        scan = ScanResult(
            user_id=user.id,
            scan_type=f"subdomain_{scan_type}",
            target=domain,
            status="running",
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        async def send_progress(msg: dict):
            try:
                await websocket.send_json(msg)
            except Exception:
                pass
                
        cancel_event = asyncio.Event()

        async def listen_for_cancel():
            try:
                while True:
                    incoming = await websocket.receive_json()
                    if incoming.get("action") == "stop":
                        cancel_event.set()
                        break
            except Exception:
                cancel_event.set()

        listener_task = asyncio.create_task(listen_for_cancel())

        from app.services.subdomain_service import run_subdomain_scan
        result = await run_subdomain_scan(
            domain=domain,
            scan_type=scan_type,
            use_crtsh=True,
            progress_callback=send_progress,
            cancel_event=cancel_event
        )
        
        listener_task.cancel()
        
        if cancel_event.is_set() and "error" not in result:
            result["error"] = "Scan cancelled by user"
            
        if "error" in result:
            scan.status = "failed"
            scan.result_data = json.dumps({"error": result.get("error", "Failed"), "subdomains": []})
            scan.result_summary = f"Error: {result.get('error', 'Failed')}"
            await db.commit()
            await websocket.send_json({"error": result.get("error", "Failed")})
        else:
            scan.status = "completed"
            scan.result_data = json.dumps(result)
            scan.risk_level = "low"
            scan.result_summary = f"Found {result['total_found']} subdomains"
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            
            # Send final response
            await websocket.send_json({
                "type": "complete",
                "data": result
            })

