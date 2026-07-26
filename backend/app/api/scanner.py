from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from datetime import datetime, timezone
import json

from app.database import get_db
from app.middleware.auth_middleware import get_current_user
from app.models.user import User, ScanResult
from app.schemas.scanner import (
    PortScanRequest, ScanResultResponse, ScanListResponse,
    ScanListItem, PortInfo
)
from app.services.scan_service import run_port_scan
from app.services.auth_service import log_audit

router = APIRouter(prefix="/scanner", tags=["Port Scanner"])


@router.post("/port-scan", response_model=ScanResultResponse)
async def start_port_scan(
    data: PortScanRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Start a port scan against a target."""
    # Create scan record as pending
    scan = ScanResult(
        user_id=current_user.id,
        scan_type=f"port_{data.scan_type}",
        target=data.target,
        status="running",
    )
    db.add(scan)
    await db.flush()
    scan_id = scan.id

    # Run the actual scan
    try:
        result = await run_port_scan(
            target=data.target,
            scan_type=data.scan_type,
            custom_ports=data.ports
        )

        if "error" in result:
            scan.status = "failed"
            scan.result_data = json.dumps({"error": result["error"], "ports": []})
            scan.risk_level = None
            await db.flush()
            raise HTTPException(400, result["error"])

        # Update scan record
        scan.status = "completed"
        scan.result_data = json.dumps(result)
        scan.risk_level = result["risk_level"]
        scan.completed_at = datetime.now(timezone.utc)
        await db.flush()

        # Log audit
        await log_audit(
            db, "port_scan_completed", current_user.id,
            "scanner", f"Scanned {data.target}: {result['total_open']} open ports",
            request.client.host
        )

        return ScanResultResponse(
            id=scan_id,
            target=data.target,
            scan_type=data.scan_type,
            status="completed",
            risk_level=result["risk_level"],
            ports=[PortInfo(**p) for p in result["ports"]],
            total_open=result["total_open"],
            total_closed=result["total_closed"],
            total_filtered=result["total_filtered"],
            scan_duration=result["scan_duration"],
            created_at=scan.created_at,
            completed_at=scan.completed_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        scan.status = "failed"
        scan.result_data = json.dumps({"error": str(e), "ports": []})
        await db.flush()
        raise HTTPException(500, f"Scan failed: {str(e)}")


@router.get("/scans", response_model=ScanListResponse)
async def list_scans(
    page: int = 1,
    per_page: int = 20,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all scans for the current user."""
    offset = (page - 1) * per_page

    # Count total
    count_q = select(func.count()).select_from(ScanResult).where(
        ScanResult.user_id == current_user.id,
        ScanResult.scan_type.like("port_%")
    )
    total = (await db.execute(count_q)).scalar() or 0

    # Fetch scans
    q = (
        select(ScanResult)
        .where(
            ScanResult.user_id == current_user.id,
            ScanResult.scan_type.like("port_%")
        )
        .order_by(desc(ScanResult.created_at))
        .offset(offset)
        .limit(per_page)
    )
    result = await db.execute(q)
    scans = result.scalars().all()

    items = []
    for s in scans:
        total_open = 0
        if s.result_data:
            try:
                rd = json.loads(s.result_data)
                total_open = rd.get("total_open", 0)
            except:
                pass
        items.append(ScanListItem(
            id=s.id,
            target=s.target,
            scan_type=s.scan_type.replace("port_", ""),
            status=s.status,
            risk_level=s.risk_level,
            total_open=total_open,
            created_at=s.created_at,
            completed_at=s.completed_at,
        ))

    return ScanListResponse(scans=items, total=total)


@router.get("/scans/{scan_id}", response_model=ScanResultResponse)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get details of a specific scan."""
    q = select(ScanResult).where(
        ScanResult.id == scan_id,
        ScanResult.user_id == current_user.id
    )
    result = await db.execute(q)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(404, "Scan not found")

    ports = []
    total_open = 0
    total_closed = 0
    total_filtered = 0
    scan_duration = None

    if scan.result_data:
        try:
            rd = json.loads(scan.result_data)
            ports = [PortInfo(**p) for p in rd.get("ports", [])]
            total_open = rd.get("total_open", 0)
            total_closed = rd.get("total_closed", 0)
            total_filtered = rd.get("total_filtered", 0)
            scan_duration = rd.get("scan_duration")
        except:
            pass

    return ScanResultResponse(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type.replace("port_", ""),
        status=scan.status,
        risk_level=scan.risk_level,
        ports=ports,
        total_open=total_open,
        total_closed=total_closed,
        total_filtered=total_filtered,
        scan_duration=scan_duration,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )


@router.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete a scan result."""
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
    
    # 1. Authenticate user from the first message
    try:
        data = await websocket.receive_json()
        token = data.get("token")
        target = data.get("target")
        scan_type = data.get("scan_type", "quick")
        custom_ports = data.get("ports")
        
        if not token or not target:
            await websocket.send_json({"error": "Missing token or target"})
            await websocket.close(code=1008)
            return

        from app.services.auth_service import decode_token, get_user_by_id
        payload = decode_token(token)
        user_id = payload.get("sub")
    except Exception as e:
        await websocket.send_json({"error": "Invalid token or data format"})
        await websocket.close(code=1008)
        return

    from app.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        user = await get_user_by_id(db, user_id)
        if not user or not user.is_active:
            await websocket.send_json({"error": "Unauthorized"})
            await websocket.close(code=1008)
            return

        # Create DB record
        scan = ScanResult(
            user_id=user.id,
            scan_type=f"port_{scan_type}",
            target=target,
            status="running",
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        # Define progress callback
        async def send_progress(msg: dict):
            try:
                await websocket.send_json(msg)
            except Exception:
                pass
                
        # Run scan
        import asyncio
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

        from app.services.scan_service import run_port_scan
        result = await run_port_scan(
            target=target,
            scan_type=scan_type,
            custom_ports=custom_ports,
            progress_callback=send_progress,
            cancel_event=cancel_event
        )
        
        listener_task.cancel()
        
        if cancel_event.is_set() and "error" not in result:
            result["error"] = "Scan cancelled by user"
        
        if "error" in result:
            scan.status = "failed"
            scan.result_data = json.dumps({"error": result["error"], "ports": []})
            scan.risk_level = None
            scan.result_summary = f"Error: {result['error']}"
            await db.commit()
            await websocket.send_json({"error": result["error"]})
        else:
            scan.status = "completed"
            scan.result_data = json.dumps(result)
            scan.risk_level = result["risk_level"]
            # Store reason in summary if high risk
            if scan.risk_level == "high":
                scan.result_summary = f"HIGH RISK: {result.get('risk_reason', 'Critical Services Open')}"
            else:
                scan.result_summary = f"Found {result['total_open']} open ports"
                
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            
            # Send final response
            await websocket.send_json({
                "type": "complete",
                "data": result
            })

