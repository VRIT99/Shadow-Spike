from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from datetime import datetime, timezone
import json

from app.database import get_db
from app.middleware.auth_middleware import get_current_user
from app.models.user import User, ScanResult
from app.schemas.xss import (
    XSSScanRequest, XSSScanResultResponse, XSSScanListResponse,
    XSSScanListItem, XSSVulnerability
)
from app.services.xss_service import run_xss_scan
from app.services.auth_service import log_audit

router = APIRouter(prefix="/xss", tags=["XSS Scanner"])


def _parse_result(scan: ScanResult) -> dict:
    if scan.result_data:
        try:
            return json.loads(scan.result_data)
        except Exception:
            pass
    return {}


@router.post("/scan", response_model=XSSScanResultResponse)
async def start_xss_scan(
    data: XSSScanRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scan = ScanResult(
        user_id=current_user.id,
        scan_type=f"xss_{data.scan_mode}",
        target=data.target,
        status="running",
    )
    db.add(scan)
    await db.flush()
    scan_id = scan.id

    try:
        result = await run_xss_scan(target=data.target, scan_mode=data.scan_mode)

        if "error" in result:
            scan.status = "failed"
            scan.result_data = json.dumps({"error": result["error"], "vulnerabilities": []})
            scan.risk_level = None
            await db.flush()
            raise HTTPException(400, result["error"])

        scan.status = "completed"
        scan.result_data = json.dumps(result)
        scan.risk_level = result["risk_level"]
        scan.result_summary = f"Found {result['total_vulnerable']} XSS vulnerabilities"
        scan.completed_at = datetime.now(timezone.utc)
        await db.flush()

        await log_audit(
            db, "xss_scan_completed", current_user.id,
            "xss", f"Scanned {data.target}: {result['total_vulnerable']} vulns",
            request.client.host,
        )

        return XSSScanResultResponse(
            id=scan_id,
            target=data.target,
            scan_mode=data.scan_mode,
            status="completed",
            risk_level=result["risk_level"],
            vulnerabilities=[XSSVulnerability(**v) for v in result["vulnerabilities"]],
            total_vulnerable=result["total_vulnerable"],
            critical_count=result["critical_count"],
            medium_count=result["medium_count"],
            payloads_tested=result["payloads_tested"],
            scan_duration=result["scan_duration"],
            waf_detected=result.get("waf_detected", False),
            waf_name=result.get("waf_name"),
            params_discovered=result.get("params_discovered", 0),
            header_vulns=result.get("header_vulns", 0),
            blind_vulns=result.get("blind_vulns", 0),
            dom_vulns=result.get("dom_vulns", 0),
            created_at=scan.created_at,
            completed_at=scan.completed_at,
        )
    except HTTPException:
        raise
    except Exception as e:
        scan.status = "failed"
        scan.result_data = json.dumps({"error": str(e), "vulnerabilities": []})
        await db.flush()
        raise HTTPException(500, f"XSS scan failed: {str(e)}")


@router.get("/scans", response_model=XSSScanListResponse)
async def list_xss_scans(
    page: int = 1,
    per_page: int = 20,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * per_page
    count_q = select(func.count()).select_from(ScanResult).where(
        ScanResult.user_id == current_user.id,
        ScanResult.scan_type.like("xss_%"),
    )
    total = (await db.execute(count_q)).scalar() or 0

    q = (
        select(ScanResult)
        .where(ScanResult.user_id == current_user.id, ScanResult.scan_type.like("xss_%"))
        .order_by(desc(ScanResult.created_at))
        .offset(offset)
        .limit(per_page)
    )
    scans = (await db.execute(q)).scalars().all()

    items = []
    for s in scans:
        rd = _parse_result(s)
        items.append(XSSScanListItem(
            id=s.id,
            target=s.target,
            scan_mode=s.scan_type.replace("xss_", ""),
            status=s.status,
            risk_level=s.risk_level,
            total_vulnerable=rd.get("total_vulnerable", 0),
            waf_detected=rd.get("waf_detected", False),
            created_at=s.created_at,
            completed_at=s.completed_at,
        ))

    return XSSScanListResponse(scans=items, total=total)


@router.get("/scans/{scan_id}", response_model=XSSScanResultResponse)
async def get_xss_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(ScanResult).where(
        ScanResult.id == scan_id, ScanResult.user_id == current_user.id
    )
    scan = (await db.execute(q)).scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")

    rd = _parse_result(scan)
    vulns = [XSSVulnerability(**v) for v in rd.get("vulnerabilities", [])]

    return XSSScanResultResponse(
        id=scan.id,
        target=scan.target,
        scan_mode=scan.scan_type.replace("xss_", ""),
        status=scan.status,
        risk_level=scan.risk_level,
        vulnerabilities=vulns,
        total_vulnerable=rd.get("total_vulnerable", 0),
        critical_count=rd.get("critical_count", 0),
        medium_count=rd.get("medium_count", 0),
        payloads_tested=rd.get("payloads_tested", 0),
        scan_duration=rd.get("scan_duration"),
        waf_detected=rd.get("waf_detected", False),
        waf_name=rd.get("waf_name"),
        params_discovered=rd.get("params_discovered", 0),
        header_vulns=rd.get("header_vulns", 0),
        blind_vulns=rd.get("blind_vulns", 0),
        dom_vulns=rd.get("dom_vulns", 0),
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )


@router.delete("/scans/{scan_id}")
async def delete_xss_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(ScanResult).where(
        ScanResult.id == scan_id, ScanResult.user_id == current_user.id
    )
    scan = (await db.execute(q)).scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    await db.delete(scan)
    await db.flush()
    return {"message": "Scan deleted"}


@router.websocket("/ws/scan")
async def websocket_xss_scan(websocket: WebSocket):
    await websocket.accept()

    try:
        msg = await websocket.receive_text()
        data = json.loads(msg)
        token = data.get("token")
        target = data.get("target")
        scan_mode = data.get("scan_mode", "quick")

        if not token or not target:
            await websocket.send_json({"error": "Missing token or target URL"})
            await websocket.close(code=1008)
            return

        from app.services.auth_service import decode_token, get_user_by_id
        try:
            payload = decode_token(token)
            user_id = payload.get("sub")
        except Exception:
            await websocket.send_json({"error": "Session expired. Please login again."})
            await websocket.close(code=1008)
            return
    except Exception as e:
        await websocket.send_json({"error": f"Invalid request data: {str(e)}"})
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

        scan = ScanResult(
            user_id=user.id,
            scan_type=f"xss_{scan_mode}",
            target=target,
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

        result = await run_xss_scan(
            url=target,
            scan_mode=scan_mode,
            progress_callback=send_progress,
            cancel_event=cancel_event,
        )

        listener_task.cancel()

        if cancel_event.is_set() and "error" not in result:
            result["error"] = "Scan cancelled by user"

        if "error" in result:
            scan.status = "failed"
            scan.result_data = json.dumps({"error": result["error"], "vulnerabilities": []})
            scan.risk_level = None
            await db.commit()
            await websocket.send_json({"error": result["error"]})
        else:
            scan.status = "completed"
            scan.result_data = json.dumps(result)
            scan.risk_level = result["risk_level"]
            scan.result_summary = f"Found {result['total_vulnerable']} XSS vulnerabilities"
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            await websocket.send_json({"type": "complete", "data": result})
