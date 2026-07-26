import json
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, WebSocket, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db, AsyncSessionLocal
from app.models.user import User, ScanResult
from app.middleware.auth_middleware import get_current_user
from app.services.sqli_service import run_sqli_scan

router = APIRouter(prefix="/sqli", tags=["SQL Injection"])

@router.get("/scans")
async def get_sqli_scans(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    q = select(ScanResult).where(
        ScanResult.user_id == current_user.id,
        ScanResult.scan_type.like("sqli_%")
    ).order_by(ScanResult.created_at.desc())
    results = (await db.execute(q)).scalars().all()
    
    return {
        "scans": [
            {
                "id": s.id,
                "target": s.target,
                "status": s.status,
                "created_at": s.created_at,
                "risk_level": s.risk_level
            } for s in results
        ]
    }

@router.get("/scans/{scan_id}")
async def get_sqli_scan_detail(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    q = select(ScanResult).where(
        ScanResult.id == scan_id,
        ScanResult.user_id == current_user.id
    )
    scan = (await db.execute(q)).scalar_one_or_none()
    if not scan: raise HTTPException(404, "Scan not found")
    
    return json.loads(scan.result_data) if scan.result_data else {}

@router.websocket("/ws/scan")
async def websocket_sqli_scan(websocket: WebSocket):
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
        
        async with AsyncSessionLocal() as db:
            user = await get_user_by_id(db, user_id)
            if not user or not user.is_active:
                await websocket.send_json({"error": "Unauthorized"})
                await websocket.close(code=1008)
                return

            scan = ScanResult(
                user_id=user.id,
                scan_type=f"sqli_{scan_mode}",
                target=target,
                status="running"
            )
            db.add(scan)
            await db.commit()
            await db.refresh(scan)

            async def progress(m):
                try: await websocket.send_json(m)
                except: pass

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
            
            result = await run_sqli_scan(target, scan_mode, progress, cancel_event)
            
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
                # Determine risk level based on max severity in vulnerabilities found
                vulns = result.get("vulnerabilities", [])
                severities = [v.get("severity", "LOW") for v in vulns]
                if "CRITICAL" in severities:
                    risk = "critical"
                elif "HIGH" in severities:
                    risk = "high"
                elif "MEDIUM" in severities:
                    risk = "medium"
                elif "LOW" in severities:
                    risk = "low"
                else:
                    risk = "info"
                
                scan.risk_level = risk
                scan.result_data = json.dumps(result)
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
                
                await websocket.send_json({"type": "complete", "data": result})
            
    except Exception as e:
        try: await websocket.send_json({"error": str(e)})
        except: pass
    finally:
        try: await websocket.close()
        except: pass
