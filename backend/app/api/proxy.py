from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.api.auth import get_current_user
from app.database import get_db, AsyncSessionLocal
from app.models.user import User, CapturedRequest
from app.services.proxy_service import proxy_manager
import json
import asyncio

router = APIRouter(prefix="/proxy", tags=["Proxy"])

# In-memory subscription for active websockets
active_ws_connections = {}

async def broadcast_capture(user_id: str, data: dict):
    print(f"[WS] Broadcasting capture for user {user_id}: {data['method']} {data['url']}")
    if user_id in active_ws_connections:
        # We need to save to DB first
        async with AsyncSessionLocal() as db:
            new_req = CapturedRequest(
                user_id=user_id,
                method=data["method"],
                url=data["url"],
                host=data["host"],
                status_code=data.get("status_code"),
                request_headers=data.get("request_headers"),
                request_body=data.get("request_body"),
                response_headers=data.get("response_headers"),
                response_body=data.get("response_body")
            )
            db.add(new_req)
            await db.commit()
            await db.refresh(new_req)
            
            # Enrich data with ID
            data["id"] = str(new_req.id)
            data["created_at"] = new_req.created_at.isoformat()

        # Send to all websockets for this user
        for ws in active_ws_connections[user_id]:
            try:
                await ws.send_json({"type": "capture", "data": data})
            except:
                pass

async def broadcast_intercept(user_id: str, data: dict):
    if user_id in active_ws_connections:
        print(f"[WS] Broadcasting INTERCEPT for user {user_id}: {data['method']} {data['url']}")
        for ws in active_ws_connections[user_id]:
            try:
                await ws.send_json({"type": "intercept", "data": data})
            except:
                pass

@router.post("/start")
async def start_proxy(user: User = Depends(get_current_user)):
    try:
        async def on_capture_wrapper(data):
            await broadcast_capture(str(user.id), data)
            
        async def on_intercept_wrapper(data):
            await broadcast_intercept(str(user.id), data)
            
        await proxy_manager.start_proxy(str(user.id), on_capture_wrapper, on_intercept_wrapper)
        return {"message": "Proxy started on port 8888", "port": 8888}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/stop")
async def stop_proxy(user: User = Depends(get_current_user)):
    await proxy_manager.stop_proxy()
    return {"message": "Proxy stopped"}

@router.get("/status")
async def get_status(user: User = Depends(get_current_user)):
    is_running = proxy_manager.active_proxy is not None
    return {
        "is_running": is_running,
        "port": 8888 if is_running else None,
        "intercept_enabled": proxy_manager.intercept_enabled
    }

@router.post("/intercept/toggle")
async def toggle_intercept(user: User = Depends(get_current_user)):
    proxy_manager.intercept_enabled = not proxy_manager.intercept_enabled
    return {"intercept_enabled": proxy_manager.intercept_enabled}

@router.post("/intercept/action")
async def intercept_action(
    request: Request,
    action: str,
    request_id: str,
    user: User = Depends(get_current_user)
):
    """Forward or drop an intercepted request. For 'forward', reads modified raw HTTP from body."""
    new_data = None
    if action == "forward":
        body_bytes = await request.body()
        if body_bytes:
            new_data = body_bytes.decode('utf-8', errors='ignore')
    
    success = await proxy_manager.release_request(request_id, action, new_data)
    if not success:
        raise HTTPException(status_code=404, detail="Request ID not found or already released")
    return {"status": "success", "action": action}


@router.post("/intercept/forward-all")
async def forward_all_intercepts(user: User = Depends(get_current_user)):
    """Forward all pending intercepted requests with their original data."""
    ids = list(proxy_manager.intercepted_requests.keys())
    for request_id in ids:
        await proxy_manager.release_request(request_id, "forward", None)
    return {"status": "success", "forwarded": len(ids)}

@router.get("/history")
async def get_history(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(CapturedRequest)
        .where(CapturedRequest.user_id == user.id)
        .order_by(desc(CapturedRequest.created_at))
        .limit(100)
    )
    requests = result.scalars().all()
    return {"history": requests}

@router.delete("/history")
async def clear_history(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    from sqlalchemy import delete
    await db.execute(delete(CapturedRequest).where(CapturedRequest.user_id == user.id))
    await db.commit()
    return {"message": "History cleared"}

@router.delete("/clear-all")
async def clear_all(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Clear all traffic history AND drop all pending intercepts in one go."""
    from sqlalchemy import delete
    await db.execute(delete(CapturedRequest).where(CapturedRequest.user_id == user.id))
    await db.commit()
    dropped_count = await proxy_manager.clear_pending_intercepts()
    return {"message": f"Cleared all history and dropped {dropped_count} pending intercepts."}

@router.get("/ca/download")
async def download_ca(user: User = Depends(get_current_user)):
    import os
    ca_path = os.path.abspath("certs/rootCA.crt")
    if not os.path.exists(ca_path):
        raise HTTPException(status_code=404, detail="CA Certificate not found. Start proxy first.")
    return FileResponse(ca_path, filename="ShadowSpike_CA.crt", media_type="application/x-x509-ca-cert")

@router.websocket("/ws/traffic")
async def websocket_traffic(websocket: WebSocket):
    await websocket.accept()
    
    # Auth via token in first message
    try:
        data = await websocket.receive_json()
        token = data.get("token")
        if not token:
            await websocket.close(code=1008)
            return

        from app.services.auth_service import decode_token
        payload = decode_token(token)
        user_id = payload.get("sub")
        if not user_id:
            await websocket.close(code=1008)
            return
            
    except Exception:
        await websocket.close(code=1008)
        return

    if user_id not in active_ws_connections:
        active_ws_connections[user_id] = []
    active_ws_connections[user_id].append(websocket)

    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_ws_connections[user_id].remove(websocket)
        if not active_ws_connections[user_id]:
            del active_ws_connections[user_id]
