from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Optional
from app.api.auth import get_current_user
from app.models.user import User
from app.services.repeater_service import repeater_service

router = APIRouter(prefix="/repeater", tags=["Repeater"])

class RepeaterRequest(BaseModel):
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str] = ""

@router.post("/send")
async def send_repeater_request(req: RepeaterRequest, user: User = Depends(get_current_user)):
    """
    Executes a manual request from the repeater.
    """
    try:
        response = await repeater_service.send_request(
            method=req.method,
            url=req.url,
            headers=req.headers,
            body=req.body
        )
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
