import httpx
import json
import asyncio
from typing import Dict, Any, Optional

class RepeaterService:
    async def send_request(self, method: str, url: str, headers: Dict[str, str], body: str):
        """
        Sends a manual request and returns the response details.
        """
        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            try:
                # Prepare headers (filter out restricted ones if necessary)
                filtered_headers = {k: v for k, v in headers.items() if k.lower() not in ['content-length', 'host']}
                
                response = await client.request(
                    method=method,
                    url=url,
                    headers=filtered_headers,
                    content=body,
                    timeout=30.0
                )
                
                return {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text
                }
            except Exception as e:
                return {
                    "error": str(e)
                }

repeater_service = RepeaterService()
