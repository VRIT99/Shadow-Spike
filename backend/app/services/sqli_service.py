import asyncio
import time
import re
import logging
import httpx
from typing import List, Dict, Any, Optional, Callable
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse, urlencode
from bs4 import BeautifulSoup
from app.services.xss_service import get_spoofed_headers, normalize_url, get_base_url, inject_param
from app.services.sqli_payloads import SQLI_PAYLOADS, SQL_ERRORS, ALL_SQLI_PAYLOADS

logger = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(20.0, connect=10.0)

# Duplicated spider_sqli_pages function removed to prevent redeclaration issues.


async def crawl_sqli_points(client: httpx.AsyncClient, pages: List[str]) -> List[Dict[str, Any]]:
    """Extract forms, URL params, headers, and cookies."""
    points = []
    seen_keys = set()
    
    async def process_page(url: str):
        try:
            resp = await client.get(url, headers=get_spoofed_headers())
            if resp.status_code != 200: return
            
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")
            
            # 1. Forms
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                target_url = urljoin(url, action)
                
                inputs = []
                for b in form.find_all(["input", "textarea", "select"]):
                    name = b.get("name")
                    if name:
                        inputs.append({"name": name, "type": b.get("type", "text"), "id": b.get("id", "")})
                
                for inp in inputs:
                    key = f"{method}::{target_url}::{inp['name']}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        points.append({
                            "type": "form_field", "url": target_url, "param": inp["name"],
                            "method": method, "fields": {i["name"]: "1" for i in inputs},
                            "label": inp["name"], "id": inp["id"]
                        })

            # 2. URL Params
            p = urlparse(url)
            if p.query:
                params = parse_qs(p.query)
                for param in params:
                    key = f"GET::{url}::{param}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        points.append({
                            "type": "url_param", "url": url, "param": param,
                            "method": "GET", "label": param, "id": ""
                        })

            # 3. Cookies
            for cookie_name in resp.cookies.keys():
                key = f"COOKIE::{url}::{cookie_name}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    points.append({
                        "type": "cookie", "url": url, "param": cookie_name,
                        "method": "GET", "label": f"Cookie: {cookie_name}", "id": ""
                    })

            # 4. Standard Vulnerable Headers
            for header_name in ["User-Agent", "Referer", "X-Forwarded-For"]:
                key = f"HEADER::{url}::{header_name}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    points.append({
                        "type": "header", "url": url, "param": header_name,
                        "method": "GET", "label": f"Header: {header_name}", "id": ""
                    })

        except Exception: pass

    await asyncio.gather(*[process_page(p) for p in pages])
    return points

async def spider_sqli_pages(client: httpx.AsyncClient, base_url: str, deep: bool = False) -> List[str]:
    pages = {base_url}
    to_visit = {base_url}
    visited = set()
    base_domain = get_base_url(base_url)
    max_depth = 3 if deep else 1

    for _ in range(max_depth):
        if not to_visit: break
        curr = to_visit.copy()
        to_visit.clear()
        for url in curr:
            if url in visited: continue
            visited.add(url)
            try:
                resp = await client.get(url, headers=get_spoofed_headers(), timeout=httpx.Timeout(10.0))
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for a in soup.find_all("a", href=True):
                        href = urljoin(url, a["href"]).split("#")[0].rstrip("/")
                        if href.startswith(base_domain):
                            if href not in visited:
                                pages.add(href)
                                to_visit.add(href)
            except: pass
    return list(pages)

async def test_sqli_point(
    client: httpx.AsyncClient,
    point: Dict[str, Any],
    payload: str,
    baseline_time: float = 0.0,
    baseline_content: str = ""
) -> Optional[Dict[str, Any]]:
    pt_type = point.get("type", "url_param")
    hdrs = get_spoofed_headers()
    cookies = {}
    is_get = point["method"] == "GET"
    
    try:
        start = time.time()
        if pt_type == "url_param":
            target_url = inject_param(point["url"], point["param"], payload)
            resp = await client.get(target_url, headers=hdrs, timeout=TIMEOUT)
        elif pt_type == "header":
            hdrs[point["param"]] = payload
            resp = await client.get(point["url"], headers=hdrs, timeout=TIMEOUT)
        elif pt_type == "cookie":
            cookies[point["param"]] = payload
            resp = await client.get(point["url"], headers=hdrs, cookies=cookies, timeout=TIMEOUT)
        elif pt_type == "form_field":
            data = dict(point.get("fields", {}))
            data[point["param"]] = payload
            if point["method"] == "POST":
                resp = await client.post(point["url"], data=data, headers=hdrs, timeout=TIMEOUT)
            else:
                resp = await client.get(point["url"], params=data, headers=hdrs, timeout=TIMEOUT)
        else:
            # Fallback
            target_url = inject_param(point["url"], point["param"], payload)
            resp = await client.get(target_url, headers=hdrs, timeout=TIMEOUT)
        
        duration = time.time() - start
        
        # 1. Error-based
        for db, patterns in SQL_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    return {
                        "type": f"Error-based SQLi ({pt_type.replace('_', ' ').title()})", 
                        "db": db, "payload": payload,
                        "endpoint": point["url"], "parameter": point["param"],
                        "vulnerable_url": inject_param(point["url"], point["param"], payload) if pt_type == "url_param" else None,
                        "point_type": pt_type,
                        "form_fields": point.get("fields") if pt_type == "form_field" else None,
                        "severity": "CRITICAL", "confidence": "HIGH",
                        "evidence": f"DB Error: {db} pattern match found", "method": point["method"]
                    }
        
        # 2. Time-based
        if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper() or "benchmark" in payload.lower():
            if duration > 8.0 and duration > (baseline_time + 4.0):
                return {
                    "type": f"Time-based SQLi ({pt_type.replace('_', ' ').title()})", 
                    "payload": payload, "endpoint": point["url"],
                    "parameter": point["param"], "severity": "CRITICAL", "confidence": "HIGH",
                    "vulnerable_url": inject_param(point["url"], point["param"], payload) if pt_type == "url_param" else None,
                    "point_type": pt_type,
                    "form_fields": point.get("fields") if pt_type == "form_field" else None,
                    "evidence": f"Delayed response: {duration:.2f}s", "method": point["method"]
                }

        # 3. Boolean-based (Simplified: content length significantly different)
        if baseline_content and abs(len(resp.text) - len(baseline_content)) > 500:
             if "' OR '1'='1" in payload or "1=1" in payload:
                 return {
                    "type": f"Boolean-based SQLi ({pt_type.replace('_', ' ').title()})", 
                    "payload": payload, "endpoint": point["url"],
                    "parameter": point["param"], "severity": "HIGH", "confidence": "MEDIUM",
                    "vulnerable_url": inject_param(point["url"], point["param"], payload) if pt_type == "url_param" else None,
                    "point_type": pt_type,
                    "form_fields": point.get("fields") if pt_type == "form_field" else None,
                    "evidence": f"Content length shift: {len(resp.text)} vs {len(baseline_content)}", "method": point["method"]
                }
                
    except: pass
    return None

async def run_sqli_scan(
    url: str,
    scan_mode: str = "quick",
    progress_callback: Optional[Callable] = None,
    cancel_event: Optional[asyncio.Event] = None
) -> Dict[str, Any]:
    url = normalize_url(url)
    deep = scan_mode == "deep"
    payloads = ALL_SQLI_PAYLOADS
    vulnerabilities = []
    
    async def send(msg: dict):
        if progress_callback:
            try: await progress_callback(msg)
            except: pass

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, verify=False, follow_redirects=True) as client:
            await send({"type": "status", "message": "INITIALIZING SCAN ENGINE..."})
            try:
                start_base = time.time()
                base_resp = await client.get(url, headers=get_spoofed_headers())
                baseline_time = time.time() - start_base
                baseline_text = base_resp.text
            except Exception:
                return {"error": "Target unreachable", "vulnerabilities": []}

            await send({"type": "status", "message": "SPIDERING TARGET AND ANALYZING PARAMETERS..."})
            pages = await spider_sqli_pages(client, url, deep)
            points = await crawl_sqli_points(client, pages)
            
            if not points:
                return {"error": "No injection points identified. Try a URL with parameters.", "vulnerabilities": []}

            await send({"type": "status", "message": f"INJECTING {len(payloads)} ADVANCED PAYLOADS ACROSS {len(points)} POINTS..."})
            
            tested = 0
            total = len(points) * len(payloads)
            sem = asyncio.Semaphore(15)

            async def task(pt, pl):
                nonlocal tested
                async with sem:
                    if cancel_event and cancel_event.is_set(): return
                    res = await test_sqli_point(client, pt, pl, baseline_time, baseline_text)
                    tested += 1
                    if res:
                        vulnerabilities.append(res)
                        await send({"type": "vuln_found", "data": res})
                    if tested % 10 == 0 or tested == total:
                        await send({"type": "progress", "progress": int((tested/total)*100)})

            tasks = [asyncio.create_task(task(pt, pl)) for pt in points for pl in payloads]
            await asyncio.gather(*tasks)

    except Exception as e:
        return {"error": str(e), "vulnerabilities": []}

    return {
        "target": url,
        "total_vulnerable": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "scan_mode": scan_mode
    }
