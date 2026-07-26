import asyncio
import logging
import sys
import httpx

# Setup basic logging to see debug messages
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

from app.services.xss_service import crawl_injection_points, run_xss_scan

async def main():
    target = 'http://testphp.vulnweb.com/'
    print(f"Testing crawler on {target}")
    
    async with httpx.AsyncClient(timeout=15.0) as client:
        points = await crawl_injection_points(client, target, deep=True)
        print(f"Found {len(points)} points.")
        for p in points[:5]:
            print(f"- {p['method']} {p['url']} param={p['param']}")
            
    print("\nRunning full scan (quick mode)...")
    res = await run_xss_scan(target, scan_mode='quick')
    print(f"Total vulnerable: {res.get('total_vulnerable')}")
    if res.get('vulnerabilities'):
        for v in res['vulnerabilities'][:5]:
            print(f"[{v['severity']}] {v['method']} {v['parameter']} -> {v['payload']}")

if __name__ == "__main__":
    asyncio.run(main())
