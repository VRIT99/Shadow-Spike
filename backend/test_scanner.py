import asyncio
from app.services.xss_service import run_xss_scan

async def main():
    res = await run_xss_scan('http://127.0.0.1:8001/', 'quick')
    print('Vulnerabilities found:', len(res['vulnerabilities']))
    for v in res['vulnerabilities']:
        print(f"- {v['method']} {v['parameter']} : {v['payload']}")

asyncio.run(main())
