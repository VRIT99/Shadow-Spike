import asyncio
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs

async def test_reflection(url, param, payload):
    async with httpx.AsyncClient() as client:
        # inject param
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        from urllib.parse import urlencode, urlunparse
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        print(f"Testing GET: {test_url}")
        resp = await client.get(test_url)
        
        # Check reflection
        from app.services.xss_service import check_reflection
        res = check_reflection(resp.text, payload)
        print(f"Reflection result for {payload}: {res}")

asyncio.run(test_reflection("http://testphp.vulnweb.com/listproducts.php?cat=1", "cat", "<script>alert(1)</script>"))
