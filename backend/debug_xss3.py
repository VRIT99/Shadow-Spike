"""Debug script - diagnose exactly why scanner shows No XSS Found"""
import asyncio
import httpx
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.services.xss_service import (
    normalize_url, get_base_url, spider_all_pages,
    crawl_injection_points, check_reflection, inject_param, HEADERS, QUICK_PAYLOADS
)

TARGET = "http://testphp.vulnweb.com"  # Known vulnerable site

async def debug():
    print(f"\n{'='*60}")
    print(f"DEBUG: {TARGET}")
    print(f"{'='*60}\n")

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0) as client:

        # Step 1: Basic connectivity
        print("[1] Testing connectivity...")
        try:
            r = await client.get(TARGET, headers=HEADERS)
            print(f"    ✅ Status: {r.status_code}, Body length: {len(r.text)} chars")
        except Exception as e:
            print(f"    ❌ FAILED: {e}")
            return

        # Step 2: Spider
        print("\n[2] Spidering pages...")
        pages = await spider_all_pages(client, TARGET, deep=False)
        print(f"    Found {len(pages)} pages:")
        for p in pages[:10]:
            print(f"      - {p}")

        # Step 3: Crawl injection points
        print("\n[3] Crawling injection points...")
        points = await crawl_injection_points(client, pages)
        print(f"    Found {len(points)} injection points:")
        for pt in points[:15]:
            print(f"      - [{pt['method']}] {pt['url']} → param={pt['param']!r} type={pt['type']}")

        if not points:
            print("    ❌ NO INJECTION POINTS FOUND - This is the problem!")
            # Try direct URL
            print("\n[3b] Trying direct URL params...")
            direct = await crawl_injection_points(client, [TARGET, TARGET + "/search.php?test=1"])
            print(f"    Direct found: {len(direct)} points")
            for pt in direct[:5]:
                print(f"      - {pt}")
            return

        # Step 4: Test reflection on first few points
        print("\n[4] Testing payload reflection...")
        for pt in points[:5]:
            test_payload = "<script>alert(1)</script>"
            try:
                if pt['method'] == 'GET' or pt['type'] == 'url_param':
                    url = inject_param(pt['url'], pt['param'], test_payload)
                    r = await client.get(url, headers=HEADERS, follow_redirects=True, timeout=12.0)
                else:
                    data = dict(pt['fields'])
                    data[pt['param']] = test_payload
                    r = await client.post(pt['url'], data=data, headers=HEADERS, follow_redirects=True, timeout=12.0)

                result = check_reflection(r.text, test_payload)
                status = "✅ REFLECTED" if result['reflected'] else "❌ NOT reflected"
                print(f"    {status} | {pt['method']} {pt['url']} param={pt['param']!r}")
                if result['reflected']:
                    print(f"      Evidence: {result['evidence'][:100]}")
                else:
                    # Show what came back
                    idx = r.text.lower().find("script")
                    if idx > 0:
                        print(f"      Note: 'script' found at idx={idx}: {r.text[max(0,idx-20):idx+50]!r}")
                    else:
                        print(f"      Response snippet: {r.text[:200]!r}")
            except Exception as e:
                print(f"    ❌ Error: {e}")

asyncio.run(debug())
