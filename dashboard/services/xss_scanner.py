"""
TwinSanity Recon V2 - XSS Scanner Service
Detects potential XSS vulnerabilities in URLs with parameters.
"""
import asyncio
import aiohttp
import logging
import re
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime

logger = logging.getLogger("XSSScanner")

# XSS Payload Library
XSS_PAYLOADS = [
    # Basic payloads
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    
    # Event handlers
    '" onmouseover="alert(1)"',
    "' onmouseover='alert(1)'",
    '" onfocus="alert(1)" autofocus="',
    
    # SVG payloads
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    
    # Encoded payloads
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '&lt;script&gt;alert(1)&lt;/script&gt;',
    
    # Polyglot payloads
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
    '<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
    
    # Template injection
    '{{constructor.constructor("alert(1)")()}}',
    '${alert(1)}',
    '#{alert(1)}',
]

# Detection patterns for reflected XSS
REFLECTION_PATTERNS = [
    r'<script[^>]*>.*?alert\s*\(',
    r'onerror\s*=\s*["\']?alert',
    r'onload\s*=\s*["\']?alert',
    r'onmouseover\s*=\s*["\']?alert',
    r'onfocus\s*=\s*["\']?alert',
    r'onclick\s*=\s*["\']?alert',
    r'<img[^>]+onerror',
    r'<svg[^>]+onload',
    r'javascript:\s*alert',
]


async def test_xss_payload(
    session: aiohttp.ClientSession,
    url: str,
    param: str,
    payload: str,
    timeout: int = 10
) -> Dict:
    """Test a single XSS payload against a URL parameter with strict validation."""
    try:
        # Parse URL and inject payload
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Inject payload into the target parameter
        original_value = params.get(param, [''])[0]
        params[param] = [payload]
        
        # Rebuild URL
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        
        async with session.get(
            test_url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            ssl=False
        ) as resp:
            if resp.status == 200:
                body = await resp.text(errors='ignore')
                content_type = resp.headers.get('content-type', '').lower()
                
                # Skip non-HTML responses (JSON, XML, etc are less likely XSS targets)
                if 'application/json' in content_type or 'application/xml' in content_type:
                    return {"vulnerable": False}
                
                # Check body size - very small or very large bodies are suspicious
                if len(body) < 100 or len(body) > 500000:
                    return {"vulnerable": False}
                
                # First check: STRICT pattern matching for actual XSS
                # Look for the payload being rendered in an executable context
                xss_confirmed = False
                evidence = ""
                
                for pattern in REFLECTION_PATTERNS:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        # Verify the match is within an HTML context, not just text
                        match_pos = match.start()
                        # Get surrounding context (200 chars before and after)
                        context_start = max(0, match_pos - 200)
                        context_end = min(len(body), match_pos + 200)
                        context = body[context_start:context_end]
                        
                        # Check if it's in a script or event handler context (not escaped)
                        # Look for signs it's NOT escaped
                        if any([
                            f'<script' in context.lower() and 'alert' in context.lower(),
                            f'onerror=' in context.lower() and 'alert' in context.lower(),
                            f'onload=' in context.lower() and 'alert' in context.lower(),
                            f'onmouseover=' in context.lower() and 'alert' in context.lower(),
                        ]):
                            # Check it's not HTML-encoded
                            if '&lt;script' not in context and '&lt;img' not in context:
                                xss_confirmed = True
                                evidence = f"Pattern matched: {pattern}"
                                break
                
                # Second check: Exact payload reflection (but verify it's not escaped)
                if not xss_confirmed and payload in body:
                    # Check if the payload is reflected in a dangerous context
                    payload_idx = body.find(payload)
                    if payload_idx != -1:
                        context_start = max(0, payload_idx - 50)
                        context_end = min(len(body), payload_idx + len(payload) + 50)
                        context = body[context_start:context_end]
                        
                        # The payload should NOT be HTML-encoded
                        encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
                        if encoded_payload not in body[context_start:context_end]:
                            # Check it's in an actual HTML element context
                            if '<' in context and '>' in context:
                                xss_confirmed = True
                                evidence = "Unescaped payload reflected in HTML context"
                
                if xss_confirmed:
                    return {
                        "vulnerable": True,
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": evidence,
                        "test_url": test_url,
                    }
                    
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        logger.debug(f"XSS test error for {url}: {e}")
    
    return {"vulnerable": False}


async def scan_url_for_xss(
    session: aiohttp.ClientSession,
    url: str,
    payloads: List[str] = None,
    max_payloads: int = 5
) -> List[Dict]:
    """Scan a single URL for XSS vulnerabilities."""
    if payloads is None:
        payloads = XSS_PAYLOADS[:max_payloads]
    
    findings = []
    
    # Parse URL to get parameters
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    
    if not params:
        return findings
    
    # Test each parameter with each payload
    for param in params:
        for payload in payloads:
            result = await test_xss_payload(session, url, param, payload)
            if result.get("vulnerable"):
                findings.append(result)
                # Stop testing this param after first finding
                break
    
    return findings


async def scan_urls_for_xss(
    urls: List[str],
    concurrency: int = 20,
    max_payloads: int = 5
) -> List[Dict]:
    """
    Scan multiple URLs for XSS vulnerabilities.
    
    Args:
        urls: List of URLs to test (preferably with parameters)
        concurrency: Max concurrent requests
        max_payloads: Max payloads to test per parameter
    
    Returns:
        List of XSS findings
    """
    # Filter URLs with parameters
    urls_with_params = [u for u in urls if '?' in u and '=' in u]
    
    if not urls_with_params:
        logger.info("No URLs with parameters to test for XSS")
        return []
    
    logger.info(f"Testing {len(urls_with_params)} URLs for XSS vulnerabilities...")
    
    all_findings = []
    semaphore = asyncio.Semaphore(concurrency)
    
    async def scan_with_semaphore(session, url):
        async with semaphore:
            return await scan_url_for_xss(session, url, max_payloads=max_payloads)
    
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TwinSanity-XSS-Scanner"
    }
    
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [scan_with_semaphore(session, url) for url in urls_with_params]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)
    
    logger.info(f"XSS scan complete: {len(all_findings)} potential vulnerabilities found")
    return all_findings


async def save_xss_findings(scan_id: str, findings: List[Dict]) -> int:
    """Save XSS findings to nuclei_findings table (using same schema)."""
    import aiosqlite
    import json
    from dashboard.database import get_db
    
    db = await get_db()
    count = 0
    
    async with aiosqlite.connect(db.db_path) as conn:
        for f in findings:
            await conn.execute(
                """INSERT INTO nuclei_findings 
                   (scan_id, template_id, name, severity, host, matched_at, extracted_results, curl_command, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    "xss-reflection",
                    f"XSS in {f.get('parameter', 'unknown')}",
                    "high",
                    f.get("url", ""),
                    f.get("test_url", ""),
                    json.dumps({"payload": f.get("payload"), "evidence": f.get("evidence")}),
                    f"curl -s '{f.get('test_url', '')}'",
                    datetime.now().isoformat()
                )
            )
            count += 1
        await conn.commit()
    
    logger.info(f"Saved {count} XSS findings for scan {scan_id}")
    return count


async def get_xss_findings(scan_id: str) -> List[Dict]:
    """Get XSS findings for a scan."""
    import aiosqlite
    import json
    from dashboard.database import get_db
    
    db = await get_db()
    
    async with aiosqlite.connect(db.db_path) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM nuclei_findings WHERE scan_id = ? AND template_id = 'xss-reflection' ORDER BY created_at",
            (scan_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            results = []
            for row in rows:
                r = dict(row)
                extracted = {}
                if r.get("extracted_results"):
                    try:
                        extracted = json.loads(r["extracted_results"])
                    except:
                        pass
                # Transform to frontend-expected format
                # name is "XSS in {param}", extract param
                param_name = r.get("name", "").replace("XSS in ", "") if r.get("name") else "unknown"
                results.append({
                    "id": r.get("id"),
                    "url": r.get("host", ""),
                    "parameter": param_name,
                    "payload": extracted.get("payload", ""),
                    "evidence": extracted.get("evidence", ""),
                    "test_url": r.get("matched_at", ""),
                    "severity": r.get("severity", "high"),
                    "created_at": r.get("created_at", "")
                })
            return results
