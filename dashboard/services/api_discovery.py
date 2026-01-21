"""
TwinSanity Recon V2 - API Discovery Service
Discovers hidden API endpoints using wordlists and pattern matching.
"""
import asyncio
import aiohttp
import logging
import json
from typing import List, Dict
from urllib.parse import urljoin
from datetime import datetime

logger = logging.getLogger("APIDiscovery")

# Common API paths to check
API_PATHS = [
    # Documentation endpoints
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger-ui.html",
    "/api-docs",
    "/api-docs.json",
    "/openapi.json",
    "/openapi/v3/api-docs",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs",
    "/redoc",
    
    # GraphQL endpoints
    "/graphql",
    "/graphiql",
    "/graphql/console",
    "/graphql/playground",
    "/api/graphql",
    "/v1/graphql",
    
    # Common API prefixes
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/rest/",
    "/rest/v1/",
    "/json/",
    
    # Health/Status endpoints
    "/health",
    "/healthz",
    "/healthcheck",
    "/status",
    "/api/health",
    "/api/status",
    "/ping",
    "/ready",
    "/live",
    
    # Common API resources
    "/api/users",
    "/api/user",
    "/api/accounts",
    "/api/account",
    "/api/config",
    "/api/settings",
    "/api/admin",
    "/api/login",
    "/api/auth",
    "/api/token",
    "/api/oauth",
    "/api/sessions",
    "/api/uploads",
    "/api/files",
    "/api/search",
    "/api/export",
    "/api/import",
    
    # Debug/Development endpoints
    "/debug",
    "/debug/vars",
    "/debug/pprof",
    "/env",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/configprops",
    "/actuator/info",
    "/metrics",
    "/prometheus",
    "/api/metrics",
    
    # Common framework paths
    "/.well-known/openid-configuration",
    "/oauth/.well-known/openid-configuration",
    "/realms/master/.well-known/openid-configuration",
    "/ws",
    "/websocket",
    "/socket.io",
    "/hub",
    "/signalr",
    
    # Hidden/Internal
    "/_internal",
    "/_admin",
    "/_api",
    "/_debug",
    "/_status",
    "/internal/",
    "/private/",
    "/admin/api",
]


async def check_api_endpoint(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
    timeout: int = 10
) -> Dict:
    """Check if an API endpoint exists and gather info with strict validation."""
    url = urljoin(base_url, path)
    
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            ssl=False,
            allow_redirects=False
        ) as resp:
            
            content_type = resp.headers.get('Content-Type', '').lower()
            content_length = int(resp.headers.get('Content-Length', 0))
            
            # Read body for validation
            body = ""
            body_preview = ""
            if resp.status == 200:
                try:
                    body = await resp.text(errors='ignore')
                    body_preview = body[:200] if len(body) > 200 else body
                except:
                    pass
            
            # STRICT VALIDATION: Only count as found if it's a real API
            is_valid_api = False
            api_type = "unknown"
            
            # 200 OK - Must have proper content
            if resp.status == 200:
                # JSON APIs
                if 'application/json' in content_type:
                    is_valid_api = True
                    api_type = "rest-json"
                # Swagger/OpenAPI docs
                elif ("swagger" in path.lower() or "openapi" in path.lower()) and ("swagger" in body.lower() or "openapi" in body.lower() or '{"' in body):
                    is_valid_api = True
                    api_type = "openapi"
                # GraphQL
                elif "graphql" in path.lower() and ("graphql" in body.lower() or "query" in body.lower()):
                    is_valid_api = True
                    api_type = "graphql"
                # Spring Actuator
                elif "actuator" in path.lower() and ('{"' in body or 'actuator' in body.lower()):
                    is_valid_api = True
                    api_type = "spring-actuator"
                # Health/Status endpoints with JSON
                elif path in ["/health", "/healthz", "/status", "/ping", "/ready", "/live"] and ('{"' in body or content_length < 500):
                    is_valid_api = True
                    api_type = "health-check"
            # 401/403 - Protected endpoints (still valid discoveries)
            elif resp.status in [401, 403]:
                # Only count if it's an API endpoint, not a generic login page
                if content_length < 5000 and ('json' in content_type or 'api' in path.lower() or 'unauthorized' in body.lower()[:200]):
                    is_valid_api = True
                    api_type = "protected"
            # 301/302 redirects - Only if redirecting to API-like URLs
            elif resp.status in [301, 302]:
                location = resp.headers.get('Location', '')
                if 'api' in location.lower() or 'swagger' in location.lower() or 'docs' in location.lower():
                    is_valid_api = True
                    api_type = "redirect"
            
            if is_valid_api:
                return {
                    "found": True,
                    "url": url,
                    "path": path,
                    "status_code": resp.status,
                    "content_type": content_type,
                    "api_type": api_type,
                    "body_preview": body_preview,
                    "content_length": len(body) if body else content_length,
                }
                
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        logger.debug(f"API check error for {url}: {e}")
    
    return {"found": False}


async def discover_apis(
    targets: List[str],
    paths: List[str] = None,
    concurrency: int = 30,
    timeout: int = 10
) -> List[Dict]:
    """
    Discover API endpoints on targets.
    
    Args:
        targets: List of base URLs to scan
        paths: Custom list of paths to check (default: built-in list)
        concurrency: Max concurrent requests
        timeout: Timeout per request
    
    Returns:
        List of discovered API endpoints
    """
    if paths is None:
        paths = API_PATHS
    
    if not targets:
        return []
    
    logger.info(f"Discovering APIs on {len(targets)} targets with {len(paths)} paths...")
    
    discoveries = []
    semaphore = asyncio.Semaphore(concurrency)
    
    async def check_with_semaphore(session, base_url, path):
        async with semaphore:
            return await check_api_endpoint(session, base_url, path, timeout)
    
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TwinSanity-API-Discovery",
        "Accept": "application/json, text/html, */*"
    }
    
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = []
        for target in targets:
            # Normalize target URL
            if not target.startswith(('http://', 'https://')):
                target = f"https://{target}"
            
            for path in paths:
                tasks.append(check_with_semaphore(session, target, path))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, dict) and result.get("found"):
                discoveries.append(result)
    
    logger.info(f"API discovery complete: {len(discoveries)} endpoints found")
    return discoveries


async def detect_openapi_spec(
    session: aiohttp.ClientSession,
    url: str
) -> Dict:
    """Attempt to fetch and parse OpenAPI/Swagger spec."""
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=15),
            ssl=False
        ) as resp:
            if resp.status == 200:
                text = await resp.text()
                try:
                    spec = json.loads(text)
                    
                    # Extract info from OpenAPI spec
                    info = spec.get("info", {})
                    paths = list(spec.get("paths", {}).keys())
                    
                    return {
                        "valid": True,
                        "url": url,
                        "title": info.get("title", "Unknown"),
                        "version": info.get("version", "Unknown"),
                        "description": info.get("description", "")[:200],
                        "paths_count": len(paths),
                        "sample_paths": paths[:10],
                        "openapi_version": spec.get("openapi") or spec.get("swagger", "Unknown"),
                    }
                except json.JSONDecodeError:
                    pass
    except:
        pass
    
    return {"valid": False}


async def save_api_discoveries(scan_id: str, discoveries: List[Dict]) -> int:
    """Save API discoveries to database."""
    import aiosqlite
    from dashboard.database import get_db
    
    db = await get_db()
    count = 0
    
    async with aiosqlite.connect(db.db_path) as conn:
        for d in discoveries:
            await conn.execute(
                """INSERT INTO nuclei_findings 
                   (scan_id, template_id, name, severity, host, matched_at, extracted_results, curl_command, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    f"api-discovery-{d.get('api_type', 'unknown')}",
                    f"API Endpoint: {d.get('path', '')}",
                    "info" if d.get("status_code") == 200 else "low",
                    d.get("url", ""),
                    d.get("url", ""),
                    json.dumps({
                        "status_code": d.get("status_code"),
                        "content_type": d.get("content_type"),
                        "api_type": d.get("api_type"),
                        "body_preview": d.get("body_preview", "")[:100],
                    }),
                    f"curl -s '{d.get('url', '')}'",
                    datetime.now().isoformat()
                )
            )
            count += 1
        await conn.commit()
    
    logger.info(f"Saved {count} API discoveries for scan {scan_id}")
    return count


async def get_api_discoveries(scan_id: str) -> List[Dict]:
    """Get API discoveries for a scan."""
    import aiosqlite
    from dashboard.database import get_db
    
    db = await get_db()
    
    async with aiosqlite.connect(db.db_path) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM nuclei_findings WHERE scan_id = ? AND template_id LIKE 'api-discovery-%' ORDER BY created_at",
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
                results.append({
                    "id": r.get("id"),
                    "url": r.get("host", ""),
                    "path": r.get("name", "").replace("API Endpoint: ", ""),
                    "status_code": extracted.get("status_code", 200),
                    "content_type": extracted.get("content_type", ""),
                    "api_type": extracted.get("api_type", "unknown"),
                    "severity": r.get("severity", "info"),
                    "created_at": r.get("created_at", "")
                })
            return results


# Convenience function to run full API discovery on a scan
async def run_api_discovery_on_scan(scan_id: str) -> int:
    """Run API discovery on alive hosts from a scan."""
    from dashboard.services.httpx_prober import get_alive_hosts
    
    alive = await get_alive_hosts(scan_id)
    targets = [h["url"] for h in alive if h.get("url")]
    
    if not targets:
        logger.warning(f"No targets for API discovery on scan {scan_id}")
        return 0
    
    discoveries = await discover_apis(targets)
    
    if discoveries:
        await save_api_discoveries(scan_id, discoveries)
    
    return len(discoveries)
