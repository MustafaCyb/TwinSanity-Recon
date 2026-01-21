"""
TwinSanity Recon V2 - HTTP Probing Service
Probes subdomains to find alive hosts with status codes, titles, and tech detection.
"""
import asyncio
import aiohttp
import logging
import re
import socket
import ipaddress
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger("HTTPProber")

# SSRF Protection: Block internal/private IP ranges
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),       # Private Class A
    ipaddress.ip_network('172.16.0.0/12'),    # Private Class B
    ipaddress.ip_network('192.168.0.0/16'),   # Private Class C
    ipaddress.ip_network('127.0.0.0/8'),      # Localhost
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local / Cloud metadata
    ipaddress.ip_network('0.0.0.0/8'),        # Invalid
    ipaddress.ip_network('100.64.0.0/10'),    # Carrier-grade NAT
    ipaddress.ip_network('192.0.0.0/24'),     # IETF Protocol Assignments
    ipaddress.ip_network('192.0.2.0/24'),     # TEST-NET-1
    ipaddress.ip_network('198.51.100.0/24'),  # TEST-NET-2
    ipaddress.ip_network('203.0.113.0/24'),   # TEST-NET-3
    ipaddress.ip_network('224.0.0.0/4'),      # Multicast
    ipaddress.ip_network('240.0.0.0/4'),      # Reserved
]

def is_safe_target(hostname: str) -> bool:
    """Check if a hostname resolves to a safe (non-internal) IP address."""
    try:
        # Extract hostname from URL if needed
        if '://' in hostname:
            hostname = hostname.split('://')[1].split('/')[0].split(':')[0]
        
        # Resolve hostname to IP
        ip_str = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip_str)
        
        # Check against blocked networks
        for network in BLOCKED_IP_NETWORKS:
            if ip_obj in network:
                logger.warning(f"SSRF Protection: Blocked internal IP {ip_str} for hostname {hostname}")
                return False
        
        return True
    except (socket.gaierror, socket.herror):
        # DNS resolution failed - likely invalid hostname
        return True  # Let aiohttp handle the error
    except Exception as e:
        logger.debug(f"SSRF check failed for {hostname}: {e}")
        return True  # Fail open to avoid breaking legitimate scans


async def probe_single_host(
    session: aiohttp.ClientSession,
    url: str,
    timeout: int = 10
) -> Optional[Dict]:
    """
    Probe a single URL and extract useful information.
    Returns dict with url, status_code, title, technologies, response_time_ms.
    """
    start_time = asyncio.get_event_loop().time()
    
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as resp:
            end_time = asyncio.get_event_loop().time()
            response_time_ms = int((end_time - start_time) * 1000)
            
            # Read response body for title/tech detection
            try:
                body = await resp.text(errors='ignore')
            except Exception:
                body = ""
            
            # Extract title
            title = None
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()[:200]  # Limit length
            
            # Simple technology detection from headers and body
            technologies = []
            
            # Check headers for common technologies
            server = resp.headers.get('Server', '')
            if server:
                technologies.append(f"Server:{server}")
            
            x_powered = resp.headers.get('X-Powered-By', '')
            if x_powered:
                technologies.append(f"X-Powered-By:{x_powered}")
            
            # Check for common frameworks in body
            tech_patterns = [
                (r'wp-content|wordpress', 'WordPress'),
                (r'Drupal', 'Drupal'),
                (r'Laravel', 'Laravel'),
                (r'Django', 'Django'),
                (r'React', 'React'),
                (r'Vue\.js|vue@', 'Vue.js'),
                (r'Angular', 'Angular'),
                (r'jQuery', 'jQuery'),
                (r'Bootstrap', 'Bootstrap'),
                (r'Next\.js|__NEXT', 'Next.js'),
                (r'Nuxt', 'Nuxt.js'),
                (r'ASP\.NET', 'ASP.NET'),
                (r'CloudFlare', 'CloudFlare'),
                (r'nginx', 'nginx'),
                (r'Apache', 'Apache'),
            ]
            
            for pattern, tech in tech_patterns:
                if re.search(pattern, body, re.IGNORECASE) or re.search(pattern, server, re.IGNORECASE):
                    if tech not in technologies:
                        technologies.append(tech)
            
            return {
                "url": url,
                "status_code": resp.status,
                "title": title,
                "technologies": technologies,
                "content_length": len(body),
                "response_time_ms": response_time_ms,
                "redirect_url": str(resp.url) if str(resp.url) != url else None,
            }
            
    except asyncio.TimeoutError:
        logger.debug(f"Timeout probing {url}")
        return None
    except aiohttp.ClientError as e:
        logger.debug(f"Client error probing {url}: {e}")
        return None
    except Exception as e:
        logger.debug(f"Error probing {url}: {e}")
        return None


async def probe_hosts(
    subdomains: List[str],
    concurrency: int = 50,
    timeout: int = 10,
    protocols: List[str] = None
) -> List[Dict]:
    """
    Probe a list of subdomains to find alive hosts.
    
    Args:
        subdomains: List of subdomain hostnames
        concurrency: Maximum concurrent connections
        timeout: Timeout per request in seconds
        protocols: List of protocols to try (default: ['https', 'http'])
    
    Returns:
        List of alive hosts with metadata
    """
    if protocols is None:
        protocols = ['https', 'http']
    
    results = []
    seen_hosts = set()  # Avoid duplicates
    semaphore = asyncio.Semaphore(concurrency)
    
    async def probe_with_semaphore(url: str) -> Optional[Dict]:
        async with semaphore:
            return await probe_single_host(session, url, timeout)
    
    # Create connector with larger limits
    connector = aiohttp.TCPConnector(
        limit=concurrency,
        limit_per_host=5,
        ttl_dns_cache=300,
        ssl=False
    )
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        # Create tasks for all subdomains with both protocols
        tasks = []
        for subdomain in subdomains:
            subdomain = subdomain.strip().lower()
            if not subdomain:
                continue
            
            # SSRF Protection: Check if target is safe before probing
            if not is_safe_target(subdomain):
                logger.warning(f"Skipping internal/private target: {subdomain}")
                continue
                
            for protocol in protocols:
                url = f"{protocol}://{subdomain}"
                tasks.append(probe_with_semaphore(url))
        
        # Execute all tasks
        logger.info(f"Probing {len(tasks)} URLs across {len(subdomains)} subdomains...")
        
        probe_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in probe_results:
            if isinstance(result, Exception):
                continue
            if result and result.get("url"):
                # Deduplicate by hostname
                from urllib.parse import urlparse
                hostname = urlparse(result["url"]).netloc
                if hostname not in seen_hosts:
                    seen_hosts.add(hostname)
                    results.append(result)
    
    logger.info(f"Found {len(results)} alive hosts out of {len(subdomains)} subdomains")
    return results


async def save_probe_results(
    scan_id: str,
    results: List[Dict]
) -> int:
    """Save probe results to database."""
    import json
    from dashboard.database import get_db
    
    db = await get_db()
    
    count = 0
    async with __import__('aiosqlite').connect(db.db_path) as conn:
        for r in results:
            await conn.execute(
                """INSERT INTO alive_hosts 
                   (scan_id, url, status_code, title, technologies, content_length, response_time_ms, redirect_url, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    r.get("url"),
                    r.get("status_code"),
                    r.get("title"),
                    json.dumps(r.get("technologies", [])),
                    r.get("content_length"),
                    r.get("response_time_ms"),
                    r.get("redirect_url"),
                    datetime.now().isoformat()
                )
            )
            count += 1
        await conn.commit()
    
    logger.info(f"Saved {count} alive hosts for scan {scan_id}")
    return count


async def get_alive_hosts(scan_id: str) -> List[Dict]:
    """Get alive hosts for a scan from database."""
    import json
    import aiosqlite
    from dashboard.database import get_db
    
    db = await get_db()
    
    async with aiosqlite.connect(db.db_path) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM alive_hosts WHERE scan_id = ? ORDER BY status_code",
            (scan_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            results = []
            for row in rows:
                r = dict(row)
                if r.get("technologies"):
                    try:
                        r["technologies"] = json.loads(r["technologies"])
                    except:
                        r["technologies"] = []
                results.append(r)
            return results
