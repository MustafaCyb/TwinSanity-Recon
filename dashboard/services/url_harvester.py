"""
TwinSanity Recon V2 - URL Harvester Service
Harvests historical and archived URLs from Wayback Machine and CommonCrawl.
"""
import asyncio
import aiohttp
import logging
import re
from typing import List, Dict, Set
from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger("URLHarvester")


async def fetch_wayback_urls(
    session: aiohttp.ClientSession,
    domain: str,
    timeout: int = 60
) -> Set[str]:
    """
    Fetch URLs from Wayback Machine CDX API.
    """
    urls = set()
    
    try:
        api_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
        
        async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status == 200:
                text = await resp.text()
                for line in text.splitlines():
                    url = line.strip()
                    if url and domain in url:
                        urls.add(url)
                        
        logger.info(f"Wayback Machine returned {len(urls)} URLs for {domain}")
        
    except asyncio.TimeoutError:
        logger.warning(f"Timeout fetching Wayback URLs for {domain}")
    except Exception as e:
        logger.error(f"Error fetching Wayback URLs: {e}")
    
    return urls


async def fetch_commoncrawl_urls(
    session: aiohttp.ClientSession,
    domain: str,
    timeout: int = 60
) -> Set[str]:
    """
    Fetch URLs from CommonCrawl index.
    """
    urls = set()
    
    try:
        # Get the latest index
        index_url = "https://index.commoncrawl.org/collinfo.json"
        async with session.get(index_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                return urls
            indexes = await resp.json()
        
        if not indexes:
            return urls
        
        # Use the most recent index
        latest_index = indexes[0]["cdx-api"]
        
        # Query for our domain
        query_url = f"{latest_index}?url=*.{domain}&output=json"
        async with session.get(query_url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status == 200:
                text = await resp.text()
                for line in text.splitlines():
                    try:
                        import json
                        data = json.loads(line)
                        url = data.get("url", "")
                        if url and domain in url:
                            urls.add(url)
                    except:
                        continue
        
        logger.info(f"CommonCrawl returned {len(urls)} URLs for {domain}")
        
    except asyncio.TimeoutError:
        logger.warning(f"Timeout fetching CommonCrawl URLs for {domain}")
    except Exception as e:
        logger.error(f"Error fetching CommonCrawl URLs: {e}")
    
    return urls


async def fetch_alienvault_urls(
    session: aiohttp.ClientSession,
    domain: str,
    timeout: int = 30
) -> Set[str]:
    """
    Fetch URLs from AlienVault OTX.
    """
    urls = set()
    
    try:
        api_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500"
        
        async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status == 200:
                data = await resp.json()
                url_list = data.get("url_list", [])
                for item in url_list:
                    url = item.get("url", "")
                    if url:
                        urls.add(url)
                        
        logger.info(f"AlienVault returned {len(urls)} URLs for {domain}")
        
    except Exception as e:
        logger.debug(f"AlienVault error (may not be available): {e}")
    
    return urls


def extract_url_info(url: str) -> Dict:
    """Extract useful information from a URL."""
    parsed = urlparse(url)
    
    # Get extension
    path = parsed.path
    extension = None
    if '.' in path:
        extension = path.rsplit('.', 1)[-1].lower()
        if len(extension) > 10 or '/' in extension:
            extension = None
    
    # Check if has parameters
    has_params = bool(parsed.query)
    
    return {
        "extension": extension,
        "has_params": has_params,
    }


async def harvest_urls(
    domain: str,
    sources: List[str] = None,
    timeout: int = 60
) -> Dict[str, List[Dict]]:
    """
    Harvest URLs from multiple sources.
    
    Args:
        domain: Target domain
        sources: List of sources to use (default: all)
        timeout: Timeout per source
    
    Returns:
        Dict with source -> list of URL dicts
    """
    if sources is None:
        sources = ["wayback", "commoncrawl", "alienvault"]
    
    results = {}
    
    connector = aiohttp.TCPConnector(limit=10, ssl=False)
    headers = {
        "User-Agent": "TwinSanity-Recon/2.0"
    }
    
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = {}
        
        if "wayback" in sources:
            tasks["wayback"] = fetch_wayback_urls(session, domain, timeout)
        if "commoncrawl" in sources:
            tasks["commoncrawl"] = fetch_commoncrawl_urls(session, domain, timeout)
        if "alienvault" in sources:
            tasks["alienvault"] = fetch_alienvault_urls(session, domain, timeout)
        
        # Execute all in parallel
        source_results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        
        all_urls = set()
        for source_name, result in zip(tasks.keys(), source_results):
            if isinstance(result, Exception):
                logger.error(f"Error from {source_name}: {result}")
                results[source_name] = []
            else:
                source_urls = []
                for url in result:
                    if url not in all_urls:
                        all_urls.add(url)
                        info = extract_url_info(url)
                        source_urls.append({
                            "url": url,
                            "source": source_name,
                            **info
                        })
                results[source_name] = source_urls
    
    total = sum(len(v) for v in results.values())
    logger.info(f"Harvested {total} unique URLs from {len(sources)} sources for {domain}")
    
    return results


async def save_harvested_urls(
    scan_id: str,
    results: Dict[str, List[Dict]]
) -> int:
    """Save harvested URLs to database."""
    import aiosqlite
    from dashboard.database import get_db
    
    db = await get_db()
    
    count = 0
    async with aiosqlite.connect(db.db_path) as conn:
        for source, urls in results.items():
            for item in urls:
                await conn.execute(
                    """INSERT INTO harvested_urls 
                       (scan_id, url, source, has_params, extension, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        scan_id,
                        item.get("url"),
                        item.get("source"),
                        item.get("has_params", False),
                        item.get("extension"),
                        datetime.now().isoformat()
                    )
                )
                count += 1
        await conn.commit()
    
    logger.info(f"Saved {count} harvested URLs for scan {scan_id}")
    return count


async def get_harvested_urls(
    scan_id: str,
    source: str = None,
    has_params: bool = None,
    extension: str = None
) -> List[Dict]:
    """Get harvested URLs for a scan with optional filters."""
    import aiosqlite
    from dashboard.database import get_db
    
    db = await get_db()
    
    query = "SELECT * FROM harvested_urls WHERE scan_id = ?"
    params = [scan_id]
    
    if source:
        query += " AND source = ?"
        params.append(source)
    
    if has_params is not None:
        query += " AND has_params = ?"
        params.append(has_params)
    
    if extension:
        query += " AND extension = ?"
        params.append(extension)
    
    query += " ORDER BY created_at"
    
    async with aiosqlite.connect(db.db_path) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


def filter_interesting_urls(urls: List[Dict]) -> List[Dict]:
    """Filter URLs to find potentially interesting endpoints."""
    interesting_extensions = {
        'js', 'json', 'xml', 'yml', 'yaml', 'config', 'conf',
        'bak', 'backup', 'old', 'sql', 'db', 'log', 'txt',
        'php', 'asp', 'aspx', 'jsp', 'do', 'action',
        'api', 'graphql', 'rest', 'swagger', 'openapi'
    }
    
    interesting_patterns = [
        r'/api/', r'/v1/', r'/v2/', r'/v3/',
        r'/admin', r'/debug', r'/test', r'/dev',
        r'/config', r'/backup', r'/internal',
        r'\.env', r'\.git', r'\.svn',
        r'/graphql', r'/swagger', r'/docs',
    ]
    
    results = []
    
    for item in urls:
        url = item.get("url", "")
        ext = item.get("extension", "")
        
        is_interesting = False
        
        # Check extension
        if ext and ext.lower() in interesting_extensions:
            is_interesting = True
        
        # Check patterns
        for pattern in interesting_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                is_interesting = True
                break
        
        # URLs with parameters are interesting for testing
        if item.get("has_params"):
            is_interesting = True
        
        if is_interesting:
            results.append(item)
    
    return results
