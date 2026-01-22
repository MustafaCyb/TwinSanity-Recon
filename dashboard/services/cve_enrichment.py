"""
TwinSanity Recon V2 - CVE Enrichment Service
Provides CVE verification, EPSS scoring, and KEV checking.
"""
import asyncio
import logging
import aiohttp
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass

logger = logging.getLogger("CVEEnrichment")


@dataclass
class EnrichedCVE:
    """Enriched CVE with verification and scoring data."""
    cve_id: str
    cvss: float
    summary: str
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    is_kev: bool = False
    kev_due_date: Optional[str] = None
    verified: bool = False
    affected_products: List[str] = None
    
    def __post_init__(self):
        if self.affected_products is None:
            self.affected_products = []


# Cache for KEV list (updates daily)
_kev_cache: Dict[str, dict] = {}
_kev_cache_time: Optional[datetime] = None


async def fetch_kev_catalog() -> Dict[str, dict]:
    """
    Fetch CISA Known Exploited Vulnerabilities catalog.
    https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    """
    global _kev_cache, _kev_cache_time
    
    # Check cache (valid for 24 hours)
    if _kev_cache and _kev_cache_time and (datetime.now() - _kev_cache_time) < timedelta(hours=24):
        return _kev_cache
    
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=30) as resp:
                if resp.status != 200:
                    logger.warning(f"Failed to fetch KEV catalog: HTTP {resp.status}")
                    return _kev_cache or {}
                
                data = await resp.json()
                
                # Build CVE -> KEV entry map
                kev_map = {}
                for vuln in data.get("vulnerabilities", []):
                    cve_id = vuln.get("cveID")
                    if cve_id:
                        kev_map[cve_id] = {
                            "vendor": vuln.get("vendorProject"),
                            "product": vuln.get("product"),
                            "due_date": vuln.get("dueDate"),
                            "notes": vuln.get("notes"),
                            "date_added": vuln.get("dateAdded")
                        }
                
                _kev_cache = kev_map
                _kev_cache_time = datetime.now()
                logger.info(f"KEV catalog loaded: {len(kev_map)} CVEs")
                return kev_map
                
    except Exception as e:
        logger.error(f"Error fetching KEV catalog: {e}")
        return _kev_cache or {}


async def fetch_epss_scores(cve_ids: List[str]) -> Dict[str, dict]:
    """
    Fetch EPSS (Exploit Prediction Scoring System) scores from FIRST.org.
    EPSS predicts the probability a CVE will be exploited in the next 30 days.
    """
    if not cve_ids:
        return {}
    
    epss_data = {}
    
    try:
        # Create single session for all requests (prevents connection leak)
        timeout = aiohttp.ClientTimeout(total=60, connect=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # EPSS API accepts multiple CVEs
            # Batch in groups of 100
            for i in range(0, len(cve_ids), 100):
                batch = cve_ids[i:i+100]
                cve_param = ",".join(batch)
                url = f"https://api.first.org/data/v1/epss?cve={cve_param}"
                
                try:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for item in data.get("data", []):
                                cve_id = item.get("cve")
                                if cve_id:
                                    epss_data[cve_id] = {
                                        "epss": float(item.get("epss", 0)),
                                        "percentile": float(item.get("percentile", 0))
                                    }
                except asyncio.TimeoutError:
                    logger.warning(f"EPSS fetch timeout for batch starting at {i}")
                except aiohttp.ClientError as e:
                    logger.warning(f"EPSS fetch error for batch: {e}")
                
                # Rate limit
                await asyncio.sleep(0.5)
        
        logger.info(f"EPSS scores fetched for {len(epss_data)} CVEs")
        
    except Exception as e:
        logger.error(f"Error fetching EPSS scores: {e}")
    
    return epss_data


def verify_cve_applicability(
    cve_id: str,
    cve_summary: str,
    detected_ports: List[int],
    detected_services: List[str]
) -> bool:
    """
    Verify if a CVE is likely applicable based on detected services.
    Reduces false positives from InternetDB/Shodan.
    """
    if not cve_summary:
        return False
    
    summary_lower = cve_summary.lower()
    
    # Service-specific keywords
    service_keywords = {
        "ssh": ["ssh", "openssh", "putty"],
        "http": ["http", "apache", "nginx", "iis", "web server", "httpd"],
        "https": ["ssl", "tls", "certificate", "https"],
        "ftp": ["ftp", "vsftpd", "proftpd", "filezilla"],
        "smtp": ["smtp", "mail", "postfix", "sendmail", "email"],
        "mysql": ["mysql", "mariadb", "database", "sql"],
        "postgresql": ["postgres", "postgresql", "database"],
        "redis": ["redis", "cache"],
        "mongodb": ["mongodb", "mongo", "nosql"],
        "rdp": ["rdp", "remote desktop", "terminal service"],
        "smb": ["smb", "samba", "cifs", "windows share"],
        "ldap": ["ldap", "active directory", "directory service"],
        "dns": ["dns", "bind", "domain name"],
    }
    
    # Port to service mapping
    port_services = {
        22: "ssh", 80: "http", 443: "https", 21: "ftp",
        25: "smtp", 3306: "mysql", 5432: "postgresql",
        6379: "redis", 27017: "mongodb", 3389: "rdp",
        445: "smb", 389: "ldap", 53: "dns"
    }
    
    # Get services from ports
    services_from_ports = set()
    for port in detected_ports:
        if port in port_services:
            services_from_ports.add(port_services[port])
    
    # Combine with detected services
    all_services = services_from_ports.union(set(s.lower() for s in detected_services))
    
    # Check if CVE relates to any detected service
    for service in all_services:
        if service in service_keywords:
            for keyword in service_keywords[service]:
                if keyword in summary_lower:
                    return True
    
    # Also check for generic terms that always apply
    generic_terms = ["remote code execution", "rce", "authentication bypass", "privilege escalation"]
    for term in generic_terms:
        if term in summary_lower:
            return True
    
    return False


async def enrich_cves(
    cves: List[dict],
    detected_ports: List[int] = None,
    detected_services: List[str] = None,
    verify: bool = True
) -> List[EnrichedCVE]:
    """
    Enrich CVE data with EPSS scores, KEV status, and verification.
    """
    if not cves:
        return []
    
    detected_ports = detected_ports or []
    detected_services = detected_services or []
    
    # Extract CVE IDs
    cve_ids = [c.get("id") or c.get("cve_id") for c in cves if c.get("id") or c.get("cve_id")]
    
    # Fetch enrichment data concurrently
    kev_task = fetch_kev_catalog()
    epss_task = fetch_epss_scores(cve_ids)
    
    kev_data, epss_data = await asyncio.gather(kev_task, epss_task)
    
    # Enrich each CVE
    enriched = []
    for cve in cves:
        cve_id = cve.get("id") or cve.get("cve_id")
        if not cve_id:
            continue
        
        summary = cve.get("summary") or cve.get("description") or ""
        cvss = float(cve.get("cvss") or cve.get("cvss3") or 0)
        
        # Verify applicability if requested
        is_verified = True
        if verify and summary:
            is_verified = verify_cve_applicability(
                cve_id, summary, detected_ports, detected_services
            )
        
        # Get EPSS data
        epss_info = epss_data.get(cve_id, {})
        epss_score = epss_info.get("epss", 0)
        epss_percentile = epss_info.get("percentile", 0)
        
        # Check KEV
        kev_info = kev_data.get(cve_id)
        is_kev = kev_info is not None
        kev_due_date = kev_info.get("due_date") if kev_info else None
        
        # Get affected products
        products = []
        if kev_info:
            products.append(f"{kev_info.get('vendor', '')} {kev_info.get('product', '')}".strip())
        
        enriched.append(EnrichedCVE(
            cve_id=cve_id,
            cvss=cvss,
            summary=summary,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            is_kev=is_kev,
            kev_due_date=kev_due_date,
            verified=is_verified,
            affected_products=products
        ))
    
    # Sort by priority: KEV first, then EPSS, then CVSS
    enriched.sort(key=lambda x: (
        not x.is_kev,  # KEV first
        -x.epss_score,  # Higher EPSS first
        -x.cvss  # Higher CVSS first
    ))
    
    logger.info(f"Enriched {len(enriched)} CVEs: {sum(1 for c in enriched if c.is_kev)} KEV, "
                f"{sum(1 for c in enriched if c.epss_score > 0.1)} high-EPSS")
    
    return enriched


def calculate_risk_score(enriched_cve: EnrichedCVE) -> float:
    """
    Calculate a combined risk score (0-100) based on multiple factors.
    """
    score = 0.0
    
    # CVSS contribution (0-40 points)
    score += min(enriched_cve.cvss * 4, 40)
    
    # EPSS contribution (0-30 points)
    # EPSS > 0.1 (10%) is considered high risk
    score += min(enriched_cve.epss_score * 300, 30)
    
    # KEV bonus (20 points)
    if enriched_cve.is_kev:
        score += 20
    
    # Verification bonus (10 points)
    if enriched_cve.verified:
        score += 10
    
    return min(score, 100)


async def get_priority_cves(
    cves: List[dict],
    limit: int = 20
) -> List[EnrichedCVE]:
    """
    Get top priority CVEs based on risk scoring.
    Returns enriched CVEs sorted by risk score.
    """
    enriched = await enrich_cves(cves, verify=False)
    
    # Calculate risk scores
    for cve in enriched:
        cve.risk_score = calculate_risk_score(cve)
    
    # Sort by risk score
    enriched.sort(key=lambda x: -getattr(x, 'risk_score', 0))
    
    return enriched[:limit]
