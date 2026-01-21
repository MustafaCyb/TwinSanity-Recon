"""
TwinSanity Recon V2 - Tools Router
API endpoints for new bug bounty tools: HTTP probing, Nuclei scanning, URL harvesting.
"""
from fastapi import APIRouter, HTTPException, Request, BackgroundTasks, Depends
from pydantic import BaseModel
from typing import List, Optional

from dashboard.config import logger
from dashboard.middleware.auth import require_auth

router = APIRouter(prefix="/api/tools", tags=["Tools"])


# =============================================================================
# Request Models
# =============================================================================

class ProbeRequest(BaseModel):
    scan_id: str
    subdomains: Optional[List[str]] = None  # If not provided, uses scan's subdomains
    concurrency: int = 50
    timeout: int = 10


class NucleiRequest(BaseModel):
    scan_id: str
    targets: Optional[List[str]] = None  # If not provided, uses alive hosts
    templates: List[str] = ["cves", "exposed-panels", "misconfigurations"]
    severity: str = "critical,high"


class HarvestRequest(BaseModel):
    scan_id: str
    domain: Optional[str] = None  # If not provided, uses scan's domain
    sources: List[str] = ["wayback", "commoncrawl", "alienvault"]


# =============================================================================
# Authorization Helper
# =============================================================================

async def verify_scan_access(scan_id: str, request: Request):
    """Verify user has access to the scan. Returns the scan if authorized."""
    from dashboard.database import get_db
    
    db = await get_db()
    scan = await db.get_scan_by_id(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    user_id = getattr(request.state, 'user_id', None)
    is_super_admin = getattr(request.state, 'is_primary_admin', False)
    
    # Super admin can access all scans
    if is_super_admin:
        return scan
    
    # Check ownership or public visibility
    scan_owner = scan.get('user_id')
    visibility = scan.get('visibility', 'private')
    
    if scan_owner != user_id and visibility != 'public':
        raise HTTPException(status_code=403, detail="Access denied to this scan")
    
    return scan


# =============================================================================
# HTTP Probing Endpoints
# =============================================================================

@router.post("/probe")
async def probe_hosts_endpoint(request: ProbeRequest, req: Request, background_tasks: BackgroundTasks, _=Depends(require_auth)):
    """Start HTTP probing for a scan's subdomains."""
    from dashboard.services.httpx_prober import probe_hosts, save_probe_results
    import json
    
    scan = await verify_scan_access(request.scan_id, req)
    
    # Get subdomains from scan results if not provided
    subdomains = request.subdomains
    if not subdomains and scan.get("result_file"):
        try:
            from pathlib import Path
            result_file = Path(scan["result_file"])
            if result_file.exists():
                with open(result_file) as f:
                    data = json.load(f)
                    # Extract subdomains from results
                    subdomains = []
                    for key, value in data.items():
                        if isinstance(value, dict) and value.get("hostnames"):
                            subdomains.extend(value["hostnames"])
                    subdomains = list(set(subdomains))
        except Exception as e:
            logger.error(f"Failed to load subdomains from scan: {e}")
    
    if not subdomains:
        raise HTTPException(status_code=400, detail="No subdomains to probe")
    
    async def run_probe():
        try:
            results = await probe_hosts(
                subdomains,
                concurrency=request.concurrency,
                timeout=request.timeout
            )
            await save_probe_results(request.scan_id, results)
        except Exception as e:
            logger.error(f"Probe task failed: {e}")
    
    background_tasks.add_task(run_probe)
    
    return {
        "status": "started",
        "message": f"Probing {len(subdomains)} subdomains",
        "scan_id": request.scan_id
    }


@router.get("/probe/{scan_id}")
async def get_probe_results(scan_id: str, req: Request, _=Depends(require_auth)):
    """Get HTTP probing results for a scan."""
    from dashboard.services.httpx_prober import get_alive_hosts
    
    await verify_scan_access(scan_id, req)
    results = await get_alive_hosts(scan_id)
    
    return {
        "scan_id": scan_id,
        "count": len(results),
        "alive_hosts": results
    }


# =============================================================================
# Nuclei Scanning Endpoints
# =============================================================================

@router.post("/nuclei")
async def run_nuclei_endpoint(request: NucleiRequest, req: Request, background_tasks: BackgroundTasks, _=Depends(require_auth)):
    """Start Nuclei vulnerability scan."""
    from dashboard.services.nuclei_scanner import (
        check_nuclei_installed, run_nuclei_scan, run_python_vuln_checks, save_nuclei_findings
    )
    from dashboard.services.httpx_prober import get_alive_hosts
    
    await verify_scan_access(request.scan_id, req)
    
    # Get targets from alive hosts if not provided
    targets = request.targets
    if not targets:
        alive = await get_alive_hosts(request.scan_id)
        targets = [h["url"] for h in alive if h.get("url")]
    
    if not targets:
        raise HTTPException(status_code=400, detail="No targets for Nuclei scan. Run HTTP probing first.")
    
    nuclei_available = check_nuclei_installed()
    
    async def run_scan():
        try:
            if nuclei_available:
                findings = await run_nuclei_scan(
                    targets,
                    templates=request.templates,
                    severity=request.severity
                )
            else:
                logger.warning("Nuclei not installed, using Python-native checks")
                findings = await run_python_vuln_checks(targets)
            
            await save_nuclei_findings(request.scan_id, findings)
        except Exception as e:
            logger.error(f"Nuclei scan task failed: {e}")
    
    background_tasks.add_task(run_scan)
    
    return {
        "status": "started",
        "message": f"Scanning {len(targets)} targets",
        "nuclei_installed": nuclei_available,
        "scan_id": request.scan_id
    }


@router.get("/nuclei/{scan_id}")
async def get_nuclei_results(scan_id: str, req: Request, severity: str = None, _=Depends(require_auth)):
    """Get Nuclei scan results."""
    from dashboard.services.nuclei_scanner import get_nuclei_findings
    
    await verify_scan_access(scan_id, req)
    findings = await get_nuclei_findings(scan_id, severity)
    
    # Group by severity
    by_severity = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(f)
    
    return {
        "scan_id": scan_id,
        "total": len(findings),
        "by_severity": {k: len(v) for k, v in by_severity.items()},
        "findings": findings
    }


@router.get("/nuclei/status")
async def nuclei_status(_=Depends(require_auth)):
    """Check if Nuclei is installed."""
    from dashboard.services.nuclei_scanner import check_nuclei_installed, get_nuclei_version
    
    installed = check_nuclei_installed()
    version = get_nuclei_version() if installed else None
    
    return {
        "installed": installed,
        "version": version,
        "fallback_available": True,
        "message": "Nuclei is ready" if installed else "Nuclei not installed, Python fallback will be used"
    }


# =============================================================================
# URL Harvesting Endpoints
# =============================================================================

@router.post("/harvest")
async def harvest_urls_endpoint(request: HarvestRequest, req: Request, background_tasks: BackgroundTasks, _=Depends(require_auth)):
    """Start URL harvesting from historical sources."""
    from dashboard.services.url_harvester import harvest_urls, save_harvested_urls
    
    scan = await verify_scan_access(request.scan_id, req)
    
    # Get domain from scan if not provided
    domain = request.domain
    if not domain:
        domain = scan.get("domain")
    
    if not domain:
        raise HTTPException(status_code=400, detail="Domain not specified")
    
    async def run_harvest():
        try:
            results = await harvest_urls(domain, sources=request.sources)
            await save_harvested_urls(request.scan_id, results)
        except Exception as e:
            logger.error(f"URL harvest task failed: {e}")
    
    background_tasks.add_task(run_harvest)
    
    return {
        "status": "started",
        "message": f"Harvesting URLs for {domain}",
        "sources": request.sources,
        "scan_id": request.scan_id
    }


@router.get("/harvest/{scan_id}")
async def get_harvested_urls_endpoint(
    scan_id: str,
    req: Request,
    source: str = None,
    has_params: bool = None,
    extension: str = None,
    interesting_only: bool = False,
    _=Depends(require_auth)
):
    """Get harvested URLs for a scan."""
    from dashboard.services.url_harvester import get_harvested_urls, filter_interesting_urls
    
    await verify_scan_access(scan_id, req)
    urls = await get_harvested_urls(scan_id, source, has_params, extension)
    
    if interesting_only:
        urls = filter_interesting_urls(urls)
    
    # Group by source
    by_source = {}
    for u in urls:
        src = u.get("source", "unknown")
        if src not in by_source:
            by_source[src] = []
        by_source[src].append(u)
    
    return {
        "scan_id": scan_id,
        "total": len(urls),
        "by_source": {k: len(v) for k, v in by_source.items()},
        "urls": urls
    }


# =============================================================================
# Combined Status Endpoint
# =============================================================================

@router.get("/status/{scan_id}")
async def get_tools_status(scan_id: str, req: Request, _=Depends(require_auth)):
    """Get status of all tools for a scan."""
    from dashboard.services.httpx_prober import get_alive_hosts
    from dashboard.services.nuclei_scanner import get_nuclei_findings
    from dashboard.services.url_harvester import get_harvested_urls
    from dashboard.services.xss_scanner import get_xss_findings
    from dashboard.services.api_discovery import get_api_discoveries
    
    await verify_scan_access(scan_id, req)
    
    alive = await get_alive_hosts(scan_id)
    nuclei = await get_nuclei_findings(scan_id)
    urls = await get_harvested_urls(scan_id)
    xss = await get_xss_findings(scan_id)
    apis = await get_api_discoveries(scan_id)
    
    return {
        "scan_id": scan_id,
        "http_probing": {
            "count": len(alive),
            "status": "completed" if alive else "pending"
        },
        "nuclei_scan": {
            "count": len(nuclei),
            "critical": len([f for f in nuclei if f.get("severity") == "critical"]),
            "high": len([f for f in nuclei if f.get("severity") == "high"]),
            "status": "completed" if nuclei else "pending"
        },
        "url_harvesting": {
            "count": len(urls),
            "with_params": len([u for u in urls if u.get("has_params")]),
            "status": "completed" if urls else "pending"
        },
        "xss_scan": {
            "count": len(xss),
            "status": "completed" if xss else "pending"
        },
        "api_discovery": {
            "count": len(apis),
            "status": "completed" if apis else "pending"
        }
    }


# =============================================================================
# XSS Scanning Endpoints
# =============================================================================

class XSSRequest(BaseModel):
    scan_id: str
    urls: Optional[List[str]] = None  # If not provided, uses harvested URLs with params
    max_payloads: int = 5


@router.post("/xss")
async def run_xss_scan(request: XSSRequest, req: Request, background_tasks: BackgroundTasks, _=Depends(require_auth)):
    """Start XSS vulnerability scanning."""
    from dashboard.services.xss_scanner import scan_urls_for_xss, save_xss_findings
    from dashboard.services.url_harvester import get_harvested_urls
    
    await verify_scan_access(request.scan_id, req)
    
    # Get URLs with parameters from harvested URLs if not provided
    urls = request.urls
    if not urls:
        harvested = await get_harvested_urls(request.scan_id, has_params=True)
        urls = [u["url"] for u in harvested if u.get("url")]
    
    if not urls:
        raise HTTPException(status_code=400, detail="No URLs to scan. Run URL harvesting first.")
    
    async def run_scan():
        try:
            findings = await scan_urls_for_xss(urls, max_payloads=request.max_payloads)
            if findings:
                await save_xss_findings(request.scan_id, findings)
        except Exception as e:
            logger.error(f"XSS scan task failed: {e}")
    
    background_tasks.add_task(run_scan)
    
    return {
        "status": "started",
        "message": f"Scanning {len(urls)} URLs for XSS",
        "scan_id": request.scan_id
    }


@router.get("/xss/{scan_id}")
async def get_xss_results(scan_id: str, req: Request, _=Depends(require_auth)):
    """Get XSS scan results."""
    from dashboard.services.xss_scanner import get_xss_findings
    
    await verify_scan_access(scan_id, req)
    findings = await get_xss_findings(scan_id)
    
    return {
        "scan_id": scan_id,
        "total": len(findings),
        "findings": findings
    }


# =============================================================================
# API Discovery Endpoints
# =============================================================================

class APIDiscoveryRequest(BaseModel):
    scan_id: str
    targets: Optional[List[str]] = None  # If not provided, uses alive hosts


@router.post("/api-discovery")
async def run_api_discovery(request: APIDiscoveryRequest, req: Request, background_tasks: BackgroundTasks, _=Depends(require_auth)):
    """Start API endpoint discovery."""
    from dashboard.services.api_discovery import discover_apis, save_api_discoveries
    from dashboard.services.httpx_prober import get_alive_hosts
    
    await verify_scan_access(request.scan_id, req)
    
    # Get targets from alive hosts if not provided
    targets = request.targets
    if not targets:
        alive = await get_alive_hosts(request.scan_id)
        targets = [h["url"] for h in alive if h.get("url")]
    
    if not targets:
        raise HTTPException(status_code=400, detail="No targets for API discovery. Run HTTP probing first.")
    
    async def run_discovery():
        try:
            discoveries = await discover_apis(targets)
            if discoveries:
                await save_api_discoveries(request.scan_id, discoveries)
        except Exception as e:
            logger.error(f"API discovery task failed: {e}")
    
    background_tasks.add_task(run_discovery)
    
    return {
        "status": "started",
        "message": f"Discovering APIs on {len(targets)} targets",
        "scan_id": request.scan_id
    }


@router.get("/api-discovery/{scan_id}")
async def get_api_discovery_results(scan_id: str, req: Request, _=Depends(require_auth)):
    """Get API discovery results."""
    from dashboard.services.api_discovery import get_api_discoveries
    
    await verify_scan_access(scan_id, req)
    discoveries = await get_api_discoveries(scan_id)
    
    # Group by API type
    by_type = {}
    for d in discoveries:
        try:
            extracted = d.get("extracted_results", {})
            api_type = extracted.get("api_type", "unknown") if isinstance(extracted, dict) else "unknown"
        except:
            api_type = "unknown"
        if api_type not in by_type:
            by_type[api_type] = []
        by_type[api_type].append(d)
    
    return {
        "scan_id": scan_id,
        "total": len(discoveries),
        "by_type": {k: len(v) for k, v in by_type.items()},
        "discoveries": discoveries
    }


# =============================================================================
# Combined All Findings Endpoint
# =============================================================================
@router.get("/all-findings/{scan_id}")
async def get_all_findings(scan_id: str, req: Request, _=Depends(require_auth)):
    """Get all tool findings for a scan in one API call."""
    from dashboard.services.httpx_prober import get_alive_hosts
    from dashboard.services.nuclei_scanner import get_nuclei_findings
    from dashboard.services.url_harvester import get_harvested_urls
    from dashboard.services.xss_scanner import get_xss_findings
    from dashboard.services.api_discovery import get_api_discoveries
    
    await verify_scan_access(scan_id, req)
    
    alive_hosts = await get_alive_hosts(scan_id)
    nuclei_findings = await get_nuclei_findings(scan_id)
    harvested_urls = await get_harvested_urls(scan_id)
    xss_findings = await get_xss_findings(scan_id)
    api_discoveries = await get_api_discoveries(scan_id)
    
    total_findings = (
        len(alive_hosts) + len(nuclei_findings) + 
        len(harvested_urls) + len(xss_findings) + len(api_discoveries)
    )
    
    return {
        "scan_id": scan_id,
        "total_findings": total_findings,
        "alive_hosts": {
            "count": len(alive_hosts),
            "items": alive_hosts[:100]  # Limit for performance
        },
        "nuclei_findings": {
            "count": len(nuclei_findings),
            "items": nuclei_findings
        },
        "harvested_urls": {
            "count": len(harvested_urls),
            "items": harvested_urls  # Return ALL URLs - frontend handles scrolling
        },
        "xss_findings": {
            "count": len(xss_findings),
            "items": xss_findings
        },
        "api_discoveries": {
            "count": len(api_discoveries),
            "items": api_discoveries
        }
    }
