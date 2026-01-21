"""
TwinSanity Recon V2 - Shodan Router
API endpoints for Shodan integration with proper error handling and security.
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import List, Optional
import re
import logging

logger = logging.getLogger("ShodanRouter")

router = APIRouter(prefix="/api/shodan", tags=["Shodan"])


# =============================================================================
# Request Models with Validation
# =============================================================================

class ShodanApiKeyRequest(BaseModel):
    api_key: str = Field(..., min_length=20, max_length=64)
    
    @validator('api_key')
    def validate_api_key(cls, v):
        if not re.match(r'^[a-zA-Z0-9]+$', v):
            raise ValueError('Invalid API key format')
        return v.strip()


class SearchRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=500)
    page: int = Field(default=1, ge=1, le=100)
    facets: Optional[str] = Field(default=None, max_length=200)


class DnsResolveRequest(BaseModel):
    hostnames: List[str] = Field(..., min_items=1, max_items=100)


class DnsReverseRequest(BaseModel):
    ips: List[str] = Field(..., min_items=1, max_items=100)


class ScanRequest(BaseModel):
    ips: List[str] = Field(..., min_items=1, max_items=50)


class ExploitSearchRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=200)
    page: int = Field(default=1, ge=1, le=50)


# =============================================================================
# API Status & Configuration
# =============================================================================

@router.get("/status")
async def get_shodan_status():
    """Get Shodan API status and account information. Auto-loads from config."""
    from dashboard.services.shodan_api import get_shodan_client
    
    try:
        client = get_shodan_client()
        status = await client.initialize(force=True)
        
        return {
            "configured": status.configured,
            "valid": status.valid,
            "plan": status.plan.value,
            "plan_display": status.plan_name,
            "query_credits": status.query_credits,
            "scan_credits": status.scan_credits,
            "monitored_ips": status.monitored_ips,
            "monitored_ips_limit": status.monitored_ips_limit,
            "unlocked": status.unlocked,
            "unlocked_left": status.unlocked_left,
            "error": status.error,
            "features": client.get_features()
        }
    except Exception as e:
        logger.error(f"Shodan status error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "valid": False, "configured": False}
        )


@router.post("/configure")
async def configure_shodan_api(request: ShodanApiKeyRequest):
    """Configure Shodan API key and validate it."""
    from dashboard.services.shodan_api import reinitialize_shodan_client
    from dashboard.config import update_config
    
    try:
        client = await reinitialize_shodan_client(request.api_key)
        status = await client.get_status()
        
        if status.valid:
            update_config("api_keys.shodan", request.api_key)
            return {
                "success": True,
                "message": f"API key configured! Plan: {status.plan_name}",
                "plan": status.plan.value,
                "plan_display": status.plan_name,
                "query_credits": status.query_credits,
                "scan_credits": status.scan_credits
            }
        else:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": status.error or "Invalid API key"}
            )
    except ValueError as e:
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})
    except Exception as e:
        logger.error(f"Shodan configure error: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})


@router.get("/features")
async def get_available_features():
    """Get list of features available for current plan."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    status = await client.get_status()
    features = client.get_features()
    
    return {
        "plan": status.plan.value,
        "plan_display": status.plan_name,
        "features": features,
        "credits": {
            "query": status.query_credits,
            "scan": status.scan_credits
        }
    }


# =============================================================================
# Host Lookup Endpoints
# =============================================================================

@router.get("/host/{ip}")
async def lookup_host(ip: str, history: bool = False):
    """Look up information about a specific IP address."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    data, error = await client.host_lookup(ip, history=history)
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    return data


@router.get("/internetdb/{ip}")
async def lookup_internetdb(ip: str):
    """Free InternetDB lookup (no API key required)."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    data, error = await client.internetdb_lookup(ip)
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    return data


@router.get("/quick/{ip}")
async def quick_ip_lookup(ip: str):
    """
    Quick IP lookup - uses full API if available, falls back to InternetDB.
    """
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    status = await client.get_status()
    
    result = {
        "ip": ip,
        "source": "internetdb",
        "plan": status.plan.value,
        "ports": [],
        "hostnames": [],
        "vulns": [],
        "cpes": [],
        "tags": [],
        "country": None,
        "city": None,
        "org": None,
        "isp": None,
        "asn": None,
        "os": None,
        "last_update": None,
        "services": []
    }
    
    # Try full Shodan API first if we have a paid plan
    if status.valid and status.plan.value != "free":
        data, error = await client.host_lookup(ip)
        if data and not error:
            result["source"] = "shodan"
            result["ports"] = data.get("ports", [])
            result["hostnames"] = data.get("hostnames", [])
            result["vulns"] = data.get("vulns", [])
            result["tags"] = data.get("tags", [])
            result["country"] = data.get("country_name") or data.get("country_code")
            result["city"] = data.get("city")
            result["org"] = data.get("org")
            result["isp"] = data.get("isp")
            result["asn"] = data.get("asn")
            result["os"] = data.get("os")
            result["last_update"] = data.get("last_update")
            if "data" in data:
                for svc in data["data"][:20]:
                    result["services"].append({
                        "port": svc.get("port"),
                        "transport": svc.get("transport"),
                        "product": svc.get("product"),
                        "version": svc.get("version"),
                        "banner": (svc.get("data") or "")[:200]
                    })
            return result
    
    # Fallback to InternetDB (free)
    data, error = await client.internetdb_lookup(ip)
    if data and not error:
        result["ports"] = data.get("ports", [])
        result["hostnames"] = data.get("hostnames", [])
        result["vulns"] = data.get("vulns", [])
        result["cpes"] = data.get("cpes", [])
        result["tags"] = data.get("tags", [])
    elif error:
        result["error"] = error
    
    return result


# =============================================================================
# Search Endpoints
# =============================================================================

@router.post("/search")
async def search_shodan(request: SearchRequest):
    """Search Shodan (requires query credits)."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    status = await client.get_status()
    
    if not status.valid:
        raise HTTPException(status_code=400, detail="Shodan API not configured or invalid")
    
    if status.query_credits <= 0:
        raise HTTPException(status_code=402, detail="No query credits remaining")
    
    data, error = await client.search(
        query=request.query,
        page=request.page,
        facets=request.facets
    )
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    matches = []
    for m in (data.get("matches") or [])[:50]:
        matches.append({
            "ip": m.get("ip_str"),
            "port": m.get("port"),
            "transport": m.get("transport"),
            "hostnames": m.get("hostnames", []),
            "org": m.get("org"),
            "isp": m.get("isp"),
            "asn": m.get("asn"),
            "country": m.get("location", {}).get("country_name"),
            "city": m.get("location", {}).get("city"),
            "product": m.get("product"),
            "version": m.get("version"),
            "os": m.get("os"),
            "banner": (m.get("data") or "")[:300]
        })
    
    return {
        "total": data.get("total", 0),
        "matches": matches,
        "facets": data.get("facets", {}),
        "query": request.query,
        "page": request.page,
        "credits_remaining": status.query_credits - 1
    }


@router.get("/search/count")
async def search_count(query: str):
    """Get count of results without using query credits."""
    from dashboard.services.shodan_api import get_shodan_client
    
    if len(query) < 2:
        raise HTTPException(status_code=400, detail="Query too short")
    
    client = get_shodan_client()
    data, error = await client.search_count(query)
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    return {
        "total": data.get("total", 0),
        "facets": data.get("facets", {}),
        "query": query
    }


# =============================================================================
# DNS Endpoints
# =============================================================================

@router.post("/dns/resolve")
async def dns_resolve(request: DnsResolveRequest):
    """Resolve hostnames to IP addresses."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    data, error = await client.dns_resolve(request.hostnames)
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    return data


@router.post("/dns/reverse")
async def dns_reverse(request: DnsReverseRequest):
    """Reverse DNS lookup for IPs."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    data, error = await client.dns_reverse(request.ips)
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    return data


@router.get("/dns/domain/{domain}")
async def dns_domain(domain: str):
    """Get DNS records for a domain."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    data, error = await client.dns_domain(domain)
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    return data


# =============================================================================
# Scanning Endpoints
# =============================================================================

@router.post("/scan")
async def request_scan(request: ScanRequest):
    """Request on-demand scan (uses scan credits)."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    status = await client.get_status()
    
    if status.scan_credits <= 0:
        raise HTTPException(status_code=402, detail="No scan credits remaining")
    
    data, error = await client.scan(request.ips)
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    return data


@router.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get status of a scan."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    data, error = await client.get_scan_status(scan_id)
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    return data


# =============================================================================
# Exploits
# =============================================================================

@router.post("/exploits/search")
async def search_exploits(request: ExploitSearchRequest):
    """Search for exploits (free, no credits needed)."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    data, error = await client.search_exploits(request.query, request.page)
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    matches = []
    for m in (data.get("matches") or [])[:30]:
        matches.append({
            "id": m.get("_id"),
            "description": (m.get("description") or "")[:500],
            "source": m.get("source"),
            "type": m.get("type"),
            "platform": m.get("platform"),
            "cve": m.get("cve", []),
            "date": m.get("date"),
            "author": m.get("author")
        })
    
    return {
        "total": data.get("total", 0),
        "matches": matches,
        "query": request.query,
        "page": request.page
    }


# =============================================================================
# Alerts
# =============================================================================

@router.get("/alerts")
async def list_alerts():
    """List all network alerts."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    data, error = await client.list_alerts()
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    return {"alerts": data or []}


# =============================================================================
# Utilities
# =============================================================================

@router.get("/myip")
async def get_my_ip():
    """Get your public IP address."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    ip, error = await client.get_my_ip()
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    return {"ip": ip}


@router.get("/ports")
async def get_shodan_ports():
    """Get list of ports Shodan scans."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    data, error = await client.get_available_ports()
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    return {"ports": data or [], "count": len(data or [])}


@router.get("/protocols")
async def get_shodan_protocols():
    """Get list of protocols Shodan detects."""
    from dashboard.services.shodan_api import get_shodan_client
    
    client = get_shodan_client()
    data, error = await client.get_protocols()
    
    if error:
        raise HTTPException(status_code=400, detail=error)
    
    return {"protocols": data or {}}
