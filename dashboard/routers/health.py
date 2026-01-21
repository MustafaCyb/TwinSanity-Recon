"""
TwinSanity Recon V2 - Health Router
Health check endpoints for monitoring.
"""
from datetime import datetime
from fastapi import APIRouter
import httpx

from dashboard.config import (
    GEMINI_API_KEY, GEMINI_MODEL,
    OLLAMA_LOCAL_HOST, OLLAMA_CLOUD_HOST, OLLAMA_API_KEY
)

router = APIRouter(tags=["Health"])

# Reference to active_scans from main app (injected at mount time)
_active_scans = set()

def set_active_scans_ref(scans_set):
    """Inject reference to active_scans from main app."""
    global _active_scans
    _active_scans = scans_set

@router.get("/health")
async def health():
    """Basic health check endpoint."""
    status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "active_scans": len(_active_scans)
    }
    try:
        from dashboard.database import get_db
        db = await get_db()
        scans = await db.list_scans(limit=1)
        status["db"] = "ok"
        status["total_scans"] = len(scans)
    except Exception as e:
        status["db"] = f"error: {e}"
        status["status"] = "degraded"
    return status


@router.get("/health/llm")
async def llm_health_check():
    """Check LLM provider availability."""
    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "providers": {}
    }
    
    # Check local Ollama
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{OLLAMA_LOCAL_HOST}/api/tags")
            results["providers"]["ollama_local"] = {
                "available": r.status_code == 200,
                "models": [m.get("name") for m in r.json().get("models", [])] if r.status_code == 200 else []
            }
    except Exception as e:
        results["providers"]["ollama_local"] = {"available": False, "error": str(e)[:50]}
    
    # Check Gemini (just config, not actual call)
    results["providers"]["gemini"] = {
        "configured": bool(GEMINI_API_KEY),
        "model": GEMINI_MODEL
    }
    
    # Check Ollama Cloud config
    results["providers"]["ollama_cloud"] = {
        "configured": bool(OLLAMA_CLOUD_HOST and OLLAMA_API_KEY),
        "host": OLLAMA_CLOUD_HOST[:30] if OLLAMA_CLOUD_HOST else None
    }
    
    return results


@router.get("/api/config/scan-defaults")
async def get_scan_defaults():
    """
    Get scan configuration defaults from config.yaml.
    This ensures the web dashboard uses the same defaults as specified in config.yaml.
    """
    from dashboard.config import CONFIG
    
    # Get scan config section
    scan_config = CONFIG.get('scan', {})
    
    # Get specific module configs from config.yaml
    http_probing_config = CONFIG.get('http_probing', {})
    nuclei_config = CONFIG.get('nuclei', {})
    url_harvesting_config = CONFIG.get('url_harvesting', {})
    xss_scan_config = CONFIG.get('xss_scan', {})
    api_discovery_config = CONFIG.get('api_discovery', {})
    
    return {
        # Core scan options
        "subdomain_discovery": True,  # Always enabled by default
        "shodan_lookup": True,  # Always enabled by default
        "cve_enrichment": True,  # Always enabled by default
        "validate_dns": scan_config.get('validate_dns', False),
        
        # Bug bounty tools - read from their respective config sections
        "http_probing": http_probing_config.get('enabled', False),
        "nuclei_scan": nuclei_config.get('enabled', False),
        "url_harvesting": url_harvesting_config.get('enabled', False),
        "xss_scan": xss_scan_config.get('enabled', False),
        "api_discovery": api_discovery_config.get('enabled', False),
        
        # LLM analysis
        "ai_analysis": CONFIG.get('llm', {}).get('analysis', {}).get('enabled', False),
        
        # Brute force
        "brute_force": False,  # Always disabled by default for safety
        
        # Proxy settings
        "use_proxies": CONFIG.get('proxy', {}).get('enabled', False),
    }
