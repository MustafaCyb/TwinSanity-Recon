"""
TwinSanity Recon V2 - Proxy Router
Proxy management endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, Request

from dashboard.dependencies import require_auth

router = APIRouter(prefix="/api/proxy", tags=["Proxy"])


@router.get("/list")
async def list_proxies(request: Request, session: dict = Depends(require_auth)):
    """Get current proxy list and stats"""
    from dashboard.proxy_manager import get_proxy_manager
    pm = get_proxy_manager()
    return {
        "proxies": pm.to_list(),
        "stats": pm.get_stats(),
        "rotation_mode": pm.rotation_mode.value,
        "total": len(pm.proxies),
        "count": len(pm.proxies)
    }


@router.post("/add")
async def add_proxy(request: Request, session: dict = Depends(require_auth)):
    """Add a single proxy"""
    body = await request.json()
    proxy_string = body.get("proxy", "")
    from dashboard.proxy_manager import get_proxy_manager
    pm = get_proxy_manager()
    success = pm.add_single_proxy(proxy_string)
    if success:
        return {"success": True, "total": len(pm.proxies)}
    raise HTTPException(status_code=400, detail="Invalid proxy format")


@router.post("/upload")
async def upload_proxies(request: Request, session: dict = Depends(require_auth)):
    """Upload a proxy list (text file content or FormData file)"""
    from dashboard.proxy_manager import get_proxy_manager
    content_type = request.headers.get("content-type", "")
    
    if "multipart/form-data" in content_type:
        form = await request.form()
        file = form.get("file")
        if file:
            content = (await file.read()).decode('utf-8')
        else:
            raise HTTPException(status_code=400, detail="No file provided")
    else:
        body = await request.json()
        content = body.get("content", "")
    
    if not content:
        raise HTTPException(status_code=400, detail="No content provided")
    
    pm = get_proxy_manager()
    count = pm.load_from_text(content)
    return {"success": True, "count": count, "added": count, "total": len(pm.proxies)}


@router.post("/validate")
async def validate_proxies(request: Request, session: dict = Depends(require_auth)):
    """Validate all proxies (async)"""
    from dashboard.proxy_manager import get_proxy_manager
    pm = get_proxy_manager()
    valid_count = await pm.validate_all_proxies()
    return {"valid": valid_count, "total": len(pm.proxies)}


@router.post("/clear")
async def clear_proxies(request: Request, session: dict = Depends(require_auth)):
    """Clear all proxies"""
    from dashboard.proxy_manager import get_proxy_manager
    pm = get_proxy_manager()
    pm.clear()
    return {"success": True}


@router.post("/rotation-mode")
async def set_rotation_mode(request: Request, session: dict = Depends(require_auth)):
    """Set proxy rotation mode"""
    from dashboard.proxy_manager import get_proxy_manager, ProxyRotationMode
    body = await request.json()
    mode = body.get("mode", "round_robin")
    pm = get_proxy_manager()
    try:
        pm.rotation_mode = ProxyRotationMode(mode)
        return {"success": True, "mode": mode}
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid rotation mode: {mode}")
