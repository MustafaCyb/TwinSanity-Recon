"""
TwinSanity Recon V2 - Scans Router
Scan management endpoints.
"""
import uuid
from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from dashboard.config import PROJECT_ROOT, logger, TEMPLATES_DIR
from dashboard.models import ScanConfig, ScanResponse, VisibilityUpdate

router = APIRouter(tags=["Scans"])
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
RESULTS_DIR = PROJECT_ROOT / "results"


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve the main dashboard page"""
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/island", response_class=HTMLResponse)
async def island_view(request: Request):
    """Serve the TwinSanity Island View - Gamified Mode"""
    return templates.TemplateResponse("island_view.html", {"request": request})


# IMPORTANT: This route MUST be defined BEFORE any /api/scans/{scan_id} routes
@router.get("/api/scans/public")
async def get_public_scans(request: Request, limit: int = 50):
    """Get all public scans from other users"""
    from dashboard.database import get_db
    import aiosqlite
    
    db = await get_db()
    user_id = getattr(request.state, "user_id", None)
    
    async with aiosqlite.connect(db.db_path) as conn:
        conn.row_factory = aiosqlite.Row
        
        if user_id:
            query = """
                SELECT s.*, u.username as owner_name 
                FROM scans s 
                LEFT JOIN users u ON s.user_id = u.id
                WHERE s.visibility = 'public' AND s.user_id != ?
                ORDER BY s.created_at DESC LIMIT ?
            """
            cursor = await conn.execute(query, (user_id, limit))
        else:
            query = """
                SELECT s.*, u.username as owner_name 
                FROM scans s 
                LEFT JOIN users u ON s.user_id = u.id
                WHERE s.visibility = 'public'
                ORDER BY s.created_at DESC LIMIT ?
            """
            cursor = await conn.execute(query, (limit,))
        
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


@router.post("/api/scans", response_model=ScanResponse)
async def start_scan(config: ScanConfig, request: Request, background_tasks: BackgroundTasks):
    """Start a new reconnaissance scan"""
    import re
    import ipaddress
    
    # Import at runtime to avoid circular imports
    from dashboard.services.scanner import run_scan
    from dashboard.state import state
    
    # Security: Validate domain to prevent internal network scanning
    domain = config.domain.strip().lower()
    
    # Reject internal/reserved domains and IPs
    BLOCKED_DOMAIN_PATTERNS = [
        r'^localhost$', r'^localhost\..*$',
        r'^.*\.local$', r'^.*\.internal$', r'^.*\.lan$',
        r'^.*\.home$', r'^.*\.localdomain$',
        r'^127\.', r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', 
        r'^192\.168\.', r'^169\.254\.', r'^0\.',
        r'^fc[0-9a-f]{2}:', r'^fd[0-9a-f]{2}:',  # IPv6 private
        r'^fe80:',  # IPv6 link-local
    ]
    
    for pattern in BLOCKED_DOMAIN_PATTERNS:
        if re.match(pattern, domain, re.IGNORECASE):
            raise HTTPException(400, "Cannot scan internal/reserved domains or IP ranges")
    
    # Additional check: Try to resolve and validate it's not an internal IP
    try:
        # If it looks like an IP, validate directly
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            ip = ipaddress.ip_address(domain)
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                raise HTTPException(400, "Cannot scan private/reserved IP addresses")
    except ValueError:
        pass  # Not an IP, it's a domain name - OK
    
    user_id = getattr(request.state, "user_id", None)
    scan_id = str(uuid.uuid4())[:8]
    
    state.create_scan(config.model_dump())
    background_tasks.add_task(run_scan, scan_id, config, user_id)
    
    logger.info(f"Started scan {scan_id} for domain {config.domain} (user_id: {user_id})")
    return ScanResponse(scan_id=scan_id, status="pending", message=f"Scan started for {config.domain}")


@router.get("/api/scans")
async def list_scans(request: Request):
    """List all scans based on permissions - Only super admin sees all"""
    user_id = getattr(request.state, "user_id", None)
    role = getattr(request.state, "role", "user")
    is_primary_admin = getattr(request.state, "is_primary_admin", False)
    
    from dashboard.database import get_db
    db = await get_db()
    # Only super admin can see ALL scans; regular admins see own + public only
    return await db.list_scans(user_id=user_id, is_super_admin=is_primary_admin)


@router.get("/api/scans/{scan_id}/status")
async def get_scan_status(scan_id: str, request: Request):
    """Get real-time scan status for polling updates"""
    from dashboard.state import state
    from dashboard.database import get_db
    
    # Check in-memory state first
    scan = state.get_scan(scan_id)
    if scan:
        return {
            "status": scan.get("status", "unknown"),
            "progress": scan.get("progress", 0),
            "message": scan.get("message", ""),
            "current_phase": scan.get("current_phase", ""),
            "stats": scan.get("stats", {})
        }
    
    # Fallback to database
    db = await get_db()
    db_scan = await db.get_scan_by_id(scan_id)
    if db_scan:
        return {
            "status": db_scan.get("status", "completed"),
            "progress": 100 if db_scan.get("status") == "completed" else 0,
            "message": f"Scan {db_scan.get('status', 'unknown')}",
            "stats": {
                "total_ips": db_scan.get("ip_count", 0),
                "total_cves": db_scan.get("cve_count", 0)
            }
        }
    
    return {"status": "not_found", "progress": 0, "message": "Scan not found"}


@router.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, request: Request):
    """Get scan details and results"""
    from dashboard.database import get_db
    db = await get_db()
    scan = await db.get_scan_by_id(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    user_id = getattr(request.state, "user_id", None)
    role = getattr(request.state, "role", "user")
    is_super_admin = getattr(request.state, "is_primary_admin", False)
    
    # Access rules:
    # 1. Super admin can see ALL scans
    # 2. Regular admin can see own scans + public scans only (not other admins' private scans)
    # 3. Users can see own scans + public scans
    if not is_super_admin:
        if scan.get('user_id') != user_id and scan.get('visibility') != 'public':
            raise HTTPException(status_code=403, detail="Access denied")
    
    return scan


@router.put("/api/scans/{scan_id}/visibility")
async def update_visibility(scan_id: str, update: VisibilityUpdate, request: Request):
    """Update scan visibility with role hierarchy"""
    from dashboard.database import get_db
    db = await get_db()
    
    scan = await db.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    user_id = getattr(request.state, "user_id", None)
    role = getattr(request.state, "role", "user")
    
    # Get requester's info for hierarchy check
    requesting_user = await db.get_user_by_id(user_id)
    is_requester_super_admin = requesting_user and requesting_user.get("is_primary_admin")
    
    # Get scan owner's info
    scan_owner = await db.get_user_by_id(scan.get('user_id')) if scan.get('user_id') else None
    owner_is_super_admin = scan_owner and scan_owner.get("is_primary_admin")
    
    # === ROLE HIERARCHY FOR VISIBILITY ===
    # 1. Only super admin can modify super admin's scan visibility
    if owner_is_super_admin and not is_requester_super_admin:
        raise HTTPException(status_code=403, detail="Only Super Admin can modify Super Admin's scan visibility")
    
    # 2. Regular users can only modify their own scans
    if role != 'admin' and scan.get('user_id') != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    if update.visibility not in ['public', 'private']:
        raise HTTPException(status_code=400, detail="Invalid visibility (public/private)")
    
    await db.update_scan_visibility(scan_id, update.visibility)
    return {"success": True, "visibility": update.visibility}


@router.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str, request: Request):
    """Cancel a running scan"""
    from dashboard.database import get_db
    from dashboard.state import state
    from dashboard.websocket.manager import manager
    
    db = await get_db()
    scan = await db.get_scan_by_id(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    user_id = getattr(request.state, "user_id", None)
    is_super_admin = getattr(request.state, "is_primary_admin", False)
    
    # Access check: Only owner or super admin can cancel
    if scan.get('user_id') != user_id and not is_super_admin:
        raise HTTPException(status_code=403, detail="Access denied")
    
    current_status = scan.get('status')
    if current_status not in ('running', 'pending'):
        raise HTTPException(status_code=400, detail=f"Cannot cancel scan with status: {current_status}")
    
    # Mark scan as cancelled in state
    if state.cancel_scan(scan_id):
        # Notify via WebSocket
        await manager.broadcast(scan_id, {
            "type": "status",
            "status": "cancelling",
            "message": "Scan cancellation requested..."
        })
        logger.info(f"Scan {scan_id} cancellation requested by user {user_id}")
        return {"success": True, "message": "Scan cancellation requested"}
    else:
        raise HTTPException(status_code=400, detail="Failed to cancel scan")


@router.get("/api/scans/{scan_id}/full")
async def get_scan_full(scan_id: str, request: Request):
    """Get full scan details including results from file if needed"""
    import json
    from dashboard.database import get_db
    
    db = await get_db()
    scan = await db.get_scan_by_id(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    user_id = getattr(request.state, "user_id", None)
    role = getattr(request.state, "role", "user")
    is_super_admin = getattr(request.state, "is_primary_admin", False)
    
    # Access rules: Super admin sees all, others see own + public only
    if not is_super_admin:
        if scan.get('user_id') != user_id and scan.get('visibility') != 'public':
            raise HTTPException(status_code=403, detail="Access denied")
    
    if not scan.get('results') and scan.get('result_file'):
        try:
            rpath = Path(scan['result_file'])
            if not rpath.exists() and not rpath.is_absolute():
                rpath = RESULTS_DIR / scan['result_file']
            
            if rpath.exists():
                with open(rpath, 'r') as f:
                    data = json.load(f)
                    scan['results'] = data.get('results', data)
        except Exception as e:
            logger.error(f"Failed to load results file for {scan_id}: {e}")
    
    return scan


@router.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str, request: Request):
    """Delete a scan and all associated data with role hierarchy protection."""
    from dashboard.database import get_db
    from dashboard.state import state, active_scans
    from dashboard.websocket.manager import manager
    
    db = await get_db()
    
    scan = await db.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    user_id = getattr(request.state, "user_id", None)
    role = getattr(request.state, "role", "user")
    scan_owner_id = scan.get('user_id')
    
    # Get current user's info to check if super admin
    current_user = await db.get_user_by_id(user_id)
    is_current_super_admin = current_user and current_user.get('is_primary_admin')
    
    # Get scan owner's info to check role hierarchy
    scan_owner = await db.get_user_by_id(scan_owner_id) if scan_owner_id else None
    owner_is_super_admin = scan_owner and scan_owner.get('is_primary_admin')
    owner_is_admin = scan_owner and scan_owner.get('role') == 'admin'
    
    # === ROLE HIERARCHY FOR SCAN DELETION ===
    # 1. Super admin scans can ONLY be deleted by super admin themselves
    if owner_is_super_admin and not is_current_super_admin:
        raise HTTPException(status_code=403, detail="Only Super Admin can delete their own scans")
    
    # 2. Admin scans can only be deleted by super admin or the admin themselves
    if owner_is_admin and not owner_is_super_admin:
        if not is_current_super_admin and scan_owner_id != user_id:
            raise HTTPException(status_code=403, detail="Only Super Admin can delete other admin's scans")
    
    # 3. Regular permission check: own scans or admin role
    if role != 'admin' and scan_owner_id != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    db_scan = await db.get_scan_by_id(scan_id)
    mem_scan = state.get_scan(scan_id)
    
    if mem_scan and mem_scan.get("status") == "running":
        state.update_scan(scan_id, status="cancelled")
        await manager.broadcast(scan_id, {"type": "status", "status": "cancelled", "message": "Scan cancelled by user"})
    
    try:
        await db.delete_scan(scan_id)
        logger.info(f"Deleted scan {scan_id} from database")
    except Exception as e:
        logger.warning(f"Database deletion failed for {scan_id}: {e}")
    
    result_file = scan.get("result_file") or (db_scan.get("result_file") if db_scan else None)
    if result_file:
        try:
            result_path = Path(result_file)
            if result_path.exists():
                result_path.unlink()
                logger.info(f"Deleted results file: {result_file}")
        except Exception as e:
            logger.warning(f"Could not delete results file: {e}")
    
    if scan_id in state.scans:
        del state.scans[scan_id]
    if scan_id in state.websockets:
        del state.websockets[scan_id]
    if scan_id in state.chat_history:
        del state.chat_history[scan_id]
    
    return {"message": f"Scan {scan_id} deleted successfully", "deleted": True}


@router.delete("/api/cache/{domain}")
async def clear_domain_cache(domain: str, request: Request):
    """Clear subdomain cache for a specific domain (used by rescan)"""
    from dashboard.subdomain_sources import clear_subdomain_cache
    
    # Basic validation
    domain = domain.strip().lower()
    if not domain or len(domain) < 3:
        raise HTTPException(status_code=400, detail="Invalid domain")
    
    cleared = clear_subdomain_cache(domain)
    
    logger.info(f"Cache clear requested for {domain}: {'cleared' if cleared else 'no cache found'}")
    return {"domain": domain, "cleared": cleared, "message": f"Cache {'cleared' if cleared else 'was already empty'} for {domain}"}


@router.get("/api/cves")
async def search_cves(request: Request, q: str = None, limit: int = 50):
    """Search CVEs across all accessible scans - Only super admin sees all"""
    user_id = getattr(request.state, "user_id", None)
    is_super_admin = getattr(request.state, "is_primary_admin", False)
    
    from dashboard.database import get_db
    db = await get_db()
    
    return await db.search_all_cves(query=q, user_id=user_id, is_admin=is_super_admin, limit=limit)


async def validate_websocket_session(websocket: WebSocket, token: str = None) -> dict:
    """Validate WebSocket connection using token param or session cookie."""
    from dashboard.database import get_db
    from datetime import datetime
    
    db = await get_db()
    session_id = token
    
    # Try token from query param first, then fall back to cookie
    if not session_id:
        session_id = websocket.cookies.get("session_id")
    
    if not session_id:
        return None
    
    session = await db.get_session(session_id)
    if not session:
        return None
    
    # Check expiration
    expires = datetime.fromisoformat(session["expires_at"])
    if expires < datetime.now():
        await db.delete_session(session_id)
        return None
    
    return session


@router.websocket("/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str, token: str = None):
    """WebSocket endpoint for real-time scan updates with authentication and authorization."""
    from dashboard.websocket.manager import manager
    from dashboard.database import get_db
    
    # Validate session from token or cookie
    session = await validate_websocket_session(websocket, token)
    
    if not session:
        await websocket.close(code=4001, reason="Authentication required")
        logger.warning(f"WebSocket connection rejected for scan {scan_id}: no valid session")
        return
    
    # Authorization check: user must own the scan or scan must be public
    db = await get_db()
    scan = await db.get_scan_by_id(scan_id)
    
    if scan:
        scan_owner_id = scan.get('user_id')
        scan_visibility = scan.get('visibility', 'private')
        requesting_user_id = session.get('user_id')
        
        # Allow if: user owns the scan OR scan is public
        if scan_owner_id != requesting_user_id and scan_visibility != 'public':
            await websocket.close(code=4003, reason="Access denied: you don't have permission to access this scan")
            logger.warning(f"WebSocket connection rejected for scan {scan_id}: user {requesting_user_id} doesn't own scan (owner: {scan_owner_id})")
            return
    # Note: If scan doesn't exist yet (new scan being created), allow connection
    # The scanner will create the scan entry
    
    await manager.connect(websocket, scan_id)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        try:
            manager.disconnect(websocket, scan_id)
        except:
            pass

