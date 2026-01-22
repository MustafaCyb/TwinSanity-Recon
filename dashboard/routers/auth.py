"""
TwinSanity Recon V2 - Authentication Router
Login, logout, registration, and setup endpoints.
"""
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from dashboard.config import (
    logger, TEMPLATES_DIR,
    MAX_LOGIN_ATTEMPTS, LOCKOUT_MINUTES, SESSION_HOURS, REMEMBER_ME_DAYS
)
from dashboard.dependencies import (
    hash_password, verify_password, validate_password_strength, require_auth
)
from dashboard.models import SetupRequest, LoginRequest

router = APIRouter(tags=["Authentication"])
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# =============================================================================
# HTML Pages
# =============================================================================
@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Serve login/setup page"""
    return templates.TemplateResponse("login.html", {"request": request})


@router.get("/public", response_class=HTMLResponse)
async def public_scans_page(request: Request):
    """Serve public scans page - accessible without authentication"""
    return templates.TemplateResponse("public_scans.html", {"request": request})


@router.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    """Alias for login page (handles first-time setup)"""
    return templates.TemplateResponse("login.html", {"request": request})


# =============================================================================
# API Endpoints
# =============================================================================
@router.get("/api/auth/check-setup")
async def check_setup():
    """Check if first-time setup is needed"""
    from dashboard.database import get_db
    db = await get_db()
    initialized = await db.is_initialized()
    return {"initialized": initialized}


@router.post("/api/auth/setup")
async def first_time_setup(data: SetupRequest):
    """First-time setup - create admin user"""
    from dashboard.database import get_db
    db = await get_db()
    
    if await db.is_initialized():
        raise HTTPException(status_code=400, detail="Setup already completed. Please log in or register.")
    
    is_valid, error = validate_password_strength(data.password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)
    
    password_hash, salt = hash_password(data.password)
    # First user is ALWAYS the super admin (is_primary_admin=True)
    await db.create_user(data.username, password_hash, salt, role='admin', is_primary_admin=True)
    
    logger.info(f"Super Admin user '{data.username}' created successfully")
    return {"success": True, "message": "Super Admin account created successfully"}


# Registration is disabled - Only admins can create users via Admin Panel
# @router.post("/api/auth/register")
# async def register(data: RegisterRequest):
#     """Register new user (default role: user) - DISABLED"""
#     raise HTTPException(status_code=403, detail="Registration is disabled. Contact an administrator.")


@router.post("/api/auth/login")
async def login(request: Request, response: Response, data: LoginRequest):
    """Login and create session"""
    from dashboard.database import get_db
    db = await get_db()
    
    client_ip = request.client.host if request.client else "unknown"
    
    # Check if this specific username from this IP is blocked
    if await db.is_ip_blocked(client_ip, MAX_LOGIN_ATTEMPTS, LOCKOUT_MINUTES, username=data.username):
        remaining = await db.get_lockout_remaining_seconds(client_ip, LOCKOUT_MINUTES, username=data.username)
        raise HTTPException(
            status_code=429, 
            detail=f"Too many failed login attempts for this account. Try again in {remaining // 60} minutes."
        )
    
    user = await db.get_user_by_username(data.username)
    
    if not user:
        await db.record_login_attempt(client_ip, data.username, success=False)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if not verify_password(data.password, user["password_hash"], user["salt"]):
        await db.record_login_attempt(client_ip, data.username, success=False)
        
        failed_count = await db.get_failed_attempts_count(client_ip, LOCKOUT_MINUTES, username=data.username)
        remaining_attempts = MAX_LOGIN_ATTEMPTS - failed_count
        
        if remaining_attempts <= 0:
            raise HTTPException(
                status_code=429,
                detail="Account temporarily locked due to multiple failed login attempts. Please try again later."
            )
        
        # Don't reveal remaining attempts count for security
        raise HTTPException(
            status_code=401, 
            detail="Invalid username or password"
        )
    
    # Clear failed login attempts on successful login
    await db.record_login_attempt(client_ip, data.username, success=True)
    await db.clear_login_attempts(client_ip, data.username)
    
    session_id = secrets.token_urlsafe(32)
    
    if data.remember_me:
        expires = datetime.now() + timedelta(days=REMEMBER_ME_DAYS)
    else:
        expires = datetime.now() + timedelta(hours=SESSION_HOURS)
    
    await db.create_session(
        user_id=user["id"],
        session_id=session_id,
        expires_at=expires.isoformat(),
        ip_address=client_ip,
        user_agent=request.headers.get("user-agent", "")[:200],
        remember_me=data.remember_me
    )
    
    await db.update_user_last_login(user["id"])
    
    # Check if running in production mode (HTTPS)
    from dashboard.config import CONFIG
    is_production = CONFIG.get('app', {}).get('production', False)
    
    max_age = REMEMBER_ME_DAYS * 24 * 60 * 60 if data.remember_me else SESSION_HOURS * 60 * 60
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=is_production,  # Only require HTTPS in production
        samesite="strict",  # Always strict to prevent CSRF attacks
        max_age=max_age,
        path="/"  # Ensure cookie is valid for all paths
    )
    
    logger.info(f"User '{data.username}' logged in from {client_ip}")
    return {"success": True}


@router.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    """Logout - destroy session"""
    session_id = request.cookies.get("session_id")
    
    if session_id:
        from dashboard.database import get_db
        db = await get_db()
        await db.delete_session(session_id)
    
    response.delete_cookie("session_id")
    return {"success": True}


@router.get("/api/auth/me")
async def get_current_user_info(request: Request, session: dict = Depends(require_auth)):
    """Get current authenticated user info"""
    from dashboard.database import get_db
    import aiosqlite
    
    db = await get_db()
    role = getattr(request.state, "role", "user")
    
    async with aiosqlite.connect(db.db_path) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT id, username, created_at, last_login, is_primary_admin FROM users WHERE id = ?",
            (session["user_id"],)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                user_data = dict(row)
                # Return flat object with username and role at top level for frontend compatibility
                return {
                    "id": user_data["id"],
                    "username": user_data["username"],
                    "role": role,
                    "is_primary_admin": bool(user_data.get("is_primary_admin", False)),
                    "created_at": user_data["created_at"],
                    "last_login": user_data["last_login"]
                }
    
    raise HTTPException(status_code=404, detail="User not found")
