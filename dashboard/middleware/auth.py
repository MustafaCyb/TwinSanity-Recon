"""
TwinSanity Recon V2 - Authentication Middleware
Protects routes and handles session validation.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

from dashboard.dependencies import get_current_session


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware to protect routes - redirects unauthenticated users to login"""
    
    # Paths that don't require authentication
    EXEMPT_PATHS = {
        "/login", "/setup", "/public", "/api/auth/login", "/api/auth/setup", 
        "/api/auth/check-setup", "/api/auth/register", "/api/scans/public", "/health",
        "/health/llm", "/api/config/scan-defaults"
    }
    EXEMPT_PREFIXES = ["/static/"]
    
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # Allow exempt paths
        if path in self.EXEMPT_PATHS:
            return await call_next(request)
        
        # Allow static files
        for prefix in self.EXEMPT_PREFIXES:
            if path.startswith(prefix):
                return await call_next(request)
        
        # Check session
        session = await get_current_session(request)
        
        if not session:
            # For API calls, return 401
            if path.startswith("/api/") or path.startswith("/ws"):
                return JSONResponse(
                    {"error": "Authentication required", "redirect": "/login"},
                    status_code=401
                )
            # For page requests, redirect to login
            return RedirectResponse(url="/login", status_code=303)
        
        # Attach user info to request state
        request.state.user_id = session["user_id"]
        request.state.session_id = session["id"]
        
        # Fetch user role for RBAC
        from dashboard.database import get_db
        db = await get_db()
        user = await db.get_user_by_id(session["user_id"])
        
        if user:
            request.state.role = user["role"]
            request.state.is_primary_admin = bool(user.get("is_primary_admin", False))
        else:
            # User no longer exists - orphaned session, invalidate it
            await db.delete_session(session["id"])
            if path.startswith("/api/") or path.startswith("/ws"):
                return JSONResponse(
                    {"error": "Session expired - user not found", "redirect": "/login"},
                    status_code=401
                )
            return RedirectResponse(url="/login", status_code=303)
            
        return await call_next(request)


async def require_auth(request: Request):
    """Dependency to ensure user is authenticated."""
    if not hasattr(request.state, "user_id") or not request.state.user_id:
        raise HTTPException(status_code=401, detail="Authentication required")


async def require_admin(request: Request):
    """Dependency to ensure user is an admin."""
    await require_auth(request)
    role = getattr(request.state, "role", "user")
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
