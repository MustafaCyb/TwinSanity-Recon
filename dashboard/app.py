import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

# Config and Logging (logger is imported from config, not logging module directly)
from dashboard.config import (
    PROJECT_ROOT, CONFIG, API_KEYS, LLM_CONFIG, logger,
    SERVER_HOST, SERVER_PORT, APP_NAME, APP_VERSION, APP_DESCRIPTION, APP_DEBUG
)

# Services and State
from dashboard.state import state, active_scans
from dashboard.llm_manager import get_llm_manager
from dashboard.llm_cache import get_llm_cache
from dashboard.middleware.auth import AuthMiddleware
from dashboard.routers import include_routers

# Rate Limiting
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    RATE_LIMITING_AVAILABLE = False
    logger.warning("slowapi not installed - rate limiting disabled")


async def startup_logic():
    """Application startup: hydrate state and init services."""
    logger.info("Starting up TwinSanity Recon V2...")
    
    # Initialize LLM Services
    try:
        get_llm_manager(LLM_CONFIG, API_KEYS)
        cache_conf = LLM_CONFIG.get('cache', {})
        if cache_conf.get('enabled', True):
            get_llm_cache(
                ttl_hours=cache_conf.get('ttl_hours', 6),
                max_entries=cache_conf.get('max_entries', 500)
            )
        logger.info("Modular services initialized")
    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")

    # Hydrate State from DB
    try:
        from dashboard.database import get_db
        db = await get_db()
        await state.hydrate(db)
        logger.info("State hydrated from database")
    except Exception as e:
        logger.error(f"Startup hydration failed: {e}")


async def shutdown_logic():
    """Wait for active scans to complete on shutdown."""
    if active_scans:
        logger.info(f"Waiting for {len(active_scans)} active scans to complete...")
        for _ in range(30):
            if not active_scans:
                break
            await asyncio.sleep(1)
        if active_scans:
            logger.warning(f"Shutting down with {len(active_scans)} scans still active")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events."""
    await startup_logic()
    yield
    await shutdown_logic()


# Initialize FastAPI app with lifespan
app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    lifespan=lifespan
)

# Initialize Rate Limiter
if RATE_LIMITING_AVAILABLE:
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Mount Static & Templates
# Use absolute paths from config
app.mount("/static", StaticFiles(directory=str(PROJECT_ROOT / "dashboard/static")), name="static")
# Note: Results served via authenticated /api/files/* endpoints, not static mount

# Middleware - CORS with dynamic origins from config
cors_origins = [
    f"http://{SERVER_HOST}:{SERVER_PORT}",
    f"http://localhost:{SERVER_PORT}",
    f"http://127.0.0.1:{SERVER_PORT}",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)
app.add_middleware(AuthMiddleware)


# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # Enable XSS protection (legacy browsers)
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Referrer policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Permissions policy (disable dangerous features)
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Content Security Policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    return response


# Include Routers
include_routers(app)

# Inject active_scans into health router
from dashboard.routers.health import set_active_scans_ref
set_active_scans_ref(active_scans)


@app.get("/")
async def root():
    return RedirectResponse(url="/dashboard")


if __name__ == "__main__":
    import uvicorn
    # Load host/port from config
    uvicorn.run("dashboard.app:app", host=SERVER_HOST, port=SERVER_PORT, reload=APP_DEBUG)

