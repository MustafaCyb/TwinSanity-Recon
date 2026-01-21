"""
TwinSanity Recon V2 - Routers Package
FastAPI routers for modular API endpoints.
"""
from dashboard.routers.health import router as health_router
from dashboard.routers.proxy import router as proxy_router
from dashboard.routers.auth import router as auth_router
from dashboard.routers.admin import router as admin_router
from dashboard.routers.wordlist import router as wordlist_router
from dashboard.routers.scans import router as scans_router
from dashboard.routers.reports import router as reports_router
from dashboard.routers.chat import router as chat_router
from dashboard.routers.ai import router as ai_router
from dashboard.routers.tools import router as tools_router  # Bug bounty tools
from dashboard.routers.shodan_router import router as shodan_router  # Shodan integration (renamed to avoid pip conflict)

__all__ = [
    'health_router',
    'proxy_router',
    'auth_router',
    'admin_router',
    'wordlist_router',
    'scans_router',
    'reports_router',
    'chat_router',

    'ai_router',
    'tools_router',
    'shodan_router',
]


def include_routers(app):
    """Include all routers in the FastAPI app."""
    # Scans router FIRST (has /api/scans/public before parameterized routes)
    app.include_router(scans_router)
    app.include_router(health_router)
    app.include_router(proxy_router)
    app.include_router(auth_router)
    app.include_router(admin_router)
    app.include_router(wordlist_router)
    app.include_router(reports_router)
    app.include_router(chat_router)
    # app.include_router(files_router)  # DISABLED - Project Files feature removed
    app.include_router(ai_router)
    app.include_router(tools_router)
    app.include_router(shodan_router)  # Shodan integration

