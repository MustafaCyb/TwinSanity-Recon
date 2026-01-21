"""
TwinSanity Recon V2 - Dashboard Package

Main dashboard module providing:
- FastAPI application factory (app.py)
- Configuration management (config.py)
- Database layer (database.py)
- Authentication middleware (middleware/)
- API routers (routers/)
- Business logic services (services/)
- LLM integration (llm_manager.py, llm_advanced.py, llm_cache.py)
- Utility managers (proxy_manager.py, wordlist_manager.py)

Usage:
    from dashboard.app import create_app
    app = create_app()
"""

__version__ = "2.0.0"
__author__ = "TwinSanity Team"
