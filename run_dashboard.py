#!/usr/bin/env python3
"""
TwinSanity Recon V2 - Web Dashboard Launcher

Usage:
    python run_dashboard.py

This will start the web dashboard using settings from config.yaml
"""
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn is not installed.")
        print("Please run: pip install -r requirements.txt")
        sys.exit(1)
    
    # Load configuration from config.yaml
    from dashboard.config import SERVER_HOST, SERVER_PORT, APP_DEBUG, APP_NAME, APP_VERSION
    
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   🔰 {APP_NAME} v{APP_VERSION}                      ║
    ║                                                              ║
    ║   Starting server at: http://{SERVER_HOST}:{SERVER_PORT}                ║
    ║   Press Ctrl+C to stop                                       ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run(
        "dashboard.app:app",
        host=SERVER_HOST,
        port=SERVER_PORT,
        reload=APP_DEBUG,
        log_level="debug" if APP_DEBUG else "info"
    )

if __name__ == "__main__":
    main()
