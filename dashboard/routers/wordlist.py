"""
TwinSanity Recon V2 - Wordlist Router
Wordlist management endpoints.
"""
from pathlib import Path
from fastapi import APIRouter, HTTPException, Request, Depends

from dashboard.dependencies import require_auth

router = APIRouter(prefix="/api/wordlist", tags=["Wordlist"])


@router.get("/list")
async def list_wordlists(request: Request, session: dict = Depends(require_auth)):
    """Get available wordlists"""
    from dashboard.wordlist_manager import get_wordlist_manager
    wm = get_wordlist_manager()
    wordlists = wm.get_available_wordlists()
    total_custom = sum(w.get("entry_count", 0) for w in wordlists if w.get("id", "").startswith("custom:"))
    return {
        "wordlists": wordlists,
        "count": total_custom
    }


@router.get("/{wordlist_id}/preview")
async def preview_wordlist(wordlist_id: str, limit: int = 100, session: dict = Depends(require_auth)):
    """Preview entries from a wordlist"""
    from dashboard.wordlist_manager import get_wordlist_manager
    wm = get_wordlist_manager()
    entries = list(wm.get_wordlist_entries(wordlist_id))
    return {
        "id": wordlist_id,
        "total_entries": len(entries),
        "preview": entries[:limit]
    }


@router.post("/upload")
async def upload_wordlist(request: Request, session: dict = Depends(require_auth)):
    """Upload a custom wordlist"""
    from dashboard.wordlist_manager import get_wordlist_manager
    content_type = request.headers.get("content-type", "")
    
    if "multipart/form-data" in content_type:
        form = await request.form()
        file = form.get("file")
        if file:
            content = (await file.read()).decode('utf-8')
            name = Path(file.filename).stem if hasattr(file, 'filename') else "custom"
        else:
            raise HTTPException(status_code=400, detail="No file provided")
    else:
        body = await request.json()
        name = body.get("name", "custom")
        content = body.get("content", "")
    
    if not content:
        raise HTTPException(status_code=400, detail="No content provided")
    
    wm = get_wordlist_manager()
    result = wm.save_custom_wordlist(name, content)
    result["count"] = result.get("entry_count", 0)
    return result


@router.post("/clear")
async def clear_wordlists(request: Request, session: dict = Depends(require_auth)):
    """Clear all custom wordlists"""
    import logging
    logger = logging.getLogger("TwinSanityDashboard")
    wordlist_dir = Path(__file__).parent.parent.parent / "wordlists"
    
    cleared = 0
    if wordlist_dir.exists():
        for f in wordlist_dir.glob("*.txt"):
            try:
                f.unlink()
                cleared += 1
            except Exception as e:
                logger.warning(f"Could not delete {f}: {e}")
    
    return {"success": True, "cleared": cleared}


@router.delete("/{wordlist_id}")
async def delete_wordlist(wordlist_id: str, session: dict = Depends(require_auth)):
    """Delete a custom wordlist"""
    from dashboard.wordlist_manager import get_wordlist_manager
    wm = get_wordlist_manager()
    if wm.delete_custom_wordlist(wordlist_id):
        return {"success": True}
    raise HTTPException(status_code=404, detail="Wordlist not found or cannot be deleted")
