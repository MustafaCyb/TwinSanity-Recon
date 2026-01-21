"""
TwinSanity Recon V2 - Shared Dependencies
Authentication helpers, path validation, and common dependencies.
"""
import hashlib
import secrets
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

from fastapi import Header, HTTPException, Request

from dashboard.config import ALLOWED_DIRS, PASSWORD_MIN_LENGTH

# =============================================================================
# Path Validation
# =============================================================================
def validate_file_path(file_path: str) -> Path:
    """Validate file path is within allowed directories."""
    requested = Path(file_path).resolve()
    
    for allowed_dir in ALLOWED_DIRS:
        try:
            requested.relative_to(allowed_dir.resolve())
            return requested
        except ValueError:
            continue
    
    raise HTTPException(403, "Access to this path is not allowed")

def secure_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal."""
    filename = Path(filename).name
    filename = re.sub(r'[^\w\-_\.]', '', filename)
    return filename

# =============================================================================
# Password Hashing
# =============================================================================
def hash_password(password: str, salt: str = None) -> Tuple[str, str]:
    """Hash password with salt using PBKDF2-SHA256"""
    if salt is None:
        salt = secrets.token_hex(32)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return password_hash, salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify password against stored hash"""
    computed_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)

def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """Validate password meets requirements. Returns (is_valid, error_message)"""
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    return True, None

# =============================================================================
# Session Management
# =============================================================================
async def get_current_session(request: Request) -> Optional[Dict]:
    """Get current session from cookie"""
    session_id = request.cookies.get("session_id")
    if not session_id:
        return None
    
    from dashboard.database import get_db
    db = await get_db()
    session = await db.get_session(session_id)
    
    if not session:
        return None
    
    # Check expiration
    expires = datetime.fromisoformat(session["expires_at"])
    if expires < datetime.now():
        await db.delete_session(session_id)
        return None
    
    return session

async def require_auth(request: Request) -> Dict:
    """Dependency that requires valid authentication"""
    session = await get_current_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="Authentication required")
    return session

# =============================================================================
# API Key Verification (currently disabled)
# =============================================================================
async def verify_api_key(x_api_key: str = Header(None)):
    """Verify API key from header."""
    # Auth disabled by user request
    return True
