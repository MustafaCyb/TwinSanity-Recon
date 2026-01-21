"""
TwinSanity Recon V2 - Admin Router
Admin-only user management endpoints.
"""
import aiosqlite
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from dashboard.middleware.auth import require_admin

router = APIRouter(prefix="/api/admin", tags=["Admin"])


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "user"


@router.get("/users")
async def admin_list_users(request: Request):
    """List all users (admin only)"""
    await require_admin(request)
    from dashboard.database import get_db
    db = await get_db()
    return await db.get_all_users()


@router.post("/users")
async def admin_create_user(data: CreateUserRequest, request: Request):
    """Create a new user (admin only)"""
    await require_admin(request)
    from dashboard.dependencies import validate_password_strength, hash_password
    
    # Validate input
    if len(data.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    
    # Use proper password validation
    is_valid, error = validate_password_strength(data.password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)
        
    if data.role not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Role must be 'user' or 'admin'")
    
    from dashboard.database import get_db
    db = await get_db()
    
    # Check if username already exists
    existing = await db.get_user_by_username(data.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create user with proper password hashing
    password_hash, salt = hash_password(data.password)
    user_id = await db.create_user(data.username, password_hash, salt, role=data.role)
    return {"success": True, "user_id": user_id, "username": data.username}


@router.delete("/users/{user_id}")
async def admin_delete_user(user_id: int, request: Request):
    """Delete a user (admin only)"""
    await require_admin(request)
    
    # Prevent self-deletion
    if user_id == request.state.user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own admin account")
    
    from dashboard.database import get_db
    db = await get_db()
    
    # Get the requesting admin's info
    requesting_user = await db.get_user_by_id(request.state.user_id)
    is_requester_super_admin = requesting_user and requesting_user.get("is_primary_admin")
    
    # Check target user
    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    target_is_super_admin = user.get("is_primary_admin")
    target_is_admin = user.get("role") == "admin"
    
    # === ROLE HIERARCHY FOR DELETION ===
    # 1. Super admin can NEVER be deleted
    if target_is_super_admin:
        raise HTTPException(status_code=403, detail="Super Admin account cannot be deleted")
    
    # 2. Only super admin can delete other admins
    if target_is_admin and not is_requester_super_admin:
        raise HTTPException(status_code=403, detail="Only Super Admin can delete administrators")
    
    await db.delete_user(user_id)
    return {"success": True}


@router.get("/users/{user_id}")
async def admin_get_user(user_id: int, request: Request):
    """Get a specific user's details (admin only)"""
    await require_admin(request)
    from dashboard.database import get_db
    db = await get_db()
    
    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Don't expose password hash for security
    return {
        "id": user.get("id"),
        "username": user.get("username"),
        "role": user.get("role"),
        "created_at": user.get("created_at"),
        "last_login": user.get("last_login"),
        "is_primary_admin": user.get("is_primary_admin", False)
    }


from typing import Optional

class UpdateUserRequest(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None


@router.put("/users/{user_id}")
async def admin_update_user(user_id: int, data: UpdateUserRequest, request: Request):
    """Update a user's password or role (admin only)"""
    await require_admin(request)
    
    from dashboard.database import get_db
    db = await get_db()
    
    # Get existing user
    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get the requesting admin's info
    requesting_user = await db.get_user_by_id(request.state.user_id)
    is_requester_super_admin = requesting_user and requesting_user.get("is_primary_admin")
    target_is_super_admin = user.get("is_primary_admin")
    target_is_admin = user.get("role") == "admin"
    
    # === ROLE HIERARCHY RULES ===
    # 1. Super admin can NEVER be edited by anyone (including themselves for role)
    if target_is_super_admin:
        # Super admin can only change their own password, not role
        if user_id != request.state.user_id:
            raise HTTPException(status_code=403, detail="Super Admin cannot be modified by other users")
        # Super admin can't demote themselves
        if data.role and data.role != "admin":
            raise HTTPException(status_code=403, detail="Super Admin cannot change their own role")
        # Only allow password change for self
        if data.role:
            data.role = None  # Ignore role change attempt
    
    # 2. Regular admins cannot edit other admins (only super admin can)
    if not is_requester_super_admin and target_is_admin and user_id != request.state.user_id:
        raise HTTPException(status_code=403, detail="Only Super Admin can modify other administrators")
    
    # 3. Only super admin can promote users to admin role
    if data.role == "admin" and not is_requester_super_admin:
        raise HTTPException(status_code=403, detail="Only Super Admin can promote users to admin role")
    
    # 4. Prevent admin from demoting themselves (security: can't lock yourself out)
    if data.role and data.role != "admin" and user_id == request.state.user_id:
        raise HTTPException(status_code=400, detail="You cannot demote yourself. Another admin must change your role.")
    
    # 5. Prevent demoting the last admin (protect system integrity)
    if data.role and data.role != "admin" and target_is_admin and not target_is_super_admin:
        users = await db.get_all_users()
        admin_count = len([u for u in users if u.get('role') == 'admin'])
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot demote the last admin")
    
    # Validate role value
    if data.role and data.role not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Role must be 'user' or 'admin'")
    
    # Update user (only include non-None values)
    await db.update_user(user_id, password=data.password, role=data.role)
    
    return {"success": True, "message": "User updated successfully"}


@router.get("/stats")
async def admin_get_stats(request: Request):
    """Get admin dashboard statistics"""
    await require_admin(request)
    
    from dashboard.database import get_db
    from dashboard.config import PROJECT_ROOT
    
    db = await get_db()
    
    # Get user stats
    users = await db.get_all_users()
    total_users = len(users)
    admin_count = len([u for u in users if u.get('role') == 'admin'])
    
    # Get scan stats (admin stats endpoint shows all scans)
    all_scans = await db.list_scans(user_id=None, is_super_admin=True)
    total_scans = len(all_scans)
    completed_scans = len([s for s in all_scans if s.get('status') == 'completed'])
    
    # Count total CVEs across all scans
    total_cves = sum(s.get('cve_count', 0) for s in all_scans)
    total_ips = sum(s.get('ip_count', 0) for s in all_scans)
    
    # Storage stats
    results_dir = PROJECT_ROOT / "results"
    reports_dir = PROJECT_ROOT / "reports"
    
    results_size = 0
    reports_size = 0
    
    if results_dir.exists():
        for f in results_dir.rglob('*'):
            if f.is_file():
                results_size += f.stat().st_size
    
    if reports_dir.exists():
        for f in reports_dir.rglob('*'):
            if f.is_file():
                reports_size += f.stat().st_size
    
    return {
        "users": {
            "total": total_users,
            "admins": admin_count,
            "regular": total_users - admin_count
        },
        "scans": {
            "total": total_scans,
            "completed": completed_scans,
            "total_cves": total_cves,
            "total_ips": total_ips
        },
        "storage": {
            "results_bytes": results_size,
            "reports_bytes": reports_size,
            "results_mb": round(results_size / (1024 * 1024), 2),
            "reports_mb": round(reports_size / (1024 * 1024), 2)
        }
    }


@router.post("/fix-super-admin")
async def fix_super_admin(request: Request):
    """
    One-time fix: Set the first admin user as super admin.
    Only works if no super admin exists yet.
    """
    await require_admin(request)
    
    from dashboard.database import get_db
    db = await get_db()
    
    # Check if there's already a super admin
    users = await db.get_all_users()
    has_super_admin = any(u.get('is_primary_admin') for u in users)
    
    if has_super_admin:
        return {"success": False, "message": "Super admin already exists"}
    
    # Find the first admin user (by ID) and make them super admin
    admins = [u for u in users if u.get('role') == 'admin']
    if not admins:
        return {"success": False, "message": "No admin users found"}
    
    # Sort by ID and get the first one
    first_admin = sorted(admins, key=lambda x: x.get('id', 999999))[0]
    
    # Update the database directly
    async with aiosqlite.connect(db.db_path) as conn:
        await conn.execute("UPDATE users SET is_primary_admin = 1 WHERE id = ?", (first_admin['id'],))
        await conn.commit()
    
    return {
        "success": True, 
        "message": f"User '{first_admin['username']}' (ID: {first_admin['id']}) is now Super Admin",
        "super_admin_id": first_admin['id'],
        "super_admin_username": first_admin['username']
    }
