"""
TwinSanity Recon V2 - SQLite Database Layer
Persistent storage for scans, findings, and chat history
With WAL mode for better concurrency (MED-4 fix)
"""
import aiosqlite
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# Import database path from central config
from dashboard.config import DB_PATH

logger = logging.getLogger("Database")


async def get_db_connection(db_path: Path = None):
    """Get database connection with WAL mode for better concurrency (MED-4 fix)."""
    path = db_path or DB_PATH
    conn = await aiosqlite.connect(path)
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA busy_timeout=5000")
    return conn


class Database:
    """Async SQLite database manager"""
    
    def __init__(self, db_path: Path = None):
        self.db_path = db_path or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
    
    async def init_db(self):
        """Initialize database tables"""
        async with aiosqlite.connect(self.db_path) as db:
            # Scans table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER,
                    domain TEXT NOT NULL,
                    config TEXT,
                    status TEXT DEFAULT 'pending',
                    progress INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    completed_at TEXT,
                    result_file TEXT,
                    error TEXT,
                    subdomains_count INTEGER DEFAULT 0,
                    ips_count INTEGER DEFAULT 0,
                    cves_count INTEGER DEFAULT 0,
                    visibility TEXT DEFAULT 'private',
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            # Chat messages table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    provider TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)
            
            # Findings table (for RAG)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    hostname TEXT,
                    finding_type TEXT,
                    cve_id TEXT,
                    cvss REAL,
                    summary TEXT,
                    ports TEXT,
                    raw_data TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)
            
            # CVE cache table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cve_id TEXT PRIMARY KEY,
                    cvss REAL,
                    summary TEXT,
                    refs TEXT,
                    source TEXT,
                    fetched_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # AI Analysis table - stores cloud AI analysis results
            await db.execute("""
                CREATE TABLE IF NOT EXISTS ai_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    analysis_type TEXT DEFAULT 'full',
                    provider TEXT,
                    content TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)
            
            # Users table for authentication (Multi-User RBAC)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_login TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    is_primary_admin BOOLEAN DEFAULT 0
                )
            """)
            
            # Add is_primary_admin column if it doesn't exist (migration for existing databases)
            try:
                await db.execute("ALTER TABLE users ADD COLUMN is_primary_admin BOOLEAN DEFAULT 0")
            except Exception:
                pass  # Column already exists - expected for existing databases
            
            # Set the first admin user as primary admin if not already set
            async with db.execute("SELECT COUNT(*) FROM users WHERE is_primary_admin = 1") as cursor:
                row = await cursor.fetchone()
                if row[0] == 0:
                    # No primary admin set - find the first admin user and make them primary
                    async with db.execute("SELECT id FROM users WHERE role = 'admin' ORDER BY id ASC LIMIT 1") as admin_cursor:
                        admin_row = await admin_cursor.fetchone()
                        if admin_row:
                            await db.execute("UPDATE users SET is_primary_admin = 1 WHERE id = ?", (admin_row[0],))
                            await db.commit()
            
            # Sessions table for session management
            await db.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    expires_at TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    remember_me BOOLEAN DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            # Login attempts table for brute force protection
            await db.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    username TEXT,
                    success BOOLEAN DEFAULT 0,
                    attempted_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # =====================================================================
            # NEW: Bug Bounty Automation Tables
            # =====================================================================
            
            # Alive hosts table (HTTP probing results)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS alive_hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    status_code INTEGER,
                    title TEXT,
                    technologies TEXT,
                    content_length INTEGER,
                    response_time_ms INTEGER,
                    redirect_url TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)
            
            # Nuclei findings table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS nuclei_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    template_id TEXT,
                    name TEXT,
                    severity TEXT,
                    host TEXT,
                    matched_at TEXT,
                    extracted_results TEXT,
                    curl_command TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)
            
            # Harvested URLs table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS harvested_urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    source TEXT,
                    has_params BOOLEAN DEFAULT 0,
                    extension TEXT,
                    status_code INTEGER,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_chat_scan ON chat_messages(scan_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_ai_analysis_scan ON ai_analysis(scan_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(attempted_at)")
            # New indexes for bug bounty tables
            await db.execute("CREATE INDEX IF NOT EXISTS idx_alive_hosts_scan ON alive_hosts(scan_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_nuclei_findings_scan ON nuclei_findings(scan_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_nuclei_findings_severity ON nuclei_findings(severity)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_harvested_urls_scan ON harvested_urls(scan_id)")
            
            await db.commit()
            logger.info(f"Database initialized at {self.db_path}")
    
    # =========================================================================
    # Scan Operations
    # =========================================================================
    
    async def create_scan(
        self,
        scan_id: str,
        domain: str,
        config: Dict[str, Any],
        user_id: int
    ) -> bool:
        """Create a new scan entry"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """INSERT INTO scans (id, user_id, domain, config, status, created_at, visibility)
                   VALUES (?, ?, ?, ?, 'pending', ?, 'private')""",
                (scan_id, user_id, domain, json.dumps(config), datetime.now().isoformat())
            )
            await db.commit()
        return True
    
    # ... update_scan unchanged ...

    async def list_scans(self, user_id: int = None, is_super_admin: bool = False, limit: int = 50) -> List[Dict]:
        """List scans based on user permissions - Only super admin sees all"""
        query = "SELECT * FROM scans"
        params = []
        
        if is_super_admin:
            # Super admin: see ALL scans (no filter)
            pass
        elif user_id:
            # Regular user/admin: see own scans OR public scans only
            query += " WHERE user_id = ? OR visibility = 'public'"
            params.append(user_id)
        else:
            # Guest: see only public scans
            query += " WHERE visibility = 'public'"
        
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                results = []
                for row in rows:
                    r = dict(row)
                    if r.get("config"):
                        r["config"] = json.loads(r["config"])
                    results.append(r)
                return results

    async def get_scan_by_id(self, scan_id: str) -> Optional[Dict]:
        """Get a single scan by ID"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    r = dict(row)
                    if r.get("config"):
                        r["config"] = json.loads(r["config"])
                    return r
                return None

    async def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all associated data from the database."""
        async with aiosqlite.connect(self.db_path) as db:
            try:
                # Delete all related data first (referential integrity)
                await db.execute("DELETE FROM chat_messages WHERE scan_id = ?", (scan_id,))
                await db.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
                await db.execute("DELETE FROM ai_analysis WHERE scan_id = ?", (scan_id,))
                await db.execute("DELETE FROM alive_hosts WHERE scan_id = ?", (scan_id,))
                await db.execute("DELETE FROM nuclei_findings WHERE scan_id = ?", (scan_id,))
                await db.execute("DELETE FROM harvested_urls WHERE scan_id = ?", (scan_id,))
                # Delete the scan itself
                cursor = await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
                await db.commit()
                return cursor.rowcount > 0
            except Exception as e:
                logger.error(f"Failed to delete scan {scan_id}: {e}")
                return False
    
    # ... (skipping to auth section) ...

    async def create_user(
        self,
        username: str,
        password_hash: str,
        salt: str,
        role: str = 'user',
        is_primary_admin: bool = False
    ) -> int:
        """Create a new user with role"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """INSERT INTO users (username, password_hash, salt, role, created_at, is_primary_admin)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (username, password_hash, salt, role, datetime.now().isoformat(), 1 if is_primary_admin else 0)
            )
            await db.commit()
            return cursor.lastrowid
    
    async def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)
            ) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None
    
    async def get_all_users(self) -> List[Dict]:
        """Admin: List all users"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT id, username, role, created_at, last_login, is_active, is_primary_admin FROM users") as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def delete_user(self, user_id: int):
        """Admin: Delete user and their data"""
        async with aiosqlite.connect(self.db_path) as db:
            # Delete user's scans first (cascading cleanup needs manual scan deletion logic if not using CASCADE)
            # For now, simplistic approach:
            await db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            await db.commit()
            
    async def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None
    
    async def update_user(self, user_id: int, password_hash: str = None, salt: str = None, role: str = None):
        """Update user password_hash/salt and/or role. Expects pre-hashed password."""
        updates = []
        values = []
        
        # Accept pre-hashed password (caller should hash it)
        if password_hash and salt:
            updates.append("password_hash = ?")
            values.append(password_hash)
            updates.append("salt = ?")
            values.append(salt)
        
        if role and role in ['user', 'admin']:
            updates.append("role = ?")
            values.append(role)
        
        if not updates:
            return
        
        values.append(user_id)
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(query, values)
            await db.commit()
    
    async def invalidate_user_sessions(self, user_id: int):
        """Invalidate all sessions for a user (e.g., after password change)"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            await db.commit()
            logger.info(f"All sessions invalidated for user {user_id}")
    
    async def set_scan_visibility(self, scan_id: str, visibility: str):
        """Toggle scan visibility (public/private)"""
        if visibility not in ['public', 'private']:
            return
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("UPDATE scans SET visibility = ? WHERE id = ?", (visibility, scan_id))
            await db.commit()
    
    async def update_scan(
        self,
        scan_id: str,
        status: str = None,
        progress: int = None,
        result_file: str = None,
        error: str = None,
        subdomains_count: int = None,
        ips_count: int = None,
        cves_count: int = None
    ):
        """Update scan status and metadata"""
        updates = []
        values = []
        
        if status is not None:
            updates.append("status = ?")
            values.append(status)
            if status == "completed":
                updates.append("completed_at = ?")
                values.append(datetime.now().isoformat())
        
        if progress is not None:
            updates.append("progress = ?")
            values.append(progress)
        
        if result_file is not None:
            updates.append("result_file = ?")
            values.append(result_file)
        
        if error is not None:
            updates.append("error = ?")
            values.append(error)
        
        if subdomains_count is not None:
            updates.append("subdomains_count = ?")
            values.append(subdomains_count)
        
        if ips_count is not None:
            updates.append("ips_count = ?")
            values.append(ips_count)
        
        if cves_count is not None:
            updates.append("cves_count = ?")
            values.append(cves_count)
        
        if not updates:
            return
        
        values.append(scan_id)
        query = f"UPDATE scans SET {', '.join(updates)} WHERE id = ?"
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(query, values)
            await db.commit()
    
    # Legacy methods (get_scan, list_scans, delete_scan) removed to use RBAC versions earlier in file
    
    # =========================================================================
    # Chat Operations
    # =========================================================================
    
    async def save_message(
        self,
        scan_id: str,
        role: str,
        content: str,
        provider: str = None
    ) -> int:
        """Save a chat message"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """INSERT INTO chat_messages (scan_id, role, content, provider, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (scan_id, role, content, provider, datetime.now().isoformat())
            )
            await db.commit()
            return cursor.lastrowid
    
    async def get_chat_history(self, scan_id: str, limit: int = 100) -> List[Dict]:
        """Get chat history for a scan"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """SELECT * FROM chat_messages 
                   WHERE scan_id = ? 
                   ORDER BY created_at ASC 
                   LIMIT ?""",
                (scan_id, limit)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
    
    async def clear_chat_history(self, scan_id: str):
        """Clear chat history for a scan"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "DELETE FROM chat_messages WHERE scan_id = ?", (scan_id,)
            )
            await db.commit()
    
    # =========================================================================
    # AI Analysis Operations
    # =========================================================================
    
    async def save_ai_analysis(
        self,
        scan_id: str,
        content: str,
        provider: str = None,
        analysis_type: str = "full"
    ) -> int:
        """Save AI analysis for a scan"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """INSERT INTO ai_analysis (scan_id, analysis_type, provider, content, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (scan_id, analysis_type, provider, content, datetime.now().isoformat())
            )
            await db.commit()
            return cursor.lastrowid
    
    async def get_ai_analysis(self, scan_id: str, analysis_type: str = None) -> List[Dict]:
        """Get AI analysis for a scan"""
        query = "SELECT * FROM ai_analysis WHERE scan_id = ?"
        params = [scan_id]
        
        if analysis_type:
            query += " AND analysis_type = ?"
            params.append(analysis_type)
        
        query += " ORDER BY created_at DESC"
        
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
    
    async def get_latest_analysis(self, scan_id: str) -> Optional[Dict]:
        """Get the most recent AI analysis for a scan"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """SELECT * FROM ai_analysis 
                   WHERE scan_id = ? 
                   ORDER BY created_at DESC LIMIT 1""",
                (scan_id,)
            ) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None
    
    async def save_ai_analysis_report(self, scan_id: str, report: Dict) -> int:
        """Save V1-style AI analysis report (chunk-based analysis)"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """INSERT INTO ai_analysis (scan_id, analysis_type, provider, content, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    "v2_report",
                    "Pipeline (Gemini→Cloud→Local)",
                    json.dumps(report),
                    datetime.now().isoformat()
                )
            )
            await db.commit()
            return cursor.lastrowid
    
    async def get_ai_analysis_report(self, scan_id: str) -> Optional[Dict]:
        """Get V1-style AI analysis report for a scan"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """SELECT * FROM ai_analysis 
                   WHERE scan_id = ? AND analysis_type = 'v2_report'
                   ORDER BY created_at DESC LIMIT 1""",
                (scan_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    r = dict(row)
                    try:
                        r['content'] = json.loads(r['content'])
                    except:
                        pass
                    return r['content'] if isinstance(r.get('content'), dict) else r
        return None
    
    # =========================================================================
    # Findings Operations
    # =========================================================================
    
    async def save_finding(
        self,
        scan_id: str,
        ip: str,
        hostname: str = None,
        finding_type: str = None,
        cve_id: str = None,
        cvss: float = None,
        summary: str = None,
        ports: List[int] = None,
        raw_data: Dict = None
    ) -> int:
        """Save a finding"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """INSERT INTO findings 
                   (scan_id, ip, hostname, finding_type, cve_id, cvss, summary, ports, raw_data, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, ip, hostname, finding_type, cve_id, cvss, summary,
                    json.dumps(ports) if ports else None,
                    json.dumps(raw_data) if raw_data else None,
                    datetime.now().isoformat()
                )
            )
            await db.commit()
            return cursor.lastrowid
    
    async def save_findings_batch(self, findings: List[Dict]):
        """Save multiple findings efficiently"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.executemany(
                """INSERT INTO findings 
                   (scan_id, ip, hostname, finding_type, cve_id, cvss, summary, ports, raw_data, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        f["scan_id"], f.get("ip"), f.get("hostname"),
                        f.get("finding_type"), f.get("cve_id"), f.get("cvss"),
                        f.get("summary"),
                        json.dumps(f.get("ports")) if f.get("ports") else None,
                        json.dumps(f.get("raw_data")) if f.get("raw_data") else None,
                        datetime.now().isoformat()
                    )
                    for f in findings
                ]
            )
            await db.commit()
    
    async def get_findings(
        self,
        scan_id: str,
        finding_type: str = None,
        min_cvss: float = None
    ) -> List[Dict]:
        """Get findings for a scan with optional filters"""
        query = "SELECT * FROM findings WHERE scan_id = ?"
        params = [scan_id]
        
        if finding_type:
            query += " AND finding_type = ?"
            params.append(finding_type)
        
        if min_cvss is not None:
            query += " AND cvss >= ?"
            params.append(min_cvss)
        
        query += " ORDER BY cvss DESC"
        
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                results = []
                for row in rows:
                    r = dict(row)
                    if r.get("ports"):
                        r["ports"] = json.loads(r["ports"])
                    if r.get("raw_data"):
                        r["raw_data"] = json.loads(r["raw_data"])
                    results.append(r)
                return results
    
    async def search_findings(
        self,
        scan_id: str,
        query: str,
        limit: int = 20
    ) -> List[Dict]:
        """Search findings by CVE ID or summary"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            search_term = f"%{query}%"
            async with db.execute(
                """SELECT * FROM findings 
                   WHERE scan_id = ? 
                   AND (cve_id LIKE ? OR summary LIKE ? OR hostname LIKE ?)
                   ORDER BY cvss DESC
                   LIMIT ?""",
                (scan_id, search_term, search_term, search_term, limit)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
    
    
    async def search_all_cves(
        self,
        query: str = None,
        user_id: int = None,
        is_admin: bool = False,
        limit: int = 50
    ) -> List[Dict]:
        """Search CVEs across all accessible scans"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            sql = """
                SELECT f.*, s.domain, s.created_at as scan_date, s.visibility 
                FROM findings f
                JOIN scans s ON f.scan_id = s.id
                WHERE f.cve_id IS NOT NULL
            """
            params = []
            
            # Permissions checks
            if not is_admin:
                if user_id:
                    sql += " AND (s.user_id = ? OR s.visibility = 'public')"
                    params.append(user_id)
                else:
                    # Guest
                    sql += " AND s.visibility = 'public'"
            
            if query:
                sql += " AND (f.cve_id LIKE ? OR f.summary LIKE ? OR f.hostname LIKE ?)"
                wildcard = f"%{query}%"
                params.extend([wildcard, wildcard, wildcard])
                
            sql += " ORDER BY f.cvss DESC LIMIT ?"
            params.append(limit)
            
            async with db.execute(sql, params) as cursor:
                rows = await cursor.fetchall()
                results = []
                for row in rows:
                    r = dict(row)
                    if r.get("ports"):
                        r["ports"] = json.loads(r["ports"])
                    results.append(r)
                return results

    # =========================================================================
    # CVE Cache Operations
    # =========================================================================
    
    async def get_cached_cve(self, cve_id: str) -> Optional[Dict]:
        """Get cached CVE details - returns data in the expected format"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM cve_cache WHERE cve_id = ?", (cve_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    r = dict(row)
                    refs = None
                    if r.get("refs"):
                        refs = json.loads(r["refs"])
                    # Return in the expected CVE format with proper field names
                    return {
                        "id": r.get("cve_id"),
                        "cvss": r.get("cvss"),
                        "cvss3": r.get("cvss"),  # Use same value for cvss3
                        "summary": r.get("summary"),
                        "references": refs,
                        "source": r.get("source") or "cache",
                        "fetched_at": r.get("fetched_at")
                    }
        return None
    
    async def cache_cve(
        self,
        cve_id: str,
        cvss: float = None,
        summary: str = None,
        refs: List[str] = None,
        source: str = None
    ):
        """Cache CVE details"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """INSERT OR REPLACE INTO cve_cache 
                   (cve_id, cvss, summary, refs, source, fetched_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    cve_id, cvss, summary,
                    json.dumps(refs) if refs else None,
                    source,
                    datetime.now().isoformat()
                )
            )
            await db.commit()

    # =========================================================================
    # Authentication Operations
    # =========================================================================
    
    async def is_initialized(self) -> bool:
        """Check if any admin user exists (first-time setup check)"""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT COUNT(*) FROM users") as cursor:
                row = await cursor.fetchone()
                return row[0] > 0
    
    
    async def update_user_last_login(self, user_id: int):
        """Update last login timestamp"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (datetime.now().isoformat(), user_id)
            )
            await db.commit()
    
    # =========================================================================
    # Session Operations
    # =========================================================================
    
    async def create_session(
        self,
        user_id: int,
        session_id: str,
        expires_at: str,
        ip_address: str = None,
        user_agent: str = None,
        remember_me: bool = False
    ) -> bool:
        """Create a new session"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """INSERT INTO sessions (id, user_id, expires_at, ip_address, user_agent, remember_me, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (session_id, user_id, expires_at, ip_address, user_agent, remember_me, datetime.now().isoformat())
            )
            await db.commit()
        return True
    
    async def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session by ID"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None
    
    async def delete_session(self, session_id: str):
        """Delete a session (logout)"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            await db.commit()
    
    async def delete_expired_sessions(self):
        """Clean up expired sessions"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "DELETE FROM sessions WHERE expires_at < ?",
                (datetime.now().isoformat(),)
            )
            await db.commit()
    
    async def delete_user_sessions(self, user_id: int):
        """Delete all sessions for a user"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            await db.commit()
    
    # =========================================================================
    # Brute Force Protection
    # =========================================================================
    
    async def record_login_attempt(
        self,
        ip_address: str,
        username: str = None,
        success: bool = False
    ):
        """Record a login attempt for brute force protection"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """INSERT INTO login_attempts (ip_address, username, success, attempted_at)
                   VALUES (?, ?, ?, ?)""",
                (ip_address, username, success, datetime.now().isoformat())
            )
            await db.commit()
    
    async def get_failed_attempts_count(
        self,
        ip_address: str,
        minutes: int = 15,
        username: str = None
    ) -> int:
        """Count failed login attempts from an IP (and optionally username) in the last N minutes"""
        from datetime import timedelta
        cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat()
        
        async with aiosqlite.connect(self.db_path) as db:
            if username:
                # Count failed attempts for this specific username from this IP
                async with db.execute(
                    """SELECT COUNT(*) FROM login_attempts 
                       WHERE ip_address = ? AND username = ? AND success = 0 AND attempted_at > ?""",
                    (ip_address, username, cutoff)
                ) as cursor:
                    row = await cursor.fetchone()
                    return row[0] if row else 0
            else:
                # Original behavior - count all failed attempts from IP
                async with db.execute(
                    """SELECT COUNT(*) FROM login_attempts 
                       WHERE ip_address = ? AND success = 0 AND attempted_at > ?""",
                    (ip_address, cutoff)
                ) as cursor:
                    row = await cursor.fetchone()
                    return row[0] if row else 0
    
    async def is_ip_blocked(self, ip_address: str, max_attempts: int = 5, block_minutes: int = 15, username: str = None) -> bool:
        """Check if an IP (and username combination) is blocked due to too many failed attempts"""
        failed_count = await self.get_failed_attempts_count(ip_address, block_minutes, username)
        return failed_count >= max_attempts
    
    async def get_lockout_remaining_seconds(self, ip_address: str, block_minutes: int = 15, username: str = None) -> int:
        """Get remaining lockout time in seconds"""
        from datetime import timedelta
        
        async with aiosqlite.connect(self.db_path) as db:
            if username:
                async with db.execute(
                    """SELECT attempted_at FROM login_attempts 
                       WHERE ip_address = ? AND username = ? AND success = 0 
                       ORDER BY attempted_at DESC LIMIT 1""",
                    (ip_address, username)
                ) as cursor:
                    row = await cursor.fetchone()
            else:
                async with db.execute(
                    """SELECT attempted_at FROM login_attempts 
                       WHERE ip_address = ? AND success = 0 
                       ORDER BY attempted_at DESC LIMIT 1""",
                    (ip_address,)
                ) as cursor:
                    row = await cursor.fetchone()
            
            if row:
                last_attempt = datetime.fromisoformat(row[0])
                unlock_time = last_attempt + timedelta(minutes=block_minutes)
                remaining = (unlock_time - datetime.now()).total_seconds()
                return max(0, int(remaining))
        return 0
    
    async def clear_login_attempts(self, ip_address: str, username: str = None):
        """Clear login attempts after successful login"""
        async with aiosqlite.connect(self.db_path) as db:
            if username:
                await db.execute(
                    "DELETE FROM login_attempts WHERE ip_address = ? AND username = ?",
                    (ip_address, username)
                )
            else:
                await db.execute(
                    "DELETE FROM login_attempts WHERE ip_address = ?",
                    (ip_address,)
                )
            await db.commit()
    
    async def cleanup_old_login_attempts(self, days: int = 7):
        """Clean up old login attempts"""
        from datetime import timedelta
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "DELETE FROM login_attempts WHERE attempted_at < ?",
                (cutoff,)
            )
            await db.commit()

    async def update_scan_visibility(self, scan_id: str, visibility: str):
        """Update scan visibility"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE scans SET visibility = ? WHERE id = ?",
                (visibility, scan_id)
            )
            await db.commit()


# Global database instance
_db: Optional[Database] = None


async def get_db() -> Database:
    """Get or create database instance"""
    global _db
    if _db is None:
        _db = Database()
        await _db.init_db()
    return _db


# Test
if __name__ == "__main__":
    import asyncio
    
    async def test():
        db = await get_db()
        
        # Test scan
        await db.create_scan("test-123", "example.com", {"test": True})
        scan = await db.get_scan_by_id("test-123")
        print(f"Created scan: {scan}")
        
        # Test chat
        await db.save_message("test-123", "user", "Hello")
        await db.save_message("test-123", "assistant", "Hi there!", "gemini")
        history = await db.get_chat_history("test-123")
        print(f"Chat history: {history}")
        
        # Test findings
        await db.save_finding(
            "test-123", "1.2.3.4", "test.example.com",
            finding_type="cve", cve_id="CVE-2024-1234",
            cvss=9.8, summary="Critical vulnerability"
        )
        findings = await db.get_findings("test-123")
        print(f"Findings: {findings}")
        
        # Cleanup
        await db.delete_scan("test-123")
        print("Test completed!")
    
    asyncio.run(test())
