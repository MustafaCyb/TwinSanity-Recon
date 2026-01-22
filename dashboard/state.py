"""
TwinSanity Recon V2 - Application State
Holds default in-memory state and global instances.
"""
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set, Any
from fastapi import WebSocket

class ScanState:
    def __init__(self):
        self.scans: Dict[str, Dict] = {}
        self.websockets: Dict[str, List[WebSocket]] = {}
        self.chat_history: Dict[str, List[Dict]] = {}
        self.cancelled_scans: Set[str] = set()  # Track cancelled scans
    
    def create_scan(self, config: Dict) -> str:
        scan_id = str(uuid.uuid4())[:8]
        self.scans[scan_id] = {
            "id": scan_id,
            "status": "pending",
            "progress": 0,
            "config": config,
            "created_at": datetime.now().isoformat(),
            "results": None,
            "logs": []
        }
        self.websockets[scan_id] = []
        self.chat_history[scan_id] = []
        return scan_id
    
    def update_scan(self, scan_id: str, **updates):
        if scan_id in self.scans:
            self.scans[scan_id].update(updates)
    
    def get_scan(self, scan_id: str) -> Optional[Dict]:
        return self.scans.get(scan_id)
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Mark a scan as cancelled. Returns True if scan was running."""
        if scan_id in self.scans:
            current_status = self.scans[scan_id].get("status")
            if current_status in ("running", "pending"):
                self.cancelled_scans.add(scan_id)
                self.scans[scan_id]["status"] = "cancelling"
                return True
        return False
    
    def is_cancelled(self, scan_id: str) -> bool:
        """Check if a scan has been cancelled."""
        return scan_id in self.cancelled_scans
    
    def clear_cancelled(self, scan_id: str):
        """Remove scan from cancelled set after it has stopped."""
        self.cancelled_scans.discard(scan_id)
    
    async def hydrate(self, db):
        """Load recent scans from DB into memory."""
        try:
            recent_scans = await db.list_scans(limit=50)
            for s in recent_scans:
                # Convert aiosqlite.Row to dict if needed
                scan_data = dict(s)
                # Database uses 'id' column, not 'scan_id'
                scan_key = scan_data.get("id") or scan_data.get("scan_id")
                if scan_key:
                    self.scans[scan_key] = scan_data
            
            # Mark any 'running' scans as 'interrupted' since we restarted
            for scan_id, scan in self.scans.items():
                if scan.get("status") == "running":
                    scan["status"] = "interrupted"
                    scan["progress"] = 0
                    # Optionally update DB
                    # await db.update_scan(scan_id, status="interrupted")
        except Exception as e:
            print(f"Failed to hydrate state: {e}")
            
    def list_scans(self) -> List[Dict]:
        return list(self.scans.values())

# Global Instances
state = ScanState()
active_scans: Set[str] = set()
conversation_memories: Dict[str, Any] = {}
