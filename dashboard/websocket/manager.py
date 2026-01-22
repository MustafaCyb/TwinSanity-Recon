"""
TwinSanity Recon V2 - WebSocket Manager
Manages WebSocket connections for real-time scan updates.
Enhanced with granular message types and statistics broadcasting.
"""
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass, field, asdict
from datetime import datetime
from fastapi import WebSocket

from dashboard.config import logger


class MessageType(Enum):
    """WebSocket message types for UI synchronization."""
    # Status messages
    STATUS = "status"
    PROGRESS = "progress"
    LOG = "log"
    ERROR = "error"
    COMPLETE = "complete"
    CANCELLED = "cancelled"
    
    # Scan phase messages
    PHASE_START = "phase_start"
    PHASE_PROGRESS = "phase_progress"
    PHASE_COMPLETE = "phase_complete"
    
    # Discovery messages
    SUBDOMAIN_FOUND = "subdomain_found"
    SUBDOMAIN_BATCH = "subdomain_batch"
    IP_RESOLVED = "ip_resolved"
    HOST_SCANNED = "host_scanned"
    
    # CVE/Vulnerability messages
    CVE_FOUND = "cve_found"
    CVE_BATCH = "cve_batch"
    VULNERABILITY_FOUND = "vulnerability_found"
    
    # Tool result messages
    HTTPX_RESULT = "httpx_result"
    NUCLEI_RESULT = "nuclei_result"
    XSS_RESULT = "xss_result"
    API_ENDPOINT = "api_endpoint"
    URL_FOUND = "url_found"
    
    # AI Analysis messages
    AI_ANALYSIS = "ai_analysis"
    AI_CHUNK_START = "ai_chunk_start"
    AI_CHUNK_COMPLETE = "ai_chunk_complete"
    AI_TOOLS_ANALYSIS = "ai_tools_analysis"
    AI_SUMMARY = "ai_summary"
    
    # Real-time statistics
    STATS_UPDATE = "stats_update"


@dataclass
class ScanStats:
    """Real-time scan statistics for UI synchronization."""
    total_subdomains: int = 0
    live_subdomains: int = 0
    total_ips: int = 0
    total_cves: int = 0
    critical_cves: int = 0
    high_cves: int = 0
    medium_cves: int = 0
    low_cves: int = 0
    total_vulnerabilities: int = 0
    http_live: int = 0
    urls_found: int = 0
    api_endpoints: int = 0
    xss_findings: int = 0
    nuclei_findings: int = 0
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def increment(self, field_name: str, amount: int = 1):
        """Safely increment a statistic field."""
        if hasattr(self, field_name):
            current = getattr(self, field_name)
            setattr(self, field_name, current + amount)
            self.last_updated = datetime.now().isoformat()


class ConnectionManager:
    """Manages WebSocket connections per scan with enhanced messaging."""
    
    def __init__(self):
        self.connections: Dict[str, List[WebSocket]] = {}
        self.scan_stats: Dict[str, ScanStats] = {}
        self.scan_phases: Dict[str, dict] = {}  # Track current phase per scan
    
    async def connect(self, websocket: WebSocket, scan_id: str):
        """Accept and register a WebSocket connection."""
        await websocket.accept()
        if scan_id not in self.connections:
            self.connections[scan_id] = []
        self.connections[scan_id].append(websocket)
        
        # Initialize stats if new scan
        if scan_id not in self.scan_stats:
            self.scan_stats[scan_id] = ScanStats()
        
        logger.info(f"WebSocket connected for scan {scan_id} (total: {len(self.connections[scan_id])})")
        
        # Send current state to newly connected client
        await self._send_initial_state(websocket, scan_id)
    
    async def _send_initial_state(self, websocket: WebSocket, scan_id: str):
        """Send current scan state to newly connected client."""
        try:
            # Send current stats
            stats = self.scan_stats.get(scan_id)
            if stats:
                await websocket.send_json({
                    "type": MessageType.STATS_UPDATE.value,
                    "stats": stats.to_dict()
                })
            
            # Send current phase info
            phase = self.scan_phases.get(scan_id)
            if phase:
                await websocket.send_json({
                    "type": MessageType.PHASE_PROGRESS.value,
                    **phase
                })
        except Exception as e:
            logger.warning(f"Failed to send initial state: {e}")
    
    def disconnect(self, websocket: WebSocket, scan_id: str):
        """Remove a WebSocket connection."""
        if scan_id in self.connections:
            if websocket in self.connections[scan_id]:
                self.connections[scan_id].remove(websocket)
        logger.info(f"WebSocket disconnected for scan {scan_id}")
    
    async def broadcast(self, scan_id: str, message: dict):
        """Send message to all connections for a scan."""
        if scan_id in self.connections:
            dead_connections = []
            for ws in self.connections[scan_id]:
                try:
                    await ws.send_json(message)
                except Exception:
                    dead_connections.append(ws)
            # Clean up dead connections
            for ws in dead_connections:
                self.disconnect(ws, scan_id)
    
    async def broadcast_typed(self, scan_id: str, msg_type: MessageType, data: dict):
        """Broadcast a typed message with consistent structure."""
        message = {
            "type": msg_type.value,
            "timestamp": datetime.now().isoformat(),
            **data
        }
        await self.broadcast(scan_id, message)
    
    async def broadcast_phase_start(self, scan_id: str, phase_name: str, phase_num: int, total_phases: int, description: str = ""):
        """Broadcast phase start event."""
        phase_data = {
            "phase_name": phase_name,
            "phase_num": phase_num,
            "total_phases": total_phases,
            "description": description,
            "status": "running"
        }
        self.scan_phases[scan_id] = phase_data
        await self.broadcast_typed(scan_id, MessageType.PHASE_START, phase_data)
    
    async def broadcast_phase_progress(self, scan_id: str, phase_name: str, current: int, total: int, item: str = ""):
        """Broadcast phase progress update."""
        progress = (current / total * 100) if total > 0 else 0
        phase_data = {
            "phase_name": phase_name,
            "current": current,
            "total": total,
            "progress": round(progress, 1),
            "current_item": item
        }
        if scan_id in self.scan_phases:
            self.scan_phases[scan_id].update(phase_data)
        await self.broadcast_typed(scan_id, MessageType.PHASE_PROGRESS, phase_data)
    
    async def broadcast_phase_complete(self, scan_id: str, phase_name: str, results_count: int, duration_ms: int = 0):
        """Broadcast phase completion event."""
        await self.broadcast_typed(scan_id, MessageType.PHASE_COMPLETE, {
            "phase_name": phase_name,
            "results_count": results_count,
            "duration_ms": duration_ms,
            "status": "complete"
        })
    
    async def broadcast_stats(self, scan_id: str):
        """Broadcast current scan statistics."""
        stats = self.scan_stats.get(scan_id)
        if stats:
            await self.broadcast_typed(scan_id, MessageType.STATS_UPDATE, {
                "stats": stats.to_dict()
            })
    
    def update_stats(self, scan_id: str, **kwargs):
        """Update scan statistics (call broadcast_stats separately for efficiency)."""
        if scan_id not in self.scan_stats:
            self.scan_stats[scan_id] = ScanStats()
        
        stats = self.scan_stats[scan_id]
        for key, value in kwargs.items():
            if hasattr(stats, key):
                if isinstance(value, int) and key.startswith("increment_"):
                    # Handle increment_field_name syntax
                    field_name = key.replace("increment_", "")
                    stats.increment(field_name, value)
                else:
                    setattr(stats, key, value)
        stats.last_updated = datetime.now().isoformat()
    
    def increment_stat(self, scan_id: str, field_name: str, amount: int = 1):
        """Increment a single statistic field."""
        if scan_id not in self.scan_stats:
            self.scan_stats[scan_id] = ScanStats()
        self.scan_stats[scan_id].increment(field_name, amount)
    
    def get_stats(self, scan_id: str) -> Optional[ScanStats]:
        """Get current statistics for a scan."""
        return self.scan_stats.get(scan_id)
    
    def get_connection_count(self, scan_id: str) -> int:
        """Get number of active connections for a scan."""
        return len(self.connections.get(scan_id, []))
    
    def cleanup_scan(self, scan_id: str):
        """Clean up all data for a completed/cancelled scan."""
        if scan_id in self.scan_stats:
            del self.scan_stats[scan_id]
        if scan_id in self.scan_phases:
            del self.scan_phases[scan_id]
        # Keep connections until they disconnect naturally



# Global manager instance
manager = ConnectionManager()


class GlobalWSManager:
    """Manages global WebSocket connections for system-wide broadcasts."""
    
    def __init__(self):
        self.connections: List[WebSocket] = []
    
    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)
        logger.info(f"Global WebSocket connected (total: {len(self.connections)})")
    
    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)
            logger.info(f"Global WebSocket disconnected (remaining: {len(self.connections)})")
    
    async def broadcast(self, message: dict):
        """Broadcast to all global connections."""
        dead = []
        for ws in self.connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)
    
    async def broadcast_system_event(self, event_type: str, data: dict):
        """Broadcast a system-wide event."""
        await self.broadcast({
            "type": "system_event",
            "event": event_type,
            "timestamp": datetime.now().isoformat(),
            **data
        })


global_ws_manager = GlobalWSManager()


def get_manager() -> ConnectionManager:
    """Get the global WebSocket manager instance."""
    return manager


def get_global_manager() -> GlobalWSManager:
    """Get the global broadcast manager instance."""
    return global_ws_manager

