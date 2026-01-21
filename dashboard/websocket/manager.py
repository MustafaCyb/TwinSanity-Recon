"""
TwinSanity Recon V2 - WebSocket Manager
Manages WebSocket connections for real-time scan updates.
"""
from typing import Dict, List
from fastapi import WebSocket

from dashboard.config import logger


class ConnectionManager:
    """Manages WebSocket connections per scan."""
    
    def __init__(self):
        self.connections: Dict[str, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, scan_id: str):
        """Accept and register a WebSocket connection."""
        await websocket.accept()
        if scan_id not in self.connections:
            self.connections[scan_id] = []
        self.connections[scan_id].append(websocket)
        logger.info(f"WebSocket connected for scan {scan_id}")
    
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
    
    def get_connection_count(self, scan_id: str) -> int:
        """Get number of active connections for a scan."""
        return len(self.connections.get(scan_id, []))



# Global manager instance
manager = ConnectionManager()


class GlobalWSManager:
    def __init__(self):
        self.connections: List[WebSocket] = []
    
    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)
    
    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)
    
    async def broadcast(self, message: dict):
        dead = []
        for ws in self.connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


global_ws_manager = GlobalWSManager()


def get_manager() -> ConnectionManager:
    """Get the global WebSocket manager instance."""
    return manager

