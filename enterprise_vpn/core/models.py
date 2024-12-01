"""Data models for the core module."""

from typing import Optional, List
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ConnectionStatus:
    """Represents the current connection status."""
    is_connected: bool
    connected_since: Optional[datetime]
    current_ip: Optional[str]
    transfer_up: int = 0
    transfer_down: int = 0
    active_peers: List[str] = None

    @property
    def uptime(self) -> Optional[float]:
        """Calculate connection uptime in seconds."""
        if self.connected_since:
            return (datetime.now() - self.connected_since).total_seconds()
        return None 