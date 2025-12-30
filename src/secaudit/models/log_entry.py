"""
Log entry data model for SecAudit
"""
from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime

@dataclass
class LogEntry:
    """Represents a parsed log entry"""
    timestamp: datetime
    hostname: str
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    target_user: Optional[str] = None
    port: Optional[int] = None
    command: Optional[str] = None
    raw_line: str = ""
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'hostname': self.hostname,
            'event_type': self.event_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'username': self.username,
            'target_user': self.target_user,
            'port': self.port,
            'command': self.command,
            'raw_line': self.raw_line,
            'metadata': self.metadata
        }
        return {k: v for k, v in result.items() if v is not None}
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogEntry':
        """Create LogEntry from dictionary"""
        timestamp = None
        if data.get('timestamp'):
            timestamp = datetime.fromisoformat(data['timestamp'])
        
        return cls(
            timestamp=timestamp,
            hostname=data.get('hostname', ''),
            event_type=data.get('event_type', ''),
            severity=data.get('severity', 'UNKNOWN'),
            source_ip=data.get('source_ip'),
            username=data.get('username'),
            target_user=data.get('target_user'),
            port=data.get('port'),
            command=data.get('command'),
            raw_line=data.get('raw_line', ''),
            metadata=data.get('metadata')
        )
    
    def is_threat(self) -> bool:
        """Check if this log entry represents a potential threat"""
        threat_events = [
            'SSH_FAILED_PASSWORD',
            'SSH_INVALID_USER',
            'SUDO_COMMAND',
            'UNAUTHORIZED_ACCESS'
        ]
        return self.event_type in threat_events or self.severity in ['HIGH', 'CRITICAL']
    
    def get_affected_assets(self) -> list:
        """Get list of affected assets (IPs, users, etc.)"""
        assets = []
        if self.source_ip:
            assets.append(self.source_ip)
        if self.username:
            assets.append(self.username)
        if self.target_user and self.target_user != self.username:
            assets.append(self.target_user)
        return assets