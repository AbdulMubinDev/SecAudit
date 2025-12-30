"""
Syslog parser stub for SecAudit
"""
from typing import Dict, Any, Optional
from .base_parser import BaseParser

class SyslogParser(BaseParser):
    """Minimal syslog parser placeholder"""

    def __init__(self):
        super().__init__()

    def can_parse(self, line: str) -> bool:
        # Basic heuristic: syslog lines usually contain a timestamp and hostname
        return bool(line and len(line.split()) >= 4)

    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        """Very small parser that returns common fields when possible"""
        fields = self.extract_common_fields(line)
        if not fields:
            return None

        # Provide a minimal parsed structure
        return {
            'timestamp': fields.get('timestamp'),
            'hostname': fields.get('hostname', ''),
            'event_type': 'SYSLOG',
            'severity': 'INFO',
            'raw_line': line
        }
