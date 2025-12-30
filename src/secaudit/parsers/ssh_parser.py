"""
SSH log parser for SecAudit
"""
import re
from typing import Dict, Any, Optional
from .base_parser import BaseParser

class SSHParser(BaseParser):
    """Parser for SSH authentication logs"""
    
    def __init__(self):
        super().__init__()
        
        # SSH log patterns
        self.patterns = {
            'failed_password': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\w+) from ([\d.]+) port (\d+)'
            ),
            'accepted_password': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Accepted (\w+) for (\w+) from ([\d.]+) port (\d+)'
            ),
            'invalid_user': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Invalid user (\w+) from ([\d.]+) port (\d+)'
            ),
            'connection_closed': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Connection closed by ([\d.]+) port (\d+)'
            ),
            'disconnected': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Disconnected from user (\w+) ([\d.]+) port (\d+)'
            ),
            'sudo_command': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sudo\[\d+\]:\s+(\w+) : TTY=([^;]+) ; PWD=([^;]+) ; USER=([^;]+) ; COMMAND=(.*)'
            )
        }
    
    def can_parse(self, line: str) -> bool:
        """Check if this parser can handle the given line"""
        return any(pattern.search(line) for pattern in self.patterns.values())
    
    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse SSH log line
        
        Args:
            line (str): Raw SSH log line
            
        Returns:
            Dict or None: Parsed log data
        """
        if not self.can_parse(line):
            return None
        
        # Try each pattern
        for event_type, pattern in self.patterns.items():
            match = pattern.match(line)
            if match:
                return self._extract_ssh_data(event_type, match, line)
        
        return None
    
    def _extract_ssh_data(self, event_type: str, match, raw_line: str) -> Dict[str, Any]:
        """Extract data from SSH log match"""
        groups = match.groups()
        
        base_data = {
            'event_type': event_type.upper(),
            'raw_line': raw_line,
            'timestamp': self.parse_timestamp(groups[0]),
            'hostname': groups[1]
        }
        
        if event_type == 'failed_password':
            base_data.update({
                'username': groups[2],
                'ip_address': groups[3],
                'port': int(groups[4]),
                'severity': 'HIGH'
            })
        
        elif event_type == 'accepted_password':
            base_data.update({
                'auth_method': groups[2],
                'username': groups[3],
                'ip_address': groups[4],
                'port': int(groups[5]),
                'severity': 'INFO'
            })
        
        elif event_type == 'invalid_user':
            base_data.update({
                'username': groups[2],
                'ip_address': groups[3],
                'port': int(groups[4]),
                'severity': 'HIGH'
            })
        
        elif event_type == 'connection_closed':
            base_data.update({
                'ip_address': groups[2],
                'port': int(groups[3]),
                'severity': 'LOW'
            })
        
        elif event_type == 'disconnected':
            base_data.update({
                'username': groups[2],
                'ip_address': groups[3],
                'port': int(groups[4]),
                'severity': 'LOW'
            })
        
        elif event_type == 'sudo_command':
            base_data.update({
                'username': groups[2],
                'tty': groups[3],
                'pwd': groups[4],
                'target_user': groups[5],
                'command': groups[6],
                'severity': 'MEDIUM'
            })
        
        # Sanitize all string fields
        for key, value in base_data.items():
            if isinstance(value, str):
                base_data[key] = self.sanitize_field(value)
        
        return base_data