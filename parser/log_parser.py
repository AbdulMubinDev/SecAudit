import re
from datetime import datetime
from typing import Dict, Optional, Union

class LogParser:
    """Parser for authentication log files (auth.log, secure, etc.)"""
    
    def __init__(self):
        # Regex patterns for different log entry types
        self.patterns = {
            'ssh_failed': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\w+) from ([\d.]+) port (\d+)'
            ),
            'ssh_accepted': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Accepted (\w+) for (\w+) from ([\d.]+) port (\d+)'
            ),
            'ssh_invalid_user': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Invalid user (\w+) from ([\d.]+) port (\d+)'
            ),
            'ssh_connection_closed': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Connection closed by ([\d.]+) port (\d+)'
            ),
            'ssh_disconnected': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Disconnected from user (\w+) ([\d.]+) port (\d+)'
            ),
            'sudo_command': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sudo\[\d+\]:\s+(\w+) : TTY=([^;]+) ; PWD=([^;]+) ; USER=([^;]+) ; COMMAND=(.*)'
            )
        }
    
    def parse_line(self, line: str) -> Optional[Dict[str, Union[str, int]]]:
        """
        Parse a single log line and extract structured information.
        
        Args:
            line (str): Raw log line
            
        Returns:
            Dict or None: Parsed log data or None if line doesn't match known patterns
        """
        line = line.strip()
        if not line:
            return None
            
        # Try SSH failed password
        match = self.patterns['ssh_failed'].match(line)
        if match:
            return {
                'timestamp': match.group(1),
                'hostname': match.group(2),
                'username': match.group(3),
                'ip_address': match.group(4),
                'port': int(match.group(5)),
                'event_type': 'SSH_FAILED_PASSWORD',
                'severity': 'HIGH',
                'raw_line': line
            }
        
        # Try SSH accepted
        match = self.patterns['ssh_accepted'].match(line)
        if match:
            return {
                'timestamp': match.group(1),
                'hostname': match.group(2),
                'auth_method': match.group(3),
                'username': match.group(4),
                'ip_address': match.group(5),
                'port': int(match.group(6)),
                'event_type': 'SSH_ACCEPTED',
                'severity': 'INFO',
                'raw_line': line
            }
        
        # Try SSH invalid user
        match = self.patterns['ssh_invalid_user'].match(line)
        if match:
            return {
                'timestamp': match.group(1),
                'hostname': match.group(2),
                'username': match.group(3),
                'ip_address': match.group(4),
                'port': int(match.group(5)),
                'event_type': 'SSH_INVALID_USER',
                'severity': 'HIGH',
                'raw_line': line
            }
        
        # Try SSH connection closed
        match = self.patterns['ssh_connection_closed'].match(line)
        if match:
            return {
                'timestamp': match.group(1),
                'hostname': match.group(2),
                'ip_address': match.group(3),
                'port': int(match.group(4)),
                'event_type': 'SSH_CONNECTION_CLOSED',
                'severity': 'LOW',
                'raw_line': line
            }
        
        # Try SSH disconnected
        match = self.patterns['ssh_disconnected'].match(line)
        if match:
            return {
                'timestamp': match.group(1),
                'hostname': match.group(2),
                'username': match.group(3),
                'ip_address': match.group(4),
                'port': int(match.group(5)),
                'event_type': 'SSH_DISCONNECTED',
                'severity': 'LOW',
                'raw_line': line
            }
        
        # Try sudo command
        match = self.patterns['sudo_command'].match(line)
        if match:
            return {
                'timestamp': match.group(1),
                'hostname': match.group(2),
                'username': match.group(3),
                'tty': match.group(4),
                'pwd': match.group(5),
                'target_user': match.group(6),
                'command': match.group(7),
                'event_type': 'SUDO_COMMAND',
                'severity': 'MEDIUM',
                'raw_line': line
            }
        
        # If no pattern matches, return basic info
        return {
            'event_type': 'UNKNOWN',
            'severity': 'LOW',
            'raw_line': line
        }