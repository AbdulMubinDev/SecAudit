"""
Windows Event Log parser for SecAudit
"""
import re
from typing import Any, Dict, Optional
from datetime import datetime
from ..base_parser import BaseParser


class WindowsParser(BaseParser):
    """Windows Event Log parser implementation"""
    
    def __init__(self):
        super().__init__()
        self.event_id_patterns = {
            # Authentication events
            4624: 'WINDOWS_SUCCESSFUL_LOGIN',      # Successful logon
            4625: 'WINDOWS_FAILED_LOGIN',          # Failed logon
            4648: 'WINDOWS_EXPLICIT_CREDENTIALS',  # Logon with explicit credentials
            4672: 'WINDOWS_PRIVILEGE_GRANTED',     # Special privileges assigned
            
            # Account events
            4720: 'WINDOWS_ACCOUNT_CREATED',       # User account created
            4726: 'WINDOWS_ACCOUNT_DELETED',       # User account deleted
            4738: 'WINDOWS_ACCOUNT_CHANGED',       # User account changed
            4740: 'WINDOWS_ACCOUNT_LOCKED',        # Account locked out
            
            # Security events
            4663: 'WINDOWS_OBJECT_ACCESS',         # Object access
            4688: 'WINDOWS_PROCESS_CREATED',       # New process created
            4697: 'WINDOWS_SERVICE_INSTALLED',     # Service installed
            4698: 'WINDOWS_SCHEDULED_TASK',        # Scheduled task created
        }
        
        # Common Windows log formats
        self.log_patterns = {
            'evtx': re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<event_id>\d+)\s+(?P<level>\w+)\s+(?P<source>\w+)\s+(?P<message>.*)'),
            'sysmon': re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<event_id>\d+)\s+(?P<process_name>\w+)\s+(?P<user>\w+)\s+(?P<message>.*)'),
            'security': re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<event_id>\d+)\s+(?P<account_name>[\w\\]+)\s+(?P<source_ip>[\d.]+)?\s+(?P<message>.*)')
        }
    
    def can_parse(self, line: str) -> bool:
        """Check if this parser can handle the given line"""
        # Check for Windows-specific patterns
        windows_indicators = [
            r'EventID=\d+',
            r'Security ID:',
            r'Account Name:',
            r'Logon Type:',
            r'Process Name:',
            r'Object Name:',
        ]
        
        for indicator in windows_indicators:
            if re.search(indicator, line, re.IGNORECASE):
                return True
        
        # Check for common Windows log formats
        for pattern in self.log_patterns.values():
            if pattern.match(line.strip()):
                return True
        
        return False
    
    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a Windows log line"""
        if not line or not line.strip():
            return None
        
        # Try different Windows log formats
        for format_name, pattern in self.log_patterns.items():
            match = pattern.match(line.strip())
            if match:
                return self._parse_windows_log(match.groupdict(), format_name)
        
        # Try generic Windows parsing
        return self._parse_generic_windows_log(line)
    
    def _parse_windows_log(self, data: Dict[str, str], format_name: str) -> Optional[Dict[str, Any]]:
        """Parse Windows log data based on format"""
        try:
            # Parse timestamp
            timestamp = self.parse_timestamp(data.get('timestamp', ''))
            if not timestamp:
                return None
            
            # Get event information
            event_id = int(data.get('event_id', 0))
            event_type = self.event_id_patterns.get(event_id, f'WINDOWS_EVENT_{event_id}')
            
            # Determine severity
            severity = self._get_windows_severity(event_id, data.get('level', 'INFO'))
            
            # Extract common fields
            result = {
                'timestamp': timestamp,
                'event_type': event_type,
                'severity': severity,
                'event_id': event_id,
                'source': data.get('source', 'Windows'),
                'message': data.get('message', ''),
                'format': format_name
            }
            
            # Add format-specific fields
            if format_name == 'evtx':
                result.update(self._parse_evtx_fields(data))
            elif format_name == 'sysmon':
                result.update(self._parse_sysmon_fields(data))
            elif format_name == 'security':
                result.update(self._parse_security_fields(data))
            
            # Sanitize fields
            for key, value in result.items():
                if isinstance(value, str):
                    result[key] = self.sanitize_field(value)
            
            return result
            
        except Exception as e:
            self.logger.warning(f"Failed to parse Windows log: {e}")
            return None
    
    def _parse_generic_windows_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse Windows log using generic patterns"""
        try:
            # Extract timestamp
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
            timestamp = None
            if timestamp_match:
                timestamp = self.parse_timestamp(timestamp_match.group(1))
            
            # Extract event ID
            event_id_match = re.search(r'EventID[=:]\s*(\d+)', line, re.IGNORECASE)
            event_id = int(event_id_match.group(1)) if event_id_match else 0
            
            # Extract account information
            account_match = re.search(r'Account Name:\s*([^\\]+)', line, re.IGNORECASE)
            username = account_match.group(1).strip() if account_match else None
            
            # Extract source IP
            ip_match = re.search(r'Source Network Address:\s*([\d.]+)', line, re.IGNORECASE)
            source_ip = ip_match.group(1) if ip_match else None
            
            # Determine event type
            event_type = self.event_id_patterns.get(event_id, 'WINDOWS_UNKNOWN_EVENT')
            if not event_type:
                # Try to determine from log content
                if 'failed' in line.lower() or 'denied' in line.lower():
                    event_type = 'WINDOWS_FAILED_LOGIN'
                elif 'success' in line.lower() or 'granted' in line.lower():
                    event_type = 'WINDOWS_SUCCESSFUL_LOGIN'
                else:
                    event_type = 'WINDOWS_GENERIC_EVENT'
            
            # Determine severity
            severity = self._get_windows_severity(event_id)
            
            result = {
                'timestamp': timestamp,
                'event_type': event_type,
                'severity': severity,
                'event_id': event_id,
                'username': username,
                'source_ip': source_ip,
                'raw_line': line.strip(),
                'format': 'generic'
            }
            
            # Sanitize fields
            for key, value in result.items():
                if isinstance(value, str):
                    result[key] = self.sanitize_field(value)
            
            return result
            
        except Exception as e:
            self.logger.warning(f"Failed to parse generic Windows log: {e}")
            return None
    
    def _parse_evtx_fields(self, data: Dict[str, str]) -> Dict[str, Any]:
        """Parse EVTX format specific fields"""
        return {
            'level': data.get('level'),
            'source': data.get('source')
        }
    
    def _parse_sysmon_fields(self, data: Dict[str, str]) -> Dict[str, Any]:
        """Parse Sysmon format specific fields"""
        return {
            'process_name': data.get('process_name'),
            'user': data.get('user')
        }
    
    def _parse_security_fields(self, data: Dict[str, str]) -> Dict[str, Any]:
        """Parse Security log format specific fields"""
        return {
            'account_name': data.get('account_name'),
            'source_ip': data.get('source_ip')
        }
    
    def _get_windows_severity(self, event_id: int, level: str = 'INFO') -> str:
        """Get severity level for Windows event"""
        # Map Windows event levels to our severity levels
        level_mapping = {
            'Critical': 'CRITICAL',
            'Error': 'HIGH',
            'Warning': 'MEDIUM',
            'Information': 'LOW',
            'Verbose': 'INFO'
        }
        
        if level in level_mapping:
            return level_mapping[level]
        
        # Map specific event IDs to severity
        critical_events = [4625, 4648, 4720, 4726, 4740]  # Failed logins, account changes, etc.
        high_events = [4624, 4672, 4663, 4688]  # Successful logins, privilege changes, etc.
        
        if event_id in critical_events:
            return 'CRITICAL'
        elif event_id in high_events:
            return 'HIGH'
        elif event_id > 0:
            return 'MEDIUM'
        else:
            return 'INFO'
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported Windows log formats"""
        return list(self.log_patterns.keys()) + ['generic']
    
    def validate_windows_log(self, log_data: Dict[str, Any]) -> bool:
        """Validate parsed Windows log data"""
        required_fields = ['timestamp', 'event_type', 'severity']
        
        for field in required_fields:
            if field not in log_data or log_data[field] is None:
                return False
        
        # Validate timestamp
        if not isinstance(log_data['timestamp'], datetime):
            return False
        
        # Validate severity
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        if log_data['severity'] not in valid_severities:
            return False
        
        return True