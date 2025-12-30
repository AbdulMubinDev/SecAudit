"""
Base parser class for SecAudit
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging
from datetime import datetime

class BaseParser(ABC):
    """Abstract base class for all log parsers"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    @abstractmethod
    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single log line
        
        Args:
            line (str): Raw log line
            
        Returns:
            Dict or None: Parsed log data or None if parsing failed
        """
        pass
    
    @abstractmethod
    def can_parse(self, line: str) -> bool:
        """
        Check if this parser can handle the given line
        
        Args:
            line (str): Log line to check
            
        Returns:
            bool: True if this parser can handle the line
        """
        pass
    
    def parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """
        Parse timestamp string into datetime object
        
        Args:
            timestamp_str (str): Timestamp string
            
        Returns:
            datetime or None: Parsed datetime or None if parsing failed
        """
        # Common timestamp formats
        formats = [
            '%b %d %H:%M:%S',  # SSH format: "Dec 30 15:30:45"
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%d/%b/%Y:%H:%M:%S %z',  # Apache format
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        self.logger.warning(f"Unable to parse timestamp: {timestamp_str}")
        return None
    
    def sanitize_field(self, value: Any) -> Any:
        """
        Sanitize field value for security
        
        Args:
            value (Any): Field value to sanitize
            
        Returns:
            Any: Sanitized value
        """
        if isinstance(value, str):
            # Remove null bytes and other control characters
            return value.replace('\x00', '').strip()
        return value
    
    def extract_common_fields(self, line: str) -> Dict[str, Any]:
        """
        Extract common fields from log line
        
        Args:
            line (str): Raw log line
            
        Returns:
            Dict: Common fields
        """
        fields = {}
        
        # Try to extract timestamp
        # This is a simple heuristic - real implementation would be more sophisticated
        words = line.split()
        if len(words) >= 3:
            timestamp_str = f"{words[0]} {words[1]} {words[2]}"
            timestamp = self.parse_timestamp(timestamp_str)
            if timestamp:
                fields['timestamp'] = timestamp
        
        # Try to extract hostname (usually after timestamp)
        if len(words) >= 4:
            fields['hostname'] = words[3]
        
        return fields