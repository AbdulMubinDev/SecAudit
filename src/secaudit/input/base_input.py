"""
Base input class for SecAudit
"""
from abc import ABC, abstractmethod
from typing import List, Optional, Generator, Dict, Any
import logging

class BaseInput(ABC):
    """Abstract base class for all input types"""
    
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    @abstractmethod
    def read(self, source: str) -> List[str]:
        """
        Read data from source
        
        Args:
            source (str): Input source identifier
            
        Returns:
            List[str]: List of raw log lines
        """
        pass
    
    @abstractmethod
    def read_stream(self, source: str) -> Generator[str, None, None]:
        """
        Read data as a stream
        
        Args:
            source (str): Input source identifier
            
        Yields:
            str: Individual log lines
        """
        pass
    
    def validate_source(self, source: str) -> bool:
        """
        Validate input source
        
        Args:
            source (str): Input source to validate
            
        Returns:
            bool: True if valid
        """
        return True
    
    def sanitize_line(self, line: str) -> str:
        """
        Sanitize log line for security
        
        Args:
            line (str): Raw log line
            
        Returns:
            str: Sanitized log line
        """
        # Remove sensitive patterns if configured
        if self.config.get('security.log_sanitization', False):
            sensitive_patterns = self.config.get('security.sensitive_patterns', [])
            for pattern in sensitive_patterns:
                line = line.replace(pattern, '[REDACTED]')
        
        return line.strip()
    
    def get_source_info(self, source: str) -> Dict[str, Any]:
        """
        Get information about the data source
        
        Args:
            source (str): Input source identifier
            
        Returns:
            Dict: Source information
        """
        return {
            'source': source,
            'type': self.__class__.__name__,
            'config': self.config
        }