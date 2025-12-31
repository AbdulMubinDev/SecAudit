"""
Base storage classes for SecAudit
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import logging


class BaseStorage(ABC):
    """Abstract base class for all storage implementations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to storage"""
        pass
    
    @abstractmethod
    def disconnect(self) -> bool:
        """Close connection to storage"""
        pass
    
    @abstractmethod
    def save(self, key: str, data: Any) -> bool:
        """
        Save data to storage
        
        Args:
            key (str): Unique identifier for the data
            data (Any): Data to store
            
        Returns:
            bool: True if successful
        """
        pass
    
    @abstractmethod
    def load(self, key: str) -> Optional[Any]:
        """
        Load data from storage
        
        Args:
            key (str): Unique identifier for the data
            
        Returns:
            Any or None: Retrieved data or None if not found
        """
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """
        Delete data from storage
        
        Args:
            key (str): Unique identifier for the data
            
        Returns:
            bool: True if successful
        """
        pass
    
    @abstractmethod
    def list_keys(self, pattern: Optional[str] = None) -> List[str]:
        """
        List all keys in storage
        
        Args:
            pattern (str, optional): Pattern to filter keys
            
        Returns:
            List[str]: List of keys
        """
        pass
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on storage
        
        Returns:
            Dict: Health status information
        """
        return {
            'status': 'unknown',
            'connection': False,
            'error': None
        }


class CacheStorage(BaseStorage):
    """Abstract base class for cache storage implementations"""
    
    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Set cache value with optional TTL
        
        Args:
            key (str): Cache key
            value (Any): Value to cache
            ttl (int, optional): Time to live in seconds
            
        Returns:
            bool: True if successful
        """
        pass
    
    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """
        Get cached value
        
        Args:
            key (str): Cache key
            
        Returns:
            Any or None: Cached value or None if not found
        """
        pass
    
    @abstractmethod
    def clear(self) -> bool:
        """Clear all cached data"""
        pass
    
    @abstractmethod
    def cleanup(self) -> bool:
        """Clean up expired cache entries"""
        pass