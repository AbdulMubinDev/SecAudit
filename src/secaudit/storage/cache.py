"""
Cache storage implementation for SecAudit
"""
import time
import json
from typing import Any, Dict, List, Optional
from ..base_storage import CacheStorage


class Cache(CacheStorage):
    """In-memory cache implementation with optional persistence"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.max_size = config.get('max_size', 1000)
        self.default_ttl = config.get('default_ttl', 3600)  # 1 hour default
        self.persistent = config.get('persistent', False)
        self.cache_file = config.get('cache_file', './data/cache.json')
        
        # In-memory cache storage
        self._cache = {}
        self._timestamps = {}
        self._ttl = {}
        
        # Load persistent cache if enabled
        if self.persistent:
            self._load_persistent_cache()
    
    def connect(self) -> bool:
        """Initialize cache storage"""
        self.logger.info("Cache storage initialized")
        return True
    
    def disconnect(self) -> bool:
        """Cleanup cache storage"""
        if self.persistent:
            self._save_persistent_cache()
        self._cache.clear()
        self._timestamps.clear()
        self._ttl.clear()
        self.logger.info("Cache storage disconnected")
        return True
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set cache value with optional TTL"""
        try:
            # Clean up expired entries if cache is full
            if len(self._cache) >= self.max_size:
                self.cleanup()
            
            # Set TTL (Time To Live)
            actual_ttl = ttl if ttl is not None else self.default_ttl
            if actual_ttl > 0:
                self._ttl[key] = time.time() + actual_ttl
            
            # Store value
            self._cache[key] = value
            self._timestamps[key] = time.time()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to set cache value: {e}")
            return False
    
    def get(self, key: str) -> Optional[Any]:
        """Get cached value"""
        try:
            # Check if key exists
            if key not in self._cache:
                return None
            
            # Check if expired
            if key in self._ttl:
                if time.time() > self._ttl[key]:
                    self.delete(key)
                    return None
            
            return self._cache[key]
        except Exception as e:
            self.logger.error(f"Failed to get cache value: {e}")
            return None
    
    def delete(self, key: str) -> bool:
        """Delete cached value"""
        try:
            if key in self._cache:
                del self._cache[key]
            if key in self._timestamps:
                del self._timestamps[key]
            if key in self._ttl:
                del self._ttl[key]
            return True
        except Exception as e:
            self.logger.error(f"Failed to delete cache value: {e}")
            return False
    
    def clear(self) -> bool:
        """Clear all cached data"""
        try:
            self._cache.clear()
            self._timestamps.clear()
            self._ttl.clear()
            
            if self.persistent:
                self._save_persistent_cache()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to clear cache: {e}")
            return False
    
    def cleanup(self) -> bool:
        """Clean up expired cache entries"""
        try:
            current_time = time.time()
            expired_keys = []
            
            # Find expired keys
            for key, ttl in self._ttl.items():
                if current_time > ttl:
                    expired_keys.append(key)
            
            # Remove expired keys
            for key in expired_keys:
                self.delete(key)
            
            # If still too large, remove oldest entries
            if len(self._cache) >= self.max_size:
                # Sort by timestamp and remove oldest
                sorted_items = sorted(self._timestamps.items(), key=lambda x: x[1])
                items_to_remove = len(self._cache) - self.max_size + 100  # Keep some buffer
                
                for key, _ in sorted_items[:items_to_remove]:
                    self.delete(key)
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to cleanup cache: {e}")
            return False
    
    def list_keys(self, pattern: Optional[str] = None) -> List[str]:
        """List all cache keys"""
        try:
            keys = list(self._cache.keys())
            
            if pattern:
                keys = [k for k in keys if pattern in k]
            
            # Filter expired keys
            current_time = time.time()
            valid_keys = []
            for key in keys:
                if key not in self._ttl or current_time <= self._ttl[key]:
                    valid_keys.append(key)
            
            return valid_keys
        except Exception as e:
            self.logger.error(f"Failed to list cache keys: {e}")
            return []
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on cache"""
        try:
            current_time = time.time()
            valid_count = 0
            expired_count = 0
            
            for key, ttl in self._ttl.items():
                if current_time > ttl:
                    expired_count += 1
                else:
                    valid_count += 1
            
            # Count keys without TTL
            valid_count += len([k for k in self._cache.keys() if k not in self._ttl])
            
            return {
                'status': 'healthy',
                'connection': True,
                'error': None,
                'total_keys': len(self._cache),
                'valid_keys': valid_count,
                'expired_keys': expired_count,
                'max_size': self.max_size,
                'persistent': self.persistent,
                'cache_file': self.cache_file if self.persistent else None
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'connection': False,
                'error': str(e),
                'total_keys': 0,
                'valid_keys': 0,
                'expired_keys': 0,
                'max_size': self.max_size,
                'persistent': self.persistent,
                'cache_file': self.cache_file if self.persistent else None
            }
    
    def _load_persistent_cache(self) -> bool:
        """Load cache from persistent storage"""
        try:
            if not os.path.exists(self.cache_file):
                return True
            
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
            
            self._cache = data.get('cache', {})
            self._timestamps = data.get('timestamps', {})
            self._ttl = data.get('ttl', {})
            
            # Clean up expired entries
            self.cleanup()
            
            self.logger.info(f"Loaded {len(self._cache)} entries from persistent cache")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load persistent cache: {e}")
            return False
    
    def _save_persistent_cache(self) -> bool:
        """Save cache to persistent storage"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            
            data = {
                'cache': self._cache,
                'timestamps': self._timestamps,
                'ttl': self._ttl
            }
            
            with open(self.cache_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.logger.info(f"Saved {len(self._cache)} entries to persistent cache")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save persistent cache: {e}")
            return False


class TempStorage(BaseStorage):
    """Temporary storage for large datasets and intermediate results"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.temp_dir = config.get('temp_dir', './temp/')
        self.max_age = config.get('max_age', 3600)  # 1 hour default
    
    def connect(self) -> bool:
        """Initialize temporary storage"""
        import os
        os.makedirs(self.temp_dir, exist_ok=True)
        self.logger.info(f"Temporary storage initialized at: {self.temp_dir}")
        return True
    
    def disconnect(self) -> bool:
        """Cleanup temporary storage"""
        self.cleanup()
        self.logger.info("Temporary storage disconnected")
        return True
    
    def save(self, key: str, data: Any) -> bool:
        """Save data to temporary storage"""
        try:
            import os
            import pickle
            import time
            
            # Create subdirectory based on key prefix
            subdir = os.path.join(self.temp_dir, key.split(':')[0])
            os.makedirs(subdir, exist_ok=True)
            
            # Save data with timestamp
            file_path = os.path.join(subdir, f"{key}.tmp")
            timestamp_file = os.path.join(subdir, f"{key}.timestamp")
            
            with open(file_path, 'wb') as f:
                pickle.dump(data, f)
            
            with open(timestamp_file, 'w') as f:
                f.write(str(time.time()))
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to save temporary data: {e}")
            return False
    
    def load(self, key: str) -> Optional[Any]:
        """Load data from temporary storage"""
        try:
            import os
            import pickle
            import time
            
            # Check if file exists and is not expired
            file_path = os.path.join(self.temp_dir, key.split(':')[0], f"{key}.tmp")
            timestamp_file = os.path.join(self.temp_dir, key.split(':')[0], f"{key}.timestamp")
            
            if not os.path.exists(file_path) or not os.path.exists(timestamp_file):
                return None
            
            # Check expiration
            with open(timestamp_file, 'r') as f:
                timestamp = float(f.read().strip())
            
            if time.time() - timestamp > self.max_age:
                # File expired, clean up
                self.delete(key)
                return None
            
            # Load data
            with open(file_path, 'rb') as f:
                data = pickle.load(f)
            
            return data
        except Exception as e:
            self.logger.error(f"Failed to load temporary data: {e}")
            return None
    
    def delete(self, key: str) -> bool:
        """Delete data from temporary storage"""
        try:
            import os
            
            file_path = os.path.join(self.temp_dir, key.split(':')[0], f"{key}.tmp")
            timestamp_file = os.path.join(self.temp_dir, key.split(':')[0], f"{key}.timestamp")
            
            if os.path.exists(file_path):
                os.remove(file_path)
            if os.path.exists(timestamp_file):
                os.remove(timestamp_file)
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to delete temporary data: {e}")
            return False
    
    def list_keys(self, pattern: Optional[str] = None) -> List[str]:
        """List all keys in temporary storage"""
        try:
            import os
            import time
            
            keys = []
            
            if not os.path.exists(self.temp_dir):
                return keys
            
            for subdir in os.listdir(self.temp_dir):
                subdir_path = os.path.join(self.temp_dir, subdir)
                if not os.path.isdir(subdir_path):
                    continue
                
                for filename in os.listdir(subdir_path):
                    if filename.endswith('.tmp'):
                        key = f"{subdir}:{filename[:-4]}"
                        
                        # Check if expired
                        timestamp_file = os.path.join(subdir_path, f"{filename[:-4]}.timestamp")
                        if os.path.exists(timestamp_file):
                            with open(timestamp_file, 'r') as f:
                                timestamp = float(f.read().strip())
                            
                            if time.time() - timestamp > self.max_age:
                                # File expired, clean up
                                self.delete(key)
                                continue
                        
                        if pattern is None or pattern in key:
                            keys.append(key)
            
            return keys
        except Exception as e:
            self.logger.error(f"Failed to list temporary storage keys: {e}")
            return []
    
    def cleanup(self) -> bool:
        """Clean up expired temporary files"""
        try:
            import os
            import time
            
            cleaned_count = 0
            
            if not os.path.exists(self.temp_dir):
                return True
            
            for subdir in os.listdir(self.temp_dir):
                subdir_path = os.path.join(self.temp_dir, subdir)
                if not os.path.isdir(subdir_path):
                    continue
                
                for filename in os.listdir(subdir_path):
                    if filename.endswith('.tmp'):
                        key = f"{subdir}:{filename[:-4]}"
                        timestamp_file = os.path.join(subdir_path, f"{filename[:-4]}.timestamp")
                        
                        if os.path.exists(timestamp_file):
                            with open(timestamp_file, 'r') as f:
                                timestamp = float(f.read().strip())
                            
                            if time.time() - timestamp > self.max_age:
                                self.delete(key)
                                cleaned_count += 1
            
            if cleaned_count > 0:
                self.logger.info(f"Cleaned up {cleaned_count} expired temporary files")
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to cleanup temporary storage: {e}")
            return False
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on temporary storage"""
        try:
            import os
            
            if not os.path.exists(self.temp_dir):
                return {
                    'status': 'healthy',
                    'connection': True,
                    'error': None,
                    'temp_dir': self.temp_dir,
                    'file_count': 0,
                    'total_size': 0
                }
            
            file_count = 0
            total_size = 0
            
            for subdir in os.listdir(self.temp_dir):
                subdir_path = os.path.join(self.temp_dir, subdir)
                if not os.path.isdir(subdir_path):
                    continue
                
                for filename in os.listdir(subdir_path):
                    if filename.endswith('.tmp'):
                        file_path = os.path.join(subdir_path, filename)
                        file_count += 1
                        total_size += os.path.getsize(file_path)
            
            return {
                'status': 'healthy',
                'connection': True,
                'error': None,
                'temp_dir': self.temp_dir,
                'file_count': file_count,
                'total_size': total_size,
                'max_age': self.max_age
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'connection': False,
                'error': str(e),
                'temp_dir': self.temp_dir,
                'file_count': 0,
                'total_size': 0,
                'max_age': self.max_age
            }