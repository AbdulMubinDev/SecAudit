"""
Base output class for SecAudit
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
import logging
import os
from datetime import datetime

class BaseOutput(ABC):
    """Abstract base class for all output handlers"""
    
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.output_path = config.get('path', './output/')
        self.compression = config.get('compression', False)
        
        # Ensure output directory exists
        os.makedirs(self.output_path, exist_ok=True)
    
    @abstractmethod
    def export(self, results: Dict[str, Any]) -> bool:
        """
        Export analysis results
        
        Args:
            results (Dict): Analysis results
            
        Returns:
            bool: True if successful
        """
        pass
    
    def generate_filename(self, prefix: str = 'secaudit') -> str:
        """Generate output filename with timestamp"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"{prefix}_{timestamp}"
    
    def should_include_raw(self) -> bool:
        """Check if raw data should be included in output"""
        return self.config.get('include_raw', False)
    
    def get_max_file_size(self) -> int:
        """Get maximum file size in bytes"""
        size_str = self.config.get('max_file_size', '100MB')
        if size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return 100 * 1024 * 1024  # Default 100MB
    
    def validate_output_path(self) -> bool:
        """Validate output path"""
        try:
            if not os.path.exists(self.output_path):
                os.makedirs(self.output_path, exist_ok=True)
            
            # Test write permissions
            test_file = os.path.join(self.output_path, '.test_write')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            
            return True
        except Exception as e:
            self.logger.error(f"Output path validation failed: {e}")
            return False