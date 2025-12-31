"""
Base output classes for SecAudit
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import logging
from datetime import datetime


class BaseOutput(ABC):
    """Abstract base class for all output implementations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    @abstractmethod
    def export(self, data: Any, output_path: Optional[str] = None) -> bool:
        """
        Export data to specified format
        
        Args:
            data (Any): Data to export
            output_path (str, optional): Output file path
            
        Returns:
            bool: True if successful
        """
        pass
    
    @abstractmethod
    def validate_config(self) -> bool:
        """Validate output configuration"""
        pass
    
    def get_output_path(self, filename: Optional[str] = None) -> str:
        """Get output file path"""
        output_dir = self.config.get('path', './output/')
        if filename:
            return f"{output_dir.rstrip('/')}/{filename}"
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            return f"{output_dir.rstrip('/')}/secaudit_output_{timestamp}"
    
    def compress_output(self, file_path: str) -> bool:
        """Compress output file if compression is enabled"""
        if not self.config.get('compression', False):
            return True
        
        try:
            import gzip
            import os
            
            with open(file_path, 'rb') as f_in:
                with gzip.open(f"{file_path}.gz", 'wb') as f_out:
                    f_out.writelines(f_in)
            
            os.remove(file_path)  # Remove original file
            self.logger.info(f"Compressed output to: {file_path}.gz")
            return True
        except Exception as e:
            self.logger.error(f"Failed to compress output: {e}")
            return False


class ReportGenerator(BaseOutput):
    """Abstract base class for report generation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.template_dir = config.get('template_dir', './templates/')
    
    @abstractmethod
    def generate_summary(self, data: Any) -> Dict[str, Any]:
        """Generate summary data for report"""
        pass
    
    @abstractmethod
    def generate_detailed_report(self, data: Any) -> Dict[str, Any]:
        """Generate detailed report data"""
        pass
    
    def get_report_metadata(self) -> Dict[str, Any]:
        """Get report metadata"""
        return {
            'generated_at': datetime.now().isoformat(),
            'secaudit_version': '1.0.0',
            'report_type': self.__class__.__name__,
            'config': self.config
        }