"""
File-based input handler for SecAudit
"""
import os
import time
from typing import List, Generator
from .base_input import BaseInput

class FileInput(BaseInput):
    """File-based log input handler"""
    
    def __init__(self, config: dict):
        super().__init__(config)
        self.buffer_size = config.get('buffer_size', 8192)
        self.encoding = config.get('encoding', 'utf-8')
        self.rotation_enabled = config.get('rotation', True)
    
    def read(self, file_path: str) -> List[str]:
        """
        Read entire file into memory
        
        Args:
            file_path (str): Path to log file
            
        Returns:
            List[str]: List of log lines
        """
        if not self.validate_source(file_path):
            raise ValueError(f"Invalid file path: {file_path}")
        
        lines = []
        try:
            with open(file_path, 'r', encoding=self.encoding) as f:
                for line in f:
                    sanitized = self.sanitize_line(line)
                    if sanitized:
                        lines.append(sanitized)
            
            self.logger.info(f"Read {len(lines)} lines from {file_path}")
            return lines
            
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            raise
    
    def read_stream(self, file_path: str) -> Generator[str, None, None]:
        """
        Read file as a stream (for real-time processing)
        
        Args:
            file_path (str): Path to log file
            
        Yields:
            str: Individual log lines
        """
        if not os.path.exists(file_path):
            raise ValueError(f"File not found: {file_path}")
        
        with open(file_path, 'r', encoding=self.encoding) as f:
            # Seek to end if following
            if self.rotation_enabled:
                f.seek(0, 2)  # Seek to end
            
            while True:
                line = f.readline()
                if line:
                    sanitized = self.sanitize_line(line)
                    if sanitized:
                        yield sanitized
                else:
                    # Check for file rotation
                    if self.rotation_enabled and not os.path.exists(file_path):
                        self.logger.info(f"File rotated: {file_path}")
                        break
                    time.sleep(0.1)  # Small delay to prevent busy waiting
    
    def validate_source(self, file_path: str) -> bool:
        """Validate file path"""
        if not os.path.exists(file_path):
            self.logger.error(f"File does not exist: {file_path}")
            return False
        
        if not os.path.isfile(file_path):
            self.logger.error(f"Path is not a file: {file_path}")
            return False
        
        return True
    
    def get_file_size(self, file_path: str) -> int:
        """Get file size in bytes"""
        try:
            return os.path.getsize(file_path)
        except OSError:
            return 0
    
    def is_file_readable(self, file_path: str) -> bool:
        """Check if file is readable"""
        try:
            with open(file_path, 'r'):
                return True
        except (OSError, IOError):
            return False