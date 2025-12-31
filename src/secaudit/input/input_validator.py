"""
Input validation system for SecAudit
"""
import re
import os
from typing import Any, Dict, List, Optional
from datetime import datetime
import logging


class InputValidator:
    """Input validation system for SecAudit"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Validation patterns
        self.ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        self.username_pattern = re.compile(r'^[a-zA-Z0-9._-]+$')
        self.hostname_pattern = re.compile(r'^[a-zA-Z0-9.-]+$')
        
        # Security patterns for sensitive data
        self.sensitive_patterns = [
            re.compile(r'password\s*=\s*["\']?([^"\'\s]+)["\']?', re.IGNORECASE),
            re.compile(r'token\s*=\s*["\']?([^"\'\s]+)["\']?', re.IGNORECASE),
            re.compile(r'key\s*=\s*["\']?([^"\'\s]+)["\']?', re.IGNORECASE),
            re.compile(r'secret\s*=\s*["\']?([^"\'\s]+)["\']?', re.IGNORECASE)
        ]
    
    def validate_file_input(self, file_path: str) -> Dict[str, Any]:
        """Validate file input parameters"""
        result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'file_info': {}
        }
        
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                result['valid'] = False
                result['errors'].append(f"File does not exist: {file_path}")
                return result
            
            # Check if it's a file (not directory)
            if not os.path.isfile(file_path):
                result['valid'] = False
                result['errors'].append(f"Path is not a file: {file_path}")
                return result
            
            # Check file size
            file_size = os.path.getsize(file_path)
            max_size = self.config.get('max_file_size', 1024 * 1024 * 1024)  # 1GB default
            
            if file_size > max_size:
                result['warnings'].append(f"File size ({file_size} bytes) exceeds recommended limit ({max_size} bytes)")
            
            # Check file permissions
            if not os.access(file_path, os.R_OK):
                result['valid'] = False
                result['errors'].append(f"No read permission for file: {file_path}")
                return result
            
            # Get file info
            stat = os.stat(file_path)
            result['file_info'] = {
                'size': file_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'permissions': oct(stat.st_mode)[-3:]
            }
            
            # Check file encoding (basic check)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    f.read(1024)  # Try to read first 1KB
            except UnicodeDecodeError:
                result['warnings'].append("File may not be UTF-8 encoded")
            
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"Validation error: {str(e)}")
        
        return result
    
    def validate_log_entry(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a parsed log entry"""
        result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'sanitized': False
        }
        
        # Check required fields
        required_fields = ['timestamp', 'hostname', 'event_type', 'severity']
        for field in required_fields:
            if field not in log_entry or log_entry[field] is None:
                result['valid'] = False
                result['errors'].append(f"Missing required field: {field}")
        
        # Validate timestamp
        if 'timestamp' in log_entry:
            if not isinstance(log_entry['timestamp'], datetime):
                result['valid'] = False
                result['errors'].append("Invalid timestamp format")
        
        # Validate hostname
        if 'hostname' in log_entry and log_entry['hostname']:
            if not self.hostname_pattern.match(log_entry['hostname']):
                result['warnings'].append(f"Invalid hostname format: {log_entry['hostname']}")
        
        # Validate source IP
        if 'source_ip' in log_entry and log_entry['source_ip']:
            if not self.ip_pattern.match(log_entry['source_ip']):
                result['warnings'].append(f"Invalid IP address format: {log_entry['source_ip']}")
        
        # Validate username
        if 'username' in log_entry and log_entry['username']:
            if not self.username_pattern.match(log_entry['username']):
                result['warnings'].append(f"Invalid username format: {log_entry['username']}")
        
        # Check for sensitive data
        if 'raw_line' in log_entry:
            sanitized, found_sensitive = self._check_sensitive_data(log_entry['raw_line'])
            if found_sensitive:
                result['warnings'].append("Sensitive data detected and sanitized")
                result['sanitized'] = True
                log_entry['raw_line'] = sanitized
        
        return result
    
    def validate_configuration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate configuration parameters"""
        result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Validate input configuration
        input_config = config.get('input', {})
        if 'type' in input_config:
            valid_types = ['file', 'stream', 'api']
            if input_config['type'] not in valid_types:
                result['valid'] = False
                result['errors'].append(f"Invalid input type: {input_config['type']}")
        
        if 'format' in input_config:
            valid_formats = ['ssh', 'syslog', 'windows', 'custom']
            if input_config['format'] not in valid_formats:
                result['valid'] = False
                result['errors'].append(f"Invalid input format: {input_config['format']}")
        
        # Validate analysis configuration
        analysis_config = config.get('analysis', {})
        threat_config = analysis_config.get('threat_detection', {})
        if 'severity_threshold' in threat_config:
            valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            if threat_config['severity_threshold'] not in valid_severities:
                result['valid'] = False
                result['errors'].append(f"Invalid severity threshold: {threat_config['severity_threshold']}")
        
        # Validate output configuration
        output_config = config.get('output', {})
        if 'format' in output_config:
            valid_formats = ['json', 'html', 'csv', 'siem']
            if output_config['format'] not in valid_formats:
                result['valid'] = False
                result['errors'].append(f"Invalid output format: {output_config['format']}")
        
        # Validate security configuration
        security_config = config.get('security', {})
        if 'log_sanitization' in security_config and not isinstance(security_config['log_sanitization'], bool):
            result['valid'] = False
            result['errors'].append("log_sanitization must be boolean")
        
        if 'sensitive_patterns' in security_config:
            if not isinstance(security_config['sensitive_patterns'], list):
                result['valid'] = False
                result['errors'].append("sensitive_patterns must be a list")
        
        return result
    
    def validate_stream_input(self, stream_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate stream input configuration"""
        result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Check required stream parameters
        required_params = ['type', 'source']
        for param in required_params:
            if param not in stream_config:
                result['valid'] = False
                result['errors'].append(f"Missing required stream parameter: {param}")
        
        # Validate stream type
        stream_type = stream_config.get('type')
        valid_types = ['syslog', 'journalctl', 'tcp', 'udp']
        if stream_type not in valid_types:
            result['valid'] = False
            result['errors'].append(f"Invalid stream type: {stream_type}")
        
        # Validate TCP/UDP parameters
        if stream_type in ['tcp', 'udp']:
            if 'port' not in stream_config:
                result['valid'] = False
                result['errors'].append("Port required for TCP/UDP streams")
            elif not (1 <= stream_config['port'] <= 65535):
                result['valid'] = False
                result['errors'].append("Port must be between 1 and 65535")
        
        return result
    
    def validate_api_input(self, api_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate API input configuration"""
        result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Check required API parameters
        required_params = ['url', 'method']
        for param in required_params:
            if param not in api_config:
                result['valid'] = False
                result['errors'].append(f"Missing required API parameter: {param}")
        
        # Validate URL
        url = api_config.get('url', '')
        if not url.startswith(('http://', 'https://')):
            result['valid'] = False
            result['errors'].append("API URL must start with http:// or https://")
        
        # Validate HTTP method
        method = api_config.get('method', '').upper()
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE']
        if method not in valid_methods:
            result['valid'] = False
            result['errors'].append(f"Invalid HTTP method: {method}")
        
        # Validate authentication
        auth_config = api_config.get('auth', {})
        if 'type' in auth_config:
            valid_auth_types = ['none', 'basic', 'bearer', 'api_key']
            if auth_config['type'] not in valid_auth_types:
                result['valid'] = False
                result['errors'].append(f"Invalid authentication type: {auth_config['type']}")
        
        return result
    
    def _check_sensitive_data(self, text: str) -> tuple:
        """Check for sensitive data in text and sanitize if found"""
        sanitized = text
        found_sensitive = False
        
        for pattern in self.sensitive_patterns:
            matches = pattern.findall(text)
            if matches:
                found_sensitive = True
                # Replace with [REDACTED]
                sanitized = pattern.sub(r'\1[REDACTED]', sanitized)
        
        return sanitized, found_sensitive
    
    def sanitize_input(self, data: Any) -> Any:
        """Sanitize input data for security"""
        if isinstance(data, str):
            return self._sanitize_string(data)
        elif isinstance(data, dict):
            return {k: self.sanitize_input(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_input(item) for item in data]
        else:
            return data
    
    def _sanitize_string(self, text: str) -> str:
        """Sanitize string input"""
        # Remove null bytes and control characters
        sanitized = text.replace('\x00', '')
        
        # Remove or escape dangerous characters
        dangerous_chars = ['<', '>', '&', '"', "'"]
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, f'&#{ord(char)};')
        
        # Check for sensitive data
        sanitized, _ = self._check_sensitive_data(sanitized)
        
        return sanitized
    
    def get_validation_report(self, validation_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate validation report from multiple results"""
        report = {
            'total_validations': len(validation_results),
            'valid_count': 0,
            'error_count': 0,
            'warning_count': 0,
            'errors': [],
            'warnings': [],
            'summary': {}
        }
        
        for result in validation_results:
            if result.get('valid', False):
                report['valid_count'] += 1
            else:
                report['error_count'] += 1
                report['errors'].extend(result.get('errors', []))
            
            warnings = result.get('warnings', [])
            if warnings:
                report['warning_count'] += len(warnings)
                report['warnings'].extend(warnings)
        
        # Generate summary
        report['summary'] = {
            'success_rate': report['valid_count'] / report['total_validations'] if report['total_validations'] > 0 else 0,
            'error_rate': report['error_count'] / report['total_validations'] if report['total_validations'] > 0 else 0,
            'warning_rate': report['warning_count'] / report['total_validations'] if report['total_validations'] > 0 else 0
        }
        
        return report