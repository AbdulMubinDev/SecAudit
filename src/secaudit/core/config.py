"""
Configuration management for SecAudit
"""
import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path

class ConfigManager:
    """Configuration manager with validation and defaults"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_path (str, optional): Path to configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        if self.config_path and os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
        else:
            config = {}

        # If user provided a top-level "secaudit" key, unwrap it
        if isinstance(config, dict) and 'secaudit' in config:
            config = config.get('secaudit', {}) or {}

        # Merge with defaults (defaults are provided under top-level keys)
        defaults = self._get_default_config()
        self._merge_config(config, defaults)

        return config
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'version': '1.0',
            'debug': False,
            'log_level': 'INFO',
            'input': {
                'type': 'file',
                'path': '/var/log/auth.log',
                'format': 'ssh',
                'encoding': 'utf-8',
                'rotation': True,
                'buffer_size': 8192
            },
            'analysis': {
                'threat_detection': {
                    'enabled': True,
                    'rules_path': 'config/rules/threat_rules.yaml',
                    'severity_threshold': 'medium',
                    'max_rules': 1000
                },
                'anomaly_detection': {
                    'enabled': True,
                    'algorithms': ['statistical'],
                    'sensitivity': 0.8,
                    'learning_period': '24h'
                },
                'correlation': {
                    'enabled': True,
                    'time_window': '1h',
                    'cross_log': True,
                    'max_correlations': 100
                }
            },
            'output': {
                'format': 'json',
                'path': './output/',
                'compression': True,
                'real_time': False,
                'include_raw': False,
                'max_file_size': '100MB'
            },
            'plugins': {
                'enabled': True,
                'paths': ['plugins/'],
                'auto_load': True,
                'sandbox_mode': False
            },
            'security': {
                'log_sanitization': True,
                'sensitive_patterns': ['password', 'token', 'key', 'secret'],
                'encryption': False,
                'audit_trail': True
            },
            'performance': {
                'batch_size': 1000,
                'workers': 4,
                'memory_limit': '2GB',
                'timeout': 300
            }
        }
    
    def _merge_config(self, config: Dict[str, Any], defaults: Dict[str, Any]) -> None:
        """Recursively merge configuration with defaults"""
        for key, value in defaults.items():
            if key not in config:
                config[key] = value
            elif isinstance(value, dict) and isinstance(config[key], dict):
                self._merge_config(config[key], value)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            key (str): Configuration key (e.g., 'input.type')
            default (Any): Default value if key not found
            
        Returns:
            Any: Configuration value
        """
        keys = key.split('.')

        # Try direct traversal first
        value = self.config
        try:
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    raise KeyError()
            return value
        except Exception:
            # Fallback: try under top-level 'secaudit' key if present in user-provided config
            top = self.config.get('secaudit') if isinstance(self.config, dict) else None
            if isinstance(top, dict):
                value = top
                for k in keys:
                    if isinstance(value, dict) and k in value:
                        value = value[k]
                    else:
                        return default
                return value
            return default
    
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value using dot notation
        
        Args:
            key (str): Configuration key
            value (Any): Value to set
        """
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self, path: Optional[str] = None) -> bool:
        """
        Save configuration to file
        
        Args:
            path (str, optional): Path to save configuration
            
        Returns:
            bool: True if successful
        """
        save_path = path or self.config_path
        if not save_path:
            raise ValueError("No path specified for saving configuration")
        
        try:
            with open(save_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            return True
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False
    
    def validate(self) -> bool:
        """Validate configuration values"""
        try:
            # Validate log level
            log_level = self.get('secaudit.log_level')
            valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if log_level not in valid_levels:
                raise ValueError(f"Invalid log level: {log_level}")
            
            # Validate input type
            input_type = self.get('input.type')
            valid_input_types = ['file', 'stream', 'api']
            if input_type not in valid_input_types:
                raise ValueError(f"Invalid input type: {input_type}")
            
            # Validate parser format
            parser_format = self.get('input.format')
            valid_formats = ['ssh', 'syslog', 'windows', 'custom']
            if parser_format not in valid_formats:
                raise ValueError(f"Invalid parser format: {parser_format}")
            
            # Validate output format
            output_format = self.get('output.format')
            valid_output_formats = ['json', 'html', 'csv', 'siem']
            if output_format not in valid_output_formats:
                raise ValueError(f"Invalid output format: {output_format}")
            
            # Validate buffer size
            buffer_size = self.get('input.buffer_size', 8192)
            if not isinstance(buffer_size, int) or buffer_size < 1024:
                raise ValueError(f"Invalid buffer size: {buffer_size}")
            
            return True
            
        except Exception as e:
            print(f"Configuration validation failed: {e}")
            return False