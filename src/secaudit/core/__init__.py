"""
SecAudit Core Module

This module provides the core functionality for SecAudit including:
- Configuration management
- Application orchestration
- Plugin management
- Logging framework
"""

from .config import (
    SecAuditConfig,
    ConfigManager,
    load_config,
    get_config_manager,
    get_config_value,
    set_config_value
)
from .config_validator import (
    ConfigValidator,
    validate_config_file,
    print_validation_report
)
from .application import SecAuditApplication
from .plugin_manager import PluginManager
# from .logger import setup_logging, get_logger  # TODO: Implement logger module

__all__ = [
    # Configuration
    'SecAuditConfig',
    'ConfigManager',
    'load_config',
    'get_config_manager',
    'get_config_value',
    'set_config_value',
    
    # Configuration Validation
    'ConfigValidator',
    'validate_config_file',
    'print_validation_report',
    
    # Application
    'SecAuditApplication',
    
    # Plugin System
    'PluginManager',
    
    # Logging
    # 'setup_logging',  # TODO: Implement logger module
    # 'get_logger'
]