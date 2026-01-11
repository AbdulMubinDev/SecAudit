"""
Configuration Management System for SecAudit

This module provides comprehensive configuration management capabilities including
YAML-based configuration loading, validation, and environment-specific configurations.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import timedelta
import logging

from pydantic import BaseModel, validator, Field, model_validator
from pydantic_yaml import parse_yaml_raw_as

logger = logging.getLogger(__name__)


class InputConfig(BaseModel):
    """Configuration for input sources"""
    type: str = Field(default="file", description="Input type: file, stream, api")
    path: str = Field(default="/var/log/auth.log", description="Input file path or stream source")
    format: str = Field(default="ssh", description="Log format: ssh, syslog, custom")
    encoding: str = Field(default="utf-8", description="File encoding")
    rotation: bool = Field(default=True, description="Enable file rotation detection")
    buffer_size: int = Field(default=8192, description="Buffer size for file/stream reading")
    timeout: int = Field(default=30, description="Connection timeout in seconds")
    
    @validator('type')
    def validate_input_type(cls, v):
        valid_types = ['file', 'stream', 'api']
        if v not in valid_types:
            raise ValueError(f"Input type must be one of: {valid_types}")
        return v
    
    @validator('format')
    def validate_format(cls, v):
        valid_formats = ['ssh', 'syslog', 'custom', 'windows', 'cloud']
        if v not in valid_formats:
            raise ValueError(f"Format must be one of: {valid_formats}")
        return v


class ThreatDetectionConfig(BaseModel):
    """Configuration for threat detection"""
    enabled: bool = Field(default=True, description="Enable threat detection")
    rules_path: str = Field(default="config/rules/threat_rules.yaml", description="Path to threat rules file")
    severity_threshold: str = Field(default="medium", description="Minimum severity threshold")
    max_rules: int = Field(default=1000, description="Maximum number of rules to load")
    real_time: bool = Field(default=False, description="Enable real-time threat detection")
    
    @validator('severity_threshold')
    def validate_severity(cls, v):
        valid_severities = ['low', 'medium', 'high', 'critical']
        if v not in valid_severities:
            raise ValueError(f"Severity must be one of: {valid_severities}")
        return v


class AnomalyDetectionConfig(BaseModel):
    """Configuration for anomaly detection"""
    enabled: bool = Field(default=True, description="Enable anomaly detection")
    algorithms: list = Field(default=["statistical"], description="List of algorithms to use")
    sensitivity: float = Field(default=0.8, ge=0.0, le=1.0, description="Detection sensitivity")
    learning_period: str = Field(default="24h", description="Time period for learning baseline")
    update_interval: str = Field(default="1h", description="How often to update baselines")
    
    @validator('algorithms')
    def validate_algorithms(cls, v):
        valid_algorithms = ['statistical', 'ml', 'behavioral']
        for algorithm in v:
            if algorithm not in valid_algorithms:
                raise ValueError(f"Invalid algorithm: {algorithm}")
        return v


class CorrelationConfig(BaseModel):
    """Configuration for event correlation"""
    enabled: bool = Field(default=True, description="Enable event correlation")
    time_window: str = Field(default="1h", description="Time window for correlation")
    cross_log: bool = Field(default=True, description="Enable cross-log correlation")
    max_correlations: int = Field(default=100, description="Maximum correlations to track")
    threshold: float = Field(default=0.5, ge=0.0, le=1.0, description="Correlation threshold")


class AnalysisConfig(BaseModel):
    """Configuration for analysis engine"""
    threat_detection: ThreatDetectionConfig = Field(default_factory=ThreatDetectionConfig)
    anomaly_detection: AnomalyDetectionConfig = Field(default_factory=AnomalyDetectionConfig)
    correlation: CorrelationConfig = Field(default_factory=CorrelationConfig)
    
    @model_validator(mode='after')
    def validate_analysis_config(self):
        # Ensure at least one analysis type is enabled
        threat_enabled = self.threat_detection.enabled
        anomaly_enabled = self.anomaly_detection.enabled
        correlation_enabled = self.correlation.enabled
        
        if not any([threat_enabled, anomaly_enabled, correlation_enabled]):
            raise ValueError("At least one analysis type must be enabled")
        
        return self


class OutputConfig(BaseModel):
    """Configuration for output formats"""
    format: str = Field(default="json", description="Output format: json, html, csv, siem")
    path: str = Field(default="./output/", description="Output directory path")
    compression: bool = Field(default=True, description="Enable output compression")
    real_time: bool = Field(default=False, description="Enable real-time output")
    include_raw: bool = Field(default=False, description="Include raw log data in output")
    max_file_size: str = Field(default="100MB", description="Maximum output file size")
    rotate_logs: bool = Field(default=True, description="Enable output log rotation")
    
    @validator('format')
    def validate_output_format(cls, v):
        valid_formats = ['json', 'html', 'csv', 'siem', 'xml']
        if v not in valid_formats:
            raise ValueError(f"Output format must be one of: {valid_formats}")
        return v


class PluginConfig(BaseModel):
    """Configuration for plugin system"""
    enabled: bool = Field(default=True, description="Enable plugin system")
    paths: list = Field(default=["plugins/"], description="List of plugin directories")
    auto_load: bool = Field(default=True, description="Auto-load plugins on startup")
    sandbox_mode: bool = Field(default=False, description="Run plugins in sandbox mode")
    timeout: int = Field(default=60, description="Plugin execution timeout in seconds")
    
    @validator('paths')
    def validate_plugin_paths(cls, v):
        for path in v:
            if not os.path.exists(path):
                logger.warning(f"Plugin path does not exist: {path}")
        return v


class SecurityConfig(BaseModel):
    """Configuration for security features"""
    log_sanitization: bool = Field(default=True, description="Enable log sanitization")
    sensitive_patterns: list = Field(
        default=["password", "token", "key", "secret", "credential"],
        description="Patterns to sanitize in logs"
    )
    encryption: bool = Field(default=False, description="Enable output encryption")
    audit_trail: bool = Field(default=True, description="Enable audit trail logging")
    access_control: bool = Field(default=False, description="Enable access control")


class PerformanceConfig(BaseModel):
    """Configuration for performance optimization"""
    batch_size: int = Field(default=1000, description="Batch size for processing")
    workers: int = Field(default=4, description="Number of worker threads")
    memory_limit: str = Field(default="2GB", description="Maximum memory usage")
    timeout: int = Field(default=300, description="Processing timeout in seconds")
    cache_size: int = Field(default=10000, description="Cache size for frequently accessed data")
    
    @validator('workers')
    def validate_workers(cls, v):
        if v < 1 or v > 32:
            raise ValueError("Workers must be between 1 and 32")
        return v


class DatabaseConfig(BaseModel):
    """Configuration for database operations"""
    type: str = Field(default="sqlite", description="Database type: sqlite, postgresql")
    path: str = Field(default="./data/secaudit.db", description="Database file path")
    backup_interval: str = Field(default="1h", description="Database backup interval")
    retention_days: int = Field(default=30, description="Data retention period in days")
    max_connections: int = Field(default=10, description="Maximum database connections")
    
    @validator('type')
    def validate_db_type(cls, v):
        valid_types = ['sqlite', 'postgresql', 'mysql']
        if v not in valid_types:
            raise ValueError(f"Database type must be one of: {valid_types}")
        return v


class SecAuditConfig(BaseModel):
    """Main SecAudit configuration model"""
    version: str = Field(default="1.0", description="Configuration version")
    debug: bool = Field(default=False, description="Enable debug mode")
    log_level: str = Field(default="INFO", description="Logging level")
    input: InputConfig = Field(default_factory=InputConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    plugins: PluginConfig = Field(default_factory=PluginConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    
    @validator('log_level')
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v


class ConfigManager:
    """Configuration Manager for SecAudit
    
    Handles loading, validation, and management of SecAudit configuration.
    Supports multiple configuration sources and environment-specific configs.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_path: Path to configuration file. If None, uses default paths.
        """
        self.config_path = config_path
        self.config: Optional[SecAuditConfig] = None
        self.environment = os.getenv('SECAUDIT_ENV', 'development')
        
    def load_config(self) -> SecAuditConfig:
        """
        Load and validate configuration from file or defaults
        
        Returns:
            SecAuditConfig: Validated configuration object
        """
        if self.config:
            return self.config
            
        # Try to load from specified path or default locations
        config_data = self._load_config_data()
        
        # Parse and validate configuration
        try:
            self.config = parse_yaml_raw_as(SecAuditConfig, config_data)
            logger.info(f"Configuration loaded successfully from {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to parse configuration: {e}")
            # Fall back to default configuration
            self.config = SecAuditConfig()
            
        return self.config
    
    def _load_config_data(self) -> str:
        """Load configuration data from file or return default"""
        if self.config_path and os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return f.read()
        
        # Try default configuration paths
        default_paths = [
            f"config/secaudit.{self.environment}.yaml",
            "config/secaudit.yaml",
            "config/default.yaml",
            "secaudit.yaml"
        ]
        
        for path in default_paths:
            if os.path.exists(path):
                self.config_path = path
                with open(path, 'r') as f:
                    return f.read()
        
        # Return default configuration as string
        logger.warning("No configuration file found, using defaults")
        return self._get_default_config_yaml()
    
    def _get_default_config_yaml(self) -> str:
        """Generate default configuration as YAML string"""
        default_config = SecAuditConfig()
        return default_config.json()
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by dot notation key
        
        Args:
            key: Configuration key in dot notation (e.g., 'input.path')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        if not self.config:
            self.load_config()
            
        # Navigate through nested configuration
        current = self.config
        for part in key.split('.'):
            if hasattr(current, part):
                current = getattr(current, part)
            else:
                return default
                
        return current
    
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value by dot notation key
        
        Args:
            key: Configuration key in dot notation
            value: New value to set
        """
        if not self.config:
            self.load_config()
            
        # Navigate to parent object
        parts = key.split('.')
        current = self.config
        for part in parts[:-1]:
            if hasattr(current, part):
                current = getattr(current, part)
            else:
                raise KeyError(f"Configuration key '{key}' not found")
        
        # Set the value
        setattr(current, parts[-1], value)
    
    def validate(self) -> bool:
        """
        Validate current configuration
        
        Returns:
            bool: True if configuration is valid, False otherwise
        """
        try:
            if not self.config:
                self.load_config()
            # Validation happens during parsing, so if we have a config object,
            # it should be valid
            return True
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            return False
    
    def save(self, path: Optional[str] = None) -> bool:
        """
        Save current configuration to file
        
        Args:
            path: Path to save configuration. If None, uses current config path.
            
        Returns:
            bool: True if save successful, False otherwise
        """
        try:
            if not self.config:
                self.load_config()
                
            save_path = path or self.config_path
            if not save_path:
                save_path = f"config/secaudit.{self.environment}.yaml"
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            with open(save_path, 'w') as f:
                yaml.dump(self.config.dict(), f, default_flow_style=False, indent=2)
            
            logger.info(f"Configuration saved to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    def reload(self) -> SecAuditConfig:
        """
        Reload configuration from file
        
        Returns:
            SecAuditConfig: Reloaded configuration
        """
        self.config = None
        return self.load_config()
    
    def get_environment(self) -> str:
        """Get current environment"""
        return self.environment
    
    def set_environment(self, environment: str) -> None:
        """Set environment and reload configuration"""
        self.environment = environment
        self.config = None
        self.load_config()


# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None


def get_config_manager() -> ConfigManager:
    """Get global configuration manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def load_config(config_path: Optional[str] = None) -> SecAuditConfig:
    """
    Load configuration using global manager
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        SecAuditConfig: Loaded configuration
    """
    manager = get_config_manager()
    if config_path:
        manager.config_path = config_path
    return manager.load_config()


def get_config_value(key: str, default: Any = None) -> Any:
    """
    Get configuration value using global manager
    
    Args:
        key: Configuration key in dot notation
        default: Default value if key not found
        
    Returns:
        Configuration value or default
    """
    manager = get_config_manager()
    return manager.get(key, default)


def set_config_value(key: str, value: Any) -> None:
    """
    Set configuration value using global manager
    
    Args:
        key: Configuration key in dot notation
        value: New value to set
    """
    manager = get_config_manager()
    manager.set(key, value)