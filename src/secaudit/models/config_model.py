"""
Configuration data model for SecAudit
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime


@dataclass
class ConfigModel:
    """Configuration data model for SecAudit"""
    
    # Basic configuration
    version: str = "1.0"
    debug: bool = False
    log_level: str = "INFO"
    
    # Input configuration
    input_type: str = "file"
    input_path: str = "/var/log/auth.log"
    input_format: str = "ssh"
    input_encoding: str = "utf-8"
    input_rotation: bool = True
    input_buffer_size: int = 8192
    
    # Analysis configuration
    threat_detection_enabled: bool = True
    threat_detection_rules_path: str = "config/rules/threat_rules.yaml"
    threat_detection_severity_threshold: str = "medium"
    threat_detection_max_rules: int = 1000
    
    anomaly_detection_enabled: bool = True
    anomaly_detection_algorithms: List[str] = field(default_factory=lambda: ["statistical"])
    anomaly_detection_sensitivity: float = 0.8
    anomaly_detection_learning_period: str = "24h"
    
    correlation_enabled: bool = True
    correlation_time_window: str = "1h"
    correlation_cross_log: bool = True
    correlation_max_correlations: int = 100
    
    # Output configuration
    output_format: str = "json"
    output_path: str = "./output/"
    output_compression: bool = True
    output_real_time: bool = False
    output_include_raw: bool = False
    output_max_file_size: str = "100MB"
    
    # Plugin configuration
    plugins_enabled: bool = True
    plugin_paths: List[str] = field(default_factory=lambda: ["plugins/"])
    plugin_auto_load: bool = True
    plugin_sandbox_mode: bool = False
    
    # Security configuration
    log_sanitization: bool = True
    sensitive_patterns: List[str] = field(default_factory=lambda: ["password", "token", "key", "secret"])
    encryption: bool = False
    audit_trail: bool = True
    
    # Performance configuration
    batch_size: int = 1000
    workers: int = 4
    memory_limit: str = "2GB"
    timeout: int = 300
    
    # Database configuration
    database_type: str = "sqlite"
    database_path: str = "./data/secaudit.db"
    database_backup_interval: str = "1h"
    database_retention_days: int = 30
    
    # Cache configuration
    cache_enabled: bool = True
    cache_max_size: int = 1000
    cache_default_ttl: int = 3600
    cache_persistent: bool = False
    cache_file: str = "./data/cache.json"
    
    # Alert configuration
    alert_threshold: str = "MEDIUM"
    notification_methods: List[str] = field(default_factory=lambda: ["console"])
    
    # Email notification configuration
    email_enabled: bool = False
    email_smtp_server: str = ""
    email_smtp_port: int = 587
    email_username: str = ""
    email_password: str = ""
    email_recipients: List[str] = field(default_factory=list)
    
    # Webhook notification configuration
    webhook_enabled: bool = False
    webhook_url: str = ""
    
    # Metadata
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_validated: Optional[datetime] = None
    
    def __post_init__(self):
        """Initialize timestamps if not provided"""
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {}
        
        # Basic configuration
        result['secaudit'] = {
            'version': self.version,
            'debug': self.debug,
            'log_level': self.log_level
        }
        
        # Input configuration
        result['input'] = {
            'type': self.input_type,
            'path': self.input_path,
            'format': self.input_format,
            'encoding': self.input_encoding,
            'rotation': self.input_rotation,
            'buffer_size': self.input_buffer_size
        }
        
        # Analysis configuration
        result['analysis'] = {
            'threat_detection': {
                'enabled': self.threat_detection_enabled,
                'rules_path': self.threat_detection_rules_path,
                'severity_threshold': self.threat_detection_severity_threshold,
                'max_rules': self.threat_detection_max_rules
            },
            'anomaly_detection': {
                'enabled': self.anomaly_detection_enabled,
                'algorithms': self.anomaly_detection_algorithms,
                'sensitivity': self.anomaly_detection_sensitivity,
                'learning_period': self.anomaly_detection_learning_period
            },
            'correlation': {
                'enabled': self.correlation_enabled,
                'time_window': self.correlation_time_window,
                'cross_log': self.correlation_cross_log,
                'max_correlations': self.correlation_max_correlations
            }
        }
        
        # Output configuration
        result['output'] = {
            'format': self.output_format,
            'path': self.output_path,
            'compression': self.output_compression,
            'real_time': self.output_real_time,
            'include_raw': self.output_include_raw,
            'max_file_size': self.output_max_file_size
        }
        
        # Plugin configuration
        result['plugins'] = {
            'enabled': self.plugins_enabled,
            'paths': self.plugin_paths,
            'auto_load': self.plugin_auto_load,
            'sandbox_mode': self.plugin_sandbox_mode
        }
        
        # Security configuration
        result['security'] = {
            'log_sanitization': self.log_sanitization,
            'sensitive_patterns': self.sensitive_patterns,
            'encryption': self.encryption,
            'audit_trail': self.audit_trail
        }
        
        # Performance configuration
        result['performance'] = {
            'batch_size': self.batch_size,
            'workers': self.workers,
            'memory_limit': self.memory_limit,
            'timeout': self.timeout
        }
        
        # Database configuration
        result['database'] = {
            'type': self.database_type,
            'path': self.database_path,
            'backup_interval': self.database_backup_interval,
            'retention_days': self.database_retention_days
        }
        
        # Cache configuration
        result['cache'] = {
            'enabled': self.cache_enabled,
            'max_size': self.cache_max_size,
            'default_ttl': self.cache_default_ttl,
            'persistent': self.cache_persistent,
            'cache_file': self.cache_file
        }
        
        # Alert configuration
        result['alert'] = {
            'threshold': self.alert_threshold,
            'notification_methods': self.notification_methods,
            'email': {
                'enabled': self.email_enabled,
                'smtp_server': self.email_smtp_server,
                'smtp_port': self.email_smtp_port,
                'username': self.email_username,
                'recipients': self.email_recipients
            },
            'webhook': {
                'enabled': self.webhook_enabled,
                'url': self.webhook_url
            }
        }
        
        # Metadata
        result['metadata'] = {
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_validated': self.last_validated.isoformat() if self.last_validated else None
        }
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConfigModel':
        """Create ConfigModel from dictionary"""
        secaudit_config = data.get('secaudit', {})
        input_config = data.get('input', {})
        analysis_config = data.get('analysis', {})
        output_config = data.get('output', {})
        plugins_config = data.get('plugins', {})
        security_config = data.get('security', {})
        performance_config = data.get('performance', {})
        database_config = data.get('database', {})
        cache_config = data.get('cache', {})
        alert_config = data.get('alert', {})
        metadata_config = data.get('metadata', {})
        
        threat_detection = analysis_config.get('threat_detection', {})
        anomaly_detection = analysis_config.get('anomaly_detection', {})
        correlation = analysis_config.get('correlation', {})
        email_config = alert_config.get('email', {})
        webhook_config = alert_config.get('webhook', {})
        
        return cls(
            # Basic configuration
            version=secaudit_config.get('version', '1.0'),
            debug=secaudit_config.get('debug', False),
            log_level=secaudit_config.get('log_level', 'INFO'),
            
            # Input configuration
            input_type=input_config.get('type', 'file'),
            input_path=input_config.get('path', '/var/log/auth.log'),
            input_format=input_config.get('format', 'ssh'),
            input_encoding=input_config.get('encoding', 'utf-8'),
            input_rotation=input_config.get('rotation', True),
            input_buffer_size=input_config.get('buffer_size', 8192),
            
            # Analysis configuration
            threat_detection_enabled=threat_detection.get('enabled', True),
            threat_detection_rules_path=threat_detection.get('rules_path', 'config/rules/threat_rules.yaml'),
            threat_detection_severity_threshold=threat_detection.get('severity_threshold', 'medium'),
            threat_detection_max_rules=threat_detection.get('max_rules', 1000),
            
            anomaly_detection_enabled=anomaly_detection.get('enabled', True),
            anomaly_detection_algorithms=anomaly_detection.get('algorithms', ['statistical']),
            anomaly_detection_sensitivity=anomaly_detection.get('sensitivity', 0.8),
            anomaly_detection_learning_period=anomaly_detection.get('learning_period', '24h'),
            
            correlation_enabled=correlation.get('enabled', True),
            correlation_time_window=correlation.get('time_window', '1h'),
            correlation_cross_log=correlation.get('cross_log', True),
            correlation_max_correlations=correlation.get('max_correlations', 100),
            
            # Output configuration
            output_format=output_config.get('format', 'json'),
            output_path=output_config.get('path', './output/'),
            output_compression=output_config.get('compression', True),
            output_real_time=output_config.get('real_time', False),
            output_include_raw=output_config.get('include_raw', False),
            output_max_file_size=output_config.get('max_file_size', '100MB'),
            
            # Plugin configuration
            plugins_enabled=plugins_config.get('enabled', True),
            plugin_paths=plugins_config.get('paths', ['plugins/']),
            plugin_auto_load=plugins_config.get('auto_load', True),
            plugin_sandbox_mode=plugins_config.get('sandbox_mode', False),
            
            # Security configuration
            log_sanitization=security_config.get('log_sanitization', True),
            sensitive_patterns=security_config.get('sensitive_patterns', ['password', 'token', 'key', 'secret']),
            encryption=security_config.get('encryption', False),
            audit_trail=security_config.get('audit_trail', True),
            
            # Performance configuration
            batch_size=performance_config.get('batch_size', 1000),
            workers=performance_config.get('workers', 4),
            memory_limit=performance_config.get('memory_limit', '2GB'),
            timeout=performance_config.get('timeout', 300),
            
            # Database configuration
            database_type=database_config.get('type', 'sqlite'),
            database_path=database_config.get('path', './data/secaudit.db'),
            database_backup_interval=database_config.get('backup_interval', '1h'),
            database_retention_days=database_config.get('retention_days', 30),
            
            # Cache configuration
            cache_enabled=cache_config.get('enabled', True),
            cache_max_size=cache_config.get('max_size', 1000),
            cache_default_ttl=cache_config.get('default_ttl', 3600),
            cache_persistent=cache_config.get('persistent', False),
            cache_file=cache_config.get('cache_file', './data/cache.json'),
            
            # Alert configuration
            alert_threshold=alert_config.get('threshold', 'MEDIUM'),
            notification_methods=alert_config.get('notification_methods', ['console']),
            
            # Email configuration
            email_enabled=email_config.get('enabled', False),
            email_smtp_server=email_config.get('smtp_server', ''),
            email_smtp_port=email_config.get('smtp_port', 587),
            email_username=email_config.get('username', ''),
            email_recipients=email_config.get('recipients', []),
            
            # Webhook configuration
            webhook_enabled=webhook_config.get('enabled', False),
            webhook_url=webhook_config.get('url', ''),
            
            # Metadata
            created_at=datetime.fromisoformat(metadata_config.get('created_at')) if metadata_config.get('created_at') else None,
            updated_at=datetime.fromisoformat(metadata_config.get('updated_at')) if metadata_config.get('updated_at') else None,
            last_validated=datetime.fromisoformat(metadata_config.get('last_validated')) if metadata_config.get('last_validated') else None
        )
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        # Validate log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.log_level not in valid_log_levels:
            errors.append(f"Invalid log level: {self.log_level}")
        
        # Validate input type
        valid_input_types = ['file', 'stream', 'api']
        if self.input_type not in valid_input_types:
            errors.append(f"Invalid input type: {self.input_type}")
        
        # Validate input format
        valid_formats = ['ssh', 'syslog', 'windows', 'custom']
        if self.input_format not in valid_formats:
            errors.append(f"Invalid input format: {self.input_format}")
        
        # Validate output format
        valid_output_formats = ['json', 'html', 'csv', 'siem']
        if self.output_format not in valid_output_formats:
            errors.append(f"Invalid output format: {self.output_format}")
        
        # Validate severity threshold
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        if self.alert_threshold not in valid_severities:
            errors.append(f"Invalid alert threshold: {self.alert_threshold}")
        
        # Validate notification methods
        valid_methods = ['console', 'email', 'webhook', 'file']
        for method in self.notification_methods:
            if method not in valid_methods:
                errors.append(f"Invalid notification method: {method}")
        
        # Validate buffer size
        if self.input_buffer_size < 1024:
            errors.append(f"Invalid buffer size: {self.input_buffer_size}")
        
        # Validate batch size
        if self.batch_size < 1:
            errors.append(f"Invalid batch size: {self.batch_size}")
        
        # Validate workers
        if self.workers < 1:
            errors.append(f"Invalid worker count: {self.workers}")
        
        # Validate timeout
        if self.timeout < 1:
            errors.append(f"Invalid timeout: {self.timeout}")
        
        # Validate retention days
        if self.database_retention_days < 1:
            errors.append(f"Invalid retention days: {self.database_retention_days}")
        
        # Validate cache size
        if self.cache_max_size < 1:
            errors.append(f"Invalid cache size: {self.cache_max_size}")
        
        # Validate TTL
        if self.cache_default_ttl < 1:
            errors.append(f"Invalid cache TTL: {self.cache_default_ttl}")
        
        return errors
    
    def update_timestamp(self) -> None:
        """Update the updated_at timestamp"""
        self.updated_at = datetime.now()
    
    def mark_validated(self) -> None:
        """Mark the configuration as validated"""
        self.last_validated = datetime.now()
    
    def is_valid(self) -> bool:
        """Check if configuration is valid"""
        return len(self.validate()) == 0