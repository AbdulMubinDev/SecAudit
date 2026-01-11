"""
Configuration Validation Utilities for SecAudit

This module provides additional validation utilities for SecAudit configuration
beyond the basic Pydantic validation, including file path validation,
performance constraint validation, and security validation.
"""

import os
import re
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timedelta
import logging

from .config import SecAuditConfig, InputConfig, AnalysisConfig, OutputConfig

logger = logging.getLogger(__name__)


class ConfigValidator:
    """Advanced configuration validator for SecAudit"""
    
    def __init__(self, config: SecAuditConfig):
        """
        Initialize validator with configuration
        
        Args:
            config: SecAudit configuration to validate
        """
        self.config = config
        self.errors: List[str] = []
        self.warnings: List[str] = []
    
    def validate_all(self) -> Tuple[bool, List[str], List[str]]:
        """
        Perform comprehensive configuration validation
        
        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        self.errors = []
        self.warnings = []
        
        # Basic structure validation (handled by Pydantic)
        # Additional validations
        self._validate_file_paths()
        self._validate_performance_settings()
        self._validate_security_settings()
        self._validate_analysis_settings()
        self._validate_output_settings()
        self._validate_database_settings()
        
        is_valid = len(self.errors) == 0
        return is_valid, self.errors, self.warnings
    
    def _validate_file_paths(self) -> None:
        """Validate file and directory paths"""
        # Validate input path
        input_path = self.config.input.path
        if self.config.input.type == "file":
            if not os.path.exists(input_path) and not input_path.startswith("./tests/"):
                self.warnings.append(f"Input file does not exist: {input_path}")
            
            # Check if path is readable
            try:
                if os.path.exists(input_path) and not os.access(input_path, os.R_OK):
                    self.errors.append(f"Input file is not readable: {input_path}")
            except Exception as e:
                self.errors.append(f"Error checking input file permissions: {e}")
        
        # Validate output directory
        output_path = self.config.output.path
        try:
            os.makedirs(output_path, exist_ok=True)
            if not os.access(output_path, os.W_OK):
                self.errors.append(f"Output directory is not writable: {output_path}")
        except Exception as e:
            self.errors.append(f"Error creating output directory: {e}")
        
        # Validate rules path
        rules_path = self.config.analysis.threat_detection.rules_path
        if not os.path.exists(rules_path):
            self.warnings.append(f"Threat rules file does not exist: {rules_path}")
        
        # Validate plugin paths
        for plugin_path in self.config.plugins.paths:
            if not os.path.exists(plugin_path):
                self.warnings.append(f"Plugin path does not exist: {plugin_path}")
    
    def _validate_performance_settings(self) -> None:
        """Validate performance-related settings"""
        perf = self.config.performance
        
        # Validate memory limit format
        memory_limit = perf.memory_limit
        if not self._is_valid_memory_limit(memory_limit):
            self.errors.append(f"Invalid memory limit format: {memory_limit}")
        
        # Validate batch size
        if perf.batch_size < 1:
            self.errors.append("Batch size must be greater than 0")
        
        if perf.batch_size > 100000:
            self.warnings.append("Very large batch size may cause memory issues")
        
        # Validate worker count
        if perf.workers < 1:
            self.errors.append("Worker count must be greater than 0")
        
        if perf.workers > 32:
            self.warnings.append("Worker count > 32 may not provide additional performance benefits")
        
        # Validate timeout
        if perf.timeout < 1:
            self.errors.append("Timeout must be greater than 0 seconds")
        
        if perf.timeout > 86400:  # 24 hours
            self.warnings.append("Very long timeout may cause issues")
    
    def _validate_security_settings(self) -> None:
        """Validate security-related settings"""
        security = self.config.security
        
        # Validate sensitive patterns
        if not security.sensitive_patterns:
            self.warnings.append("No sensitive patterns defined for log sanitization")
        
        # Check for common sensitive patterns
        common_patterns = ["password", "token", "key", "secret"]
        missing_patterns = [p for p in common_patterns if p not in security.sensitive_patterns]
        if missing_patterns:
            self.warnings.append(f"Consider adding sensitive patterns: {missing_patterns}")
        
        # Validate encryption settings
        if security.encryption and self.config.output.format not in ["json", "xml"]:
            self.warnings.append("Encryption is only supported for JSON and XML output formats")
    
    def _validate_analysis_settings(self) -> None:
        """Validate analysis-related settings"""
        analysis = self.config.analysis
        
        # Validate threat detection settings
        if analysis.threat_detection.enabled:
            if analysis.threat_detection.max_rules < 1:
                self.errors.append("Max rules must be greater than 0")
            
            if analysis.threat_detection.max_rules > 10000:
                self.warnings.append("Very high rule count may impact performance")
        
        # Validate anomaly detection settings
        if analysis.anomaly_detection.enabled:
            sensitivity = analysis.anomaly_detection.sensitivity
            if sensitivity <= 0 or sensitivity > 1:
                self.errors.append("Anomaly detection sensitivity must be between 0 and 1")
            
            if sensitivity > 0.9:
                self.warnings.append("High sensitivity may result in many false positives")
            
            if sensitivity < 0.3:
                self.warnings.append("Low sensitivity may miss important anomalies")
        
        # Validate correlation settings
        if analysis.correlation.enabled:
            threshold = analysis.correlation.threshold
            if threshold <= 0 or threshold > 1:
                self.errors.append("Correlation threshold must be between 0 and 1")
            
            if threshold > 0.8:
                self.warnings.append("High correlation threshold may miss valid correlations")
    
    def _validate_output_settings(self) -> None:
        """Validate output-related settings"""
        output = self.config.output
        
        # Validate file size limit
        max_file_size = output.max_file_size
        if not self._is_valid_file_size(max_file_size):
            self.errors.append(f"Invalid file size format: {max_file_size}")
        
        # Validate output format compatibility
        if output.compression and output.format not in ["json", "csv"]:
            self.warnings.append("Compression may not be supported for all output formats")
    
    def _validate_database_settings(self) -> None:
        """Validate database-related settings"""
        db = self.config.database
        
        # Validate database type
        if db.type == "sqlite":
            # For SQLite, path should be a file path
            if not db.path.endswith(".db"):
                self.warnings.append("SQLite database path should end with .db")
        elif db.type in ["postgresql", "mysql"]:
            # For network databases, path should be a connection string
            if not db.path.startswith(("postgresql://", "mysql://")):
                self.warnings.append("Network database path should be a connection string")
        
        # Validate retention settings
        if db.retention_days < 1:
            self.errors.append("Retention days must be greater than 0")
        
        if db.retention_days > 3650:  # 10 years
            self.warnings.append("Very long retention may cause storage issues")
        
        # Validate connection settings
        if db.max_connections < 1:
            self.errors.append("Max connections must be greater than 0")
        
        if db.max_connections > 100:
            self.warnings.append("High connection count may cause database issues")
    
    def _is_valid_memory_limit(self, memory_limit: str) -> bool:
        """Validate memory limit format (e.g., '2GB', '512MB')"""
        pattern = r'^\d+(KB|MB|GB|TB)$'
        return bool(re.match(pattern, memory_limit, re.IGNORECASE))
    
    def _is_valid_file_size(self, file_size: str) -> bool:
        """Validate file size format (e.g., '100MB', '1GB')"""
        pattern = r'^\d+(B|KB|MB|GB|TB)$'
        return bool(re.match(pattern, file_size, re.IGNORECASE))
    
    def validate_environment_specific(self, environment: str) -> List[str]:
        """
        Validate configuration for specific environment
        
        Args:
            environment: Environment name (development, production, test)
            
        Returns:
            List of validation issues
        """
        issues = []
        
        if environment == "production":
            # Production-specific validations
            if self.config.debug:
                issues.append("Debug mode should be disabled in production")
            
            if self.config.log_level not in ["WARNING", "ERROR", "CRITICAL"]:
                issues.append("Log level should be WARNING or higher in production")
            
            if not self.config.security.log_sanitization:
                issues.append("Log sanitization should be enabled in production")
            
            if not self.config.security.audit_trail:
                issues.append("Audit trail should be enabled in production")
        
        elif environment == "development":
            # Development-specific validations
            if not self.config.debug:
                issues.append("Consider enabling debug mode for development")
        
        elif environment == "test":
            # Test-specific validations
            if self.config.performance.workers != 1:
                issues.append("Use single worker for predictable test results")
        
        return issues


def validate_config_file(config_path: str, environment: str = "development") -> Tuple[bool, List[str], List[str]]:
    """
    Validate a configuration file
    
    Args:
        config_path: Path to configuration file
        environment: Environment name for specific validations
        
    Returns:
        Tuple of (is_valid, errors, warnings)
    """
    try:
        # Load configuration
        from .config import load_config
        config = load_config(config_path)
        
        # Validate configuration
        validator = ConfigValidator(config)
        is_valid, errors, warnings = validator.validate_all()
        
        # Add environment-specific validations
        env_issues = validator.validate_environment_specific(environment)
        errors.extend(env_issues)
        
        return is_valid, errors, warnings
        
    except Exception as e:
        return False, [f"Failed to load configuration: {e}"], []


def print_validation_report(is_valid: bool, errors: List[str], warnings: List[str]) -> None:
    """
    Print a formatted validation report
    
    Args:
        is_valid: Whether configuration is valid
        errors: List of validation errors
        warnings: List of validation warnings
    """
    print("=" * 60)
    print("SECURITY CONFIGURATION VALIDATION REPORT")
    print("=" * 60)
    
    if is_valid:
        print("✅ Configuration is VALID")
    else:
        print("❌ Configuration has ERRORS")
    
    print(f"\nErrors: {len(errors)}")
    for error in errors:
        print(f"  ❌ {error}")
    
    print(f"\nWarnings: {len(warnings)}")
    for warning in warnings:
        print(f"  ⚠️  {warning}")
    
    print("=" * 60)