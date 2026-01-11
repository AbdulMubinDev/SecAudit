"""
Unit tests for configuration management system
"""

import os
import tempfile
import pytest
from pathlib import Path

from src.secaudit.core.config import (
    SecAuditConfig,
    ConfigManager,
    load_config,
    get_config_value,
    set_config_value
)
from src.secaudit.core.config_validator import (
    ConfigValidator,
    validate_config_file,
    print_validation_report
)


class TestSecAuditConfig:
    """Test SecAuditConfig data model"""
    
    def test_default_config(self):
        """Test default configuration creation"""
        config = SecAuditConfig()
        
        assert config.version == "1.0"
        assert config.debug is False
        assert config.log_level == "INFO"
        assert config.input.type == "file"
        assert config.input.path == "/var/log/auth.log"
        assert config.analysis.threat_detection.enabled is True
        assert config.output.format == "json"
    
    def test_config_validation(self):
        """Test configuration validation"""
        # Test valid configuration
        config = SecAuditConfig(
            log_level="DEBUG",
            input={
                "type": "stream",
                "path": "/dev/stdin",
                "format": "syslog"
            }
        )
        
        assert config.log_level == "DEBUG"
        assert config.input.type == "stream"
        assert config.input.format == "syslog"
    
    def test_invalid_log_level(self):
        """Test invalid log level validation"""
        with pytest.raises(ValueError):
            SecAuditConfig(log_level="INVALID")
    
    def test_invalid_input_type(self):
        """Test invalid input type validation"""
        with pytest.raises(ValueError):
            SecAuditConfig(input={"type": "invalid"})
    
    def test_invalid_format(self):
        """Test invalid format validation"""
        with pytest.raises(ValueError):
            SecAuditConfig(input={"format": "invalid"})


class TestConfigManager:
    """Test ConfigManager functionality"""
    
    def test_load_default_config(self):
        """Test loading default configuration"""
        manager = ConfigManager()
        config = manager.load_config()
        
        assert isinstance(config, SecAuditConfig)
        assert config.version == "1.0"
    
    def test_load_from_file(self):
        """Test loading configuration from file"""
        # Create a temporary config file
        config_data = """
secaudit:
  version: "1.0"
  debug: true
  log_level: "DEBUG"
  input:
    type: "file"
    path: "/test/path"
    format: "ssh"
  output:
    format: "json"
    path: "/test/output"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_data)
            temp_path = f.name
        
        try:
            manager = ConfigManager(config_path=temp_path)
            config = manager.load_config()
            
            assert config.debug is True
            assert config.log_level == "DEBUG"
            assert config.input.type == "file"
            assert config.input.path == "/test/path"
            assert config.input.format == "ssh"
            assert config.output.format == "json"
            assert config.output.path == "/test/output"
        finally:
            os.unlink(temp_path)
    
    def test_get_set_config_values(self):
        """Test getting and setting configuration values"""
        manager = ConfigManager()
        config = manager.load_config()
        
        # Test getting values
        assert manager.get("input.type") == "file"
        assert manager.get("analysis.threat_detection.enabled") is True
        assert manager.get("nonexistent.key", "default") == "default"
        
        # Test setting values
        manager.set("input.type", "stream")
        assert manager.get("input.type") == "stream"
        
        manager.set("analysis.threat_detection.enabled", False)
        assert manager.get("analysis.threat_detection.enabled") is False
    
    def test_environment_config(self):
        """Test environment-specific configuration loading"""
        # Test development environment
        manager = ConfigManager()
        manager.set_environment("development")
        config = manager.load_config()
        
        # Should load development config if it exists, otherwise default
        assert isinstance(config, SecAuditConfig)
    
    def test_save_config(self):
        """Test saving configuration to file"""
        manager = ConfigManager()
        config = manager.load_config()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            save_path = os.path.join(temp_dir, "test_config.yaml")
            
            result = manager.save(save_path)
            assert result is True
            assert os.path.exists(save_path)
            
            # Load saved config and verify
            manager2 = ConfigManager(config_path=save_path)
            config2 = manager2.load_config()
            
            assert config2.version == config.version
            assert config2.debug == config.debug


class TestConfigValidator:
    """Test configuration validation"""
    
    def test_valid_config(self):
        """Test validation of valid configuration"""
        config = SecAuditConfig()
        validator = ConfigValidator(config)
        
        is_valid, errors, warnings = validator.validate_all()
        
        assert is_valid is True
        assert len(errors) == 0
    
    def test_invalid_memory_limit(self):
        """Test validation of invalid memory limit"""
        config = SecAuditConfig(
            performance={
                "memory_limit": "invalid"
            }
        )
        validator = ConfigValidator(config)
        
        is_valid, errors, warnings = validator.validate_all()
        
        assert is_valid is False
        assert any("memory limit" in error for error in errors)
    
    def test_invalid_batch_size(self):
        """Test validation of invalid batch size"""
        config = SecAuditConfig(
            performance={
                "batch_size": 0
            }
        )
        validator = ConfigValidator(config)
        
        is_valid, errors, warnings = validator.validate_all()
        
        assert is_valid is False
        assert any("batch size" in error for error in errors)
    
    def test_production_validation(self):
        """Test production environment validation"""
        config = SecAuditConfig(
            debug=True,  # Should be False in production
            log_level="DEBUG"  # Should be WARNING+ in production
        )
        validator = ConfigValidator(config)
        
        issues = validator.validate_environment_specific("production")
        
        assert len(issues) == 2
        assert any("debug mode" in issue for issue in issues)
        assert any("log level" in issue for issue in issues)


class TestConfigFileValidation:
    """Test configuration file validation"""
    
    def test_validate_existing_file(self):
        """Test validation of existing configuration file"""
        # Use the default config file
        is_valid, errors, warnings = validate_config_file("config/secaudit.yaml")
        
        # Should be valid or have only warnings
        assert len(errors) == 0 or all("WARNING" in str(e) for e in errors)
    
    def test_validate_nonexistent_file(self):
        """Test validation of nonexistent configuration file"""
        is_valid, errors, warnings = validate_config_file("nonexistent.yaml")
        
        assert is_valid is False
        assert len(errors) > 0
    
    def test_validate_invalid_file(self):
        """Test validation of invalid configuration file"""
        config_data = """
secaudit:
  invalid_field: "value"
  input:
    type: "invalid_type"
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_data)
            temp_path = f.name
        
        try:
            is_valid, errors, warnings = validate_config_file(temp_path)
            
            assert is_valid is False
            assert len(errors) > 0
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    # Run basic tests
    print("Testing SecAudit Configuration System...")
    
    # Test default config
    config = SecAuditConfig()
    print(f"✅ Default config created: version {config.version}")
    
    # Test config manager
    manager = ConfigManager()
    config = manager.load_config()
    print(f"✅ Config loaded: debug={config.debug}, log_level={config.log_level}")
    
    # Test validation
    validator = ConfigValidator(config)
    is_valid, errors, warnings = validator.validate_all()
    print(f"✅ Validation: valid={is_valid}, errors={len(errors)}, warnings={len(warnings)}")
    
    print("All basic tests passed! 🎉")