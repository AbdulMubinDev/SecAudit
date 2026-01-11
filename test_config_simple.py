#!/usr/bin/env python3
"""
Simple test script for SecAudit Configuration System
Tests only the configuration components without dependencies
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_configuration_system():
    """Test the configuration system components"""
    print("Testing SecAudit Configuration System")
    print("=" * 50)
    
    # Test 1: Import configuration classes
    try:
        from secaudit.core.config import SecAuditConfig, ConfigManager
        print("✅ Successfully imported configuration classes")
    except Exception as e:
        print(f"❌ Failed to import configuration classes: {e}")
        return False
    
    # Test 2: Create default configuration
    try:
        config = SecAuditConfig()
        print(f"✅ Created default config: version={config.version}, debug={config.debug}")
        print(f"   Input type: {config.input.type}")
        print(f"   Output format: {config.output.format}")
    except Exception as e:
        print(f"❌ Failed to create default config: {e}")
        return False
    
    # Test 3: Test configuration validation
    try:
        from secaudit.core.config_validator import ConfigValidator
        validator = ConfigValidator(config)
        is_valid, errors, warnings = validator.validate_all()
        print(f"✅ Configuration validation: valid={is_valid}, errors={len(errors)}, warnings={len(warnings)}")
    except Exception as e:
        print(f"❌ Configuration validation failed: {e}")
        return False
    
    # Test 4: Test configuration manager
    try:
        manager = ConfigManager()
        loaded_config = manager.load_config()
        print(f"✅ Configuration manager loaded config: {loaded_config.version}")
    except Exception as e:
        print(f"❌ Configuration manager failed: {e}")
        return False
    
    # Test 5: Test environment-specific loading
    try:
        manager.set_environment("development")
        dev_config = manager.load_config()
        print(f"✅ Environment-specific config loaded: {dev_config.log_level}")
    except Exception as e:
        print(f"❌ Environment-specific loading failed: {e}")
        return False
    
    # Test 6: Test configuration file loading
    try:
        manager = ConfigManager("config/secaudit.yaml")
        file_config = manager.load_config()
        print(f"✅ File-based config loaded: {file_config.log_level}")
    except Exception as e:
        print(f"❌ File-based config loading failed: {e}")
        return False
    
    # Test 7: Test configuration value access
    try:
        input_type = manager.get("input.type")
        output_format = manager.get("output.format")
        print(f"✅ Configuration values: input.type={input_type}, output.format={output_format}")
    except Exception as e:
        print(f"❌ Configuration value access failed: {e}")
        return False
    
    # Test 8: Test configuration saving
    try:
        manager.set("debug", True)
        manager.set("log_level", "DEBUG")
        save_result = manager.save("test_config.yaml")
        print(f"✅ Configuration save: {save_result}")
        
        # Clean up
        if os.path.exists("test_config.yaml"):
            os.remove("test_config.yaml")
    except Exception as e:
        print(f"❌ Configuration save failed: {e}")
        return False
    
    print("=" * 50)
    print("✅ All configuration system tests passed!")
    return True

if __name__ == "__main__":
    success = test_configuration_system()
    sys.exit(0 if success else 1)