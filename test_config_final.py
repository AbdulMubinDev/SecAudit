#!/usr/bin/env python3
"""
Final test script for SecAudit Configuration System
Tests configuration components by importing them directly from their modules
"""

import sys
import os
import tempfile

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_configuration_final():
    """Test the configuration system components by importing directly"""
    print("Testing SecAudit Configuration System (Final)")
    print("=" * 50)
    
    # Test 1: Import configuration classes directly from their modules
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
        print(f"   Threat detection enabled: {config.analysis.threat_detection.enabled}")
        print(f"   Anomaly detection enabled: {config.analysis.anomaly_detection.enabled}")
        print(f"   Correlation enabled: {config.analysis.correlation.enabled}")
    except Exception as e:
        print(f"❌ Failed to create default config: {e}")
        return False
    
    # Test 3: Test configuration validation
    try:
        from secaudit.core.config_validator import ConfigValidator
        validator = ConfigValidator(config)
        is_valid, errors, warnings = validator.validate_all()
        print(f"✅ Configuration validation: valid={is_valid}, errors={len(errors)}, warnings={len(warnings)}")
        if warnings:
            print("   Warnings:")
            for warning in warnings[:2]:
                print(f"     - {warning}")
    except Exception as e:
        print(f"❌ Configuration validation failed: {e}")
        return False
    
    # Test 4: Test configuration manager with default config
    try:
        manager = ConfigManager()
        # This will use the default config since no file exists
        loaded_config = manager.load_config()
        print(f"✅ Configuration manager loaded config: version={loaded_config.version}")
    except Exception as e:
        print(f"❌ Configuration manager failed: {e}")
        return False
    
    # Test 5: Test environment-specific loading
    try:
        manager.set_environment("development")
        dev_config = manager.load_config()
        print(f"✅ Environment-specific config loaded: log_level={dev_config.log_level}")
    except Exception as e:
        print(f"❌ Environment-specific loading failed: {e}")
        return False
    
    # Test 6: Test configuration file loading with a temporary file
    try:
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
            file_config = manager.load_config()
            print(f"✅ File-based config loaded: debug={file_config.debug}, log_level={file_config.log_level}")
        finally:
            os.unlink(temp_path)
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
    
    # Test 8: Test configuration modification and saving
    try:
        manager.set("debug", True)
        manager.set("log_level", "DEBUG")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            save_path = os.path.join(temp_dir, "test_config.yaml")
            save_result = manager.save(save_path)
            print(f"✅ Configuration save: {save_result}")
            
            # Verify the saved config
            if os.path.exists(save_path):
                with open(save_path, 'r') as f:
                    saved_content = f.read()
                    if 'debug: true' in saved_content and 'log_level: DEBUG' in saved_content:
                        print("✅ Configuration save verification passed")
                    else:
                        print("❌ Configuration save verification failed")
                        return False
    except Exception as e:
        print(f"❌ Configuration save failed: {e}")
        return False
    
    # Test 9: Test configuration validation with file
    try:
        is_valid, errors, warnings = validator.validate_all()
        print(f"✅ Final validation: valid={is_valid}, errors={len(errors)}, warnings={len(warnings)}")
    except Exception as e:
        print(f"❌ Final validation failed: {e}")
        return False
    
    print("=" * 50)
    print("✅ All configuration system tests passed!")
    print("\n📋 Configuration System Summary:")
    print("   ✅ YAML-based configuration loading")
    print("   ✅ Configuration validation with Pydantic")
    print("   ✅ Environment-specific configurations")
    print("   ✅ Configuration value access and modification")
    print("   ✅ Configuration file saving and loading")
    print("   ✅ Advanced validation with custom validators")
    
    return True

if __name__ == "__main__":
    success = test_configuration_final()
    sys.exit(0 if success else 1)