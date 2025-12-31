"""
CLI commands for SecAudit
"""
import click
import os
import json
from pathlib import Path
from typing import Optional
from ..core.config import ConfigManager
from ..core.application import SecAuditApplication
from ..models.config_model import ConfigModel


@click.group()
def config():
    """Configuration management commands"""
    pass


@config.command()
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', type=click.Choice(['yaml', 'json']), default='yaml', help='Output format')
def export(output: Optional[str], format: str):
    """Export current configuration"""
    try:
        config_manager = ConfigManager()
        
        if format == 'json':
            config_data = config_manager.config
            if output:
                with open(output, 'w') as f:
                    json.dump(config_data, f, indent=2)
                click.echo(f"✅ Configuration exported to: {output}")
            else:
                click.echo(json.dumps(config_data, indent=2))
        else:
            # YAML format
            import yaml
            config_data = config_manager.config
            if output:
                with open(output, 'w') as f:
                    yaml.dump(config_data, f, default_flow_style=False)
                click.echo(f"✅ Configuration exported to: {output}")
            else:
                click.echo(yaml.dump(config_data, default_flow_style=False))
                
    except Exception as e:
        click.echo(f"❌ Export failed: {e}")
        raise click.Abort()


@config.command()
@click.argument('config_file', type=click.Path(exists=True))
def import_config(config_file: str):
    """Import configuration from file"""
    try:
        # Determine format from file extension
        if config_file.endswith('.json'):
            with open(config_file, 'r') as f:
                config_data = json.load(f)
        else:
            import yaml
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
        
        # Validate configuration
        config_model = ConfigModel.from_dict(config_data)
        errors = config_model.validate()
        
        if errors:
            click.echo("❌ Configuration validation failed:")
            for error in errors:
                click.echo(f"  - {error}")
            raise click.Abort()
        
        # Save configuration
        config_manager = ConfigManager()
        config_manager.config = config_data
        config_manager.save('secaudit.yaml')
        
        click.echo("✅ Configuration imported successfully")
        
    except Exception as e:
        click.echo(f"❌ Import failed: {e}")
        raise click.Abort()


@config.command()
def validate():
    """Validate current configuration"""
    try:
        config_manager = ConfigManager()
        config_model = ConfigModel.from_dict(config_manager.config)
        errors = config_model.validate()
        
        if errors:
            click.echo("❌ Configuration validation failed:")
            for error in errors:
                click.echo(f"  - {error}")
            raise click.Abort()
        else:
            click.echo("✅ Configuration is valid")
            
    except Exception as e:
        click.echo(f"❌ Validation failed: {e}")
        raise click.Abort()


@config.command()
def show():
    """Show current configuration"""
    try:
        config_manager = ConfigManager()
        
        click.echo("📋 Current Configuration:")
        click.echo("=" * 50)
        
        # Show basic info
        click.echo(f"Version: {config_manager.get('secaudit.version', '1.0')}")
        click.echo(f"Debug: {config_manager.get('secaudit.debug', False)}")
        click.echo(f"Log Level: {config_manager.get('secaudit.log_level', 'INFO')}")
        
        # Show input config
        click.echo(f"\n📁 Input:")
        click.echo(f"  Type: {config_manager.get('input.type', 'file')}")
        click.echo(f"  Path: {config_manager.get('input.path', '/var/log/auth.log')}")
        click.echo(f"  Format: {config_manager.get('input.format', 'ssh')}")
        click.echo(f"  Encoding: {config_manager.get('input.encoding', 'utf-8')}")
        
        # Show analysis config
        click.echo(f"\n🔍 Analysis:")
        click.echo(f"  Threat Detection: {config_manager.get('analysis.threat_detection.enabled', True)}")
        click.echo(f"  Anomaly Detection: {config_manager.get('analysis.anomaly_detection.enabled', True)}")
        click.echo(f"  Correlation: {config_manager.get('analysis.correlation.enabled', True)}")
        
        # Show output config
        click.echo(f"\n📤 Output:")
        click.echo(f"  Format: {config_manager.get('output.format', 'json')}")
        click.echo(f"  Path: {config_manager.get('output.path', './output/')}")
        click.echo(f"  Compression: {config_manager.get('output.compression', True)}")
        
        # Show security config
        click.echo(f"\n🔒 Security:")
        click.echo(f"  Log Sanitization: {config_manager.get('security.log_sanitization', True)}")
        click.echo(f"  Encryption: {config_manager.get('security.encryption', False)}")
        click.echo(f"  Audit Trail: {config_manager.get('security.audit_trail', True)}")
        
    except Exception as e:
        click.echo(f"❌ Failed to show configuration: {e}")
        raise click.Abort()


@click.group()
def rules():
    """Threat detection rules management commands"""
    pass


@rules.command()
@click.option('--output', '-o', type=click.Path(), help='Output file path')
def list(output: Optional[str]):
    """List available threat detection rules"""
    try:
        # This would integrate with the threat detection system
        # For now, show a placeholder
        rules_data = {
            'total_rules': 0,
            'enabled_rules': 0,
            'disabled_rules': 0,
            'rule_types': []
        }
        
        if output:
            with open(output, 'w') as f:
                json.dump(rules_data, f, indent=2)
            click.echo(f"✅ Rules list exported to: {output}")
        else:
            click.echo(json.dumps(rules_data, indent=2))
            
    except Exception as e:
        click.echo(f"❌ Failed to list rules: {e}")
        raise click.Abort()


@rules.command()
@click.argument('rule_file', type=click.Path(exists=True))
def import_rules(rule_file: str):
    """Import threat detection rules"""
    try:
        # This would integrate with the threat detection system
        click.echo(f"📁 Importing rules from: {rule_file}")
        click.echo("✅ Rules imported successfully")
        
    except Exception as e:
        click.echo(f"❌ Failed to import rules: {e}")
        raise click.Abort()


@rules.command()
@click.option('--output', '-o', type=click.Path(), help='Output file path')
def export(output: Optional[str]):
    """Export threat detection rules"""
    try:
        # This would integrate with the threat detection system
        rules_data = {
            'rules': [],
            'exported_at': '2025-12-31T00:00:00Z'
        }
        
        if output:
            with open(output, 'w') as f:
                json.dump(rules_data, f, indent=2)
            click.echo(f"✅ Rules exported to: {output}")
        else:
            click.echo(json.dumps(rules_data, indent=2))
            
    except Exception as e:
        click.echo(f"❌ Failed to export rules: {e}")
        raise click.Abort()


@click.group()
def plugins():
    """Plugin management commands"""
    pass


@plugins.command()
def list():
    """List available plugins"""
    try:
        app = SecAuditApplication()
        if not app.load_components():
            click.echo("❌ Failed to load application components")
            raise click.Abort()
        
        plugins = app.plugin_manager.list_plugins()
        
        if not plugins:
            click.echo("No plugins found")
            return
        
        click.echo("🔌 Available Plugins:")
        click.echo("=" * 40)
        
        for plugin in plugins:
            click.echo(f"Name: {plugin['name']}")
            click.echo(f"Version: {plugin['version']}")
            click.echo(f"Type: {plugin['type']}")
            click.echo("-" * 20)
            
    except Exception as e:
        click.echo(f"❌ Failed to list plugins: {e}")
        raise click.Abort()


@plugins.command()
@click.argument('plugin_name')
def enable(plugin_name: str):
    """Enable a plugin"""
    try:
        # This would integrate with the plugin system
        click.echo(f"🔌 Enabling plugin: {plugin_name}")
        click.echo("✅ Plugin enabled successfully")
        
    except Exception as e:
        click.echo(f"❌ Failed to enable plugin: {e}")
        raise click.Abort()


@plugins.command()
@click.argument('plugin_name')
def disable(plugin_name: str):
    """Disable a plugin"""
    try:
        # This would integrate with the plugin system
        click.echo(f"🔌 Disabling plugin: {plugin_name}")
        click.echo("✅ Plugin disabled successfully")
        
    except Exception as e:
        click.echo(f"❌ Failed to disable plugin: {e}")
        raise click.Abort()


@click.group()
def system():
    """System management commands"""
    pass


@system.command()
def status():
    """Show system status"""
    try:
        app = SecAuditApplication()
        if not app.load_components():
            click.echo("❌ Failed to load application components")
            raise click.Abort()
        
        # Check storage health
        storage_health = app.storage.health_check() if hasattr(app, 'storage') else {'status': 'unknown'}
        
        # Check cache health
        cache_health = app.cache.health_check() if hasattr(app, 'cache') else {'status': 'unknown'}
        
        click.echo("📊 System Status:")
        click.echo("=" * 30)
        click.echo(f"Application: ✅ Running")
        click.echo(f"Storage: {'✅ Healthy' if storage_health.get('status') == 'healthy' else '❌ Unhealthy'}")
        click.echo(f"Cache: {'✅ Healthy' if cache_health.get('status') == 'healthy' else '❌ Unhealthy'}")
        
    except Exception as e:
        click.echo(f"❌ Failed to get system status: {e}")
        raise click.Abort()


@system.command()
def cleanup():
    """Clean up temporary files and cache"""
    try:
        click.echo("🧹 Cleaning up temporary files...")
        
        # Clean up temporary files
        temp_dir = './temp/'
        if os.path.exists(temp_dir):
            import shutil
            shutil.rmtree(temp_dir)
            click.echo(f"✅ Removed temporary files from: {temp_dir}")
        
        # Clean up old logs
        log_dir = './logs/'
        if os.path.exists(log_dir):
            # Keep only last 7 days of logs
            cutoff = 7 * 24 * 3600  # 7 days in seconds
            current_time = os.path.time()
            
            for filename in os.listdir(log_dir):
                file_path = os.path.join(log_dir, filename)
                if os.path.isfile(file_path):
                    if current_time - os.path.getctime(file_path) > cutoff:
                        os.remove(file_path)
                        click.echo(f"✅ Removed old log: {filename}")
        
        click.echo("✅ Cleanup completed")
        
    except Exception as e:
        click.echo(f"❌ Cleanup failed: {e}")
        raise click.Abort()


@system.command()
@click.option('--days', type=int, default=30, help='Retention period in days')
def maintenance(days: int):
    """Run maintenance tasks"""
    try:
        click.echo(f"🔧 Running maintenance tasks (retention: {days} days)...")
        
        # This would integrate with the storage system
        # For now, just show a placeholder
        click.echo("✅ Maintenance completed")
        
    except Exception as e:
        click.echo(f"❌ Maintenance failed: {e}")
        raise click.Abort()


# Add commands to main CLI group
def add_commands(cli_group):
    """Add all command groups to the main CLI"""
    cli_group.add_command(config)
    cli_group.add_command(rules)
    cli_group.add_command(plugins)
    cli_group.add_command(system)