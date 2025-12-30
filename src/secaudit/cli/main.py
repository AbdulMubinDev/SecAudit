"""
Main CLI entry point for SecAudit
"""
import sys
import click
from pathlib import Path
from ..core.application import SecAuditApplication
from ..core.config import ConfigManager

@click.group()
@click.version_option(version='1.0.0')
@click.option('--config', '-c', type=click.Path(exists=True), help='Path to configuration file')
@click.pass_context
def cli(ctx, config):
    """🛡️  SecAudit - Modular and extensible system log analysis tool"""
    ctx.ensure_object(dict)
    ctx.obj['config_path'] = config

@cli.command()
@click.argument('log_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output directory')
@click.option('--format', '-f', type=click.Choice(['json', 'html']), default='json', help='Output format')
@click.option('--interactive', '-i', is_flag=True, help='Run in interactive mode after analysis')
@click.pass_context
def analyze(ctx, log_file, output, format, interactive):
    """Analyze a log file for security threats"""
    try:
        # Initialize application
        app = SecAuditApplication(ctx.obj.get('config_path'))
        
        # Load components
        if not app.load_components():
            click.echo("❌ Failed to load application components")
            sys.exit(1)
        
        # Override configuration if options provided
        if output:
            app.config.set('output.path', output)
        if format:
            app.config.set('output.format', format)
        
        # Run analysis
        click.echo(f"🔍 Analyzing log file: {log_file}")
        results = app.run_analysis(log_file)
        
        # Show results
        click.echo(f"\n✅ Analysis complete!")
        click.echo(f"📊 Total entries: {results.total_entries}")
        click.echo(f"✅ Parsed entries: {results.parsed_entries}")
        click.echo(f"🚨 Threats detected: {len(results.threats_detected)}")
        click.echo(f"🔍 Anomalies found: {len(results.anomalies)}")
        click.echo(f"⏱️  Processing time: {results.processing_time:.2f} seconds")
        
        if interactive:
            app.run_interactive()
            
    except Exception as e:
        click.echo(f"❌ Analysis failed: {e}")
        sys.exit(1)

@cli.command()
@click.option('--config', '-c', type=click.Path(), help='Path to save configuration')
@click.pass_context
def init(ctx, config):
    """Initialize SecAudit configuration"""
    try:
        config_path = config or 'secaudit.yaml'
        config_manager = ConfigManager()
        
        if config_manager.save(config_path):
            click.echo(f"✅ Configuration saved to: {config_path}")
            click.echo("📝 Edit the configuration file to customize SecAudit settings")
        else:
            click.echo("❌ Failed to save configuration")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Initialization failed: {e}")
        sys.exit(1)

@cli.command()
@click.pass_context
def interactive(ctx):
    """Run SecAudit in interactive mode"""
    try:
        app = SecAuditApplication(ctx.obj.get('config_path'))
        
        if not app.load_components():
            click.echo("❌ Failed to load application components")
            sys.exit(1)
        
        app.run_interactive()
        
    except Exception as e:
        click.echo(f"❌ Interactive mode failed: {e}")
        sys.exit(1)

@cli.command()
@click.pass_context
def status(ctx):
    """Show SecAudit status and configuration"""
    try:
        app = SecAuditApplication(ctx.obj.get('config_path'))
        
        if not app.load_components():
            click.echo("❌ Failed to load application components")
            sys.exit(1)
        
        app._show_status()
        
    except Exception as e:
        click.echo(f"❌ Status check failed: {e}")
        sys.exit(1)

@cli.command()
@click.argument('rule_file', type=click.Path(exists=True))
@click.pass_context
def test_rules(ctx, rule_file):
    """Test threat detection rules against a log file"""
    try:
        app = SecAuditApplication(ctx.obj.get('config_path'))
        
        if not app.load_components():
            click.echo("❌ Failed to load application components")
            sys.exit(1)
        
        # Override rules path
        app.config.set('analysis.threat_detection.rules_path', rule_file)
        
        click.echo(f"🧪 Testing rules from: {rule_file}")
        click.echo("📝 This feature will be implemented in future versions")
        
    except Exception as e:
        click.echo(f"❌ Rule testing failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    cli()