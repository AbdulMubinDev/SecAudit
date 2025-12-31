"""
CLI utilities for SecAudit
"""
import os
import sys
import json
import yaml
import click
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime


class CLIUtils:
    """Utility functions for CLI operations"""
    
    @staticmethod
    def format_size(size_bytes: int) -> str:
        """Format file size in human-readable format"""
        if size_bytes == 0:
            return "0B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f}{size_names[i]}"
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 1:
            return f"{seconds * 1000:.0f}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"
    
    @staticmethod
    def format_percentage(value: float, total: float) -> str:
        """Format percentage with proper rounding"""
        if total == 0:
            return "0%"
        percentage = (value / total) * 100
        return f"{percentage:.1f}%"
    
    @staticmethod
    def print_table(headers: List[str], rows: List[List[str]], title: Optional[str] = None):
        """Print formatted table to console"""
        if title:
            click.echo(f"\n{title}")
            click.echo("=" * len(title))
        
        if not rows:
            click.echo("No data to display")
            return
        
        # Calculate column widths
        col_widths = [len(header) for header in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Print header
        header_row = "  ".join(header.ljust(width) for header, width in zip(headers, col_widths))
        click.echo(header_row)
        click.echo("-" * len(header_row))
        
        # Print rows
        for row in rows:
            row_str = "  ".join(str(cell).ljust(width) for cell, width in zip(row, col_widths))
            click.echo(row_str)
    
    @staticmethod
    def print_progress(current: int, total: int, prefix: str = '', suffix: str = '', bar_length: int = 30):
        """Print progress bar to console"""
        if total == 0:
            return
        
        percent = (current / total) * 100
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        click.echo(f'\r{prefix} |{bar}| {percent:6.2f}% {suffix}', nl=False)
        if current == total:
            click.echo()
    
    @staticmethod
    def confirm_action(message: str, default: bool = False) -> bool:
        """Ask user for confirmation"""
        return click.confirm(message, default=default)
    
    @staticmethod
    def get_user_input(prompt: str, default: Optional[str] = None, hide_input: bool = False) -> str:
        """Get user input with optional default and hiding"""
        return click.prompt(prompt, default=default, hide_input=hide_input)
    
    @staticmethod
    def validate_file_path(file_path: str, must_exist: bool = True) -> bool:
        """Validate file path"""
        path = Path(file_path)
        
        if must_exist and not path.exists():
            click.echo(f"❌ File does not exist: {file_path}")
            return False
        
        if path.exists() and not path.is_file():
            click.echo(f"❌ Path is not a file: {file_path}")
            return False
        
        return True
    
    @staticmethod
    def validate_directory_path(dir_path: str, create_if_missing: bool = False) -> bool:
        """Validate directory path"""
        path = Path(dir_path)
        
        if not path.exists():
            if create_if_missing:
                try:
                    path.mkdir(parents=True, exist_ok=True)
                    click.echo(f"✅ Created directory: {dir_path}")
                    return True
                except Exception as e:
                    click.echo(f"❌ Failed to create directory: {e}")
                    return False
            else:
                click.echo(f"❌ Directory does not exist: {dir_path}")
                return False
        
        if not path.is_dir():
            click.echo(f"❌ Path is not a directory: {dir_path}")
            return False
        
        return True
    
    @staticmethod
    def load_json_file(file_path: str) -> Dict[str, Any]:
        """Load JSON file"""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            click.echo(f"❌ Invalid JSON in {file_path}: {e}")
            raise click.Abort()
        except Exception as e:
            click.echo(f"❌ Failed to load {file_path}: {e}")
            raise click.Abort()
    
    @staticmethod
    def save_json_file(data: Dict[str, Any], file_path: str, indent: int = 2) -> bool:
        """Save data to JSON file"""
        try:
            # Ensure directory exists
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=indent)
            return True
        except Exception as e:
            click.echo(f"❌ Failed to save {file_path}: {e}")
            return False
    
    @staticmethod
    def load_yaml_file(file_path: str) -> Dict[str, Any]:
        """Load YAML file"""
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            click.echo(f"❌ Invalid YAML in {file_path}: {e}")
            raise click.Abort()
        except Exception as e:
            click.echo(f"❌ Failed to load {file_path}: {e}")
            raise click.Abort()
    
    @staticmethod
    def save_yaml_file(data: Dict[str, Any], file_path: str) -> bool:
        """Save data to YAML file"""
        try:
            # Ensure directory exists
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w') as f:
                yaml.dump(data, f, default_flow_style=False)
            return True
        except Exception as e:
            click.echo(f"❌ Failed to save {file_path}: {e}")
            return False
    
    @staticmethod
    def get_file_info(file_path: str) -> Dict[str, Any]:
        """Get file information"""
        try:
            stat = os.stat(file_path)
            return {
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'permissions': oct(stat.st_mode)[-3:]
            }
        except Exception as e:
            click.echo(f"❌ Failed to get file info: {e}")
            return {}
    
    @staticmethod
    def format_log_entry(entry: Dict[str, Any]) -> str:
        """Format log entry for display"""
        timestamp = entry.get('timestamp', '')
        hostname = entry.get('hostname', '')
        event_type = entry.get('event_type', '')
        severity = entry.get('severity', '')
        source_ip = entry.get('source_ip', '')
        username = entry.get('username', '')
        
        parts = []
        if timestamp:
            parts.append(f"[{timestamp}]")
        if hostname:
            parts.append(f"HOST:{hostname}")
        if event_type:
            parts.append(f"EVENT:{event_type}")
        if severity:
            parts.append(f"SEV:{severity}")
        if source_ip:
            parts.append(f"IP:{source_ip}")
        if username:
            parts.append(f"USER:{username}")
        
        return " ".join(parts)
    
    @staticmethod
    def format_threat_alert(alert: Dict[str, Any]) -> str:
        """Format threat alert for display"""
        rule_name = alert.get('rule_name', '')
        severity = alert.get('severity', '')
        confidence = alert.get('confidence', 0.0)
        affected_assets = alert.get('affected_assets', [])
        
        parts = []
        if rule_name:
            parts.append(f"RULE:{rule_name}")
        if severity:
            parts.append(f"SEV:{severity}")
        if confidence:
            parts.append(f"CONF:{confidence:.2f}")
        if affected_assets:
            parts.append(f"ASSETS:{len(affected_assets)}")
        
        return " | ".join(parts)
    
    @staticmethod
    def print_error(message: str):
        """Print error message in red"""
        click.echo(click.style(f"❌ {message}", fg='red'))
    
    @staticmethod
    def print_warning(message: str):
        """Print warning message in yellow"""
        click.echo(click.style(f"⚠️  {message}", fg='yellow'))
    
    @staticmethod
    def print_success(message: str):
        """Print success message in green"""
        click.echo(click.style(f"✅ {message}", fg='green'))
    
    @staticmethod
    def print_info(message: str):
        """Print info message in blue"""
        click.echo(click.style(f"ℹ️  {message}", fg='blue'))
    
    @staticmethod
    def print_header(title: str):
        """Print section header"""
        click.echo(f"\n{click.style(title, fg='cyan', bold=True)}")
        click.echo("=" * len(title))
    
    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """Get system information"""
        import platform
        import psutil
        
        return {
            'platform': platform.platform(),
            'python_version': sys.version,
            'cpu_count': psutil.cpu_count(),
            'memory_total': CLIUtils.format_size(psutil.virtual_memory().total),
            'memory_available': CLIUtils.format_size(psutil.virtual_memory().available),
            'disk_usage': CLIUtils.format_size(psutil.disk_usage('/').total) if os.name != 'nt' else CLIUtils.format_size(psutil.disk_usage('C:').total)
        }
    
    @staticmethod
    def check_dependencies() -> List[str]:
        """Check if required dependencies are installed"""
        missing_deps = []
        
        # Check for required packages
        required_packages = [
            'click', 'pyyaml', 'psutil'
        ]
        
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_deps.append(package)
        
        return missing_deps
    
    @staticmethod
    def create_default_config() -> Dict[str, Any]:
        """Create default configuration"""
        return {
            'secaudit': {
                'version': '1.0',
                'debug': False,
                'log_level': 'INFO'
            },
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