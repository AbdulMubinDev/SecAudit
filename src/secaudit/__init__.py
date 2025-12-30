"""
SecAudit - Modular and extensible system log analysis tool

This package provides comprehensive security log analysis capabilities
including threat detection, anomaly detection, and multi-format output.
"""

__version__ = "1.0.0"
__author__ = "Abdul Mubin"
__email__ = "abdulmubin.dev@gmail.com"

# Import main application class
from .core.application import SecAuditApplication

# Import core components
from .core.config import ConfigManager
from .core.plugin_manager import PluginManager, BasePlugin

# Import input components
from .input.base_input import BaseInput
from .input.file_input import FileInput
from .input.stream_input import StreamInput

# Import parser components
from .parsers.base_parser import BaseParser
from .parsers.ssh_parser import SSHParser
from .parsers.syslog_parser import SyslogParser

# Import analysis components
from .analysis.threat_detector import ThreatDetector

# Import output components
from .output.base_output import BaseOutput
from .output.json_exporter import JSONExporter
from .output.html_reporter import HTMLReporter

# Import data models
from .models.log_entry import LogEntry
from .models.threat_alert import ThreatAlert
from .models.analysis_result import AnalysisResult

__all__ = [
    # Main application
    'SecAuditApplication',
    
    # Core components
    'ConfigManager', 'PluginManager', 'BasePlugin',
    
    # Input components
    'BaseInput', 'FileInput', 'StreamInput',
    
    # Parser components
    'BaseParser', 'SSHParser', 'SyslogParser',
    
    # Analysis components
    'ThreatDetector',
    
    # Output components
    'BaseOutput', 'JSONExporter', 'HTMLReporter',
    
    # Data models
    'LogEntry', 'ThreatAlert', 'AnalysisResult',
]