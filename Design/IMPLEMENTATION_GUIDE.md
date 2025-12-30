# SecAudit Implementation Guide

## 🚀 Quick Start Implementation

This guide provides step-by-step instructions for implementing the improved SecAudit architecture.

## 📦 Phase 1: Foundation Setup (Week 1)

### Step 1: Project Structure Creation

Create the basic project structure:

```bash
# Create project directories
mkdir -p SecAudit/src/secaudit/{core,input,parsers,analysis,output,storage,models,cli}
mkdir -p SecAudit/{tests/{unit,integration,fixtures},docs,config/rules,plugins,examples,scripts,tools}

# Create __init__.py files
find SecAudit/src/secaudit -type d -exec touch {}/__init__.py \;
```

### Step 2: Core Base Classes Implementation

#### 2.1 Base Application Class (`src/secaudit/core/application.py`)

```python
"""
Main application orchestrator for SecAudit
"""
import logging
from typing import Dict, Any, Optional
from .config import ConfigManager
from .logger import setup_logging
from .plugin_manager import PluginManager

class SecAuditApplication:
    """Main SecAudit application orchestrator"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the SecAudit application
        
        Args:
            config_path (str, optional): Path to configuration file
        """
        self.config = ConfigManager(config_path)
        self.logger = setup_logging(self.config.get('log_level', 'INFO'))
        self.plugin_manager = PluginManager(self.config)
        
        # Initialize components
        self.input_handler = None
        self.parser = None
        self.analyzer = None
        self.output_handler = None
        
        self.logger.info("SecAudit application initialized")
    
    def load_components(self) -> bool:
        """Load and initialize all application components"""
        try:
            # Load plugins
            self.plugin_manager.load_plugins()
            
            # Initialize input handler
            from ..input import FileInput, StreamInput, APIInput
            input_type = self.config.get('input.type', 'file')
            
            if input_type == 'file':
                self.input_handler = FileInput(self.config.get('input'))
            elif input_type == 'stream':
                self.input_handler = StreamInput(self.config.get('input'))
            elif input_type == 'api':
                self.input_handler = APIInput(self.config.get('input'))
            else:
                raise ValueError(f"Unknown input type: {input_type}")
            
            # Initialize parser
            from ..parsers import SSHParser, SyslogParser
            parser_type = self.config.get('input.format', 'ssh')
            
            if parser_type == 'ssh':
                self.parser = SSHParser()
            elif parser_type == 'syslog':
                self.parser = SyslogParser()
            else:
                raise ValueError(f"Unknown parser type: {parser_type}")
            
            # Initialize analyzer
            from ..analysis import ThreatDetector, AnomalyDetector
            self.analyzer = ThreatDetector(self.config.get('analysis'))
            self.anomaly_detector = AnomalyDetector(self.config.get('analysis'))
            
            # Initialize output handler
            from ..output import JSONExporter, HTMLReporter
            output_format = self.config.get('output.format', 'json')
            
            if output_format == 'json':
                self.output_handler = JSONExporter(self.config.get('output'))
            elif output_format == 'html':
                self.output_handler = HTMLReporter(self.config.get('output'))
            else:
                raise ValueError(f"Unknown output format: {output_format}")
            
            self.logger.info("All components loaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load components: {e}")
            return False
    
    def run_analysis(self, input_path: str) -> Dict[str, Any]:
        """
        Run complete analysis on input data
        
        Args:
            input_path (str): Path to input file or stream identifier
            
        Returns:
            Dict: Analysis results
        """
        try:
            self.logger.info(f"Starting analysis on: {input_path}")
            
            # Read input
            raw_data = self.input_handler.read(input_path)
            self.logger.info(f"Read {len(raw_data)} lines from input")
            
            # Parse logs
            parsed_logs = []
            for line in raw_data:
                parsed = self.parser.parse(line)
                if parsed:
                    parsed_logs.append(parsed)
            
            self.logger.info(f"Parsed {len(parsed_logs)} valid log entries")
            
            # Analyze logs
            threats = self.analyzer.detect_threats(parsed_logs)
            anomalies = self.anomaly_detector.detect_anomalies(parsed_logs)
            
            # Generate results
            results = {
                'total_entries': len(raw_data),
                'parsed_entries': len(parsed_logs),
                'threats_detected': threats,
                'anomalies': anomalies,
                'processing_time': 0.0  # Add timing logic
            }
            
            # Export results
            self.output_handler.export(results)
            
            self.logger.info("Analysis completed successfully")
            return results
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            raise
```

#### 2.2 Configuration Manager (`src/secaudit/core/config.py`)

```python
"""
Configuration management for SecAudit
"""
import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path

class ConfigManager:
    """Configuration manager with validation and defaults"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_path (str, optional): Path to configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        if self.config_path and os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
        else:
            config = self._get_default_config()
        
        # Merge with defaults
        defaults = self._get_default_config()
        self._merge_config(config, defaults)
        
        return config
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'secaudit': {
                'version': '1.0',
                'debug': False,
                'log_level': 'INFO',
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
        }
    
    def _merge_config(self, config: Dict[str, Any], defaults: Dict[str, Any]) -> None:
        """Recursively merge configuration with defaults"""
        for key, value in defaults.items():
            if key not in config:
                config[key] = value
            elif isinstance(value, dict) and isinstance(config[key], dict):
                self._merge_config(config[key], value)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            key (str): Configuration key (e.g., 'input.type')
            default (Any): Default value if key not found
            
        Returns:
            Any: Configuration value
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value using dot notation
        
        Args:
            key (str): Configuration key
            value (Any): Value to set
        """
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self, path: Optional[str] = None) -> bool:
        """
        Save configuration to file
        
        Args:
            path (str, optional): Path to save configuration
            
        Returns:
            bool: True if successful
        """
        save_path = path or self.config_path
        if not save_path:
            raise ValueError("No path specified for saving configuration")
        
        try:
            with open(save_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            return True
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False
```

### Step 3: Plugin System Implementation

#### 3.1 Base Plugin Class (`src/secaudit/core/plugin_manager.py`)

```python
"""
Plugin management system for SecAudit
"""
import importlib
import inspect
import os
from typing import Dict, List, Any, Type, Optional
from abc import ABC, abstractmethod

class BasePlugin(ABC):
    """Base class for all SecAudit plugins"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize plugin with configuration"""
        pass
    
    @abstractmethod
    def process(self, data: Any) -> Any:
        """Process input data"""
        pass
    
    @abstractmethod
    def cleanup(self) -> None:
        """Cleanup resources"""
        pass

class PluginManager:
    """Manages plugin loading and execution"""
    
    def __init__(self, config):
        self.config = config
        self.plugins = {}
        self.plugin_paths = config.get('plugins.paths', ['plugins/'])
        self.sandbox_mode = config.get('plugins.sandbox_mode', False)
    
    def load_plugins(self) -> bool:
        """Load all available plugins"""
        if not self.config.get('plugins.enabled', True):
            return True
        
        for plugin_path in self.plugin_paths:
            if os.path.exists(plugin_path):
                self._load_plugins_from_path(plugin_path)
        
        return True
    
    def _load_plugins_from_path(self, path: str) -> None:
        """Load plugins from a specific directory"""
        for filename in os.listdir(path):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]  # Remove .py extension
                try:
                    module = importlib.import_module(f'plugins.{module_name}')
                    self._register_plugins_from_module(module)
                except ImportError as e:
                    print(f"Failed to import plugin {module_name}: {e}")
    
    def _register_plugins_from_module(self, module) -> None:
        """Register all plugin classes from a module"""
        for name, obj in inspect.getmembers(module):
            if (inspect.isclass(obj) and 
                issubclass(obj, BasePlugin) and 
                obj != BasePlugin):
                
                try:
                    plugin_instance = obj()
                    self.plugins[plugin_instance.name] = plugin_instance
                    print(f"Loaded plugin: {plugin_instance.name}")
                except Exception as e:
                    print(f"Failed to instantiate plugin {name}: {e}")
    
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get a plugin by name"""
        return self.plugins.get(name)
    
    def get_plugins_by_type(self, plugin_type: Type) -> List[BasePlugin]:
        """Get all plugins of a specific type"""
        return [p for p in self.plugins.values() if isinstance(p, plugin_type)]
    
    def execute_plugin(self, name: str, data: Any) -> Any:
        """Execute a plugin with given data"""
        plugin = self.get_plugin(name)
        if plugin:
            return plugin.process(data)
        else:
            raise ValueError(f"Plugin {name} not found")
```

## 📊 Phase 2: Input and Parsing System (Week 2)

### Step 4: Input System Implementation

#### 4.1 Base Input Class (`src/secaudit/input/base_input.py`)

```python
"""
Base input class for SecAudit
"""
from abc import ABC, abstractmethod
from typing import List, Optional, Generator
import logging

class BaseInput(ABC):
    """Abstract base class for all input types"""
    
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    @abstractmethod
    def read(self, source: str) -> List[str]:
        """
        Read data from source
        
        Args:
            source (str): Input source identifier
            
        Returns:
            List[str]: List of raw log lines
        """
        pass
    
    @abstractmethod
    def read_stream(self, source: str) -> Generator[str, None, None]:
        """
        Read data as a stream
        
        Args:
            source (str): Input source identifier
            
        Yields:
            str: Individual log lines
        """
        pass
    
    def validate_source(self, source: str) -> bool:
        """
        Validate input source
        
        Args:
            source (str): Input source to validate
            
        Returns:
            bool: True if valid
        """
        return True
    
    def sanitize_line(self, line: str) -> str:
        """
        Sanitize log line for security
        
        Args:
            line (str): Raw log line
            
        Returns:
            str: Sanitized log line
        """
        # Remove sensitive patterns if configured
        if self.config.get('security.log_sanitization', False):
            sensitive_patterns = self.config.get('security.sensitive_patterns', [])
            for pattern in sensitive_patterns:
                line = line.replace(pattern, '[REDACTED]')
        
        return line.strip()
```

#### 4.2 File Input Implementation (`src/secaudit/input/file_input.py`)

```python
"""
File-based input handler for SecAudit
"""
import os
import time
from typing import List, Generator
from .base_input import BaseInput

class FileInput(BaseInput):
    """File-based log input handler"""
    
    def __init__(self, config: dict):
        super().__init__(config)
        self.buffer_size = config.get('buffer_size', 8192)
        self.encoding = config.get('encoding', 'utf-8')
        self.rotation_enabled = config.get('rotation', True)
    
    def read(self, file_path: str) -> List[str]:
        """
        Read entire file into memory
        
        Args:
            file_path (str): Path to log file
            
        Returns:
            List[str]: List of log lines
        """
        if not self.validate_source(file_path):
            raise ValueError(f"Invalid file path: {file_path}")
        
        lines = []
        try:
            with open(file_path, 'r', encoding=self.encoding) as f:
                for line in f:
                    sanitized = self.sanitize_line(line)
                    if sanitized:
                        lines.append(sanitized)
            
            self.logger.info(f"Read {len(lines)} lines from {file_path}")
            return lines
            
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            raise
    
    def read_stream(self, file_path: str) -> Generator[str, None, None]:
        """
        Read file as a stream (for real-time processing)
        
        Args:
            file_path (str): Path to log file
            
        Yields:
            str: Individual log lines
        """
        if not os.path.exists(file_path):
            raise ValueError(f"File not found: {file_path}")
        
        with open(file_path, 'r', encoding=self.encoding) as f:
            # Seek to end if following
            if self.rotation_enabled:
                f.seek(0, 2)  # Seek to end
            
            while True:
                line = f.readline()
                if line:
                    sanitized = self.sanitize_line(line)
                    if sanitized:
                        yield sanitized
                else:
                    # Check for file rotation
                    if self.rotation_enabled and not os.path.exists(file_path):
                        self.logger.info(f"File rotated: {file_path}")
                        break
                    time.sleep(0.1)  # Small delay to prevent busy waiting
    
    def validate_source(self, file_path: str) -> bool:
        """Validate file path"""
        if not os.path.exists(file_path):
            self.logger.error(f"File does not exist: {file_path}")
            return False
        
        if not os.path.isfile(file_path):
            self.logger.error(f"Path is not a file: {file_path}")
            return False
        
        return True
```

### Step 5: Parser System Implementation

#### 5.1 Base Parser Class (`src/secaudit/parsers/base_parser.py`)

```python
"""
Base parser class for SecAudit
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging
from datetime import datetime

class BaseParser(ABC):
    """Abstract base class for all log parsers"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    @abstractmethod
    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single log line
        
        Args:
            line (str): Raw log line
            
        Returns:
            Dict or None: Parsed log data or None if parsing failed
        """
        pass
    
    @abstractmethod
    def can_parse(self, line: str) -> bool:
        """
        Check if this parser can handle the given line
        
        Args:
            line (str): Log line to check
            
        Returns:
            bool: True if this parser can handle the line
        """
        pass
    
    def parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """
        Parse timestamp string into datetime object
        
        Args:
            timestamp_str (str): Timestamp string
            
        Returns:
            datetime or None: Parsed datetime or None if parsing failed
        """
        # Common timestamp formats
        formats = [
            '%b %d %H:%M:%S',  # SSH format: "Dec 30 15:30:45"
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        self.logger.warning(f"Unable to parse timestamp: {timestamp_str}")
        return None
    
    def sanitize_field(self, value: Any) -> Any:
        """
        Sanitize field value for security
        
        Args:
            value (Any): Field value to sanitize
            
        Returns:
            Any: Sanitized value
        """
        if isinstance(value, str):
            # Remove null bytes and other control characters
            return value.replace('\x00', '').strip()
        return value
```

#### 5.2 SSH Parser Implementation (`src/secaudit/parsers/ssh_parser.py`)

```python
"""
SSH log parser for SecAudit
"""
import re
from typing import Dict, Any, Optional
from .base_parser import BaseParser

class SSHParser(BaseParser):
    """Parser for SSH authentication logs"""
    
    def __init__(self):
        super().__init__()
        
        # SSH log patterns
        self.patterns = {
            'failed_password': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\w+) from ([\d.]+) port (\d+)'
            ),
            'accepted_password': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Accepted (\w+) for (\w+) from ([\d.]+) port (\d+)'
            ),
            'invalid_user': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Invalid user (\w+) from ([\d.]+) port (\d+)'
            ),
            'connection_closed': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Connection closed by ([\d.]+) port (\d+)'
            ),
            'disconnected': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[\d+\]:\s+Disconnected from user (\w+) ([\d.]+) port (\d+)'
            ),
            'sudo_command': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sudo\[\d+\]:\s+(\w+) : TTY=([^;]+) ; PWD=([^;]+) ; USER=([^;]+) ; COMMAND=(.*)'
            )
        }
    
    def can_parse(self, line: str) -> bool:
        """Check if this parser can handle the given line"""
        return any(pattern.search(line) for pattern in self.patterns.values())
    
    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse SSH log line
        
        Args:
            line (str): Raw SSH log line
            
        Returns:
            Dict or None: Parsed log data
        """
        if not self.can_parse(line):
            return None
        
        # Try each pattern
        for event_type, pattern in self.patterns.items():
            match = pattern.match(line)
            if match:
                return self._extract_ssh_data(event_type, match, line)
        
        return None
    
    def _extract_ssh_data(self, event_type: str, match, raw_line: str) -> Dict[str, Any]:
        """Extract data from SSH log match"""
        groups = match.groups()
        
        base_data = {
            'event_type': event_type.upper(),
            'raw_line': raw_line,
            'timestamp': self.parse_timestamp(groups[0]),
            'hostname': groups[1]
        }
        
        if event_type == 'failed_password':
            base_data.update({
                'username': groups[2],
                'ip_address': groups[3],
                'port': int(groups[4]),
                'severity': 'HIGH'
            })
        
        elif event_type == 'accepted_password':
            base_data.update({
                'auth_method': groups[2],
                'username': groups[3],
                'ip_address': groups[4],
                'port': int(groups[5]),
                'severity': 'INFO'
            })
        
        elif event_type == 'invalid_user':
            base_data.update({
                'username': groups[2],
                'ip_address': groups[3],
                'port': int(groups[4]),
                'severity': 'HIGH'
            })
        
        elif event_type == 'connection_closed':
            base_data.update({
                'ip_address': groups[2],
                'port': int(groups[3]),
                'severity': 'LOW'
            })
        
        elif event_type == 'disconnected':
            base_data.update({
                'username': groups[2],
                'ip_address': groups[3],
                'port': int(groups[4]),
                'severity': 'LOW'
            })
        
        elif event_type == 'sudo_command':
            base_data.update({
                'username': groups[2],
                'tty': groups[3],
                'pwd': groups[4],
                'target_user': groups[5],
                'command': groups[6],
                'severity': 'MEDIUM'
            })
        
        # Sanitize all string fields
        for key, value in base_data.items():
            if isinstance(value, str):
                base_data[key] = self.sanitize_field(value)
        
        return base_data
```

## 🚨 Phase 3: Analysis Engine (Week 3-4)

### Step 6: Threat Detection Implementation

#### 6.1 Threat Detector (`src/secaudit/analysis/threat_detector.py`)

```python
"""
Threat detection engine for SecAudit
"""
import yaml
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import logging

class ThreatDetector:
    """Rule-based threat detection engine"""
    
    def __init__(self, config: dict):
        self.config = config
        self.rules = self._load_rules()
        self.logger = logging.getLogger(__name__)
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load threat detection rules from configuration"""
        rules_path = self.config.get('rules_path', 'config/rules/threat_rules.yaml')
        
        try:
            with open(rules_path, 'r') as f:
                rules_data = yaml.safe_load(f)
                return rules_data.get('rules', [])
        except FileNotFoundError:
            self.logger.warning(f"Rules file not found: {rules_path}")
            return self._get_default_rules()
        except Exception as e:
            self.logger.error(f"Error loading rules: {e}")
            return []
    
    def _get_default_rules(self) -> List[Dict[str, Any]]:
        """Get default threat detection rules"""
        return [
            {
                'id': 'SSH_BRUTE_FORCE',
                'name': 'SSH Brute Force Attack',
                'description': 'Multiple failed SSH login attempts from same IP',
                'severity': 'HIGH',
                'enabled': True,
                'pattern': {
                    'event_type': 'SSH_FAILED_PASSWORD',
                    'conditions': [
                        {'field': 'ip_address', 'operator': 'same'},
                        {'field': 'count', 'operator': '>', 'value': 5}
                    ],
                    'time_window': '10m'
                }
            },
            {
                'id': 'INVALID_USER_ATTEMPTS',
                'name': 'Invalid User Login Attempts',
                'description': 'Login attempts with non-existent users',
                'severity': 'MEDIUM',
                'enabled': True,
                'pattern': {
                    'event_type': 'SSH_INVALID_USER',
                    'conditions': [
                        {'field': 'count', 'operator': '>', 'value': 3}
                    ],
                    'time_window': '5m'
                }
            }
        ]
    
    def detect_threats(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect threats in parsed logs
        
        Args:
            logs (List[Dict]): List of parsed log entries
            
        Returns:
            List[Dict]: List of detected threats
        """
        threats = []
        
        # Group logs by time windows
        time_windows = self._create_time_windows(logs)
        
        # Apply each rule
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
            
            rule_threats = self._apply_rule(rule, time_windows)
            threats.extend(rule_threats)
        
        return threats
    
    def _create_time_windows(self, logs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Create time windows for analysis"""
        windows = defaultdict(list)
        
        for log in logs:
            timestamp = log.get('timestamp')
            if timestamp:
                # Create 10-minute windows
                window_key = timestamp.replace(minute=(timestamp.minute // 10) * 10, second=0, microsecond=0)
                windows[window_key].append(log)
        
        return windows
    
    def _apply_rule(self, rule: Dict[str, Any], time_windows: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Apply a single rule to time windows"""
        threats = []
        pattern = rule.get('pattern', {})
        event_type = pattern.get('event_type')
        conditions = pattern.get('conditions', [])
        time_window = pattern.get('time_window', '10m')
        
        for window_start, window_logs in time_windows.items():
            # Filter logs by event type
            relevant_logs = [log for log in window_logs if log.get('event_type') == event_type]
            
            if not relevant_logs:
                continue
            
            # Apply conditions
            if self._check_conditions(relevant_logs, conditions):
                threat = self._create_threat_alert(rule, relevant_logs, window_start)
                threats.append(threat)
        
        return threats
    
    def _check_conditions(self, logs: List[Dict[str, Any]], conditions: List[Dict[str, Any]]) -> bool:
        """Check if logs meet all conditions"""
        for condition in conditions:
            field = condition.get('field')
            operator = condition.get('operator')
            value = condition.get('value')
            
            if field == 'count':
                count = len(logs)
                if operator == '>' and count <= value:
                    return False
                elif operator == '<' and count >= value:
                    return False
                elif operator == '=' and count != value:
                    return False
            else:
                # Group by field value
                field_values = [log.get(field) for log in logs if log.get(field)]
                if operator == 'same':
                    if len(set(field_values)) > 1:
                        return False
        
        return True
    
    def _create_threat_alert(self, rule: Dict[str, Any], logs: List[Dict[str, Any]], window_start: datetime) -> Dict[str, Any]:
        """Create threat alert from rule and logs"""
        return {
            'rule_id': rule['id'],
            'rule_name': rule['name'],
            'severity': rule['severity'],
            'description': rule['description'],
            'timestamp': window_start,
            'affected_assets': list(set(log.get('ip_address', '') for log in logs if log.get('ip_address'))),
            'evidence': logs,
            'confidence': 1.0,  # Could be calculated based on rule specificity
            'mitigation': self._get_mitigation(rule['id'])
        }
    
    def _get_mitigation(self, rule_id: str) -> Optional[str]:
        """Get mitigation advice for rule"""
        mitigations = {
            'SSH_BRUTE_FORCE': 'Consider implementing rate limiting, fail2ban, or IP blocking for repeated failed attempts',
            'INVALID_USER_ATTEMPTS': 'Review user accounts and consider blocking IPs attempting invalid usernames'
        }
        return mitigations.get(rule_id)
```

## 📤 Phase 4: Output System (Week 5)

### Step 7: Output System Implementation

#### 7.1 Base Output Class (`src/secaudit/output/base_output.py`)

```python
"""
Base output class for SecAudit
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
import logging
import os
from datetime import datetime

class BaseOutput(ABC):
    """Abstract base class for all output handlers"""
    
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.output_path = config.get('path', './output/')
        self.compression = config.get('compression', False)
        
        # Ensure output directory exists
        os.makedirs(self.output_path, exist_ok=True)
    
    @abstractmethod
    def export(self, results: Dict[str, Any]) -> bool:
        """
        Export analysis results
        
        Args:
            results (Dict): Analysis results
            
        Returns:
            bool: True if successful
        """
        pass
    
    def generate_filename(self, prefix: str = 'secaudit') -> str:
        """Generate output filename with timestamp"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"{prefix}_{timestamp}"
    
    def should_include_raw(self) -> bool:
        """Check if raw data should be included in output"""
        return self.config.get('include_raw', False)
    
    def get_max_file_size(self) -> int:
        """Get maximum file size in bytes"""
        size_str = self.config.get('max_file_size', '100MB')
        if size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return 100 * 1024 * 1024  # Default 100MB
```

#### 7.2 JSON Exporter (`src/secaudit/output/json_exporter.py`)

```python
"""
JSON output exporter for SecAudit
"""
import json
import gzip
from typing import Dict, Any
from .base_output import BaseOutput

class JSONExporter(BaseOutput):
    """Export results to JSON format"""
    
    def export(self, results: Dict[str, Any]) -> bool:
        """
        Export results to JSON file
        
        Args:
            results (Dict): Analysis results
            
        Returns:
            bool: True if successful
        """
        try:
            filename = self.generate_filename('secaudit_results')
            filepath = os.path.join(self.output_path, f"{filename}.json")
            
            # Prepare output data
            output_data = self._prepare_output_data(results)
            
            # Write JSON file
            if self.compression:
                filepath += '.gz'
                with gzip.open(filepath, 'wt', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, default=str)
            else:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, default=str)
            
            self.logger.info(f"Results exported to: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting to JSON: {e}")
            return False
    
    def _prepare_output_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for JSON output"""
        output = {
            'metadata': {
                'secaudit_version': '1.0',
                'export_timestamp': datetime.now().isoformat(),
                'total_entries': results.get('total_entries', 0),
                'parsed_entries': results.get('parsed_entries', 0),
                'threats_detected': len(results.get('threats_detected', [])),
                'anomalies_found': len(results.get('anomalies', []))
            },
            'summary': {
                'processing_time': results.get('processing_time', 0),
                'threats_by_severity': self._count_threats_by_severity(results.get('threats_detected', [])),
                'top_threat_types': self._get_top_threat_types(results.get('threats_detected', [])),
                'affected_assets': self._get_affected_assets(results.get('threats_detected', []))
            },
            'threats': results.get('threats_detected', []),
            'anomalies': results.get('anomalies', [])
        }
        
        # Include raw data if configured
        if self.should_include_raw():
            output['raw_logs'] = results.get('raw_logs', [])
        
        return output
    
    def _count_threats_by_severity(self, threats: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count threats by severity level"""
        severity_counts = {}
        for threat in threats:
            severity = threat.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts
    
    def _get_top_threat_types(self, threats: List[Dict[str, Any]]) -> List[Dict[str, int]]:
        """Get top threat types by count"""
        type_counts = {}
        for threat in threats:
            rule_name = threat.get('rule_name', 'Unknown')
            type_counts[rule_name] = type_counts.get(rule_name, 0) + 1
        
        # Sort by count and return top 5
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        return [{'type': name, 'count': count} for name, count in sorted_types[:5]]
    
    def _get_affected_assets(self, threats: List[Dict[str, Any]]) -> List[str]:
        """Get list of affected assets"""
        assets = set()
        for threat in threats:
            assets.update(threat.get('affected_assets', []))
        return list(assets)
```

## 🛠️ Development Workflow

### 1. Testing Strategy

#### Unit Tests (`tests/unit/test_core/test_application.py`)
```python
"""
Unit tests for SecAudit application
"""
import pytest
from unittest.mock import Mock, patch
from secaudit.core.application import SecAuditApplication
from secaudit.core.config import ConfigManager

class TestSecAuditApplication:
    def test_application_initialization(self):
        """Test application initialization"""
        app = SecAuditApplication()
        assert app.config is not None
        assert app.logger is not None
        assert app.plugin_manager is not None
    
    @patch('secaudit.core.application.FileInput')
    def test_load_file_input(self, mock_file_input):
        """Test loading file input handler"""
        config = {'input': {'type': 'file', 'path': '/var/log/test.log'}}
        app = SecAuditApplication()
        app.config = Mock()
        app.config.get.return_value = 'file'
        
        app.load_components()
        
        mock_file_input.assert_called_once()
    
    def test_run_analysis(self):
        """Test running complete analysis"""
        app = SecAuditApplication()
        app.input_handler = Mock()
        app.input_handler.read.return_value = ['test log line']
        app.parser = Mock()
        app.parser.parse.return_value = {'event_type': 'test'}
        app.analyzer = Mock()
        app.analyzer.detect_threats.return_value = []
        app.output_handler = Mock()
        app.output_handler.export.return_value = True
        
        results = app.run_analysis('/test/path')
        
        assert results['total_entries'] == 1
        assert results['parsed_entries'] == 1
```

### 2. Configuration Validation

#### Configuration Schema (`config/schema.yaml`)
```yaml
# Configuration schema for validation
secaudit:
  type: object
  properties:
    version:
      type: string
    debug:
      type: boolean
    log_level:
      type: string
      enum: ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    input:
      type: object
      properties:
        type:
          type: string
          enum: ['file', 'stream', 'api']
        path:
          type: string
        format:
          type: string
          enum: ['ssh', 'syslog', 'windows', 'custom']
        encoding:
          type: string
        rotation:
          type: boolean
        buffer_size:
          type: integer
          minimum: 1024
          maximum: 65536
    analysis:
      type: object
      properties:
        threat_detection:
          type: object
          properties:
            enabled:
              type: boolean
            rules_path:
              type: string
            severity_threshold:
              type: string
              enum: ['low', 'medium', 'high', 'critical']
        anomaly_detection:
          type: object
          properties:
            enabled:
              type: boolean
            algorithms:
              type: array
              items:
                type: string
                enum: ['statistical', 'ml']
            sensitivity:
              type: number
              minimum: 0.0
              maximum: 1.0
    output:
      type: object
      properties:
        format:
          type: string
          enum: ['json', 'html', 'csv', 'siem']
        path:
          type: string
        compression:
          type: boolean
        real_time:
          type: boolean
        include_raw:
          type: boolean
        max_file_size:
          type: string
          pattern: '^\d+(MB|GB)$'
```

### 3. Build and Deployment

#### PyProject.toml
```toml
[build-system]
requires = ["setuptools>=45", "wheel", "setuptools_scm[toml]>=6.2"]
build-backend = "setuptools.build_meta"

[project]
name = "secaudit"
version = "1.0.0"
description = "Modular and extensible system log analysis tool"
readme = "README.md"
license = {file = "LICENSE"}
authors = [{name = "Abdul Mubin", email = "abdulmubin.dev@gmail.com"}]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Intended Audience :: System Administrators",
    "License :: OSI Approved :: GNU Affero General Public License v3",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Topic :: Security",
    "Topic :: System :: Logging",
    "Topic :: System :: Monitoring",
]

[project.urls]
Homepage = "https://github.com/AbdulMubinDev/SecAudit"
Documentation = "https://github.com/AbdulMubinDev/SecAudit/wiki"
Repository = "https://github.com/AbdulMubinDev/SecAudit"
Issues = "https://github.com/AbdulMubinDev/SecAudit/issues"

[project.scripts]
secaudit = "secaudit.cli.main:main"

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "black>=22.0.0",
    "flake8>=5.0.0",
    "mypy>=0.991",
    "pre-commit>=2.20.0",
]
test = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "pytest-mock>=3.10.0",
]
docs = [
    "sphinx>=5.0.0",
    "sphinx-rtd-theme>=1.0.0",
    "sphinx-autodoc-typehints>=1.18.0",
]

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
secaudit = ["py.typed"]

[tool.black]
line-length = 88
target-version = ['py38']
include = '\.pyi?$'
extend-exclude = '''
/(
  # directories
  \.eggs
  | \.git
  | \.hg
  | \.mypy_cache
  | \.tox
  | \.venv
  | build
  | dist
)/
'''

[tool.mypy]
python_version = "3.8"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
ignore_missing_imports = true

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = "-v --tb=short --strict-config --strict-markers"
filterwarnings = [
    "error",
    "ignore:.*U.*mode is deprecated:DeprecationWarning",
]
```

This implementation guide provides a comprehensive foundation for building the improved SecAudit system. Each component is designed to be modular, testable, and maintainable while supporting the project's goals of extensibility and performance.

The guide follows modern Python development practices including:
- Type hints for better code documentation
- Comprehensive error handling
- Structured logging
- Configuration management
- Plugin architecture
- Testing strategy
- Security considerations

This foundation enables the development team to build a robust, enterprise-ready security log analysis tool that can grow and adapt to future requirements.