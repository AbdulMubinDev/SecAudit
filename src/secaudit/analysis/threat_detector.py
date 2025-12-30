"""
Threat detection engine for SecAudit
"""
import yaml
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import logging
from ..models.log_entry import LogEntry
from ..models.threat_alert import ThreatAlert

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
            },
            {
                'id': 'SUSPICIOUS_COMMAND_EXECUTION',
                'name': 'Suspicious Command Execution',
                'description': 'Execution of potentially dangerous commands',
                'severity': 'HIGH',
                'enabled': True,
                'pattern': {
                    'event_type': 'SUDO_COMMAND',
                    'conditions': [
                        {'field': 'command', 'operator': 'contains', 'value': ['rm -rf', 'dd if=', 'mkfs', 'fdisk']}
                    ],
                    'time_window': '1h'
                }
            }
        ]
    
    def detect_threats(self, logs: List[LogEntry]) -> List[ThreatAlert]:
        """
        Detect threats in parsed logs
        
        Args:
            logs (List[LogEntry]): List of parsed log entries
            
        Returns:
            List[ThreatAlert]: List of detected threats
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
    
    def _create_time_windows(self, logs: List[LogEntry]) -> Dict[datetime, List[LogEntry]]:
        """Create time windows for analysis"""
        windows = defaultdict(list)
        
        for log in logs:
            timestamp = log.timestamp
            if timestamp:
                # Create 10-minute windows
                window_key = timestamp.replace(minute=(timestamp.minute // 10) * 10, second=0, microsecond=0)
                windows[window_key].append(log)
        
        return windows
    
    def _apply_rule(self, rule: Dict[str, Any], time_windows: Dict[datetime, List[LogEntry]]) -> List[ThreatAlert]:
        """Apply a single rule to time windows"""
        threats = []
        pattern = rule.get('pattern', {})
        event_type = pattern.get('event_type')
        conditions = pattern.get('conditions', [])
        time_window = pattern.get('time_window', '10m')
        
        for window_start, window_logs in time_windows.items():
            # Filter logs by event type
            relevant_logs = [log for log in window_logs if log.event_type == event_type]
            
            if not relevant_logs:
                continue
            
            # Apply conditions
            if self._check_conditions(relevant_logs, conditions):
                threat = self._create_threat_alert(rule, relevant_logs, window_start)
                threats.append(threat)
        
        return threats
    
    def _check_conditions(self, logs: List[LogEntry], conditions: List[Dict[str, Any]]) -> bool:
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
            elif field == 'ip_address' and operator == 'same':
                # Check if all logs have the same IP
                ip_addresses = [log.source_ip for log in logs if log.source_ip]
                if len(set(ip_addresses)) > 1:
                    return False
            elif field == 'command' and operator == 'contains':
                # Check if any log contains suspicious commands
                if isinstance(value, list):
                    for log in logs:
                        if log.command:
                            for suspicious_cmd in value:
                                if suspicious_cmd in log.command.lower():
                                    break
                            else:
                                continue
                            break
                    else:
                        return False
                else:
                    return False
        
        return True
    
    def _create_threat_alert(self, rule: Dict[str, Any], logs: List[LogEntry], window_start: datetime) -> ThreatAlert:
        """Create threat alert from rule and logs"""
        # Extract affected assets
        affected_assets = set()
        for log in logs:
            if log.source_ip:
                affected_assets.add(log.source_ip)
            if log.username:
                affected_assets.add(log.username)
        
        # Calculate confidence based on rule specificity and evidence count
        confidence = min(0.5 + (len(logs) * 0.1), 0.95)
        
        return ThreatAlert(
            rule_id=rule['id'],
            rule_name=rule['name'],
            severity=rule['severity'],
            description=rule['description'],
            confidence=confidence,
            timestamp=window_start,
            affected_assets=list(affected_assets),
            evidence=logs,
            mitigation=self._get_mitigation(rule['id'])
        )
    
    def _get_mitigation(self, rule_id: str) -> Optional[str]:
        """Get mitigation advice for rule"""
        mitigations = {
            'SSH_BRUTE_FORCE': 'Consider implementing rate limiting, fail2ban, or IP blocking for repeated failed attempts',
            'INVALID_USER_ATTEMPTS': 'Review user accounts and consider blocking IPs attempting invalid usernames',
            'SUSPICIOUS_COMMAND_EXECUTION': 'Review sudo permissions and monitor for unauthorized system modifications'
        }
        return mitigations.get(rule_id)