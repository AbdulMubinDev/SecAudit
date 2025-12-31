"""
Alert management system for SecAudit
"""
import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, List, Optional
from datetime import datetime
from ..base_output import BaseOutput
from ..models.threat_alert import ThreatAlert


class AlertManager(BaseOutput):
    """Alert management system for SecAudit"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.alert_threshold = config.get('alert_threshold', 'MEDIUM')
        self.notification_methods = config.get('notification_methods', ['console'])
        self.email_config = config.get('email', {})
        self.webhook_config = config.get('webhook', {})
        self.alert_history = []
    
    def export(self, data: Any, output_path: Optional[str] = None) -> bool:
        """Send alerts for detected threats"""
        try:
            if isinstance(data, list) and all(isinstance(item, ThreatAlert) for item in data):
                return self._send_threat_alerts(data)
            elif isinstance(data, ThreatAlert):
                return self._send_threat_alert(data)
            else:
                self.logger.error(f"Unsupported data type for alerting: {type(data)}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to send alerts: {e}")
            return False
    
    def _send_threat_alerts(self, threats: List[ThreatAlert]) -> bool:
        """Send alerts for multiple threats"""
        success = True
        for threat in threats:
            if self._should_send_alert(threat):
                if not self._send_threat_alert(threat):
                    success = False
        return success
    
    def _send_threat_alert(self, threat: ThreatAlert) -> bool:
        """Send alert for a single threat"""
        try:
            # Add to alert history
            alert_record = {
                'timestamp': datetime.now().isoformat(),
                'threat_id': threat.rule_id,
                'threat_name': threat.rule_name,
                'severity': threat.severity,
                'confidence': threat.confidence,
                'threat_score': threat.get_threat_score(),
                'is_critical': threat.is_critical()
            }
            self.alert_history.append(alert_record)
            
            # Send notifications
            success = True
            for method in self.notification_methods:
                if method == 'console':
                    success &= self._send_console_alert(threat)
                elif method == 'email':
                    success &= self._send_email_alert(threat)
                elif method == 'webhook':
                    success &= self._send_webhook_alert(threat)
                elif method == 'file':
                    success &= self._send_file_alert(threat)
                else:
                    self.logger.warning(f"Unknown notification method: {method}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to send alert: {e}")
            return False
    
    def _should_send_alert(self, threat: ThreatAlert) -> bool:
        """Check if alert should be sent based on threshold"""
        severity_weights = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'INFO': 0
        }
        
        threshold_weight = severity_weights.get(self.alert_threshold.upper(), 2)
        threat_weight = severity_weights.get(threat.severity.upper(), 0)
        
        return threat_weight >= threshold_weight
    
    def _send_console_alert(self, threat: ThreatAlert) -> bool:
        """Send alert to console"""
        try:
            print(f"\n🚨 SECURITY ALERT")
            print(f"Rule: {threat.rule_name}")
            print(f"Severity: {threat.severity}")
            print(f"Confidence: {threat.confidence:.2f}")
            print(f"Threat Score: {threat.get_threat_score():.2f}")
            print(f"Affected Assets: {', '.join(threat.affected_assets)}")
            print(f"Description: {threat.description}")
            if threat.mitigation:
                print(f"Mitigation: {threat.mitigation}")
            print("-" * 60)
            return True
        except Exception as e:
            self.logger.error(f"Failed to send console alert: {e}")
            return False
    
    def _send_email_alert(self, threat: ThreatAlert) -> bool:
        """Send alert via email"""
        try:
            if not self.email_config.get('enabled', False):
                return True
            
            # Email configuration
            smtp_server = self.email_config.get('smtp_server')
            smtp_port = self.email_config.get('smtp_port', 587)
            username = self.email_config.get('username')
            password = self.email_config.get('password')
            recipients = self.email_config.get('recipients', [])
            
            if not all([smtp_server, username, password, recipients]):
                self.logger.error("Email configuration incomplete")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = username
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"🚨 SecAudit Alert: {threat.rule_name} ({threat.severity})"
            
            # Email body
            body = f"""
Security Alert Detected

Rule: {threat.rule_name}
Severity: {threat.severity}
Confidence: {threat.confidence:.2f}
Threat Score: {threat.get_threat_score():.2f}
Timestamp: {threat.timestamp.isoformat()}

Affected Assets:
{chr(10).join(f"  - {asset}" for asset in threat.affected_assets)}

Description:
{threat.description}

Evidence Count: {len(threat.evidence)}

Mitigation:
{threat.mitigation or 'No specific mitigation provided'}

This alert was generated by SecAudit at {datetime.now().isoformat()}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email alert sent to: {', '.join(recipients)}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _send_webhook_alert(self, threat: ThreatAlert) -> bool:
        """Send alert via webhook"""
        try:
            if not self.webhook_config.get('enabled', False):
                return True
            
            webhook_url = self.webhook_config.get('url')
            if not webhook_url:
                self.logger.error("Webhook URL not configured")
                return False
            
            # Prepare payload
            payload = {
                'timestamp': datetime.now().isoformat(),
                'alert_type': 'secaudit_threat',
                'rule_id': threat.rule_id,
                'rule_name': threat.rule_name,
                'severity': threat.severity,
                'confidence': threat.confidence,
                'threat_score': threat.get_threat_score(),
                'is_critical': threat.is_critical(),
                'affected_assets': threat.affected_assets,
                'description': threat.description,
                'evidence_count': len(threat.evidence),
                'mitigation': threat.mitigation
            }
            
            # Send webhook
            import requests
            response = requests.post(
                webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info(f"Webhook alert sent to: {webhook_url}")
                return True
            else:
                self.logger.error(f"Webhook request failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to send webhook alert: {e}")
            return False
    
    def _send_file_alert(self, threat: ThreatAlert) -> bool:
        """Send alert to file"""
        try:
            alert_dir = self.config.get('path', './alerts/')
            os.makedirs(alert_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{alert_dir}alert_{threat.rule_id}_{timestamp}.json"
            
            alert_data = {
                'timestamp': datetime.now().isoformat(),
                'threat': {
                    'rule_id': threat.rule_id,
                    'rule_name': threat.rule_name,
                    'severity': threat.severity,
                    'confidence': threat.confidence,
                    'threat_score': threat.get_threat_score(),
                    'is_critical': threat.is_critical(),
                    'affected_assets': threat.affected_assets,
                    'description': threat.description,
                    'evidence_count': len(threat.evidence),
                    'mitigation': threat.mitigation
                }
            }
            
            with open(filename, 'w') as f:
                json.dump(alert_data, f, indent=2)
            
            self.logger.info(f"Alert saved to file: {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save alert to file: {e}")
            return False
    
    def get_alert_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get alert history"""
        if limit:
            return self.alert_history[-limit:]
        return self.alert_history
    
    def clear_alert_history(self) -> bool:
        """Clear alert history"""
        try:
            self.alert_history.clear()
            self.logger.info("Alert history cleared")
            return True
        except Exception as e:
            self.logger.error(f"Failed to clear alert history: {e}")
            return False
    
    def validate_config(self) -> bool:
        """Validate alert configuration"""
        try:
            # Check alert threshold
            valid_thresholds = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            if self.alert_threshold.upper() not in valid_thresholds:
                self.logger.error(f"Invalid alert threshold: {self.alert_threshold}")
                return False
            
            # Check notification methods
            valid_methods = ['console', 'email', 'webhook', 'file']
            for method in self.notification_methods:
                if method not in valid_methods:
                    self.logger.error(f"Invalid notification method: {method}")
                    return False
            
            # Validate email config if enabled
            if 'email' in self.notification_methods and self.email_config.get('enabled', False):
                required_fields = ['smtp_server', 'username', 'password', 'recipients']
                for field in required_fields:
                    if not self.email_config.get(field):
                        self.logger.error(f"Missing required email field: {field}")
                        return False
            
            # Validate webhook config if enabled
            if 'webhook' in self.notification_methods and self.webhook_config.get('enabled', False):
                if not self.webhook_config.get('url'):
                    self.logger.error("Missing webhook URL")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {e}")
            return False