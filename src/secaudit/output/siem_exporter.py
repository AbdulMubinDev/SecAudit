"""
SIEM export implementation for SecAudit
"""
import json
import os
from typing import Any, Dict, List, Optional
from ..base_output import BaseOutput
from ..models.log_entry import LogEntry
from ..models.threat_alert import ThreatAlert
from ..models.analysis_result import AnalysisResult


class SIEMExporter(BaseOutput):
    """SIEM export implementation for SecAudit"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.format = config.get('siem_format', 'splunk')  # splunk, elk, qradar, arcsight
        self.include_raw = config.get('include_raw', False)
        self.batch_size = config.get('batch_size', 1000)
    
    def export(self, data: Any, output_path: Optional[str] = None) -> bool:
        """Export data to SIEM format"""
        try:
            if isinstance(data, AnalysisResult):
                return self._export_analysis_result(data, output_path)
            elif isinstance(data, list) and all(isinstance(item, LogEntry) for item in data):
                return self._export_log_entries(data, output_path)
            elif isinstance(data, list) and all(isinstance(item, ThreatAlert) for item in data):
                return self._export_threat_alerts(data, output_path)
            else:
                self.logger.error(f"Unsupported data type for SIEM export: {type(data)}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to export to SIEM format: {e}")
            return False
    
    def _export_analysis_result(self, result: AnalysisResult, output_path: Optional[str] = None) -> bool:
        """Export analysis result to SIEM format"""
        if not output_path:
            output_path = self.get_output_path(f"analysis_result_{self.format}.json")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        try:
            # Export as individual events
            events = []
            
            # Add summary event
            summary_event = {
                'timestamp': result.end_time.isoformat() if result.end_time else None,
                'event_type': 'secaudit_analysis_summary',
                'secaudit_version': '1.0.0',
                'total_entries': result.total_entries,
                'parsed_entries': result.parsed_entries,
                'threats_detected': len(result.threats_detected),
                'anomalies_found': len(result.anomalies),
                'processing_time': result.processing_time,
                'start_time': result.start_time.isoformat() if result.start_time else None,
                'end_time': result.end_time.isoformat() if result.end_time else None
            }
            events.append(self._format_siem_event(summary_event))
            
            # Export threats
            threat_events = self._format_threat_alerts(result.threats_detected)
            events.extend(threat_events)
            
            # Export anomalies
            anomaly_events = self._format_anomalies(result.anomalies)
            events.extend(anomaly_events)
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                for event in events:
                    f.write(json.dumps(event) + '\n')
            
            self.logger.info(f"Analysis result exported to SIEM format: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export analysis result to SIEM: {e}")
            return False
    
    def _export_log_entries(self, log_entries: List[LogEntry], output_path: Optional[str] = None) -> bool:
        """Export log entries to SIEM format"""
        if not output_path:
            output_path = self.get_output_path(f"log_entries_{self.format}.json")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        try:
            events = []
            for entry in log_entries:
                event = {
                    'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                    'hostname': entry.hostname,
                    'event_type': entry.event_type,
                    'severity': entry.severity,
                    'source_ip': entry.source_ip,
                    'username': entry.username,
                    'target_user': entry.target_user,
                    'port': entry.port,
                    'command': entry.command,
                    'is_threat': entry.is_threat(),
                    'affected_assets': entry.get_affected_assets()
                }
                
                if self.include_raw:
                    event['raw_line'] = entry.raw_line
                
                events.append(self._format_siem_event(event))
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                for event in events:
                    f.write(json.dumps(event) + '\n')
            
            self.logger.info(f"Log entries exported to SIEM format: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export log entries to SIEM: {e}")
            return False
    
    def _export_threat_alerts(self, threats: List[ThreatAlert], output_path: Optional[str] = None) -> bool:
        """Export threat alerts to SIEM format"""
        if not output_path:
            output_path = self.get_output_path(f"threat_alerts_{self.format}.json")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        try:
            events = self._format_threat_alerts(threats)
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                for event in events:
                    f.write(json.dumps(event) + '\n')
            
            self.logger.info(f"Threat alerts exported to SIEM format: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export threat alerts to SIEM: {e}")
            return False
    
    def _format_threat_alerts(self, threats: List[ThreatAlert]) -> List[Dict[str, Any]]:
        """Format threat alerts for SIEM"""
        events = []
        for threat in threats:
            event = {
                'timestamp': threat.timestamp.isoformat(),
                'event_type': 'secaudit_threat_detected',
                'rule_id': threat.rule_id,
                'rule_name': threat.rule_name,
                'severity': threat.severity,
                'description': threat.description,
                'confidence': threat.confidence,
                'threat_score': threat.get_threat_score(),
                'is_critical': threat.is_critical(),
                'affected_assets': threat.affected_assets,
                'evidence_count': len(threat.evidence),
                'mitigation': threat.mitigation
            }
            events.append(self._format_siem_event(event))
        return events
    
    def _format_anomalies(self, anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format anomalies for SIEM"""
        events = []
        for anomaly in anomalies:
            event = {
                'timestamp': anomaly.get('timestamp'),
                'event_type': 'secaudit_anomaly_detected',
                'anomaly_type': anomaly.get('type'),
                'anomaly_score': anomaly.get('score'),
                'description': anomaly.get('description'),
                'details': anomaly
            }
            events.append(self._format_siem_event(event))
        return events
    
    def _format_siem_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Format event according to SIEM format"""
        if self.format == 'splunk':
            return self._format_splunk_event(event)
        elif self.format == 'elk':
            return self._format_elk_event(event)
        elif self.format == 'qradar':
            return self._format_qradar_event(event)
        elif self.format == 'arcsight':
            return self._format_arcsight_event(event)
        else:
            return event
    
    def _format_splunk_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Format event for Splunk"""
        formatted_event = {
            'time': event.get('timestamp'),
            'host': event.get('hostname', 'secaudit'),
            'source': 'secaudit',
            'sourcetype': 'secaudit:log',
            'index': 'security',
            '_raw': json.dumps(event)
        }
        return formatted_event
    
    def _format_elk_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Format event for ELK Stack"""
        formatted_event = {
            '@timestamp': event.get('timestamp'),
            'host': {
                'name': event.get('hostname', 'secaudit')
            },
            'source': 'secaudit',
            'event': {
                'category': 'security',
                'type': event.get('event_type', 'log'),
                'severity': event.get('severity', 'INFO')
            },
            'message': json.dumps(event)
        }
        return formatted_event
    
    def _format_qradar_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Format event for QRadar"""
        formatted_event = {
            'timestamp': event.get('timestamp'),
            'sourceip': event.get('source_ip'),
            'destinationip': event.get('target_ip'),
            'username': event.get('username'),
            'logsourceid': 'secaudit',
            'devicetype': 'secaudit',
            'category': 'SECURITY',
            'severity': self._map_severity_to_qradar(event.get('severity', 'INFO')),
            'message': json.dumps(event)
        }
        return formatted_event
    
    def _format_arcsight_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Format event for ArcSight"""
        formatted_event = {
            'startTime': event.get('timestamp'),
            'deviceExternalId': 'secaudit',
            'deviceProduct': 'SecAudit',
            'deviceVendor': 'OpenSource',
            'deviceVersion': '1.0.0',
            'name': event.get('event_type', 'Log Entry'),
            'severity': self._map_severity_to_arcsight(event.get('severity', 'INFO')),
            'sourceAddress': event.get('source_ip'),
            'sourceUserName': event.get('username'),
            'destinationUserName': event.get('target_user'),
            'message': json.dumps(event)
        }
        return formatted_event
    
    def _map_severity_to_qradar(self, severity: str) -> int:
        """Map severity to QRadar numeric severity"""
        severity_map = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 5,
            'LOW': 3,
            'INFO': 1
        }
        return severity_map.get(severity.upper(), 1)
    
    def _map_severity_to_arcsight(self, severity: str) -> int:
        """Map severity to ArcSight numeric severity"""
        severity_map = {
            'CRITICAL': 10,
            'HIGH': 8,
            'MEDIUM': 6,
            'LOW': 4,
            'INFO': 2
        }
        return severity_map.get(severity.upper(), 2)
    
    def validate_config(self) -> bool:
        """Validate SIEM export configuration"""
        try:
            # Check supported formats
            supported_formats = ['splunk', 'elk', 'qradar', 'arcsight']
            if self.format not in supported_formats:
                self.logger.error(f"Unsupported SIEM format: {self.format}")
                return False
            
            # Check output directory
            output_dir = self.config.get('path', './output/')
            if not os.path.exists(output_dir):
                try:
                    os.makedirs(output_dir, exist_ok=True)
                except Exception as e:
                    self.logger.error(f"Cannot create output directory: {e}")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {e}")
            return False