"""
CSV export implementation for SecAudit
"""
import csv
import os
from typing import Any, Dict, List, Optional
from ..base_output import BaseOutput
from ..models.log_entry import LogEntry
from ..models.threat_alert import ThreatAlert
from ..models.analysis_result import AnalysisResult


class CSVExporter(BaseOutput):
    """CSV export implementation for SecAudit"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.include_raw = config.get('include_raw', False)
        self.max_file_size = self._parse_size(config.get('max_file_size', '100MB'))
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string to bytes"""
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)  # Assume bytes
    
    def export(self, data: Any, output_path: Optional[str] = None) -> bool:
        """Export data to CSV format"""
        try:
            if isinstance(data, AnalysisResult):
                return self._export_analysis_result(data, output_path)
            elif isinstance(data, list) and all(isinstance(item, LogEntry) for item in data):
                return self._export_log_entries(data, output_path)
            elif isinstance(data, list) and all(isinstance(item, ThreatAlert) for item in data):
                return self._export_threat_alerts(data, output_path)
            else:
                self.logger.error(f"Unsupported data type for CSV export: {type(data)}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to export to CSV: {e}")
            return False
    
    def _export_analysis_result(self, result: AnalysisResult, output_path: Optional[str] = None) -> bool:
        """Export analysis result to CSV"""
        if not output_path:
            output_path = self.get_output_path("analysis_result.csv")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        try:
            # Export summary
            summary_path = output_path.replace('.csv', '_summary.csv')
            with open(summary_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Metric', 'Value'])
                writer.writerow(['Total Entries', result.total_entries])
                writer.writerow(['Parsed Entries', result.parsed_entries])
                writer.writerow(['Threats Detected', len(result.threats_detected)])
                writer.writerow(['Anomalies Found', len(result.anomalies)])
                writer.writerow(['Processing Time', f"{result.processing_time:.2f} seconds"])
                writer.writerow(['Start Time', result.start_time.isoformat() if result.start_time else ''])
                writer.writerow(['End Time', result.end_time.isoformat() if result.end_time else ''])
            
            # Export threats
            threats_path = output_path.replace('.csv', '_threats.csv')
            self._export_threat_alerts(result.threats_detected, threats_path)
            
            # Export anomalies
            anomalies_path = output_path.replace('.csv', '_anomalies.csv')
            self._export_anomalies(result.anomalies, anomalies_path)
            
            self.logger.info(f"Analysis result exported to: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export analysis result: {e}")
            return False
    
    def _export_log_entries(self, log_entries: List[LogEntry], output_path: Optional[str] = None) -> bool:
        """Export log entries to CSV"""
        if not output_path:
            output_path = self.get_output_path("log_entries.csv")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                header = [
                    'Timestamp', 'Hostname', 'Event Type', 'Severity',
                    'Source IP', 'Username', 'Target User', 'Port',
                    'Command', 'Is Threat'
                ]
                
                if self.include_raw:
                    header.append('Raw Line')
                
                writer.writerow(header)
                
                # Write data
                for entry in log_entries:
                    row = [
                        entry.timestamp.isoformat() if entry.timestamp else '',
                        entry.hostname,
                        entry.event_type,
                        entry.severity,
                        entry.source_ip or '',
                        entry.username or '',
                        entry.target_user or '',
                        entry.port or '',
                        entry.command or '',
                        entry.is_threat()
                    ]
                    
                    if self.include_raw:
                        row.append(entry.raw_line)
                    
                    writer.writerow(row)
            
            self.logger.info(f"Log entries exported to: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export log entries: {e}")
            return False
    
    def _export_threat_alerts(self, threats: List[ThreatAlert], output_path: Optional[str] = None) -> bool:
        """Export threat alerts to CSV"""
        if not output_path:
            output_path = self.get_output_path("threat_alerts.csv")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                header = [
                    'Rule ID', 'Rule Name', 'Severity', 'Description',
                    'Confidence', 'Timestamp', 'Threat Score', 'Is Critical',
                    'Affected Assets', 'Evidence Count', 'Mitigation'
                ]
                writer.writerow(header)
                
                # Write data
                for threat in threats:
                    row = [
                        threat.rule_id,
                        threat.rule_name,
                        threat.severity,
                        threat.description,
                        threat.confidence,
                        threat.timestamp.isoformat(),
                        f"{threat.get_threat_score():.2f}",
                        threat.is_critical(),
                        '; '.join(threat.affected_assets),
                        len(threat.evidence),
                        threat.mitigation or ''
                    ]
                    
                    writer.writerow(row)
            
            self.logger.info(f"Threat alerts exported to: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export threat alerts: {e}")
            return False
    
    def _export_anomalies(self, anomalies: List[Dict[str, Any]], output_path: Optional[str] = None) -> bool:
        """Export anomalies to CSV"""
        if not output_path:
            output_path = self.get_output_path("anomalies.csv")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header (assuming anomalies have consistent structure)
                if anomalies:
                    header = list(anomalies[0].keys())
                    writer.writerow(header)
                    
                    # Write data
                    for anomaly in anomalies:
                        row = [anomaly.get(field, '') for field in header]
                        writer.writerow(row)
                else:
                    writer.writerow(['No anomalies detected'])
            
            self.logger.info(f"Anomalies exported to: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export anomalies: {e}")
            return False
    
    def validate_config(self) -> bool:
        """Validate CSV export configuration"""
        try:
            # Check output directory
            output_dir = self.config.get('path', './output/')
            if not os.path.exists(output_dir):
                try:
                    os.makedirs(output_dir, exist_ok=True)
                except Exception as e:
                    self.logger.error(f"Cannot create output directory: {e}")
                    return False
            
            # Validate file size limit
            max_size = self.config.get('max_file_size', '100MB')
            try:
                self._parse_size(max_size)
            except ValueError:
                self.logger.error(f"Invalid max_file_size: {max_size}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {e}")
            return False