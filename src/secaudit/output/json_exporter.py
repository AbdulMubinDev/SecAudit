"""
JSON output exporter for SecAudit
"""
import os
import json
import gzip
from typing import Dict, Any, List
from datetime import datetime
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
            if not self.validate_output_path():
                return False

            filename = self.generate_filename('secaudit_results')
            filepath = os.path.join(self.output_path, f"{filename}.json")

            # Accept either AnalysisResult objects with to_dict() or plain dicts
            if hasattr(results, 'to_dict') and callable(getattr(results, 'to_dict')):
                output_data = results.to_dict()
            elif isinstance(results, dict):
                output_data = results
            else:
                # Fallback: try to serialize __dict__
                try:
                    output_data = dict(results.__dict__)
                except Exception:
                    output_data = {'message': 'unserializable_results'}

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
                'affected_assets': self._get_affected_assets(results.get('threats_detected', [])),
                'critical_threats': len([t for t in results.get('threats_detected', []) if t.is_critical()])
            },
            'threats': [t.to_dict() for t in results.get('threats_detected', [])],
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