"""
Analysis result data model for SecAudit
"""
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from datetime import datetime
from .log_entry import LogEntry
from .threat_alert import ThreatAlert

@dataclass
class AnalysisResult:
    """Complete analysis result"""
    total_entries: int
    parsed_entries: int
    threats_detected: List[ThreatAlert]
    anomalies: List[Dict[str, Any]]
    processing_time: float
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    raw_logs: Optional[List[str]] = None
    
    def __post_init__(self):
        """Initialize timestamps if not provided"""
        if self.start_time is None:
            self.start_time = datetime.now()
        if self.end_time is None:
            self.end_time = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'metadata': {
                'secaudit_version': '1.0',
                'export_timestamp': datetime.now().isoformat(),
                'total_entries': self.total_entries,
                'parsed_entries': self.parsed_entries,
                'threats_detected': len(self.threats_detected),
                'anomalies_found': len(self.anomalies),
                'processing_time': self.processing_time,
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': self.end_time.isoformat() if self.end_time else None
            },
            'summary': {
                'processing_time': self.processing_time,
                'threats_by_severity': self._count_threats_by_severity(),
                'top_threat_types': self._get_top_threat_types(),
                'affected_assets': self._get_affected_assets(),
                'critical_threats': len([t for t in self.threats_detected if t.is_critical()])
            },
            'threats': [t.to_dict() for t in self.threats_detected],
            'anomalies': self.anomalies,
            'raw_logs': self.raw_logs if self.raw_logs else []
        }
    
    def _count_threats_by_severity(self) -> Dict[str, int]:
        """Count threats by severity level"""
        severity_counts = {}
        for threat in self.threats_detected:
            severity = threat.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts
    
    def _get_top_threat_types(self) -> List[Dict[str, Any]]:
        """Get top threat types by count"""
        type_counts = {}
        for threat in self.threats_detected:
            rule_name = threat.rule_name
            type_counts[rule_name] = type_counts.get(rule_name, 0) + 1
        
        # Sort by count and return top 5
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        return [{'type': name, 'count': count} for name, count in sorted_types[:5]]
    
    def _get_affected_assets(self) -> List[str]:
        """Get list of affected assets"""
        assets = set()
        for threat in self.threats_detected:
            assets.update(threat.affected_assets)
        return list(assets)
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get comprehensive threat statistics"""
        if not self.threats_detected:
            return {
                'total_threats': 0,
                'critical_threats': 0,
                'high_threats': 0,
                'medium_threats': 0,
                'low_threats': 0,
                'average_confidence': 0.0,
                'highest_threat_score': 0.0
            }
        
        critical_count = len([t for t in self.threats_detected if t.severity == 'CRITICAL'])
        high_count = len([t for t in self.threats_detected if t.severity == 'HIGH'])
        medium_count = len([t for t in self.threats_detected if t.severity == 'MEDIUM'])
        low_count = len([t for t in self.threats_detected if t.severity == 'LOW'])
        
        confidences = [t.confidence for t in self.threats_detected]
        threat_scores = [t.get_threat_score() for t in self.threats_detected]
        
        return {
            'total_threats': len(self.threats_detected),
            'critical_threats': critical_count,
            'high_threats': high_count,
            'medium_threats': medium_count,
            'low_threats': low_count,
            'average_confidence': sum(confidences) / len(confidences),
            'highest_threat_score': max(threat_scores) if threat_scores else 0.0
        }
    
    def is_successful(self) -> bool:
        """Check if analysis was successful"""
        return self.parsed_entries > 0 or len(self.threats_detected) > 0