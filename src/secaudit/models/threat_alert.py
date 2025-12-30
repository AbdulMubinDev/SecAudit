"""
Threat alert data model for SecAudit
"""
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime
from .log_entry import LogEntry

@dataclass
class ThreatAlert:
    """Represents a detected security threat"""
    rule_id: str
    rule_name: str
    severity: str
    description: str
    confidence: float
    timestamp: datetime
    affected_assets: List[str]
    evidence: List[LogEntry]
    mitigation: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'severity': self.severity,
            'description': self.description,
            'confidence': self.confidence,
            'timestamp': self.timestamp.isoformat(),
            'affected_assets': self.affected_assets,
            'evidence': [e.to_dict() for e in self.evidence],
            'mitigation': self.mitigation
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatAlert':
        """Create ThreatAlert from dictionary"""
        evidence = [LogEntry.from_dict(e) for e in data.get('evidence', [])]
        
        return cls(
            rule_id=data['rule_id'],
            rule_name=data['rule_name'],
            severity=data['severity'],
            description=data['description'],
            confidence=data['confidence'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            affected_assets=data.get('affected_assets', []),
            evidence=evidence,
            mitigation=data.get('mitigation')
        )
    
    def get_threat_score(self) -> float:
        """Calculate threat score based on severity and confidence"""
        severity_weights = {
            'LOW': 1.0,
            'MEDIUM': 2.5,
            'HIGH': 5.0,
            'CRITICAL': 10.0
        }
        
        base_score = severity_weights.get(self.severity, 1.0)
        weighted_score = base_score * self.confidence
        
        return min(weighted_score, 10.0)  # Cap at 10.0
    
    def is_critical(self) -> bool:
        """Check if this is a critical threat"""
        return self.severity in ['CRITICAL', 'HIGH'] and self.confidence > 0.7
    
    def get_summary(self) -> str:
        """Get a summary of the threat"""
        return f"{self.rule_name} ({self.severity}) - {len(self.evidence)} evidence items"