"""
Scoring engine implementation for SecAudit
"""
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from collections import Counter
from ..base_analysis import ScoringEngine
from ..models.log_entry import LogEntry
from ..models.threat_alert import ThreatAlert


class ScoringEngineImpl(ScoringEngine):
    """Scoring engine implementation for SecAudit"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = None  # Will be set by application
        
        # Default weights and multipliers
        self._setup_default_weights()
    
    def set_logger(self, logger) -> None:
        """Set logger for the scoring engine"""
        self.logger = logger
    
    def _setup_default_weights(self) -> None:
        """Setup default scoring weights"""
        # Base event weights
        self.base_weights = {
            'SSH_FAILED_PASSWORD': 2.0,
            'SSH_INVALID_USER': 3.0,
            'SSH_SUCCESS': 1.0,
            'SUDO_COMMAND': 4.0,
            'UNAUTHORIZED_ACCESS': 5.0,
            'PRIVILEGE_ESCALATION': 6.0,
            'SUSPICIOUS_COMMAND': 3.0,
            'ANOMALOUS_LOGIN': 2.5
        }
        
        # Severity multipliers
        self.multipliers = {
            'CRITICAL': 3.0,
            'HIGH': 2.0,
            'MEDIUM': 1.5,
            'LOW': 1.0,
            'INFO': 0.5
        }
        
        # Time-based multipliers
        self.time_multipliers = {
            'off_hours': 1.5,  # 10 PM - 6 AM
            'weekend': 1.3,
            'holiday': 2.0
        }
        
        # Thresholds
        self.thresholds = {
            'low_risk': 3.0,
            'medium_risk': 6.0,
            'high_risk': 8.0,
            'critical_risk': 9.0
        }
    
    def analyze(self, data: Any) -> List[Dict[str, Any]]:
        """Analyze data and return scoring results"""
        if isinstance(data, list) and all(isinstance(item, LogEntry) for item in data):
            return self._score_log_entries(data)
        elif isinstance(data, list) and all(isinstance(item, ThreatAlert) for item in data):
            return self._score_threat_alerts(data)
        else:
            if self.logger:
                self.logger.error(f"Unsupported data type for scoring: {type(data)}")
            return []
    
    def get_analysis_type(self) -> str:
        """Get the type of analysis performed"""
        return "scoring"
    
    def calculate_score(self, data: Any) -> float:
        """Calculate risk score for data"""
        if isinstance(data, LogEntry):
            return self._calculate_log_entry_score(data)
        elif isinstance(data, ThreatAlert):
            return self._calculate_threat_alert_score(data)
        else:
            return 0.0
    
    def _score_log_entries(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Score a list of log entries"""
        scores = []
        
        for entry in log_entries:
            score = self._calculate_log_entry_score(entry)
            breakdown = self._get_log_entry_score_breakdown(entry)
            
            scores.append({
                'entry_id': entry.source_ip or entry.username or 'unknown',
                'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                'event_type': entry.event_type,
                'base_score': breakdown['base_score'],
                'severity_multiplier': breakdown['severity_multiplier'],
                'time_multiplier': breakdown['time_multiplier'],
                'total_score': score,
                'risk_level': self._get_risk_level(score),
                'factors': breakdown['factors']
            })
        
        return scores
    
    def _score_threat_alerts(self, threats: List[ThreatAlert]) -> List[Dict[str, Any]]:
        """Score a list of threat alerts"""
        scores = []
        
        for threat in threats:
            score = self._calculate_threat_alert_score(threat)
            breakdown = self._get_threat_alert_score_breakdown(threat)
            
            scores.append({
                'threat_id': threat.rule_id,
                'threat_name': threat.rule_name,
                'severity': threat.severity,
                'confidence': threat.confidence,
                'base_score': breakdown['base_score'],
                'severity_multiplier': breakdown['severity_multiplier'],
                'confidence_multiplier': breakdown['confidence_multiplier'],
                'asset_multiplier': breakdown['asset_multiplier'],
                'total_score': score,
                'risk_level': self._get_risk_level(score),
                'factors': breakdown['factors']
            })
        
        return scores
    
    def _calculate_log_entry_score(self, entry: LogEntry) -> float:
        """Calculate risk score for a single log entry"""
        base_score = self.base_weights.get(entry.event_type, 1.0)
        severity_multiplier = self.multipliers.get(entry.severity, 1.0)
        time_multiplier = self._get_time_multiplier(entry.timestamp)
        
        total_score = base_score * severity_multiplier * time_multiplier
        
        # Cap score at 10.0
        return min(total_score, 10.0)
    
    def _calculate_threat_alert_score(self, threat: ThreatAlert) -> float:
        """Calculate risk score for a threat alert"""
        # Base score from threat confidence and severity
        base_score = threat.confidence * 10.0  # Scale confidence to 0-10
        severity_multiplier = self.multipliers.get(threat.severity, 1.0)
        
        # Confidence multiplier (higher confidence = higher score)
        confidence_multiplier = 1.0 + (threat.confidence * 0.5)
        
        # Asset multiplier (more affected assets = higher score)
        asset_count = len(threat.affected_assets)
        asset_multiplier = 1.0 + (asset_count * 0.1)
        
        total_score = base_score * severity_multiplier * confidence_multiplier * asset_multiplier
        
        # Cap score at 10.0
        return min(total_score, 10.0)
    
    def _get_time_multiplier(self, timestamp: Optional[datetime]) -> float:
        """Get time-based multiplier for risk scoring"""
        if not timestamp:
            return 1.0
        
        multiplier = 1.0
        
        # Check if off-hours (10 PM - 6 AM)
        hour = timestamp.hour
        if hour >= 22 or hour < 6:
            multiplier *= self.time_multipliers['off_hours']
        
        # Check if weekend
        if timestamp.weekday() >= 5:  # Saturday = 5, Sunday = 6
            multiplier *= self.time_multipliers['weekend']
        
        # Check if holiday (simplified - just check for common holidays)
        month_day = f"{timestamp.month:02d}-{timestamp.day:02d}"
        holidays = ['12-25', '01-01', '07-04']  # Christmas, New Year, Independence Day
        if month_day in holidays:
            multiplier *= self.time_multipliers['holiday']
        
        return multiplier
    
    def _get_log_entry_score_breakdown(self, entry: LogEntry) -> Dict[str, Any]:
        """Get detailed score breakdown for log entry"""
        base_score = self.base_weights.get(entry.event_type, 1.0)
        severity_multiplier = self.multipliers.get(entry.severity, 1.0)
        time_multiplier = self._get_time_multiplier(entry.timestamp)
        
        factors = []
        if entry.event_type in self.base_weights:
            factors.append(f"Event type: {entry.event_type} (weight: {base_score})")
        if entry.severity in self.multipliers:
            factors.append(f"Severity: {entry.severity} (multiplier: {severity_multiplier})")
        if time_multiplier > 1.0:
            factors.append(f"Time-based risk factor (multiplier: {time_multiplier})")
        
        return {
            'base_score': base_score,
            'severity_multiplier': severity_multiplier,
            'time_multiplier': time_multiplier,
            'factors': factors
        }
    
    def _get_threat_alert_score_breakdown(self, threat: ThreatAlert) -> Dict[str, Any]:
        """Get detailed score breakdown for threat alert"""
        base_score = threat.confidence * 10.0
        severity_multiplier = self.multipliers.get(threat.severity, 1.0)
        confidence_multiplier = 1.0 + (threat.confidence * 0.5)
        asset_multiplier = 1.0 + (len(threat.affected_assets) * 0.1)
        
        factors = [
            f"Base confidence score: {base_score:.2f}",
            f"Severity multiplier: {severity_multiplier}",
            f"Confidence multiplier: {confidence_multiplier:.2f}",
            f"Asset multiplier: {asset_multiplier:.2f} ({len(threat.affected_assets)} assets)"
        ]
        
        return {
            'base_score': base_score,
            'severity_multiplier': severity_multiplier,
            'confidence_multiplier': confidence_multiplier,
            'asset_multiplier': asset_multiplier,
            'factors': factors
        }
    
    def _get_risk_level(self, score: float) -> str:
        """Get risk level based on score"""
        if score >= self.thresholds['critical_risk']:
            return 'CRITICAL'
        elif score >= self.thresholds['high_risk']:
            return 'HIGH'
        elif score >= self.thresholds['medium_risk']:
            return 'MEDIUM'
        elif score >= self.thresholds['low_risk']:
            return 'LOW'
        else:
            return 'INFO'
    
    def get_score_statistics(self, scores: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get statistics about scores"""
        if not scores:
            return {
                'total_scores': 0,
                'average_score': 0.0,
                'max_score': 0.0,
                'min_score': 0.0,
                'risk_distribution': {}
            }
        
        total_scores = len(scores)
        average_score = sum(s['total_score'] for s in scores) / total_scores
        max_score = max(s['total_score'] for s in scores)
        min_score = min(s['total_score'] for s in scores)
        
        # Count risk levels
        risk_counts = Counter(s['risk_level'] for s in scores)
        
        return {
            'total_scores': total_scores,
            'average_score': average_score,
            'max_score': max_score,
            'min_score': min_score,
            'risk_distribution': dict(risk_counts)
        }