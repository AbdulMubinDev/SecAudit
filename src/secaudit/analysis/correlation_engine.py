"""
Correlation engine implementation for SecAudit
"""
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from collections import defaultdict
import re
from ..base_analysis import CorrelationEngine
from ..models.log_entry import LogEntry


class CorrelationEngineImpl(CorrelationEngine):
    """Correlation engine implementation for SecAudit"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = None  # Will be set by application
    
    def set_logger(self, logger) -> None:
        """Set logger for the correlation engine"""
        self.logger = logger
    
    def analyze(self, data: Any) -> List[Dict[str, Any]]:
        """Analyze data for correlations"""
        if isinstance(data, list) and all(isinstance(item, LogEntry) for item in data):
            return self.correlate_events(data)
        else:
            if self.logger:
                self.logger.error(f"Unsupported data type for correlation: {type(data)}")
            return []
    
    def get_analysis_type(self) -> str:
        """Get the type of analysis performed"""
        return "correlation"
    
    def correlate_events(self, events: List[LogEntry]) -> List[Dict[str, Any]]:
        """Correlate events to find relationships"""
        if not events:
            return []
        
        correlations = []
        
        try:
            # Group events by time windows
            time_window_seconds = self._parse_time_window()
            time_groups = self._group_by_time_windows(events, time_window_seconds)
            
            # Find correlations within each time window
            for time_window, window_events in time_groups.items():
                window_correlations = self._find_correlations_in_window(window_events)
                correlations.extend(window_correlations)
            
            # Sort correlations by severity and confidence
            correlations.sort(key=lambda x: (x.get('severity', 'LOW'), x.get('confidence', 0)), reverse=True)
            
            # Limit results if configured
            if self.max_correlations > 0:
                correlations = correlations[:self.max_correlations]
            
            if self.logger:
                self.logger.info(f"Found {len(correlations)} correlations")
            
            return correlations
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Correlation analysis failed: {e}")
            return []
    
    def _parse_time_window(self) -> int:
        """Parse time window string to seconds"""
        time_window = self.time_window.lower()
        
        if time_window.endswith('s'):
            return int(time_window[:-1])
        elif time_window.endswith('m'):
            return int(time_window[:-1]) * 60
        elif time_window.endswith('h'):
            return int(time_window[:-1]) * 3600
        elif time_window.endswith('d'):
            return int(time_window[:-1]) * 86400
        else:
            return 3600  # Default 1 hour
    
    def _group_by_time_windows(self, events: List[LogEntry], window_seconds: int) -> Dict[str, List[LogEntry]]:
        """Group events by time windows"""
        time_groups = defaultdict(list)
        
        for event in events:
            if event.timestamp:
                # Round timestamp to window boundary
                window_start = event.timestamp.replace(
                    minute=(event.timestamp.minute // (window_seconds // 60)) * (window_seconds // 60),
                    second=0,
                    microsecond=0
                )
                window_key = window_start.isoformat()
                time_groups[window_key].append(event)
        
        return time_groups
    
    def _find_correlations_in_window(self, events: List[LogEntry]) -> List[Dict[str, Any]]:
        """Find correlations within a time window"""
        correlations = []
        
        # Group events by common attributes
        ip_groups = defaultdict(list)
        user_groups = defaultdict(list)
        host_groups = defaultdict(list)
        
        for event in events:
            if event.source_ip:
                ip_groups[event.source_ip].append(event)
            if event.username:
                user_groups[event.username].append(event)
            if event.hostname:
                host_groups[event.hostname].append(event)
        
        # Find IP-based correlations
        for ip, ip_events in ip_groups.items():
            if len(ip_events) > 1:
                correlation = self._create_ip_correlation(ip, ip_events)
                if correlation:
                    correlations.append(correlation)
        
        # Find user-based correlations
        for user, user_events in user_groups.items():
            if len(user_events) > 1:
                correlation = self._create_user_correlation(user, user_events)
                if correlation:
                    correlations.append(correlation)
        
        # Find host-based correlations
        for host, host_events in host_groups.items():
            if len(host_events) > 1:
                correlation = self._create_host_correlation(host, host_events)
                if correlation:
                    correlations.append(correlation)
        
        # Find cross-attribute correlations
        cross_correlations = self._find_cross_attribute_correlations(events)
        correlations.extend(cross_correlations)
        
        return correlations
    
    def _create_ip_correlation(self, ip: str, events: List[LogEntry]) -> Optional[Dict[str, Any]]:
        """Create correlation based on IP address"""
        if len(events) < 2:
            return None
        
        # Count event types
        event_types = defaultdict(int)
        severities = []
        timestamps = []
        
        for event in events:
            event_types[event.event_type] += 1
            severities.append(event.severity)
            if event.timestamp:
                timestamps.append(event.timestamp)
        
        # Determine correlation type
        correlation_type = "multiple_events_from_ip"
        if any(et in ['SSH_FAILED_PASSWORD', 'SSH_INVALID_USER'] for et in event_types):
            correlation_type = "brute_force_attempt"
        elif any(et == 'SUDO_COMMAND' for et in event_types):
            correlation_type = "privilege_escalation_attempt"
        
        # Calculate confidence
        confidence = self._calculate_correlation_confidence(event_types, severities)
        
        return {
            'correlation_id': f"ip_{ip}_{correlation_type}",
            'type': correlation_type,
            'severity': self._determine_correlation_severity(severities),
            'confidence': confidence,
            'timestamp': min(timestamps).isoformat() if timestamps else None,
            'source_ip': ip,
            'event_count': len(events),
            'event_types': dict(event_types),
            'affected_assets': list(set([e.hostname for e in events if e.hostname])),
            'description': f"Multiple events from IP {ip}: {', '.join(event_types.keys())}"
        }
    
    def _create_user_correlation(self, user: str, events: List[LogEntry]) -> Optional[Dict[str, Any]]:
        """Create correlation based on username"""
        if len(events) < 2:
            return None
        
        event_types = defaultdict(int)
        severities = []
        timestamps = []
        source_ips = set()
        
        for event in events:
            event_types[event.event_type] += 1
            severities.append(event.severity)
            if event.timestamp:
                timestamps.append(event.timestamp)
            if event.source_ip:
                source_ips.add(event.source_ip)
        
        correlation_type = "multiple_events_for_user"
        if len(source_ips) > 1:
            correlation_type = "user_multiple_sources"
        elif any(et in ['SSH_FAILED_PASSWORD', 'SSH_INVALID_USER'] for et in event_types):
            correlation_type = "user_failed_attempts"
        
        confidence = self._calculate_correlation_confidence(event_types, severities)
        
        return {
            'correlation_id': f"user_{user}_{correlation_type}",
            'type': correlation_type,
            'severity': self._determine_correlation_severity(severities),
            'confidence': confidence,
            'timestamp': min(timestamps).isoformat() if timestamps else None,
            'username': user,
            'event_count': len(events),
            'event_types': dict(event_types),
            'source_ips': list(source_ips),
            'affected_assets': list(set([e.hostname for e in events if e.hostname])),
            'description': f"Multiple events for user {user} from {len(source_ips)} sources"
        }
    
    def _create_host_correlation(self, host: str, events: List[LogEntry]) -> Optional[Dict[str, Any]]:
        """Create correlation based on hostname"""
        if len(events) < 2:
            return None
        
        event_types = defaultdict(int)
        severities = []
        timestamps = []
        source_ips = set()
        
        for event in events:
            event_types[event.event_type] += 1
            severities.append(event.severity)
            if event.timestamp:
                timestamps.append(event.timestamp)
            if event.source_ip:
                source_ips.add(event.source_ip)
        
        correlation_type = "multiple_events_on_host"
        if len(source_ips) > 3:  # Multiple sources attacking same host
            correlation_type = "distributed_attack"
        
        confidence = self._calculate_correlation_confidence(event_types, severities)
        
        return {
            'correlation_id': f"host_{host}_{correlation_type}",
            'type': correlation_type,
            'severity': self._determine_correlation_severity(severities),
            'confidence': confidence,
            'timestamp': min(timestamps).isoformat() if timestamps else None,
            'hostname': host,
            'event_count': len(events),
            'event_types': dict(event_types),
            'source_ips': list(source_ips),
            'description': f"Multiple events on host {host} from {len(source_ips)} sources"
        }
    
    def _find_cross_attribute_correlations(self, events: List[LogEntry]) -> List[Dict[str, Any]]:
        """Find correlations across different attributes"""
        correlations = []
        
        # Look for patterns that span multiple attributes
        for i, event1 in enumerate(events):
            for j, event2 in enumerate(events[i+1:], i+1):
                correlation = self._find_pairwise_correlation(event1, event2)
                if correlation:
                    correlations.append(correlation)
        
        return correlations
    
    def _find_pairwise_correlation(self, event1: LogEntry, event2: LogEntry) -> Optional[Dict[str, Any]]:
        """Find correlation between two specific events"""
        # Check for time proximity
        if not (event1.timestamp and event2.timestamp):
            return None
        
        time_diff = abs((event1.timestamp - event2.timestamp).total_seconds())
        if time_diff > self._parse_time_window():
            return None
        
        # Check for related attributes
        related = False
        correlation_type = "temporal_correlation"
        
        if event1.source_ip == event2.source_ip:
            related = True
            correlation_type = "ip_correlation"
        elif event1.username == event2.username:
            related = True
            correlation_type = "user_correlation"
        elif event1.hostname == event2.hostname:
            related = True
            correlation_type = "host_correlation"
        
        if not related:
            return None
        
        # Determine if this is a significant correlation
        threat_events = ['SSH_FAILED_PASSWORD', 'SSH_INVALID_USER', 'SUDO_COMMAND']
        is_threat1 = event1.event_type in threat_events
        is_threat2 = event2.event_type in threat_events
        
        if is_threat1 or is_threat2:
            correlation_type = f"threat_{correlation_type}"
        
        return {
            'correlation_id': f"pair_{event1.source_ip or 'unknown'}_{event2.source_ip or 'unknown'}_{correlation_type}",
            'type': correlation_type,
            'severity': max(event1.severity, event2.severity),
            'confidence': 0.8 if (is_threat1 or is_threat2) else 0.5,
            'timestamp': min(event1.timestamp, event2.timestamp).isoformat(),
            'event1': event1.to_dict(),
            'event2': event2.to_dict(),
            'time_difference': time_diff,
            'description': f"Related events: {event1.event_type} and {event2.event_type}"
        }
    
    def _calculate_correlation_confidence(self, event_types: Dict[str, int], severities: List[str]) -> float:
        """Calculate confidence score for correlation"""
        base_confidence = 0.5
        
        # Boost confidence for multiple events of same type
        max_count = max(event_types.values()) if event_types else 1
        if max_count > 2:
            base_confidence += 0.2
        
        # Boost confidence for high severity events
        high_severity_count = severities.count('HIGH') + severities.count('CRITICAL')
        if high_severity_count > 0:
            base_confidence += 0.3
        
        # Boost confidence for threat-related events
        threat_events = ['SSH_FAILED_PASSWORD', 'SSH_INVALID_USER', 'SUDO_COMMAND']
        threat_count = sum(event_types.get(et, 0) for et in threat_events)
        if threat_count > 0:
            base_confidence += 0.2
        
        return min(base_confidence, 1.0)
    
    def _determine_correlation_severity(self, severities: List[str]) -> str:
        """Determine severity of correlation based on constituent events"""
        if not severities:
            return 'INFO'
        
        severity_weights = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'INFO': 0
        }
        
        max_weight = max(severity_weights.get(s, 0) for s in severities)
        
        for severity, weight in severity_weights.items():
            if weight == max_weight:
                return severity
        
        return 'INFO'