"""
Base analysis classes for SecAudit
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from datetime import datetime


class BaseAnalyzer(ABC):
    """Abstract base class for all analyzers"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = None  # Will be set by concrete implementations
    
    @abstractmethod
    def analyze(self, data: Any) -> List[Dict[str, Any]]:
        """
        Analyze data and return results
        
        Args:
            data (Any): Data to analyze
            
        Returns:
            List[Dict]: Analysis results
        """
        pass
    
    @abstractmethod
    def get_analysis_type(self) -> str:
        """Get the type of analysis performed"""
        pass
    
    def set_logger(self, logger) -> None:
        """Set logger for the analyzer"""
        self.logger = logger


class CorrelationEngine(BaseAnalyzer):
    """Abstract base class for correlation engines"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.time_window = config.get('time_window', '1h')
        self.cross_log = config.get('cross_log', True)
        self.max_correlations = config.get('max_correlations', 100)
    
    @abstractmethod
    def correlate_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate events to find relationships
        
        Args:
            events (List[Dict]): List of events to correlate
            
        Returns:
            List[Dict]: Correlated events
        """
        pass
    
    def get_correlation_rules(self) -> List[Dict[str, Any]]:
        """Get correlation rules"""
        return self.config.get('correlation_rules', [])
    
    def validate_correlation_config(self) -> bool:
        """Validate correlation configuration"""
        try:
            # Validate time window format
            time_window = self.time_window
            if not time_window.endswith(('s', 'm', 'h', 'd')):
                raise ValueError(f"Invalid time window format: {time_window}")
            
            # Validate max correlations
            if self.max_correlations <= 0:
                raise ValueError(f"Invalid max_correlations: {self.max_correlations}")
            
            return True
        except Exception as e:
            if self.logger:
                self.logger.error(f"Correlation configuration validation failed: {e}")
            return False


class ScoringEngine(BaseAnalyzer):
    """Abstract base class for scoring engines"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_weights = config.get('base_weights', {})
        self.multipliers = config.get('multipliers', {})
        self.thresholds = config.get('thresholds', {})
    
    @abstractmethod
    def calculate_score(self, data: Any) -> float:
        """
        Calculate risk score for data
        
        Args:
            data (Any): Data to score
            
        Returns:
            float: Risk score
        """
        pass
    
    def get_score_breakdown(self, data: Any) -> Dict[str, float]:
        """
        Get detailed score breakdown
        
        Args:
            data (Any): Data to score
            
        Returns:
            Dict: Score breakdown by component
        """
        return {}
    
    def is_high_risk(self, score: float) -> bool:
        """Check if score indicates high risk"""
        high_risk_threshold = self.thresholds.get('high_risk', 7.0)
        return score >= high_risk_threshold
    
    def is_critical_risk(self, score: float) -> bool:
        """Check if score indicates critical risk"""
        critical_risk_threshold = self.thresholds.get('critical_risk', 9.0)
        return score >= critical_risk_threshold