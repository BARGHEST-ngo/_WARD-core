"""
Analysis result domain models.

Contains the data structures for representing the final analysis results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional

from .detection import Detection


class RiskLevel(Enum):
    """Risk levels for overall analysis results."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    
    def __lt__(self, other):
        """Enable comparison between risk levels."""
        if not isinstance(other, RiskLevel):
            return NotImplemented
        
        risk_order = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4
        }
        return risk_order[self] < risk_order[other]
    
    def __le__(self, other):
        """Enable comparison between risk levels."""
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self < other or self == other
    
    def __gt__(self, other):
        """Enable comparison between risk levels."""
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return not self <= other
    
    def __ge__(self, other):
        """Enable comparison between risk levels."""
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return not self < other


@dataclass
class HeuristicResult:
    """Result from a single heuristic analysis."""
    name: str
    score: float
    normalized_score: float
    weight: float
    detections: List[Detection] = field(default_factory=list)
    execution_time: float = 0.0
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate heuristic result after initialization."""
        if self.score < 0:
            raise ValueError(f"Score cannot be negative, got {self.score}")
        
        if not 0.0 <= self.normalized_score <= 1.0:
            raise ValueError(f"Normalized score must be between 0.0 and 1.0, got {self.normalized_score}")


@dataclass 
class AnalysisResult:
    """
    Complete analysis result containing all findings and metadata.
    
    This is the main output of the analysis process.
    """
    
    # Core results
    overall_score: float
    risk_level: RiskLevel
    detections: List[Detection] = field(default_factory=list)
    heuristic_results: Dict[str, HeuristicResult] = field(default_factory=dict)
    
    # Metadata
    device_id: str = "Unknown Device"
    device_model: str = "Unknown Model"
    android_version: str = "Unknown"
    build_fingerprint: str = ""
    timestamp: Optional[datetime] = None
    
    # Analysis metadata
    total_heuristics: int = 0
    triggered_heuristics: int = 0
    lines_analyzed: int = 0
    packages_analyzed: int = 0
    execution_time: float = 0.0
    
    # Quality indicators
    missing_sections: List[str] = field(default_factory=list)
    coverage_score: float = 1.0
    confidence_score: float = 0.8
    
    def __post_init__(self):
        """Validate analysis result after initialization."""
        if not 0.0 <= self.overall_score <= 100.0:
            raise ValueError(f"Overall score must be between 0.0 and 100.0, got {self.overall_score}")
        
        if not 0.0 <= self.coverage_score <= 1.0:
            raise ValueError(f"Coverage score must be between 0.0 and 1.0, got {self.coverage_score}")
        
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValueError(f"Confidence score must be between 0.0 and 1.0, got {self.confidence_score}")
    
    def get_risk_color(self) -> str:
        """Get color code for risk level display."""
        colors = {
            RiskLevel.CRITICAL: "red",
            RiskLevel.HIGH: "red", 
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.LOW: "green"
        }
        return colors.get(self.risk_level, "white")
    
    def get_detections_by_severity(self, severity) -> List[Detection]:
        """Get all detections of a specific severity."""
        return [d for d in self.detections if d.severity == severity]
    
    def get_detections_by_category(self, category: str) -> List[Detection]:
        """Get all detections in a specific category.""" 
        return [d for d in self.detections if d.category == category]
    
    def get_summary_statistics(self) -> Dict[str, Any]:
        """Get summary statistics for the analysis."""
        severity_counts = {}
        for severity in ['low', 'medium', 'high', 'critical']:
            severity_counts[severity] = len([d for d in self.detections if d.severity.value == severity])
        
        category_counts = {}
        for detection in self.detections:
            category_counts[detection.category] = category_counts.get(detection.category, 0) + 1
        
        return {
            'total_detections': len(self.detections),
            'severity_counts': severity_counts,
            'category_counts': category_counts,
            'risk_level': self.risk_level.value,
            'overall_score': round(self.overall_score, 2),
            'coverage_score': round(self.coverage_score, 2),
            'confidence_score': round(self.confidence_score, 2),
            'execution_time': round(self.execution_time, 3)
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis result to dictionary for serialization."""
        return {
            'overall_score': round(self.overall_score, 2),
            'risk_level': self.risk_level.value,
            'risk_color': self.get_risk_color(),
            'detections': [detection.to_dict() for detection in self.detections],
            'heuristic_results': {
                name: {
                    'name': result.name,
                    'score': result.score,
                    'normalized_score': result.normalized_score,
                    'weight': result.weight,
                    'detection_count': len(result.detections),  # Just the count, not the full detections
                    'execution_time': result.execution_time,
                    'error': result.error,
                    'metadata': result.metadata
                }
                for name, result in self.heuristic_results.items()
            },
            'device_id': self.device_id,
            'device_model': self.device_model,
            'android_version': self.android_version,
            'build_fingerprint': self.build_fingerprint,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'total_heuristics': self.total_heuristics,
            'triggered_heuristics': self.triggered_heuristics,
            'lines_analyzed': self.lines_analyzed,
            'packages_analyzed': self.packages_analyzed,
            'execution_time': self.execution_time,
            'missing_sections': self.missing_sections,
            'coverage_score': self.coverage_score,
            'confidence_score': self.confidence_score,
            'summary_statistics': self.get_summary_statistics()
        }

