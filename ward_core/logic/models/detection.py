"""
Detection domain models.

Contains the core data structures for representing security detections and evidence.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from uuid import uuid4


class EvidenceType(Enum):
    """Types of evidence that can be attached to detections."""
    LOG_ANCHOR = "log_anchor"          # Direct log line that triggered detection
    METADATA_ONLY = "metadata_only"    # Package/installer info without log anchor  
    CORRELATED = "correlated"          # Related log found via time window
    DERIVED = "derived"                # Computed/aggregated from other evidence


class Severity(Enum):
    """Severity levels for detections."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    def __lt__(self, other):
        """Enable comparison between severity levels."""
        if not isinstance(other, Severity):
            return NotImplemented
        
        severity_order = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4
        }
        return severity_order[self] < severity_order[other]
    
    def __le__(self, other):
        """Enable comparison between severity levels."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self < other or self == other
    
    def __gt__(self, other):
        """Enable comparison between severity levels."""
        if not isinstance(other, Severity):
            return NotImplemented
        return not self <= other
    
    def __ge__(self, other):
        """Enable comparison between severity levels."""
        if not isinstance(other, Severity):
            return NotImplemented
        return not self < other


@dataclass
class Evidence:
    """Individual piece of evidence supporting a detection."""
    type: EvidenceType
    content: str
    timestamp: Optional[datetime] = None
    confidence: float = 1.0
    source_line_number: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate evidence after initialization."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
        
        if not self.content.strip():
            raise ValueError("Evidence content cannot be empty")
    
    def __str__(self) -> str:
        """String representation of evidence for UI display."""
        if self.type == EvidenceType.METADATA_ONLY:
            return f"[METADATA-ONLY] {self.content}"
        elif self.type == EvidenceType.LOG_ANCHOR:
            return f"Log: {self.content}"
        elif self.type == EvidenceType.CORRELATED:
            return f"Related: {self.content}"
        else:
            return self.content


@dataclass
class Detection:
    """
    Represents a security detection with associated evidence.
    
    This is the core domain entity representing a security finding.
    """
    
    # Core identification
    id: str = field(default_factory=lambda: str(uuid4()))
    category: str = ""
    subcategory: Optional[str] = None
    package: Optional[str] = None
    
    # Risk assessment
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.8
    
    # Description
    title: str = ""
    description: str = ""
    technical_details: Dict[str, Any] = field(default_factory=dict)
    
    # Evidence
    evidence: List[Evidence] = field(default_factory=list)
    primary_anchor: Optional[Evidence] = None
    
    # Temporal information
    timestamp: Optional[datetime] = None
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    
    def __post_init__(self):
        """Validate detection after initialization."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
        
        if not self.category:
            raise ValueError("Detection must have a category")
    
    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence to this detection."""
        self.evidence.append(evidence)
        
        # Set as primary anchor if it's the first log anchor
        if (evidence.type == EvidenceType.LOG_ANCHOR and 
            self.primary_anchor is None):
            self.primary_anchor = evidence
    
    def has_log_evidence(self) -> bool:
        """Check if this detection has any real log evidence."""
        return any(e.type == EvidenceType.LOG_ANCHOR for e in self.evidence)
    
    def get_summary(self) -> str:
        """Generate summary string for display."""
        if self.package and self.package != "unknown":
            return f"[{self.category}] {self.package}: {self.title or self.description}"
        else:
            return f"[{self.category}] {self.title or self.description}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert detection to dictionary for serialization."""
        return {
            'id': self.id,
            'category': self.category,
            'subcategory': self.subcategory,
            'package': self.package,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'title': self.title,
            'description': self.description,
            'technical_details': self.technical_details,
            'evidence': [
                {
                    'type': evidence.type.value,
                    'content': evidence.content,
                    'timestamp': evidence.timestamp.isoformat() if evidence.timestamp else None,
                    'confidence': evidence.confidence,
                    'source_line_number': evidence.source_line_number,
                    'metadata': evidence.metadata
                }
                for evidence in self.evidence
            ],
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'window_start': self.window_start.isoformat() if self.window_start else None,
            'window_end': self.window_end.isoformat() if self.window_end else None
        }




