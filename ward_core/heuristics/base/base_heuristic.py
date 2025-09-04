"""
Base heuristic interface.

Defines the contract that all heuristics must implement.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import time
import logging

from ward_core.logic.models import Detection, LogData, HeuristicConfig


@dataclass
class HeuristicResult:
    """Result from running a heuristic."""
    name: str
    detections: List[Detection]
    score: float
    execution_time: float
    error: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class BaseHeuristic(ABC):
    """
    Base class for all heuristic implementations.
    
    This defines the interface that all heuristics must implement and provides
    common functionality like timing, error handling, and logging.
    """
    
    def __init__(self, config: Optional[HeuristicConfig] = None):
        """Initialize the heuristic with configuration."""
        self.config = config or HeuristicConfig(name=self.name)
        self.logger = logging.getLogger(f"heuristic.{self.name}")
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get the name of this heuristic."""
        pass
    
    @property
    @abstractmethod
    def category(self) -> str:
        """Get the category of this heuristic (e.g., 'System Security')."""
        pass
    
    @property
    def max_score(self) -> float:
        """Get the maximum possible score for this heuristic."""
        return 10.0
    
    @property
    def description(self) -> str:
        """Get a description of what this heuristic detects."""
        return f"Heuristic: {self.name}"
    
    @abstractmethod
    def analyze(self, log_data: LogData) -> List[Detection]:
        """
        Analyze the log data and return detections.
        
        This is the main method that must be implemented by each heuristic.
        
        Args:
            log_data: The log data to analyze
            
        Returns:
            List of detections found by this heuristic
        """
        pass
    
    def run(self, log_data: LogData) -> HeuristicResult:
        """
        Run the heuristic with timing and error handling.
        
        This method wraps the analyze() method with common functionality.
        
        Args:
            log_data: The log data to analyze
            
        Returns:
            HeuristicResult containing detections and metadata
        """
        start_time = time.time()
        detections = []
        error = None
        
        try:
            self.logger.info(f"Starting analysis with {self.name}")
            
            # Check if heuristic is enabled
            if not self.config.enabled:
                self.logger.info(f"Heuristic {self.name} is disabled, skipping")
                return HeuristicResult(
                    name=self.name,
                    detections=[],
                    score=0.0,
                    execution_time=0.0
                )
            
            # Run the analysis
            detections = self.analyze(log_data)
            
            # Validate detections
            detections = self._validate_detections(detections)
            
            self.logger.info(f"Completed analysis with {self.name}, found {len(detections)} detections")
            
        except Exception as e:
            error_msg = f"Error in heuristic {self.name}: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            error = error_msg
        
        execution_time = time.time() - start_time
        
        # Calculate score based on detections
        score = self._calculate_score(detections)
        
        return HeuristicResult(
            name=self.name,
            detections=detections,
            score=score,
            execution_time=execution_time,
            error=error,
            metadata={
                'category': self.category,
                'max_score': self.max_score,
                'description': self.description,
                'config': self.config.to_dict() if hasattr(self.config, 'to_dict') else str(self.config)
            }
        )
    
    def _validate_detections(self, detections: List[Detection]) -> List[Detection]:
        """
        Validate and filter detections.
        
        Args:
            detections: Raw detections from analyze()
            
        Returns:
            Validated and filtered detections
        """
        valid_detections = []
        
        for detection in detections:
            try:
                # Ensure detection has required fields
                if not detection.category:
                    detection.category = self.category
                
                # Validate detection
                if self._is_valid_detection(detection):
                    valid_detections.append(detection)
                else:
                    self.logger.warning(f"Invalid detection filtered out: {detection.id}")
                    
            except Exception as e:
                self.logger.warning(f"Error validating detection: {e}")
        
        return valid_detections
    
    def _is_valid_detection(self, detection: Detection) -> bool:
        """
        Check if a detection is valid.
        
        Args:
            detection: Detection to validate
            
        Returns:
            True if detection is valid
        """
        # Must have a category
        if not detection.category:
            return False
        
        # Must have some content (title or description)
        if not detection.title and not detection.description:
            return False
        
        # Must have valid confidence
        if not (0.0 <= detection.confidence <= 1.0):
            return False
        
        return True
    
    def _calculate_score(self, detections: List[Detection]) -> float:
        """
        Calculate overall score for this heuristic based on detections.
        
        Args:
            detections: List of detections
            
        Returns:
            Calculated score
        """
        if not detections:
            return 0.0
        
        # Simple scoring: sum of severity weights * confidence
        severity_weights = {
            'low': 1.0,
            'medium': 2.5,
            'high': 5.0,
            'critical': 10.0
        }
        
        total_score = 0.0
        for detection in detections:
            severity_weight = severity_weights.get(detection.severity.value, 2.5)
            total_score += severity_weight * detection.confidence
        
        # Cap at max_score
        return min(total_score, self.max_score)
    
    def create_detection(
        self,
        title: str,
        description: str = "",
        severity: str = "medium",
        confidence: float = 0.8,
        package: Optional[str] = None,
        technical_details: Optional[Dict[str, Any]] = None
    ) -> Detection:
        """
        Helper method to create a detection with common fields filled in.
        
        Args:
            title: Detection title
            description: Detection description
            severity: Severity level (low, medium, high, critical)
            confidence: Confidence score (0.0-1.0)
            package: Associated package name
            technical_details: Additional technical details
            
        Returns:
            Created detection
        """
        from logic.models.detection import Severity
        
        # Convert string severity to enum
        severity_map = {
            'low': Severity.LOW,
            'medium': Severity.MEDIUM,
            'high': Severity.HIGH,
            'critical': Severity.CRITICAL
        }
        
        return Detection(
            category=self.category,
            package=package,
            severity=severity_map.get(severity, Severity.MEDIUM),
            confidence=confidence,
            title=title,
            description=description,
            technical_details=technical_details or {}
        )

