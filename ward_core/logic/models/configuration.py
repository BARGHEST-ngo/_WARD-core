"""
Configuration domain models.

Contains the data structures for managing analysis configuration and settings.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
import json
from pathlib import Path

from ward_core.infrastructure.collectors.base_collector import CollectionConfig

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class HeuristicConfig:
    """Configuration for a single heuristic."""
    name: str
    enabled: bool = True
    weight: float = 1.0
    confidence: str = "medium"  # low, medium, high
    timeout_seconds: int = 300
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate heuristic configuration."""
        if self.weight < 0:
            raise ValueError(f"Weight cannot be negative for {self.name}")
        
        if self.confidence not in ['low', 'medium', 'high']:
            raise ValueError(f"Invalid confidence level for {self.name}: {self.confidence}")
        
        if self.timeout_seconds <= 0:
            raise ValueError(f"Timeout must be positive for {self.name}")


@dataclass
class QualityGateConfig:
    """Configuration for quality gates and filtering."""
    min_evidence_items: int = 1
    require_log_evidence: bool = True
    min_suspicious_indicators: int = 2
    max_metadata_only_detections: int = 10
    time_window_minutes: int = 30
    
    def __post_init__(self):
        """Validate quality gate configuration."""
        if self.min_evidence_items < 0:
            raise ValueError("min_evidence_items cannot be negative")
        
        if self.min_suspicious_indicators < 1:
            raise ValueError("min_suspicious_indicators must be at least 1")
        
        if self.time_window_minutes <= 0:
            raise ValueError("time_window_minutes must be positive")


@dataclass
class ScoringConfig:
    """Configuration for scoring and risk assessment."""
    # Risk thresholds (0-100 scale)
    risk_thresholds: Dict[str, int] = field(default_factory=lambda: {
        "LOW": 20,
        "MEDIUM": 49, 
        "HIGH": 74,
        "CRITICAL": 100
    })
    
    # Category weights
    category_weights: Dict[str, float] = field(default_factory=lambda: {
        "Permission Abuse": 1.2,
        "Persistence": 1.5,
        "Network Behavior": 1.4,
        "Stealth / Visibility": 1.6,
        "Crash or Kernel Abuse": 1.7,
        "System Privilege Abuse": 2.0,
        "Privacy Abuse": 1.3,
        # NEW: Enhanced security categories
        "Accessibility Abuse": 2.2,  # Very high weight for accessibility abuse
        "Persistent Surveillance": 2.0,  # High weight for surveillance
        "Policy Violation": 1.8,  # High weight for Play Store violations
        "Malicious Intent": 1.6,  # Medium-high weight for blocked operations
        "Security Risk": 1.7,  # High weight for old SDK + permissions
        "Suspicious Naming": 1.1  # Low weight for naming patterns alone
    })
    
    # Moderation factors
    breadth_factor_weight: float = 0.4
    confidence_factor_weight: float = 1.0
    coverage_penalty: float = 0.1
    
    def __post_init__(self):
        """Validate scoring configuration."""
        # Validate risk thresholds are in ascending order
        thresholds = [self.risk_thresholds[k] for k in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]]
        if thresholds != sorted(thresholds):
            raise ValueError("Risk thresholds must be in ascending order")
        
        # Validate weights are positive
        for category, weight in self.category_weights.items():
            if weight <= 0:
                raise ValueError(f"Category weight for {category} must be positive")


@dataclass 
class AnalysisConfig:
    """
    Main configuration for the analysis system.
    
    This centralizes all configuration instead of having magic numbers scattered throughout the code.
    """
    
    # Heuristic configurations
    heuristics: Dict[str, HeuristicConfig] = field(default_factory=dict)
    
    # Quality gates
    quality_gates: QualityGateConfig = field(default_factory=QualityGateConfig)
    
    # Scoring configuration  
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    
    # Analysis settings
    analysis_timeout_minutes: int = 15
    max_log_lines: int = 1000000
    enable_preprocessing: bool = True
    enable_correlation: bool = True
    
    # Output settings
    output_format: str = "json"  # json, yaml, html
    include_raw_logs: bool = False
    max_evidence_per_detection: int = 10

    # Collection settings (loaded from collection section)
    collection: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize default heuristic configurations if not provided."""
        if not self.heuristics:
            self._initialize_default_heuristics()
    
    def _initialize_default_heuristics(self):
        """Initialize default heuristic configurations."""
        default_heuristics = [
            'system_security', 'permission_analysis',
            'behavioral_analysis', 'resource_analysis', 'exploitation_crash',
            'memory_exploitation', 'crash_analysis', 'kernel_threats', 'system_anomalies'
        ]
        
        for heuristic_name in default_heuristics:
            self.heuristics[heuristic_name] = HeuristicConfig(
                name=heuristic_name,
                weight=self._get_default_weight(heuristic_name)
            )
    
    def _get_default_weight(self, heuristic_name: str) -> float:
        """Get default weight for a heuristic."""
        default_weights = {
            "system_security": 1.8,
            "permission_analysis": 1.5,
            "behavioral_analysis": 1.4,
            "resource_analysis": 1.3,
            "exploitation_crash": 1.3,
            "memory_exploitation": 1.1,
            "crash_analysis": 1.6,
            "kernel_threats": 1.7,
            "system_anomalies": 1.5
        }
        return default_weights.get(heuristic_name, 1.0)
    
    def get_enabled_heuristics(self) -> List[str]:
        """Get list of enabled heuristic names."""
        return [name for name, config in self.heuristics.items() if config.enabled]
    
    def get_heuristic_weight(self, heuristic_name: str) -> float:
        """Get weight for a specific heuristic."""
        config = self.heuristics.get(heuristic_name)
        return config.weight if config else 1.0
    
    @classmethod
    def from_file(cls, file_path: str) -> 'AnalysisConfig':
        """Load configuration from a file (JSON or YAML)."""
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            if path.suffix.lower() in ['.yml', '.yaml']:
                if not HAS_YAML:
                    raise ImportError("PyYAML is required for YAML configuration files. Install with: pip install pyyaml")
                data = yaml.safe_load(f)
            else:
                data = json.load(f)
        
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnalysisConfig':
        """Create configuration from dictionary."""
        # Parse heuristics
        heuristics = {}
        for name, config_data in data.get('heuristics', {}).items():
            heuristics[name] = HeuristicConfig(
                name=name,
                enabled=config_data.get('enabled', True),
                weight=config_data.get('weight', 1.0),
                confidence=config_data.get('confidence', 'medium'),
                timeout_seconds=config_data.get('timeout_seconds', 300),
                parameters=config_data.get('parameters', {})
            )
        
        # Parse quality gates
        quality_gates_data = data.get('quality_gates', {})
        quality_gates = QualityGateConfig(
            min_evidence_items=quality_gates_data.get('min_evidence_items', 1),
            require_log_evidence=quality_gates_data.get('require_log_evidence', True),
            min_suspicious_indicators=quality_gates_data.get('min_suspicious_indicators', 2),
            max_metadata_only_detections=quality_gates_data.get('max_metadata_only_detections', 10),
            time_window_minutes=quality_gates_data.get('time_window_minutes', 30)
        )
        
        # Parse scoring
        scoring_data = data.get('scoring', {})
        scoring = ScoringConfig(
            risk_thresholds=scoring_data.get('risk_thresholds', ScoringConfig().risk_thresholds),
            category_weights=scoring_data.get('category_weights', ScoringConfig().category_weights),
            breadth_factor_weight=scoring_data.get('breadth_factor_weight', 0.4),
            confidence_factor_weight=scoring_data.get('confidence_factor_weight', 1.0),
            coverage_penalty=scoring_data.get('coverage_penalty', 0.1)
        )
        
        return cls(
            heuristics=heuristics,
            quality_gates=quality_gates,
            scoring=scoring,
            analysis_timeout_minutes=data.get('analysis_timeout_minutes', 15),
            max_log_lines=data.get('max_log_lines', 1000000),
            enable_preprocessing=data.get('enable_preprocessing', True),
            enable_correlation=data.get('enable_correlation', True),
            output_format=data.get('output_format', 'json'),
            include_raw_logs=data.get('include_raw_logs', False),
            max_evidence_per_detection=data.get('max_evidence_per_detection', 10),
            collection=data.get('collection', {})
        )

    def create_collection_config(self) -> 'CollectionConfig':
        """
        Create a CollectionConfig from the collection settings.

        Returns:
            CollectionConfig instance with settings from config.yaml
        """
        from ward_core.infrastructure.collectors.base_collector import CollectionConfig

        collection_data = self.collection

        # Map config.yaml collection settings to CollectionConfig fields
        config_kwargs = {
            # Collection methods
            'collect_bugreport': collection_data.get('enable_bugreport', True),
            'collect_adb_commands': True,  # Always enabled for hybrid/adb collectors
            'collect_system_logs': True,   # Always enabled
            'supplement_with_adb': True,   # Always enabled

            # Timeouts and limits
            'adb_timeout_seconds': 300,
            'bugreport_timeout_seconds': collection_data.get('bugreport_timeout_seconds', 600),
            'max_logcat_lines': 100000,
            'max_file_size_mb': 500,

            # Output settings
            'preserve_temp_files': False,
            'compress_output': False,

            # Security and privacy
            'include_sensitive_data': True,
            'anonymize_data': False,

            # APK collection settings
            'collect_userland_apks': collection_data.get('collect_userland_apks', False),
            'collect_all_apks': collection_data.get('collect_all_apks', False),
        }

        return CollectionConfig(**config_kwargs)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'heuristics': {
                name: {
                    'enabled': config.enabled,
                    'weight': config.weight,
                    'confidence': config.confidence,
                    'timeout_seconds': config.timeout_seconds,
                    'parameters': config.parameters
                }
                for name, config in self.heuristics.items()
            },
            'quality_gates': {
                'min_evidence_items': self.quality_gates.min_evidence_items,
                'require_log_evidence': self.quality_gates.require_log_evidence,
                'min_suspicious_indicators': self.quality_gates.min_suspicious_indicators,
                'max_metadata_only_detections': self.quality_gates.max_metadata_only_detections,
                'time_window_minutes': self.quality_gates.time_window_minutes
            },
            'scoring': {
                'risk_thresholds': self.scoring.risk_thresholds,
                'category_weights': self.scoring.category_weights,
                'breadth_factor_weight': self.scoring.breadth_factor_weight,
                'confidence_factor_weight': self.scoring.confidence_factor_weight,
                'coverage_penalty': self.scoring.coverage_penalty
            },
            'analysis_timeout_minutes': self.analysis_timeout_minutes,
            'max_log_lines': self.max_log_lines,
            'enable_preprocessing': self.enable_preprocessing,
            'enable_correlation': self.enable_correlation,
            'output_format': self.output_format,
            'include_raw_logs': self.include_raw_logs,
            'max_evidence_per_detection': self.max_evidence_per_detection
        }
    
    def save_to_file(self, file_path: str):
        """Save configuration to a file."""
        path = Path(file_path)
        
        with open(path, 'w', encoding='utf-8') as f:
            if path.suffix.lower() in ['.yml', '.yaml']:
                if not HAS_YAML:
                    raise ImportError("PyYAML is required for YAML configuration files. Install with: pip install pyyaml")
                yaml.dump(self.to_dict(), f, default_flow_style=False, indent=2)
            else:
                json.dump(self.to_dict(), f, indent=2)

