"""
Domain models for BARGHEST WARD analysis system.

This module contains all the core data structures used throughout the system.
These models represent the business domain and are independent of any external concerns.
"""

from .detection import Detection, Evidence, EvidenceType, Severity
from .analysis_result import AnalysisResult, RiskLevel, HeuristicResult
from .log_data import LogData, PackageInfo, DeviceInfo
from .configuration import AnalysisConfig, HeuristicConfig, ScoringConfig

__all__ = [
    'Detection',
    'Evidence', 
    'EvidenceType',
    'Severity',
    'AnalysisResult',
    'RiskLevel',
    'HeuristicResult',
    'LogData',
    'PackageInfo',
    'DeviceInfo',
    'AnalysisConfig',
    'HeuristicConfig',
    'ScoringConfig'
]

