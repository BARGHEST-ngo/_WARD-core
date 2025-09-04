"""
Heuristic registry and configuration.

This module provides the central registry for all heuristic implementations.
"""

from .system.system_security import SystemSecurityHeuristic
from .anomalies.system_anomalies import SystemAnomaliesHeuristic
from .anomalies.process_anomaly import ProcessAnomalyHeuristic
from .user.user_analysis import UserAnalysisHeuristic
from .permissions.permission_analysis import PermissionAnalysisHeuristic

from .behavior.behavioral_analysis import BehavioralAnalysisHeuristic
from .crashes.exploitation_crash import ExploitationCrashHeuristic
from .memory.memory_exploitation import MemoryExploitationHeuristic
from .memory.dex_analysis import DexAnalysisHeuristic


# Registry of all available heuristics
HEURISTICS = [
    SystemSecurityHeuristic,
    SystemAnomaliesHeuristic,
    ProcessAnomalyHeuristic,
    UserAnalysisHeuristic,
    PermissionAnalysisHeuristic,

    BehavioralAnalysisHeuristic,
    ExploitationCrashHeuristic,
    MemoryExploitationHeuristic,
    DexAnalysisHeuristic,

]

# Heuristic categories for organization
HEURISTIC_CATEGORIES = {
    "System Security": [
        SystemSecurityHeuristic,
        SystemAnomaliesHeuristic,
        ProcessAnomalyHeuristic,
        UserAnalysisHeuristic,
    ],
    "Memory Analysis": [
        MemoryExploitationHeuristic,
        DexAnalysisHeuristic,
    ],

    "Behavioral Analysis": [
        BehavioralAnalysisHeuristic,
    ],
    "Permission Analysis": [
        PermissionAnalysisHeuristic,
    ],
    "Crash Analysis": [
        ExploitationCrashHeuristic,
    ],

}

def get_heuristic_by_name(name: str):
    """Get a heuristic class by name."""
    for heuristic in HEURISTICS:
        if heuristic().name == name:
            return heuristic
    return None

def get_heuristics_by_category(category: str):
    """Get all heuristics in a specific category."""
    return HEURISTIC_CATEGORIES.get(category, [])

def get_all_heuristic_names():
    """Get all available heuristic names."""
    return [h().name for h in HEURISTICS]
