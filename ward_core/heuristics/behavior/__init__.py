"""
Behavioral analysis heuristics for BARGHEST WARD.

This module contains heuristics that analyze Android app behavioral patterns
to detect suspicious activities like background service abuse, wakelock abuse,
and device fingerprinting.
"""

from .behavioral_analysis import BehavioralAnalysisHeuristic

__all__ = ['BehavioralAnalysisHeuristic']



