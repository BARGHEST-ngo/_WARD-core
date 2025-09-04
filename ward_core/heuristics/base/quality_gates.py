"""
Quality gates for filtering and improving detection quality.

This module implements quality gates to reduce false positives and noise.
"""

from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import re

from ward_core.logic.models import Detection, Evidence, EvidenceType


class QualityGate(ABC):
    """Base class for quality gates."""
    
    @abstractmethod
    def filter(self, detections: List[Detection]) -> List[Detection]:
        """
        Filter detections based on quality criteria.
        
        Args:
            detections: List of detections to filter
            
        Returns:
            Filtered list of detections
        """
        pass


class EvidenceQualityGate(QualityGate):
    """
    Quality gate that filters detections based on evidence quality.
    
    This gate implements the requirement for real log evidence and prevents
    metadata-only detections from cluttering results.
    """
    
    def __init__(self, require_log_evidence: bool = True, min_evidence_items: int = 1):
        """
        Initialize the evidence quality gate.
        
        Args:
            require_log_evidence: Whether to require at least one log anchor
            min_evidence_items: Minimum number of evidence items required
        """
        self.require_log_evidence = require_log_evidence
        self.min_evidence_items = min_evidence_items
    
    def filter(self, detections: List[Detection]) -> List[Detection]:
        """Filter detections based on evidence quality."""
        filtered = []
        
        for detection in detections:
            if self._passes_quality_check(detection):
                filtered.append(detection)
            else:
                # Log why this detection was filtered
                reason = self._get_filter_reason(detection)
                print(f"EvidenceQualityGate filtered: {detection.title} - {reason}")
        
        return filtered
    
    def _passes_quality_check(self, detection: Detection) -> bool:
        """Check if a detection passes the quality gate."""
        # Check minimum evidence items
        if len(detection.evidence) < self.min_evidence_items:
            return False
        
        # Check for log evidence requirement
        if self.require_log_evidence:
            has_log_evidence = any(
                evidence.type == EvidenceType.LOG_ANCHOR 
                for evidence in detection.evidence
            )
            if not has_log_evidence:
                return False
        
        return True
    
    def _get_filter_reason(self, detection: Detection) -> str:
        """Get the reason why a detection was filtered."""
        if len(detection.evidence) < self.min_evidence_items:
            return f"Insufficient evidence items ({len(detection.evidence)} < {self.min_evidence_items})"
        
        if self.require_log_evidence:
            has_log_evidence = any(
                evidence.type == EvidenceType.LOG_ANCHOR 
                for evidence in detection.evidence
            )
            if not has_log_evidence:
                return "No log evidence found (require_log_evidence=True)"
        
        return "Unknown reason"


class TimeWindowGrouper:
    """
    Groups similar detections by time windows to reduce noise.
    
    This addresses the issue of repeated similar events cluttering the results.
    """
    
    def __init__(self, window_minutes: int = 30):
        """
        Initialize the time window grouper.
        
        Args:
            window_minutes: Size of time window for grouping in minutes
        """
        self.window_minutes = window_minutes
    
    def group_detections(self, detections: List[Detection]) -> List[Detection]:
        """
        Group similar detections by time windows.
        
        Args:
            detections: List of detections to group
            
        Returns:
            List of grouped detections (may be fewer than input)
        """
        if not detections:
            return []
        
        # Group detections by pattern
        pattern_groups = defaultdict(list)
        
        for detection in detections:
            pattern = self._extract_pattern(detection)
            pattern_groups[pattern].append(detection)
        
        grouped_detections = []
        
        for pattern, group_detections in pattern_groups.items():
            if len(group_detections) == 1:
                # Single detection - no grouping needed
                grouped_detections.extend(group_detections)
            else:
                # Multiple detections - group by time windows
                time_groups = self._group_by_time_windows(group_detections)
                grouped_detections.extend(time_groups)
        
        return grouped_detections
    
    def _extract_pattern(self, detection: Detection) -> str:
        """Extract a pattern from detection for grouping."""
        # Use category and evidence patterns to group similar detections
        category = detection.category.lower().replace(' ', '_')
        
        # Look for patterns in log evidence
        for evidence in detection.evidence:
            if evidence.type == EvidenceType.LOG_ANCHOR:
                log_line = evidence.content
                
                # Extract common patterns
                if 'storaged: getDiskStats failed' in log_line:
                    return f"{category}_storaged_disk_stats_failure"
                elif 'dumpstate: Failed to take screenshot' in log_line:
                    return f"{category}_dumpstate_screenshot_failure"
                elif 'ActivityManager: Scheduling restart' in log_line:
                    return f"{category}_activity_manager_restart"
                elif 'avc:' in log_line:
                    return f"{category}_selinux_avc_denial"
                elif 'crash' in log_line.lower():
                    return f"{category}_process_crash"
                else:
                    # Extract first few words as pattern
                    words = log_line.split()[:3]
                    pattern_suffix = '_'.join(w.lower() for w in words if w.isalnum())
                    return f"{category}_{pattern_suffix}"
        
        # Fallback to category and package
        package = detection.package or "unknown"
        return f"{category}_{package}"
    
    def _group_by_time_windows(self, detections: List[Detection]) -> List[Detection]:
        """Group detections within time windows."""
        # Sort detections by timestamp
        detections_with_time = []
        detections_without_time = []
        
        for detection in detections:
            timestamp = self._extract_timestamp(detection)
            if timestamp:
                detections_with_time.append((timestamp, detection))
            else:
                detections_without_time.append(detection)
        
        # Sort by timestamp
        detections_with_time.sort(key=lambda x: x[0])
        
        grouped = []
        
        if detections_with_time:
            # Group by time windows
            current_window_start = None
            current_window_detections = []
            
            for timestamp, detection in detections_with_time:
                if current_window_start is None:
                    current_window_start = timestamp
                    current_window_detections = [detection]
                else:
                    time_diff = (timestamp - current_window_start).total_seconds() / 60
                    if time_diff <= self.window_minutes:
                        # Add to current window
                        current_window_detections.append(detection)
                    else:
                        # Create grouped detection for current window
                        if len(current_window_detections) > 1:
                            grouped_detection = self._create_grouped_detection(current_window_detections)
                            grouped.append(grouped_detection)
                        else:
                            grouped.extend(current_window_detections)
                        
                        # Start new window
                        current_window_start = timestamp
                        current_window_detections = [detection]
            
            # Handle final window
            if current_window_detections:
                if len(current_window_detections) > 1:
                    grouped_detection = self._create_grouped_detection(current_window_detections)
                    grouped.append(grouped_detection)
                else:
                    grouped.extend(current_window_detections)
        
        # Add detections without timestamps
        grouped.extend(detections_without_time)
        
        return grouped
    
    def _extract_timestamp(self, detection: Detection) -> Optional[datetime]:
        """Extract timestamp from detection evidence."""
        # Check detection timestamp first
        if detection.timestamp:
            return detection.timestamp
        
        # Look for timestamps in evidence
        for evidence in detection.evidence:
            if evidence.timestamp:
                return evidence.timestamp
            
            # Try to parse timestamp from log content
            if evidence.type == EvidenceType.LOG_ANCHOR:
                timestamp = self._parse_log_timestamp(evidence.content)
                if timestamp:
                    return timestamp
        
        return None
    
    def _parse_log_timestamp(self, log_line: str) -> Optional[datetime]:
        """Parse timestamp from log line."""
        # Android log format: MM-dd HH:mm:ss.SSS
        timestamp_match = re.search(r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})', log_line)
        if timestamp_match:
            try:
                timestamp_str = timestamp_match.group(1)
                # Assume current year
                current_year = datetime.now().year
                full_timestamp = f"{current_year}-{timestamp_str}"
                return datetime.strptime(full_timestamp, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                pass
        
        return None
    
    def _create_grouped_detection(self, detections: List[Detection]) -> Detection:
        """Create a single detection representing a group of similar detections."""
        if not detections:
            raise ValueError("Cannot create grouped detection from empty list")
        
        # Use the first detection as the base
        base_detection = detections[0]
        count = len(detections)
        
        # Calculate time window
        timestamps = [self._extract_timestamp(d) for d in detections]
        valid_timestamps = [t for t in timestamps if t is not None]
        
        if valid_timestamps:
            window_start = min(valid_timestamps)
            window_end = max(valid_timestamps)
            time_range = f"{window_start.strftime('%H:%M:%S')}-{window_end.strftime('%H:%M:%S')}"
            title = f"{count} similar events ({time_range})"
        else:
            window_start = window_end = None
            title = f"{count} similar events"
        
        # Create grouped detection
        grouped_detection = Detection(
            category=base_detection.category,
            subcategory=base_detection.subcategory,
            package=base_detection.package,
            severity=base_detection.severity,
            confidence=min(1.0, base_detection.confidence + 0.1 * (count - 1)),  # Increase confidence with more occurrences
            title=title,
            description=f"Grouped detection of {count} similar events: {base_detection.description}",
            technical_details={
                'grouped_count': count,
                'original_detections': [d.id for d in detections],
                'time_window_minutes': self.window_minutes
            },
            timestamp=base_detection.timestamp,
            window_start=window_start,
            window_end=window_end
        )
        
        # Combine evidence from all detections
        all_evidence = []
        
        # Add pattern information
        pattern = self._extract_pattern(base_detection)
        all_evidence.append(Evidence(
            type=EvidenceType.DERIVED,
            content=f"Pattern: {pattern}",
            confidence=0.9
        ))
        
        # Add count information
        all_evidence.append(Evidence(
            type=EvidenceType.DERIVED,
            content=f"Event Count: {count}",
            confidence=1.0
        ))
        
        # Add time window if available
        if window_start and window_end:
            all_evidence.append(Evidence(
                type=EvidenceType.DERIVED,
                content=f"Time Window: {time_range}",
                confidence=0.8
            ))
        
        # Add sample evidence from original detections (limit to avoid clutter)
        sample_count = min(3, count)
        for i, detection in enumerate(detections[:sample_count]):
            for evidence in detection.evidence:
                if evidence.type == EvidenceType.LOG_ANCHOR:
                    all_evidence.append(evidence)
                    break  # Only one log line per detection
        
        grouped_detection.evidence = all_evidence
        
        return grouped_detection


class SuspiciousIndicatorGate(QualityGate):
    """
    Quality gate that requires multiple suspicious indicators for a detection.
    
    This prevents single weak indicators from creating detections.
    """
    
    def __init__(self, min_suspicious_indicators: int = 2):
        """
        Initialize the suspicious indicator gate.
        
        Args:
            min_suspicious_indicators: Minimum number of suspicious indicators required
        """
        self.min_suspicious_indicators = min_suspicious_indicators
    
    def filter(self, detections: List[Detection]) -> List[Detection]:
        """Filter detections based on suspicious indicator count."""
        filtered = []
        
        for detection in detections:
            indicator_count = self._count_suspicious_indicators(detection)
            if indicator_count >= self.min_suspicious_indicators:
                filtered.append(detection)
            else:
                # Log why this detection was filtered
                print(f"SuspiciousIndicatorGate filtered: {detection.title} - Insufficient indicators ({indicator_count} < {self.min_suspicious_indicators})")
        
        return filtered
    
    def _count_suspicious_indicators(self, detection: Detection) -> int:
        """Count suspicious indicators in a detection."""
        indicators = 0
        
        # Count evidence items as indicators (weighted by type)
        for evidence in detection.evidence:
            if evidence.type == EvidenceType.LOG_ANCHOR:
                indicators += 2  # Log evidence is strong
            elif evidence.type == EvidenceType.CORRELATED:
                indicators += 2  # Correlated evidence is strong
            elif evidence.type == EvidenceType.METADATA_ONLY:
                indicators += 1  # Metadata is weak
            else:
                indicators += 1  # Other types
        
        # Count meaningful technical details as indicators (not just metadata fields)
        if detection.technical_details:
            meaningful_details = 0
            for key, value in detection.technical_details.items():
                # Only count actual suspicious indicators, not metadata fields
                if key in ['data_collection_score', 'suspicious_indicators', 'risk_score', 'threat_level']:
                    if isinstance(value, (int, float)) and value > 0:
                        meaningful_details += value
                    elif isinstance(value, bool) and value:
                        meaningful_details += 1
                elif key in ['data_operations', 'permissions', 'suspicious_activities']:
                    if isinstance(value, list) and len(value) > 0:
                        meaningful_details += min(len(value), 3)  # Cap at 3
                elif key not in ['heuristic_name', 'package_name', 'abuse_type']:  # Skip metadata fields
                    if value:
                        meaningful_details += 1
            
            indicators += meaningful_details
        
        return indicators
