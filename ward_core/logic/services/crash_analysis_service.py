"""
Crash Analysis Service - Centralized crash detection and analysis.

Consolidates crash detection patterns from exploitation_crash.py and memory_exploitation.py
to eliminate redundancy and provide consistent crash analysis across the system.

This service replaces duplicate logic found in:
- exploitation_crash.py (native crash detection, episode clustering)
- memory_exploitation.py (memory episode detection, crash correlation)
- services/crash_analysis.py (duplicate service implementation)
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional, Set
from enum import Enum
import logging

from ward_core.logic.models import LogData, Detection, Evidence, EvidenceType, Severity
from .episode_service import EpisodeService, Episode, EpisodeItem


class CrashType(Enum):
    """Types of crashes that can be detected."""
    NATIVE_CRASH = "native_crash"
    JAVA_CRASH = "java_crash"
    KERNEL_CRASH = "kernel_crash"
    GPU_CRASH = "gpu_crash"
    SYSTEM_CRASH = "system_crash"
    ANR = "anr"
    TOMBSTONE = "tombstone"
    DROPBOX = "dropbox"


@dataclass
class CrashEvent(EpisodeItem):
    """Represents a single crash event."""
    crash_type: CrashType
    process_name: str
    package_name: str
    raw_line: str
    confidence: float
    exploitation_indicators: List[str]
    cve_indicators: List[str]
    timestamp: Optional[datetime] = None
    pid: Optional[str] = None
    signal: Optional[str] = None
    signal_name: Optional[str] = None
    fault_address: Optional[str] = None
    
    @property
    def identifier(self) -> str:
        """Get identifier for grouping similar crashes."""
        return f"{self.crash_type.value}_{self.process_name}_{self.signal or 'unknown'}"
    
    def is_similar_to(self, other: 'CrashEvent') -> bool:
        """Check if this crash is similar to another for merging."""
        return (self.crash_type == other.crash_type and
                self.process_name == other.process_name and
                self.signal == other.signal)


class CrashAnalysisService:
    """
    Centralized service for crash detection and analysis.
    
    This service consolidates crash detection patterns that were previously
    duplicated across multiple heuristics.
    """
    
    # Common crash patterns used across heuristics
    CRASH_PATTERNS = {
        'native_crash': [
            re.compile(r'Fatal signal (\d+) \(([^)]+)\).*pid (\d+) \(([^)]+)\)', re.IGNORECASE),
            re.compile(r'signal (\d+) \(([^)]+)\).*fault addr (0x[0-9a-f]+)', re.IGNORECASE),
            re.compile(r'SIGSEGV.*fault addr (0x[0-9a-f]+)', re.IGNORECASE),
        ],
        'java_crash': [
            re.compile(r'FATAL EXCEPTION.*([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)', re.IGNORECASE),
            re.compile(r'AndroidRuntime.*FATAL EXCEPTION', re.IGNORECASE),
        ],
        'kernel_crash': [
            re.compile(r'kernel BUG at', re.IGNORECASE),
            re.compile(r'Oops:', re.IGNORECASE),
            re.compile(r'Call Trace:', re.IGNORECASE),
        ],
        'anr': [
            re.compile(r'ANR in ([^(]+)\(([^)]+)\)', re.IGNORECASE),
            re.compile(r'Application Not Responding', re.IGNORECASE),
        ],
        'tombstone': [
            re.compile(r'tombstone_(\d+)', re.IGNORECASE),
            re.compile(r'/data/tombstones/', re.IGNORECASE),
        ],
        'dropbox': [
            re.compile(r'dropbox_file_copy.*tombstone', re.IGNORECASE),
            re.compile(r'SYSTEM_TOMBSTONE', re.IGNORECASE),
        ]
    }
    
    # Signal mappings for exploitation analysis
    SIGNAL_MAPPINGS = {
        '4': ('SIGILL', 'Illegal instruction (potential code injection)'),
        '6': ('SIGABRT', 'Abort signal (assertion failure or explicit abort)'),
        '8': ('SIGFPE', 'Floating point exception (division by zero)'),
        '9': ('SIGKILL', 'Kill signal (forced termination)'),
        '11': ('SIGSEGV', 'Segmentation fault (potential buffer overflow)'),
        '13': ('SIGPIPE', 'Broken pipe (network/IPC issue)'),
        '15': ('SIGTERM', 'Termination signal (graceful shutdown)'),
    }
    
    def __init__(self, episode_service: Optional[EpisodeService] = None):
        """Initialize the crash analysis service."""
        self.episode_service = episode_service or EpisodeService()
        self.logger = logging.getLogger("crash.analysis")
    
    def detect_crashes(self, log_data: LogData) -> List[CrashEvent]:
        """
        Detect all types of crashes in log data.
        
        Args:
            log_data: The log data to analyze
            
        Returns:
            List of detected crash events
        """
        crashes = []
        
        for line_num, line in enumerate(log_data.raw_lines):
            # Try each crash pattern type
            for crash_type_name, patterns in self.CRASH_PATTERNS.items():
                for pattern in patterns:
                    match = pattern.search(line)
                    if match:
                        crash = self._create_crash_event(
                            line, line_num, crash_type_name, match
                        )
                        if crash:
                            crashes.append(crash)
                        break  # Only match first pattern per line
        
        return crashes
    
    def create_crash_episodes(self, crashes: List[CrashEvent], 
                            window_seconds: int = 60) -> List[Episode[CrashEvent]]:
        """
        Create crash episodes from individual crash events.
        
        Args:
            crashes: List of crash events
            window_seconds: Time window for episode clustering
            
        Returns:
            List of crash episodes
        """
        if not crashes:
            return []
        
        # Use the episode service for consistent clustering
        episodes = self.episode_service.cluster_by_time(
            crashes,
            get_timestamp=lambda c: c.timestamp,
            get_identifier=lambda c: c.identifier,
            episode_type="crash_episode"
        )
        
        # Enhance episodes with crash-specific analysis
        enhanced_episodes = []
        for episode in episodes:
            enhanced_episode = self._enhance_crash_episode(episode)
            enhanced_episodes.append(enhanced_episode)
        
        return enhanced_episodes
    
    def analyze_exploitation_likelihood(self, crash: CrashEvent) -> float:
        """
        Analyze the likelihood that a crash indicates exploitation.
        
        Args:
            crash: The crash event to analyze
            
        Returns:
            Exploitation likelihood score (0.0 to 1.0)
        """
        score = 0.0
        
        # Signal-based scoring
        if crash.signal in ['11', '4', '6']:  # SIGSEGV, SIGILL, SIGABRT
            score += 0.3
        
        # Process-based scoring
        system_processes = ['system_server', 'zygote', 'surfaceflinger', 'mediaserver']
        if any(proc in crash.process_name.lower() for proc in system_processes):
            score += 0.2
        
        # CVE indicators
        if crash.cve_indicators:
            score += 0.3
        
        # Exploitation indicators
        if crash.exploitation_indicators:
            score += 0.2 * len(crash.exploitation_indicators)
        
        # Fault address analysis (null pointer vs heap corruption)
        if crash.fault_address:
            if crash.fault_address in ['0x0', '0x00000000']:
                score += 0.1  # Null pointer dereference
            elif not crash.fault_address.startswith('0x0'):
                score += 0.2  # Potential heap corruption
        
        return min(score, 1.0)
    
    def consolidate_similar_crashes(self, crashes: List[CrashEvent]) -> List[CrashEvent]:
        """
        Consolidate similar crashes to reduce noise.
        
        Args:
            crashes: List of crash events
            
        Returns:
            List of consolidated crash events
        """
        return self.episode_service.deduplicate_items(
            crashes,
            get_key=lambda c: c.identifier,
            merge_func=self._merge_crash_events
        )
    
    def _create_crash_event(self, line: str, line_num: int, 
                          crash_type_name: str, match: re.Match) -> Optional[CrashEvent]:
        """Create a crash event from a matched line."""
        try:
            crash_type = CrashType(crash_type_name)
            
            # Extract common fields
            process_name = "unknown"
            package_name = "unknown"
            pid = None
            signal = None
            signal_name = None
            fault_address = None
            
            # Extract fields based on crash type and match groups
            if crash_type == CrashType.NATIVE_CRASH:
                if len(match.groups()) >= 4:
                    signal = match.group(1)
                    signal_name = match.group(2)
                    pid = match.group(3)
                    process_name = match.group(4)
                elif len(match.groups()) >= 3:
                    signal = match.group(1)
                    signal_name = match.group(2)
                    fault_address = match.group(3)
            
            elif crash_type == CrashType.JAVA_CRASH:
                if len(match.groups()) >= 1:
                    package_name = match.group(1)
            
            elif crash_type == CrashType.ANR:
                if len(match.groups()) >= 2:
                    process_name = match.group(1)
                    package_name = match.group(2)
            
            # Extract package name from process name if not found
            if package_name == "unknown" and process_name != "unknown":
                # Try to extract package name from process name
                if '.' in process_name and not process_name.startswith('/'):
                    package_name = process_name
            
            # Analyze exploitation indicators
            exploitation_indicators = self._analyze_exploitation_indicators(line)
            cve_indicators = self._analyze_cve_indicators(line)
            
            # Calculate confidence
            confidence = 0.8 if signal and process_name != "unknown" else 0.6
            
            return CrashEvent(
                timestamp=self._extract_timestamp(line),
                crash_type=crash_type,
                process_name=process_name,
                package_name=package_name,
                pid=pid,
                signal=signal,
                signal_name=signal_name,
                fault_address=fault_address,
                raw_line=line.strip(),
                confidence=confidence,
                exploitation_indicators=exploitation_indicators,
                cve_indicators=cve_indicators
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to create crash event from line {line_num}: {e}")
            return None
    
    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        """Extract timestamp from log line."""
        # Look for common Android log timestamp formats
        timestamp_patterns = [
            r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})',  # MM-dd HH:mm:ss.SSS
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',   # yyyy-MM-dd HH:mm:ss
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    timestamp_str = match.group(1)
                    # Try to parse timestamp (simplified)
                    return datetime.now()  # Placeholder - would need proper parsing
                except:
                    continue
        
        return None
    
    def _analyze_exploitation_indicators(self, line: str) -> List[str]:
        """Analyze line for exploitation indicators."""
        indicators = []
        line_lower = line.lower()
        
        # Common exploitation patterns
        if 'heap' in line_lower and ('corrupt' in line_lower or 'overflow' in line_lower):
            indicators.append('heap_corruption')
        
        if 'stack' in line_lower and 'overflow' in line_lower:
            indicators.append('stack_overflow')
        
        if 'use after free' in line_lower or 'uaf' in line_lower:
            indicators.append('use_after_free')
        
        if 'double free' in line_lower:
            indicators.append('double_free')
        
        return indicators
    
    def _analyze_cve_indicators(self, line: str) -> List[str]:
        """Analyze line for CVE indicators."""
        indicators = []
        line_lower = line.lower()
        
        # Look for CVE-related patterns (simplified)
        if 'binder' in line_lower and ('uaf' in line_lower or 'use after free' in line_lower):
            indicators.append('CVE-2019-2215')
        
        if 'mali' in line_lower and 'gpu' in line_lower:
            indicators.append('Mali_GPU_CVE')
        
        return indicators
    
    def _enhance_crash_episode(self, episode: Episode[CrashEvent]) -> Episode[CrashEvent]:
        """Enhance crash episode with additional analysis."""
        # Calculate exploitation score for the episode
        exploitation_scores = [
            self.analyze_exploitation_likelihood(crash) for crash in episode.items
        ]
        avg_exploitation_score = sum(exploitation_scores) / len(exploitation_scores)
        
        # Update episode metadata
        episode.metadata.update({
            'exploitation_score': avg_exploitation_score,
            'crash_types': list(set(c.crash_type.value for c in episode.items)),
            'affected_processes': list(set(c.process_name for c in episode.items)),
            'signals': list(set(c.signal for c in episode.items if c.signal))
        })
        
        return episode
    
    def _merge_crash_events(self, crash1: CrashEvent, crash2: CrashEvent) -> CrashEvent:
        """Merge two similar crash events."""
        # Use the crash with higher confidence as base
        base_crash = crash1 if crash1.confidence >= crash2.confidence else crash2
        other_crash = crash2 if base_crash == crash1 else crash1
        
        # Merge indicators
        merged_exploitation = list(set(base_crash.exploitation_indicators + other_crash.exploitation_indicators))
        merged_cve = list(set(base_crash.cve_indicators + other_crash.cve_indicators))
        
        # Create merged crash
        return CrashEvent(
            timestamp=base_crash.timestamp or other_crash.timestamp,
            crash_type=base_crash.crash_type,
            process_name=base_crash.process_name,
            package_name=base_crash.package_name,
            pid=base_crash.pid or other_crash.pid,
            signal=base_crash.signal or other_crash.signal,
            signal_name=base_crash.signal_name or other_crash.signal_name,
            fault_address=base_crash.fault_address or other_crash.fault_address,
            raw_line=base_crash.raw_line,
            confidence=max(base_crash.confidence, other_crash.confidence),
            exploitation_indicators=merged_exploitation,
            cve_indicators=merged_cve
        )
