"""
DEX Analysis Heuristic - In-Memory DEX Loading Detection

Detects secondary DEX loading, code cache anomalies, and in-memory DEX execution
that may indicate fileless code execution or dynamic code loading.

Focuses on realistic ADB log patterns from:
- dex2oat and dexopt compilation logs
- code_cache directory analysis
- secondary DEX loading patterns
"""

import re
from typing import List, Dict, Any, Set
from collections import defaultdict

from ward_core.heuristics.base import BaseHeuristic
from ward_core.logic.models import Detection, Evidence, EvidenceType, Severity, LogData


class DexAnalysisHeuristic(BaseHeuristic):
    """Detects in-memory DEX loading and code cache anomalies."""
    
    # Enhanced DEX compilation patterns from realistic logcat output
    DEX_PATTERNS = {
        # Realistic dex2oat patterns from actual logcat
        'dex2oat_start': re.compile(r'dex2oat.*took\s+(\d+)ms', re.IGNORECASE),
        'dex2oat_compilation': re.compile(r'dex2oat.*--dex-file=([^\s]+)', re.IGNORECASE),
        'dex2oat_classpath': re.compile(r'dex2oat.*--classpath-dir\s+([^\s]+)', re.IGNORECASE),
        'dex2oat_failed': re.compile(r'dex2oat.*failed', re.IGNORECASE),

        # Real package manager dexopt patterns
        'pm_dexopt': re.compile(r'Running dexopt for ([^\s]+)', re.IGNORECASE),
        'pm_compile': re.compile(r'PackageManager.*compile.*([^\s]+)', re.IGNORECASE),
        'dexopt_trigger': re.compile(r'DexOptTrigger.*([^\s]+)', re.IGNORECASE),
        'compilation_filter': re.compile(r'compilation-filter=([^\s]+)', re.IGNORECASE),
        'compilation_reason': re.compile(r'compilation-reason=([^\s]+)', re.IGNORECASE),

        # Real process and app loading patterns
        'app_process_start': re.compile(r'ActivityManager.*Start proc.*([^\s]+)', re.IGNORECASE),
        'zygote_fork': re.compile(r'Zygote.*fork.*([^\s]+)', re.IGNORECASE),
        'app_died': re.compile(r'ActivityManager.*Process.*([^\s]+).*died', re.IGNORECASE),

        # Real DEX loading and optimization patterns
        'dexopt_analyzer': re.compile(r'DexOptAnalyzer.*package.*([^\s]+)', re.IGNORECASE),
        'oat_file_assistant': re.compile(r'OatFileAssistant.*([^\s]+)', re.IGNORECASE),
        'class_linker': re.compile(r'ClassLinker.*([^\s]+\.dex)', re.IGNORECASE),

        # Real secondary DEX patterns (from actual logs)
        'secondary_dex_loading': re.compile(r'Loading.*secondary.*dex.*([^\s]+)', re.IGNORECASE),
        'code_cache_compilation': re.compile(r'code_cache.*([^\s]+)', re.IGNORECASE),

        # Real suspicious activity patterns
        'shell_dex_activity': re.compile(r'shell.*dex.*([^\s]+)', re.IGNORECASE),
        'tmp_dex_files': re.compile(r'/tmp/.*\.dex', re.IGNORECASE),
        'external_dex_files': re.compile(r'/sdcard/.*\.dex', re.IGNORECASE),

        # Actor/UID extraction patterns (realistic)
        'uid_extraction': re.compile(r'uid=(\d+)', re.IGNORECASE),
        'package_extraction': re.compile(r'package[=:\s]([^\s]+)', re.IGNORECASE),
        'pid_extraction': re.compile(r'pid=(\d+)', re.IGNORECASE),
    }
    
    # Actually suspicious compilation reasons (not routine ones)
    SUSPICIOUS_COMPILATION_REASONS = {
        'cmdline',      # Manual/shell-invoked (high suspicion)
        'error',        # Error-triggered recompilation
        'force-dexopt', # Forced optimization
        'shared'        # Unexpected shared compilation
    }
    
    # Actually suspicious classpath directories (excluding legitimate system paths)
    SUSPICIOUS_CLASSPATH_DIRS = [
        r'/data/local/tmp/',     # Shell/debug access
        r'/sdcard/',             # External storage
        r'/storage/',            # External storage
        r'/tmp/',                # Temporary files
        r'/cache/',              # Cache directories
        r'/data/priv-downloads/', # Private downloads
    ]

    # Legitimate system paths (should NOT be flagged)
    LEGITIMATE_SYSTEM_PATHS = [
        r'/system/app/',
        r'/system/priv-app/',
        r'/product/app/',
        r'/vendor/app/',
        r'/apex/',               # APEX modules
        r'/data/app/',           # Normal app installations
    ]
    
    def __init__(self, config=None):
        super().__init__(config)
        self.min_suspicious_indicators = 2  # Require multiple signals to reduce FPs
    
    @property
    def name(self) -> str:
        return "dex_analysis"
    
    @property
    def category(self) -> str:
        return "Memory Analysis"
    
    @property
    def description(self) -> str:
        return "Detects in-memory DEX loading and code cache anomalies"
    
    def analyze(self, log_data: LogData) -> List[Detection]:
        """Analyze log data for DEX anomalies with multi-signal gating."""
        detections = []

        # Collect all suspicious indicators first
        suspicious_indicators = self._collect_suspicious_indicators(log_data)

        # Apply multi-signal gating - require multiple indicators
        high_confidence_indicators = self._apply_multi_signal_gating(suspicious_indicators)

        # Create detections for high-confidence cases
        for indicator_group in high_confidence_indicators:
            detection = self._create_dex_detection(indicator_group)
            if detection:
                detections.append(detection)

        return detections

    def _collect_suspicious_indicators(self, log_data: LogData) -> List[Dict]:
        """Collect all suspicious DEX indicators from log data."""
        indicators = []

        for line in log_data.raw_lines:
            line_indicators = self._analyze_line_for_indicators(line)
            if line_indicators:
                indicators.extend(line_indicators)

        return indicators

    def _analyze_line_for_indicators(self, line: str) -> List[Dict]:
        """Analyze a single line for suspicious DEX indicators."""
        indicators = []

        # Check for suspicious shell DEX activity (CRITICAL)
        if self.DEX_PATTERNS['shell_dex_activity'].search(line):
            indicators.append({
                'type': 'shell_dex_activity',
                'severity': 'CRITICAL',
                'line': line.strip(),
                'confidence': 0.9
            })

        # Check for DEX files in suspicious locations (HIGH)
        if self.DEX_PATTERNS['tmp_dex_files'].search(line) or \
           self.DEX_PATTERNS['external_dex_files'].search(line):
            indicators.append({
                'type': 'suspicious_dex_location',
                'severity': 'HIGH',
                'line': line.strip(),
                'confidence': 0.8
            })

        # Check for suspicious paths in realistic patterns
        for pattern_name in ['dex2oat_compilation', 'secondary_dex_loading', 'code_cache_compilation']:
            if pattern_name in self.DEX_PATTERNS:
                match = self.DEX_PATTERNS[pattern_name].search(line)
                if match:
                    path = match.group(1)
                    if self._is_suspicious_path(path):
                        indicators.append({
                            'type': 'suspicious_path',
                            'severity': 'HIGH',
                            'path': path,
                            'line': line.strip(),
                            'confidence': 0.8
                        })

        # Check for suspicious compilation reasons
        reason_match = self.DEX_PATTERNS['compilation_reason'].search(line)
        if reason_match:
            reason = reason_match.group(1)
            if reason in self.SUSPICIOUS_COMPILATION_REASONS:
                severity = 'HIGH' if reason == 'cmdline' else 'MEDIUM'
                indicators.append({
                    'type': 'suspicious_reason',
                    'severity': severity,
                    'reason': reason,
                    'line': line.strip(),
                    'confidence': 0.7 if reason == 'cmdline' else 0.5
                })

        # Extract package and UID context
        package_match = self.DEX_PATTERNS['package_extraction'].search(line)
        uid_match = self.DEX_PATTERNS['uid_extraction'].search(line)

        # Add context to all indicators
        for indicator in indicators:
            if package_match:
                indicator['package'] = package_match.group(1)
            if uid_match:
                indicator['uid'] = uid_match.group(1)
            indicator['actor'] = self._extract_actor(line)

        return indicators

    def _apply_multi_signal_gating(self, indicators: List[Dict]) -> List[List[Dict]]:
        """Apply multi-signal gating to reduce false positives."""
        high_confidence_groups = []

        # Group indicators by context (package, UID, time window)
        grouped_indicators = self._group_indicators_by_context(indicators)

        for group in grouped_indicators:
            # Check for high-confidence patterns
            if self._is_high_confidence_group(group):
                high_confidence_groups.append(group)

        return high_confidence_groups

    def _is_high_confidence_group(self, indicators: List[Dict]) -> bool:
        """Check if a group of indicators represents high-confidence threat."""
        # CRITICAL: In-memory loader + external path
        has_in_memory = any(ind['type'] in ['in_memory_dex_loader', 'dex_file_in_memory']
                           for ind in indicators)
        has_external_path = any(ind.get('type') == 'suspicious_path' and
                               self._is_suspicious_path(ind.get('path', ''))
                               for ind in indicators)

        if has_in_memory and has_external_path:
            return True

        # HIGH: cmdline dex2oat by adbd/shell touching external path
        has_cmdline = any(ind.get('reason') == 'cmdline' for ind in indicators)
        has_shell_actor = any(ind.get('actor') in ['adbd', 'shell'] for ind in indicators)

        if has_cmdline and has_shell_actor and has_external_path:
            return True

        # MEDIUM: Multiple suspicious indicators (≥2)
        suspicious_count = len([ind for ind in indicators
                               if ind.get('severity') in ['HIGH', 'CRITICAL']])

        return suspicious_count >= self.min_suspicious_indicators

    def _analyze_dex_compilation(self, log_data: LogData) -> List[Detection]:
        """Analyze DEX compilation logs for suspicious patterns."""
        detections = []
        
        for entry in log_data.get_entries_by_source('shell_logcat_main.txt'):
            line = entry.raw_line
            
            # Check for suspicious classpath directories
            classpath_match = self.DEX_PATTERNS['dex2oat_compilation'].search(line)
            if classpath_match:
                classpath_dir = classpath_match.group(1)
                
                if self._is_suspicious_path(classpath_dir):
                    evidence = [
                        Evidence(
                            type=EvidenceType.LOG_ANCHOR,
                            content=f"Suspicious DEX compilation classpath: {line.strip()}",
                            confidence=0.8
                        )
                    ]
                    
                    detections.append(Detection(
                        title="Suspicious DEX Compilation",
                        description=f"DEX compilation from suspicious directory: {classpath_dir}",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        package_name="system",
                        heuristic_name=self.name
                    ))
            
            # Check for suspicious compilation reasons
            reason_match = self.DEX_PATTERNS['compilation_reason'].search(line)
            if reason_match:
                reason = reason_match.group(1)
                
                if reason in self.SUSPICIOUS_COMPILATION_REASONS:
                    evidence = [
                        Evidence(
                            type=EvidenceType.LOG_ANCHOR,
                            content=f"Suspicious DEX compilation reason: {line.strip()}",
                            confidence=0.7
                        )
                    ]
                    
                    detections.append(Detection(
                        title="Suspicious DEX Compilation Reason",
                        description=f"DEX compilation with suspicious reason: {reason}",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        package_name="system",
                        heuristic_name=self.name
                    ))
        
        return detections
    
    def _detect_secondary_dex_loading(self, log_data: LogData) -> List[Detection]:
        """Detect secondary DEX loading outside normal locations."""
        detections = []
        
        for entry in log_data.get_entries_by_source('shell_logcat_main.txt'):
            line = entry.raw_line
            
            # Check for secondary DEX loading
            secondary_match = self.DEX_PATTERNS['secondary_dex_loading'].search(line)
            if secondary_match:
                dex_path = secondary_match.group(1)
                
                if self._is_suspicious_path(dex_path):
                    evidence = [
                        Evidence(
                            type=EvidenceType.LOG_ANCHOR,
                            content=f"Suspicious secondary DEX loading: {line.strip()}",
                            confidence=0.8
                        )
                    ]
                    
                    detections.append(Detection(
                        title="Suspicious Secondary DEX Loading",
                        description=f"Secondary DEX loading from suspicious path: {dex_path}",
                        severity=Severity.HIGH,
                        evidence=evidence,
                        package_name="system",
                        heuristic_name=self.name
                    ))
        
        return detections
    
    def _analyze_code_cache_anomalies(self, log_data: LogData) -> List[Detection]:
        """Analyze code cache for suspicious modifications."""
        detections = []
        
        for entry in log_data.get_entries_by_source('shell_logcat_main.txt'):
            line = entry.raw_line
            
            # Check for code cache compilation
            cache_match = self.DEX_PATTERNS['code_cache_compilation'].search(line)
            if cache_match:
                cache_path = cache_match.group(1)
                
                if self._is_suspicious_path(cache_path):
                    evidence = [
                        Evidence(
                            type=EvidenceType.LOG_ANCHOR,
                            content=f"Suspicious code cache activity: {line.strip()}",
                            confidence=0.7
                        )
                    ]
                    
                    detections.append(Detection(
                        title="Suspicious Code Cache Activity",
                        description=f"Code cache compilation from suspicious path: {cache_path}",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        package_name="system",
                        heuristic_name=self.name
                    ))
        
        return detections

    def check_in_memory_dex_indicators(self, pid: str, log_data: LogData) -> List[str]:
        """Check for in-memory DEX loading indicators via log analysis.

        This method was moved from process_anomaly.py as it's DEX analysis functionality.
        """
        indicators = []

        # Look for DEX-related log entries
        for entry in log_data.raw_lines:
            if f'pid {pid}' in entry or f'({pid})' in entry:
                line_lower = entry.lower()

                # Check for in-memory DEX patterns
                if any(pattern in line_lower for pattern in [
                    'dexclassloader', 'inmemoryDexclassloader', 'memfd:',
                    'anonymous:', '[anon:', 'dex file', 'classes.dex'
                ]):
                    indicators.append('in_memory_dex_loading')

                # Check for dynamic code loading
                if any(pattern in line_lower for pattern in [
                    'dlopen', 'dlsym', 'mmap', 'mprotect'
                ]):
                    indicators.append('dynamic_code_loading')

                # Check for hooking framework indicators
                if any(pattern in line_lower for pattern in [
                    'xposed', 'substrate', 'frida', 'cydia'
                ]):
                    indicators.append('hooking_framework')

        return list(set(indicators))  # Remove duplicates

    def _is_suspicious_path(self, path: str) -> bool:
        """
        Unified path checking function - checks if path is suspicious for DEX operations.
        Consolidates all path checking logic to eliminate duplication.
        """
        if not path:
            return False

        # First check if it's a legitimate system path
        for legitimate_path in self.LEGITIMATE_SYSTEM_PATHS:
            if path.startswith(legitimate_path):
                return False

        # Check against all suspicious patterns (consolidated from all functions)
        suspicious_patterns = [
            r'/data/priv-downloads/',
            r'/data/local/',
            r'/sdcard/',
            r'/storage/',
            r'/tmp/',
            r'/cache/',
            r'\.\.',  # Path traversal
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True

        # Also check against the predefined suspicious directories
        for suspicious_dir in self.SUSPICIOUS_CLASSPATH_DIRS:
            if suspicious_dir in path:
                return True

        return False

    def _extract_actor(self, line: str) -> str:
        """Extract the actor (who initiated the action) from log line."""
        # Check for common actors in log lines
        if 'adbd' in line.lower():
            return 'adbd'
        elif 'shell' in line.lower():
            return 'shell'
        elif 'system_server' in line.lower():
            return 'system_server'
        elif 'packagemanager' in line.lower():
            return 'packagemanager'
        else:
            return 'unknown'

    def _group_indicators_by_context(self, indicators: List[Dict]) -> List[List[Dict]]:
        """Group indicators by package/UID/time context."""
        # Simple grouping by package for now
        groups = {}

        for indicator in indicators:
            package = indicator.get('package', 'unknown')
            uid = indicator.get('uid', 'unknown')
            key = f"{package}:{uid}"

            if key not in groups:
                groups[key] = []
            groups[key].append(indicator)

        return list(groups.values())

    def _create_dex_detection(self, indicators: List[Dict]) -> Detection:
        """Create a detection from a group of indicators."""
        if not indicators:
            return None

        # Determine severity based on indicators
        has_critical = any(ind.get('severity') == 'CRITICAL' for ind in indicators)
        has_high = any(ind.get('severity') == 'HIGH' for ind in indicators)

        if has_critical:
            severity = Severity.CRITICAL
            confidence = 0.9
        elif has_high:
            severity = Severity.HIGH
            confidence = 0.8
        else:
            severity = Severity.MEDIUM
            confidence = 0.6

        # Create evidence from indicators
        evidence = []
        for indicator in indicators:
            evidence.append(Evidence(
                type=EvidenceType.LOG_ANCHOR,
                content=indicator['line'],
                confidence=indicator.get('confidence', 0.5)
            ))

        # Create summary
        indicator_types = [ind['type'] for ind in indicators]
        summary = f"Suspicious DEX activity detected: {', '.join(set(indicator_types))}"

        return Detection(
            heuristic_name=self.name,
            severity=severity,
            confidence=confidence,
            summary=summary,
            evidence=evidence
        )


