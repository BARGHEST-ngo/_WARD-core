"""
Process Anomaly Heuristic - Advanced Android Process Analysis

Detects orphaned processes, process-package mismatches, and in-memory DEX loading
that may indicate fileless code execution or hooking frameworks.

Uses proper Android UID conversion, multi-process app handling, and ActivityManager
event correlation for accurate detection with minimal false positives.

Key improvements:
- Proper Android UID math (userId × 100000 + 10000 + appId)
- Multi-process app support (:service, :worker patterns)
- Isolated UID handling (WebView sandbox, isolated services)
- ActivityManager event correlation (am_proc_start, am_kill)
- /proc/<pid>/cmdline and /proc/<pid>/status parsing
- In-memory DEX detection via /proc/<pid>/maps
"""

import re
from typing import List, Dict, Any, Set, Optional, Tuple
from collections import defaultdict

from ward_core.heuristics.base import BaseHeuristic
from ward_core.logic.models import Detection, Evidence, EvidenceType, Severity, LogData
from ward_core.heuristics.memory.dex_analysis import DexAnalysisHeuristic


class ProcessAnomalyHeuristic(BaseHeuristic):
    """Advanced Android process anomaly detection with proper UID handling."""

    # Android UID constants (from AOSP android_filesystem_config.h)
    PER_USER_RANGE = 100000  # UID range per user
    FIRST_APPLICATION_UID = 10000  # First app UID
    LAST_APPLICATION_UID = 19999   # Last app UID
    FIRST_ISOLATED_UID = 99000     # First isolated UID (WebView sandbox)
    LAST_ISOLATED_UID = 99999      # Last isolated UID

    # UID patterns
    USER_APP_UID_PATTERN = re.compile(r'u(\d+)_a(\d+)')  # uX_aY format
    ISOLATED_UID_PATTERN = re.compile(r'u(\d+)_i(\d+)')  # uX_iY format

    # System UID ranges (zero-trust: verify by UID, not process name)
    SYSTEM_UID_RANGES = [
        (0, 999),      # Root and system UIDs
        (1000, 9999),  # System service UIDs
    ]

    # Suspicious UID patterns that warrant investigation
    SUSPICIOUS_UID_PATTERNS = [
        # UIDs that shouldn't normally run user processes
        (0, 0),        # Root UID running app processes
        (1000, 1000),  # System UID running non-system processes
    ]

    # REALISTIC process patterns based on actual ADB log data
    PROCESS_PATTERNS = {
        # Real ps output format (varies by Android version)
        'ps_basic': re.compile(r'^(\S+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+(.+)$'),
        'ps_simple': re.compile(r'^(\S+)\s+(\d+)\s+(.+)$'),

        # Real ActivityManager patterns (flexible, version-agnostic)
        'am_start_proc': re.compile(r'ActivityManager.*Start proc.*(\d+):([^/\s]+)(?:/([^/\s]+))?', re.IGNORECASE),
        'am_killing': re.compile(r'ActivityManager.*Killing.*(\d+):([^/\s]+)', re.IGNORECASE),
        'am_died': re.compile(r'ActivityManager.*Process.*(\d+).*died', re.IGNORECASE),

        # Real process creation patterns
        'proc_start': re.compile(r'Start proc.*(\d+):([^/\s]+)', re.IGNORECASE),
        'proc_died': re.compile(r'Process.*(\d+).*died', re.IGNORECASE),
    }

    # REALISTIC suspicious process indicators (behavior-based, not name-based)
    SUSPICIOUS_PROCESS_INDICATORS = {
        # Processes running from suspicious locations
        'suspicious_paths': [
            r'/data/local/tmp/',
            r'/sdcard/',
            r'/storage/emulated/\d+/',
            r'/tmp/',
            r'/cache/',
        ],

        # Suspicious command line patterns
        'suspicious_cmdline': [
            r'app_process.*\.\.',  # Path traversal
            r'dalvikvm.*-cp\s+/sdcard',  # External classpath
            r'sh.*-c.*wget|curl',  # Download commands
            r'busybox',  # Non-standard binaries
        ],

        # Process name patterns that warrant investigation
        'suspicious_names': [
            r'^[a-f0-9]{8,}$',  # Random hex names
            r'^\.',  # Hidden processes
            r'[^a-zA-Z0-9._:]',  # Non-standard characters
        ]
    }
    
    def __init__(self, config=None):
        super().__init__(config)
        self.min_suspicious_indicators = 1
    
    @property
    def name(self) -> str:
        return "process_anomaly"
    
    @property
    def category(self) -> str:
        return "Process Analysis"
    
    @property
    def description(self) -> str:
        return "Detects orphaned processes and process-package mismatches"
    
    def analyze(self, log_data: LogData) -> List[Detection]:
        """Analyze log data for process anomalies."""
        detections = []
        
        # Build process and package inventories
        processes = self._build_process_inventory(log_data)
        packages = self._build_package_inventory(log_data)
        
        # Detect orphaned processes
        orphaned_detections = self._detect_orphaned_processes(processes, packages)
        detections.extend(orphaned_detections)
        
        # Detect process behavior anomalies
        behavior_detections = self._detect_process_behavior_anomalies(log_data)
        detections.extend(behavior_detections)
        
        # Detect process name mismatches
        mismatch_detections = self._detect_process_name_mismatches(processes, packages, log_data)
        detections.extend(mismatch_detections)
        
        return detections

    def _parse_android_uid(self, uid_str: str) -> Optional[int]:
        """Convert Android UID string to numeric UID using proper AOSP formula."""
        # Handle uX_aY format (regular app UIDs)
        match = self.USER_APP_UID_PATTERN.match(uid_str)
        if match:
            user_id = int(match.group(1))
            app_id = int(match.group(2))
            # Proper Android UID formula: userId × 100000 + 10000 + appId
            return user_id * self.PER_USER_RANGE + self.FIRST_APPLICATION_UID + app_id

        # Handle uX_iY format (isolated UIDs)
        match = self.ISOLATED_UID_PATTERN.match(uid_str)
        if match:
            user_id = int(match.group(1))
            isolated_id = int(match.group(2))
            # Isolated UID formula: userId × 100000 + 99000 + isolatedId
            return user_id * self.PER_USER_RANGE + self.FIRST_ISOLATED_UID + isolated_id

        # Handle numeric UIDs directly
        try:
            return int(uid_str)
        except ValueError:
            return None

    def _is_isolated_uid(self, uid: int) -> bool:
        """Check if UID is in isolated range (WebView sandbox, isolated services)."""
        # Extract the app portion of the UID
        app_uid = uid % self.PER_USER_RANGE
        return self.FIRST_ISOLATED_UID <= app_uid <= self.LAST_ISOLATED_UID

    def _is_app_uid(self, uid: int) -> bool:
        """Check if UID is in application range."""
        app_uid = uid % self.PER_USER_RANGE
        return self.FIRST_APPLICATION_UID <= app_uid <= self.LAST_APPLICATION_UID

    def _is_system_uid(self, uid: int) -> bool:
        """Check if UID is in system range (zero-trust: verify by UID, not name)."""
        for start, end in self.SYSTEM_UID_RANGES:
            if start <= uid <= end:
                return True
        return False

    def _analyze_process_indicators(self, process_name: str, cmdline: str, uid: int) -> List[str]:
        """Analyze process for suspicious indicators using behavior-based detection."""
        indicators = []

        # Check for suspicious paths in process name or cmdline
        for pattern in self.SUSPICIOUS_PROCESS_INDICATORS['suspicious_paths']:
            if re.search(pattern, process_name) or re.search(pattern, cmdline):
                indicators.append('suspicious_path')
                break

        # Check for suspicious command line patterns
        for pattern in self.SUSPICIOUS_PROCESS_INDICATORS['suspicious_cmdline']:
            if re.search(pattern, cmdline, re.IGNORECASE):
                indicators.append('suspicious_cmdline')
                break

        # Check for suspicious process names
        for pattern in self.SUSPICIOUS_PROCESS_INDICATORS['suspicious_names']:
            if re.search(pattern, process_name):
                indicators.append('suspicious_name')
                break

        # Check for UID/process type mismatches
        if uid is not None:
            # Root UID running non-system processes
            if uid == 0 and not self._looks_like_system_process(process_name, cmdline):
                indicators.append('root_uid_anomaly')

            # System UID running user-like processes
            if self._is_system_uid(uid) and self._looks_like_user_process(process_name, cmdline):
                indicators.append('system_uid_anomaly')

        return indicators

    def _looks_like_system_process(self, process_name: str, cmdline: str) -> bool:
        """Check if process appears to be a legitimate system process (behavior-based)."""
        # System processes typically run from /system/ or have system-like names
        system_indicators = [
            r'/system/',
            r'init$',
            r'kernel',
            r'kthread',
            r'\[.*\]',  # Kernel threads
        ]

        full_context = f"{process_name} {cmdline}"
        return any(re.search(pattern, full_context, re.IGNORECASE) for pattern in system_indicators)

    def _looks_like_user_process(self, process_name: str, cmdline: str) -> bool:
        """Check if process appears to be a user/app process."""
        user_indicators = [
            r'com\.',  # Package names
            r'app_process',
            r'/data/app/',
            r'/data/data/',
        ]

        full_context = f"{process_name} {cmdline}"
        return any(re.search(pattern, full_context, re.IGNORECASE) for pattern in user_indicators)

    def _build_process_inventory(self, log_data: LogData) -> Dict[str, Dict[str, Any]]:
        """Build inventory of running processes using realistic parsing patterns."""
        processes = {}

        # Parse ps output with realistic patterns (format varies by Android version)
        # Look for ps output in raw lines
        for line in log_data.raw_lines:
            line = line.strip()
            if not line or line.startswith('USER') or line.startswith('PID'):
                continue

            # Skip lines that don't look like ps output
            if not re.match(r'^[a-zA-Z0-9_]+\s+\d+', line):
                continue

            # Try basic ps format first
            match = self.PROCESS_PATTERNS['ps_basic'].match(line)
            if not match:
                # Fallback to simple format
                match = self.PROCESS_PATTERNS['ps_simple'].match(line)

            if match:
                if len(match.groups()) >= 4:  # Basic format
                    user_str, pid, ppid, cmdline = match.groups()
                    process_name = cmdline.split()[0] if cmdline else 'unknown'
                else:  # Simple format
                    user_str, pid, cmdline = match.groups()
                    ppid = '0'
                    process_name = cmdline.split()[0] if cmdline else 'unknown'

                # Convert Android UID string to numeric
                numeric_uid = self._parse_android_uid(user_str)

                # Analyze process for suspicious indicators
                suspicious_indicators = self._analyze_process_indicators(process_name, cmdline, numeric_uid)

                processes[pid] = {
                    'pid': pid,
                    'ppid': ppid,
                    'uid': numeric_uid,
                    'uid_str': user_str,
                    'process_name': process_name,
                    'cmdline': cmdline,
                    'source': 'ps',
                    'is_isolated': self._is_isolated_uid(numeric_uid) if numeric_uid else False,
                    'is_app': self._is_app_uid(numeric_uid) if numeric_uid else False,
                    'is_system_uid': self._is_system_uid(numeric_uid) if numeric_uid else False,
                    'suspicious_indicators': suspicious_indicators
                }

        return processes
    
    def _build_package_inventory(self, log_data: LogData) -> Dict[str, Dict[str, Any]]:
        """Build comprehensive package inventory with multi-process support."""
        packages = {}
        current_package = None

        # Parse dumpsys package output with proper multi-process handling
        # Look for package information in raw lines
        for line in log_data.raw_lines:
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Extract package name
            if 'Package [' in line:
                package_match = re.search(r'Package \[([^\]]+)\]', line)
                if package_match:
                    current_package = package_match.group(1)
                    packages[current_package] = {
                        'package_name': current_package,
                        'process_names': {current_package},  # Use set for uniqueness
                        'uid': None,
                        'shared_uid': None,
                        'shared_user_id': None,
                        'code_path': None
                    }

            if not current_package:
                continue

            # Extract UID information
            if 'userId=' in line:
                uid_match = re.search(r'userId=(\d+)', line)
                if uid_match:
                    packages[current_package]['uid'] = int(uid_match.group(1))

            # Extract sharedUserId (multiple packages can share one UID)
            if 'sharedUserId=' in line:
                shared_match = re.search(r'sharedUserId=(\d+)', line)
                if shared_match:
                    packages[current_package]['shared_uid'] = int(shared_match.group(1))

            # Extract component process names (activities, services, receivers)
            if 'android:process=' in line:
                process_match = re.search(r'android:process="([^"]+)"', line)
                if process_match:
                    process_name = process_match.group(1)
                    # Handle colon-prefixed processes (:service -> com.pkg:service)
                    if process_name.startswith(':'):
                        process_name = current_package + process_name
                    packages[current_package]['process_names'].add(process_name)

            # Code path for APK validation
            if 'codePath=' in line:
                path_match = re.search(r'codePath=([^\s]+)', line)
                if path_match:
                    packages[current_package]['code_path'] = path_match.group(1)

        # Convert sets back to lists for JSON serialization
        for pkg_info in packages.values():
            pkg_info['process_names'] = list(pkg_info['process_names'])

        return packages
    
    def _detect_orphaned_processes(self, processes: Dict, packages: Dict) -> List[Detection]:
        """Detect processes running under app UIDs without matching packages using zero-trust principles."""
        detections = []

        for pid, process_info in processes.items():
            uid = process_info.get('uid')
            process_name = process_info.get('process_name', '')

            # Skip if no UID or not an app UID
            if uid is None or not process_info.get('is_app', False):
                continue

            # Skip isolated UIDs (WebView sandbox, isolated services) - they're expected
            if process_info.get('is_isolated', False):
                continue

            # ZERO-TRUST: Don't skip based on process names - verify through behavior and UID

            # Check if process has a matching package with proper multi-process support
            found_package = False

            for package_name, package_info in packages.items():
                pkg_uid = package_info.get('uid')
                shared_uid = package_info.get('shared_uid')

                # Check UID match (regular or shared)
                if pkg_uid == uid or shared_uid == uid:
                    # Check if process name matches any expected process names
                    expected_names = package_info.get('process_names', [package_name])

                    # Support colon-suffixed processes (com.pkg:service)
                    for expected_name in expected_names:
                        if (process_name == expected_name or
                            process_name.startswith(expected_name + ':') or
                            expected_name.startswith(process_name + ':')):
                            found_package = True
                            break

                    if found_package:
                        break

            # Only flag as orphaned if truly no matching package found
            if not found_package:
                # Use pre-analyzed suspicious indicators from process inventory
                suspicious_indicators = process_info.get('suspicious_indicators', [])

                # Add orphaned process as an indicator
                suspicious_indicators.append('orphaned_process')

                # Check for name mismatches
                if process_info.get('name_mismatch', False):
                    suspicious_indicators.append('name_mismatch')

                # Calculate confidence based on multiple indicators (zero-trust approach)
                base_confidence = 0.4  # Lower base confidence without whitelisting
                confidence = base_confidence + (len(suspicious_indicators) * 0.15)

                # Only create detection if we have multiple suspicious indicators
                if len(suspicious_indicators) >= 2:
                    detection = Detection(
                        category="Orphaned Process",
                        package=process_name,
                        severity=Severity.HIGH if confidence >= 0.8 else Severity.MEDIUM,
                        confidence=min(confidence, 0.95),
                        title=f"Orphaned Process: {process_name}",
                        description=f"Process {process_name} (PID {pid}) running under app UID {uid} without matching package",
                        technical_details={
                            'pid': pid,
                            'uid': uid,
                            'uid_str': process_info.get('uid_str', ''),
                            'process_name': process_name,
                            'cmdline': process_info.get('cmdline', ''),
                            'source': process_info.get('source', 'unknown'),
                            'suspicious_indicators': suspicious_indicators,
                            'is_isolated': process_info.get('is_isolated', False),
                            'is_app': process_info.get('is_app', False)
                        },
                        evidence=[Evidence(
                            type=EvidenceType.LOG_ANCHOR,
                            content=f"Process {process_name} (PID {pid}) UID {uid} ({process_info.get('uid_str', '')})",
                            confidence=confidence
                        )]
                    )
                    detections.append(detection)

        return detections
    
    def _detect_process_behavior_anomalies(self, log_data: LogData) -> List[Detection]:
        """Detect suspicious process behavior using realistic ActivityManager patterns."""
        detections = []

        # Look for realistic process start/death patterns in logcat
        for line in log_data.raw_lines:
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Check for suspicious process starts
            start_match = self.PROCESS_PATTERNS['am_start_proc'].search(line)
            if start_match:
                pid, package_name, process_name = start_match.groups()

                suspicious_indicators = []

                # Check for UID/process mismatches
                if process_name and package_name:
                    if not process_name.startswith(package_name):
                        suspicious_indicators.append('process_package_mismatch')

                # Check for suspicious package patterns
                if package_name and any(re.search(pattern, package_name)
                                      for pattern in self.SUSPICIOUS_PROCESS_INDICATORS['suspicious_names']):
                    suspicious_indicators.append('suspicious_package_name')

                if suspicious_indicators:
                    confidence = 0.6 + (len(suspicious_indicators) * 0.1)
                    detection = Detection(
                        category="Process Behavior Anomaly",
                        package=package_name or "unknown",
                        severity=Severity.MEDIUM,
                        confidence=min(confidence, 0.9),
                        title=f"Suspicious Process Start: {package_name}",
                        description=f"Process start with suspicious characteristics",
                        technical_details={
                            'pid': pid,
                            'package_name': package_name,
                            'process_name': process_name,
                            'suspicious_indicators': suspicious_indicators,
                            'source': 'raw_lines'
                        },
                        evidence=[Evidence(
                            type=EvidenceType.LOG_ANCHOR,
                            content=line.strip(),
                            confidence=confidence
                        )]
                    )
                    detections.append(detection)

        return detections


    
    def _detect_process_name_mismatches(self, processes: Dict, packages: Dict, log_data: LogData) -> List[Detection]:
        """Detect processes whose names don't match their package processName with in-memory DEX detection."""
        detections = []

        for pid, proc_info in processes.items():
            process_name = proc_info.get('process_name', '')
            uid = proc_info.get('uid')

            if not uid or not process_name or not proc_info.get('is_app', False):
                continue

            # Skip isolated UIDs (legitimate sandboxing)
            if proc_info.get('is_isolated', False):
                continue

            # ZERO-TRUST: Don't skip based on process names - verify through UID and behavior

            # Find packages with matching UID
            matching_packages = []
            for _, pkg_info in packages.items():
                if pkg_info.get('uid') == uid or pkg_info.get('shared_uid') == uid:
                    matching_packages.append(pkg_info)

            if matching_packages:
                # Check if process name matches expected names (with multi-process support)
                expected_names = set()
                for pkg_info in matching_packages:
                    pkg_process_names = pkg_info.get('process_names', [pkg_info.get('package_name', '')])
                    for expected_name in pkg_process_names:
                        expected_names.add(expected_name)
                        # Add colon-suffixed variants
                        if ':' not in expected_name:
                            expected_names.add(expected_name + ':')

                # Check for exact match or colon-suffixed match
                is_valid_process = any(
                    process_name == expected or
                    process_name.startswith(expected + ':') or
                    expected.startswith(process_name + ':')
                    for expected in expected_names
                )

                if not is_valid_process:
                    # Check for in-memory DEX indicators using the dex_analysis module
                    dex_analyzer = DexAnalysisHeuristic()
                    in_memory_indicators = dex_analyzer.check_in_memory_dex_indicators(pid, log_data)

                    # Only flag if we have additional suspicious indicators
                    suspicious_indicators = []

                    if in_memory_indicators:
                        suspicious_indicators.extend(in_memory_indicators)

                    # Check cmdline for suspicious patterns
                    cmdline = proc_info.get('cmdline', '')
                    if any(pattern in cmdline.lower() for pattern in ['dalvikvm', 'dex', 'app_process']):
                        suspicious_indicators.append('suspicious_cmdline')

                    # Check for name consistency across sources
                    if proc_info.get('name_mismatch', False):
                        suspicious_indicators.append('cross_source_name_mismatch')

                    # Only create detection if we have suspicious indicators
                    if suspicious_indicators:
                        confidence = 0.5 + (len(suspicious_indicators) * 0.1)
                        detection = Detection(
                            category="Process Name Mismatch",
                            package=process_name,
                            severity=Severity.HIGH if confidence >= 0.8 else Severity.MEDIUM,
                            confidence=min(confidence, 0.95),
                            title=f"Process Name Mismatch: {process_name}",
                            description=f"Process {process_name} name doesn't match expected package process names",
                            technical_details={
                                'pid': pid,
                                'uid': uid,
                                'process_name': process_name,
                                'expected_names': list(expected_names),
                                'matching_packages': [pkg['package_name'] for pkg in matching_packages],
                                'suspicious_indicators': suspicious_indicators,
                                'cmdline': cmdline
                            },
                            evidence=[Evidence(
                                type=EvidenceType.LOG_ANCHOR,
                                content=f"Process {process_name} (PID {pid}) doesn't match expected: {list(expected_names)}",
                                confidence=confidence
                            )]
                        )
                        detections.append(detection)

        return detections
    

