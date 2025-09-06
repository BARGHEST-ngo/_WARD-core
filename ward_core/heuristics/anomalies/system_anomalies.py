"""
SystemAnomaliesHeuristic
"""

import re
from collections import defaultdict, Counter
from typing import List, Dict, Any, Optional, Set
from enum import Enum

from ward_core.logic.models import LogData, Detection, Evidence, EvidenceType, Severity
from ward_core.heuristics.base import BaseHeuristic


class SystemAnomalyType(Enum):
    """Types of system anomalies detected."""
    PROPERTY_CHANGE = "property_change"
    FRAMEWORK_ANOMALY = "framework_anomaly"
    DAEMON_FAILURE = "daemon_failure"
    RESOURCE_ANOMALY = "resource_anomaly"
    FILESYSTEM_ANOMALY = "filesystem_anomaly"


class SystemAnomaliesHeuristic(BaseHeuristic):
    """Heuristic for detecting Android system-level anomalies."""
    
    # SPYWARE-FOCUSED patterns based on actual compromise indicators in ADB logs

    # REALISTIC SYSTEM ANOMALIES - Based on actual ADB log patterns
    # Focus on strange system behavior that doesn't fit other heuristics

    # Property changes (setprop/resetprop/property service)
    PROPERTY_CHANGE_PATTERNS = [
        re.compile(r'\bsetprop\s+([a-zA-Z0-9_.]+)\s+([^\s]+)', re.IGNORECASE),
        re.compile(r'\bresetprop\s+([a-zA-Z0-9_.]+)\s+([^\s]+)', re.IGNORECASE),
        re.compile(r'property_service:\s*set property\s+([a-zA-Z0-9_.]+)\s+to\s+([^\s]+)', re.IGNORECASE),
    ]

    # Framework anomalies (watchdog/ANR/boot issues)
    FRAMEWORK_ANOMALY_PATTERNS = [
        re.compile(r'Watchdog.*!.*system_server.*(?:hung|not responding)', re.IGNORECASE),
        re.compile(r'ActivityManager: ANR in ', re.IGNORECASE),
        re.compile(r'ActivityManager: Slow operation.*(>\s*\d+ms)', re.IGNORECASE),
        re.compile(r'PackageManager.*failed to (?:install|scan|parse)', re.IGNORECASE),
        re.compile(r'WindowManager.*(freeze|unfreeze|timeout|orientation).*failed', re.IGNORECASE),
    ]

    # System daemon failures (realistic daemon names)
    DAEMON_FAILURE_PATTERNS = [
        re.compile(r'init: Service (\S+) (?:crashed|died), restarting', re.IGNORECASE),
        re.compile(r'init: Service (\S+) repeatedly crashed, restarting too quickly', re.IGNORECASE),
        re.compile(r'(\baudioserver|cameraserver|mediaserver|media\.extractor|media\.codec|vold|netd|keystore2)\b.*(crash|died|fatal)', re.IGNORECASE),
    ]

    # Resource exhaustion (realistic patterns)
    RESOURCE_ANOMALY_PATTERNS = [
        re.compile(r'lowmemorykiller: Killing proc', re.IGNORECASE),
        re.compile(r'OutOfMemoryError', re.IGNORECASE),
        re.compile(r'ProcessRecord.*skipping GC.*due to low memory', re.IGNORECASE),
        re.compile(r'SurfaceFlinger:.*failed to allocate', re.IGNORECASE),
    ]

    # Filesystem anomalies (realistic filesystem errors)
    FILESYSTEM_ANOMALY_PATTERNS = [
        re.compile(r'EXT4-fs error \(device ([^)]+)\):', re.IGNORECASE),
        re.compile(r'Buffer I/O error on dev (\S+)', re.IGNORECASE),
        re.compile(r'fsck(?:\[[0-9]+\])?:.*(UNEXPECTED INCONSISTENCY|Filesystem check failed)', re.IGNORECASE),
        re.compile(r'vold:.*(mount|umount).*failed for (\S+)', re.IGNORECASE),
    ]

    # Timing and sequence anomalies (realistic patterns)
    TIMING_ANOMALY_PATTERNS = [
        re.compile(r'Watchdog.*timeout.*system_server.*(\d+).*seconds', re.IGNORECASE),
        re.compile(r'init.*service.*restarting.*too.*frequently', re.IGNORECASE),
        re.compile(r'Zygote.*died.*unexpectedly.*restarting', re.IGNORECASE),
    ]

    # Process behavior anomalies (realistic patterns)
    PROCESS_ANOMALY_PATTERNS = [
        re.compile(r'ActivityManager.*Killing.*\d+.*processes.*due.*to.*system.*pressure', re.IGNORECASE),
        re.compile(r'Process.*\d+.*died.*due.*to.*signal.*(\d+).*unexpectedly', re.IGNORECASE),
    ]

    # System state anomalies (realistic patterns)
    SYSTEM_STATE_ANOMALY_PATTERNS = [
        re.compile(r'SystemServer.*entered.*safe.*mode', re.IGNORECASE),
        re.compile(r'ActivityManager.*System.*not.*ready.*after.*(\d+).*seconds', re.IGNORECASE),
    ]

    # Communication anomalies (realistic IPC patterns)
    COMMUNICATION_ANOMALY_PATTERNS = [
        re.compile(r'ActivityManager.*Broadcast.*timeout.*(\d+).*receivers', re.IGNORECASE),
        re.compile(r'ServiceManager.*Service.*\w+.*died.*(\d+).*times', re.IGNORECASE),
    ]

    # Hardware interaction anomalies (realistic hardware patterns)
    HARDWARE_ANOMALY_PATTERNS = [
        re.compile(r'SensorManager.*Sensor.*\w+.*stopped.*responding', re.IGNORECASE),
        re.compile(r'AudioManager.*Audio.*device.*disconnected.*unexpectedly', re.IGNORECASE),
    ]

    # Security-critical property changes
     # OEM specific most likely
    # TODO: catalog based on OEM
    CRITICAL_PROPERTIES = {
        'ro.build.type', 'ro.debuggable', 'ro.secure', 'ro.adb.secure',
        'ro.boot.verifiedbootstate', 'ro.boot.veritymode', 'ro.build.tags',
        'ro.boot.mode', 'ro.boot.selinux', 'ro.boot.flash.locked'
    }

    # Critical system daemons (updated for modern Android)
    CRITICAL_DAEMONS = {
        'installd', 'vold', 'netd', 'keystore2', 'audioserver', 'cameraserver',
        'mediaserver', 'media.extractor', 'media.codec', 'drmserver'
    }

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.max_detections_per_type = 10
        self.anomaly_thresholds = {
            'daemon_failure_limit': 3,
            'framework_anomaly_limit': 5,
            'resource_anomaly_limit': 4
        }

    @property
    def name(self) -> str:
        return "system_anomalies"

    @property
    def category(self) -> str:
        return "System Anomalies"

    @property
    def description(self) -> str:
        return "Detects Android system-level anomalies including property changes, framework issues, and daemon failures"

    def analyze(self, log_data: LogData) -> List[Detection]:
        """Analyze system anomalies in Android logs."""
        detections = []
        
        # Analyze ALL types of system anomalies
        property_detections = self._analyze_property_changes(log_data)
        framework_detections = self._analyze_framework_anomalies(log_data)
        daemon_detections = self._analyze_daemon_failures(log_data)
        resource_detections = self._analyze_resource_anomalies(log_data)
        filesystem_detections = self._analyze_filesystem_anomalies(log_data)
        timing_detections = self._analyze_timing_anomalies(log_data)
        process_detections = self._analyze_process_anomalies(log_data)
        system_state_detections = self._analyze_system_state_anomalies(log_data)
        communication_detections = self._analyze_communication_anomalies(log_data)
        hardware_detections = self._analyze_hardware_anomalies(log_data)

        # Combine all detections
        all_detections = (
            property_detections + framework_detections + daemon_detections +
            resource_detections + filesystem_detections + timing_detections +
            process_detections + system_state_detections + communication_detections +
            hardware_detections
        )
        
        # Limit total detections to avoid spam
        return all_detections[:50]

    def _analyze_property_changes(self, log_data: LogData) -> List[Detection]:
        """Analyze system property changes for security implications."""
        detections = []
        
        for i, line in enumerate(log_data.raw_lines):
            for pattern in self.PROPERTY_CHANGE_PATTERNS:
                match = pattern.search(line)
                if match:
                    groups = match.groups()
                    if len(groups) >= 1:
                        property_name = groups[0]
                        old_value = groups[1] if len(groups) >= 2 else 'unknown'
                        new_value = groups[2] if len(groups) >= 3 else groups[1] if len(groups) >= 2 else 'unknown'
                        
                        # Check if this is a critical property change
                        is_critical = any(prop in property_name for prop in self.CRITICAL_PROPERTIES)
                        
                        if is_critical or 'resetprop' in line:  # Magisk property modification
                            severity = Severity.CRITICAL if is_critical else Severity.HIGH
                            confidence = 0.9 if is_critical else 0.7
                            
                            detection = Detection(
                                category="System Anomalies",
                                package="system",
                                title=f"Property modification: {property_name}",
                                description=f"System property modification: {property_name}",
                                severity=severity,
                                confidence=confidence,
                                technical_details={
                                    'property_name': property_name,
                                    'old_value': old_value,
                                    'new_value': new_value,
                                    'is_critical': is_critical,
                                    'modification_method': 'resetprop' if 'resetprop' in line else 'standard'
                                },
                                evidence=[self._create_evidence(line, confidence)]
                            )
                            detections.append(detection)
                            
                            # Limit detections per type
                            if len(detections) >= self.max_detections_per_type:
                                break
                    break
        
        return detections

    def _analyze_framework_anomalies(self, log_data: LogData) -> List[Detection]:
        """Analyze Android framework service anomalies."""
        detections = []
        framework_counts = defaultdict(int)
        
        for i, line in enumerate(log_data.raw_lines):
            for pattern in self.FRAMEWORK_ANOMALY_PATTERNS:
                if pattern.search(line):
                    # Extract framework service name
                    service_name = self._extract_framework_service(line)
                    framework_counts[service_name] += 1
                    
                    # Determine severity based on frequency
                    count = framework_counts[service_name]
                    if count >= self.anomaly_thresholds['framework_anomaly_limit']:
                        severity = Severity.HIGH
                        confidence = 0.8
                    else:
                        severity = Severity.MEDIUM
                        confidence = 0.6
                    
                    detection = Detection(
                        category="System Anomalies",
                        package="system",
                        title=f"Framework service issue: {service_name}",
                        description=f"Framework service issue: {service_name}",
                        severity=severity,
                        confidence=confidence,
                        technical_details={
                            'service_name': service_name,
                            'occurrence_count': count,
                            'anomaly_type': self._classify_framework_anomaly(line)
                        },
                        evidence=[self._create_evidence(line, confidence)]
                    )
                    detections.append(detection)
                    
                    if len(detections) >= self.max_detections_per_type:
                        break
                    break
        
        return detections

    def _analyze_daemon_failures(self, log_data: LogData) -> List[Detection]:
        """Analyze system daemon failures."""
        detections = []
        daemon_counts = defaultdict(int)
        
        for i, line in enumerate(log_data.raw_lines):
            for pattern in self.DAEMON_FAILURE_PATTERNS:
                if pattern.search(line):
                    daemon_name = self._extract_daemon_name(line)
                    daemon_counts[daemon_name] += 1
                    
                    # Determine severity based on daemon criticality and frequency
                    is_critical = daemon_name in self.CRITICAL_DAEMONS
                    count = daemon_counts[daemon_name]
                    
                    if count >= self.anomaly_thresholds['daemon_failure_limit']:
                        severity = Severity.CRITICAL if is_critical else Severity.HIGH
                        confidence = 0.9 if is_critical else 0.7
                    else:
                        severity = Severity.HIGH if is_critical else Severity.MEDIUM
                        confidence = 0.8 if is_critical else 0.6
                    
                    detection = Detection(
                        category="System Anomalies",
                        package="system",
                        title=f"Daemon failure: {daemon_name}",
                        description=f"System daemon failure: {daemon_name}",
                        severity=severity,
                        confidence=confidence,
                        technical_details={
                            'daemon_name': daemon_name,
                            'is_critical': is_critical,
                            'failure_count': count,
                            'failure_type': self._classify_daemon_failure(line)
                        },
                        evidence=[self._create_evidence(line, confidence)]
                    )
                    detections.append(detection)
                    
                    if len(detections) >= self.max_detections_per_type:
                        break
                    break
        
        return detections

    def _analyze_resource_anomalies(self, log_data: LogData) -> List[Detection]:
        """Analyze system resource exhaustion anomalies."""
        detections = []
        resource_counts = defaultdict(int)
        
        for i, line in enumerate(log_data.raw_lines):
            for pattern in self.RESOURCE_ANOMALY_PATTERNS:
                if pattern.search(line):
                    resource_type = self._classify_resource_anomaly(line)
                    resource_counts[resource_type] += 1
                    
                    # Determine severity based on frequency and type
                    count = resource_counts[resource_type]
                    if count >= self.anomaly_thresholds['resource_anomaly_limit']:
                        severity = Severity.HIGH
                        confidence = 0.8
                    else:
                        severity = Severity.MEDIUM
                        confidence = 0.6
                    
                    detection = Detection(
                        category="System Anomalies",
                        package="system",
                        title=f"Resource exhaustion: {resource_type}",
                        description=f"System resource issue: {resource_type}",
                        severity=severity,
                        confidence=confidence,
                        technical_details={
                            'resource_type': resource_type,
                            'occurrence_count': count,
                            'system_impact': self._assess_resource_impact(line)
                        },
                        evidence=[self._create_evidence(line, confidence)]
                    )
                    detections.append(detection)
                    
                    if len(detections) >= self.max_detections_per_type:
                        break
                    break
        
        return detections

    def _analyze_filesystem_anomalies(self, log_data: LogData) -> List[Detection]:
        """Analyze filesystem and storage anomalies."""
        detections = []
        
        for i, line in enumerate(log_data.raw_lines):
            for pattern in self.FILESYSTEM_ANOMALY_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Extract device or path information
                    target = match.group(1) if match.groups() else 'unknown'
                    
                    # Filesystem errors are generally serious
                    severity = Severity.HIGH
                    confidence = 0.8
                    
                    detection = Detection(
                        category="System Anomalies",
                        package="system",
                        title=f"Filesystem issue: {target}",
                        description=f"Filesystem issue on {target}",
                        severity=severity,
                        confidence=confidence,
                        technical_details={
                            'target_device': target,
                            'filesystem_error': self._classify_filesystem_error(line),
                            'system_impact': 'storage_integrity'
                        },
                        evidence=[self._create_evidence(line, confidence)]
                    )
                    detections.append(detection)
                    
                    if len(detections) >= self.max_detections_per_type:
                        break
                    break
        
        return detections

    def _create_evidence(self, content: str, confidence: float = 0.8) -> Evidence:
        """Create evidence object from log line."""
        return Evidence(
            type=EvidenceType.LOG_ANCHOR,
            content=content.strip(),
            confidence=confidence
        )

    def _extract_framework_service(self, line: str) -> str:
        """Extract framework service name from log line."""
        if 'PackageManager' in line:
            return 'PackageManager'
        elif 'WindowManager' in line:
            return 'WindowManager'
        elif 'ActivityManager' in line:
            return 'ActivityManager'
        elif 'SystemServiceRegistry' in line:
            return 'SystemServiceRegistry'
        elif 'TelephonyRegistry' in line:
            return 'TelephonyRegistry'
        elif 'ConnectivityManager' in line:
            return 'ConnectivityManager'
        elif 'PowerManager' in line:
            return 'PowerManager'
        elif 'BatteryService' in line:
            return 'BatteryService'
        else:
            return 'unknown_framework_service'

    def _classify_framework_anomaly(self, line: str) -> str:
        """Classify the type of framework anomaly."""
        if 'Failed to' in line:
            return 'operation_failure'
        elif 'Timeout' in line:
            return 'timeout_error'
        elif 'Unable to' in line:
            return 'capability_failure'
        elif 'critically low' in line:
            return 'resource_critical'
        else:
            return 'general_anomaly'

    def _extract_daemon_name(self, line: str) -> str:
        """Extract daemon name from log line."""
        if 'installd' in line:
            return 'installd'
        elif 'vold' in line:
            return 'vold'
        elif 'netd' in line:
            return 'netd'
        elif 'keystore' in line:
            return 'keystore'
        elif 'media.server' in line or 'media server' in line:
            return 'media.server'
        elif 'drmserver' in line:
            return 'drmserver'
        else:
            return 'unknown_daemon'

    def _classify_daemon_failure(self, line: str) -> str:
        """Classify the type of daemon failure."""
        if 'Failed to' in line:
            return 'operation_failure'
        elif 'Permission denied' in line:
            return 'permission_error'
        elif 'crashed' in line or 'died' in line:
            return 'process_crash'
        elif 'error accessing' in line:
            return 'access_error'
        else:
            return 'general_failure'

    def _classify_resource_anomaly(self, line: str) -> str:
        """Classify the type of resource anomaly."""
        if 'memory' in line.lower():
            return 'memory_exhaustion'
        elif 'SurfaceFlinger' in line or 'GraphicBuffer' in line:
            return 'graphics_memory'
        elif 'AudioFlinger' in line:
            return 'audio_resources'
        elif 'CameraService' in line:
            return 'camera_resources'
        elif 'GC' in line:
            return 'garbage_collection'
        else:
            return 'general_resource'

    def _assess_resource_impact(self, line: str) -> str:
        """Assess the system impact of resource anomaly."""
        if 'Unable to start' in line:
            return 'service_startup_failure'
        elif 'No longer have activities' in line:
            return 'activity_termination'
        elif 'failed to allocate' in line:
            return 'allocation_failure'
        elif 'could not create' in line:
            return 'creation_failure'
        elif 'GC' in line and ('took' in line or 'ms' in line):
            return 'performance_degradation'
        else:
            return 'system_degradation'

    def _classify_filesystem_error(self, line: str) -> str:
        """Classify the type of filesystem error."""
        if 'EXT4-fs error' in line:
            return 'ext4_filesystem_error'
        elif 'I/O error' in line:
            return 'io_error'
        elif 'Buffer I/O error' in line:
            return 'buffer_io_error'
        elif 'Filesystem check failed' in line:
            return 'fsck_failure'
        elif 'failed to prepare' in line:
            return 'volume_preparation_failure'
        elif 'UNEXPECTED INCONSISTENCY' in line:
            return 'filesystem_corruption'
        elif 'Permission denied' in line:
            return 'filesystem_permission_error'
        else:
            return 'general_filesystem_error'

    def _analyze_timing_anomalies(self, log_data: LogData) -> List[Detection]:
        """Analyze timing and sequence anomalies in system behavior."""
        detections = []

        for line in log_data.raw_lines:
            for pattern in self.TIMING_ANOMALY_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Extract numeric values for severity assessment
                    numbers = [int(g) for g in match.groups() if g and g.isdigit()]
                    severity = self._assess_timing_severity(numbers)

                    detection = Detection(
                        category="System Anomalies",
                        package="system",
                        title="Timing anomaly detected",
                        description=f"System timing anomaly detected",
                        severity=severity,
                        confidence=0.8,
                        technical_details={
                            "anomaly_type": "timing",
                            "line": line.strip(),
                            "pattern": pattern.pattern,
                            "values": numbers
                        },
                        evidence=[self._create_evidence(line, 0.8)]
                    )
                    detections.append(detection)

                    if len(detections) >= self.max_detections_per_type:
                        break

        return detections

    def _analyze_process_anomalies(self, log_data: LogData) -> List[Detection]:
        """Analyze process behavior anomalies."""
        detections = []

        for line in log_data.raw_lines:
            for pattern in self.PROCESS_ANOMALY_PATTERNS:
                match = pattern.search(line)
                if match:
                    numbers = [int(g) for g in match.groups() if g and g.isdigit()]
                    severity = self._assess_process_severity(numbers)

                    detection = Detection(
                        category="System Anomalies",
                        package="system",
                        title="Process anomaly detected",
                        description=f"Process behavior anomaly detected",
                        severity=severity,
                        confidence=0.7,
                        technical_details={
                            "anomaly_type": "process",
                            "line": line.strip(),
                            "values": numbers
                        },
                        evidence=[self._create_evidence(line, 0.7)]
                    )
                    detections.append(detection)

                    if len(detections) >= self.max_detections_per_type:
                        break

        return detections

    def _analyze_system_state_anomalies(self, log_data: LogData) -> List[Detection]:
        """Analyze system state anomalies."""
        detections = []

        for line in log_data.raw_lines:
            for pattern in self.SYSTEM_STATE_ANOMALY_PATTERNS:
                match = pattern.search(line)
                if match:
                    detection = Detection(
                        category="System Anomalies",
                        package="system",
                        title="System state anomaly detected",
                        description=f"System state anomaly detected",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        technical_details={
                            "anomaly_type": "system_state",
                            "line": line.strip()
                        },
                        evidence=[self._create_evidence(line, 0.8)]
                    )
                    detections.append(detection)

                    if len(detections) >= self.max_detections_per_type:
                        break

        return detections

    def _analyze_communication_anomalies(self, log_data: LogData) -> List[Detection]:
        """Analyze communication and IPC anomalies."""
        detections = []

        for line in log_data.raw_lines:
            for pattern in self.COMMUNICATION_ANOMALY_PATTERNS:
                match = pattern.search(line)
                if match:
                    numbers = [int(g) for g in match.groups() if g and g.isdigit()]
                    severity = self._assess_communication_severity(numbers)

                    detection = Detection(
                        category="System Anomalies",
                        package="system",
                        title="Communication anomaly detected",
                        description=f"Communication anomaly detected",
                        severity=severity,
                        confidence=0.7,
                        technical_details={
                            "anomaly_type": "communication",
                            "line": line.strip(),
                            "values": numbers
                        },
                        evidence=[self._create_evidence(line, 0.7)]
                    )
                    detections.append(detection)

                    if len(detections) >= self.max_detections_per_type:
                        break

        return detections

    def _analyze_hardware_anomalies(self, log_data: LogData) -> List[Detection]:
        """Analyze hardware interaction anomalies."""
        detections = []

        for line in log_data.raw_lines:
            for pattern in self.HARDWARE_ANOMALY_PATTERNS:
                match = pattern.search(line)
                if match:
                    detection = Detection(
                        category="System Anomalies",
                        package="system",
                        title="Hardware anomaly detected",
                        description=f"Hardware interaction anomaly detected",
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        technical_details={
                            "anomaly_type": "hardware",
                            "line": line.strip()
                        },
                        evidence=[self._create_evidence(line, 0.6)]
                    )
                    detections.append(detection)

                    if len(detections) >= self.max_detections_per_type:
                        break

        return detections

    def _assess_timing_severity(self, numbers: List[int]) -> Severity:
        """Assess severity based on timing values."""
        if not numbers:
            return Severity.MEDIUM

        max_val = max(numbers)
        if max_val > 100:  # Very high counts/times
            return Severity.CRITICAL
        elif max_val > 10:
            return Severity.HIGH
        else:
            return Severity.MEDIUM

    def _assess_process_severity(self, numbers: List[int]) -> Severity:
        """Assess severity based on process metrics."""
        if not numbers:
            return Severity.MEDIUM

        max_val = max(numbers)
        if max_val > 1000:  # Very high memory/activity counts
            return Severity.HIGH
        elif max_val > 100:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _assess_communication_severity(self, numbers: List[int]) -> Severity:
        """Assess severity based on communication metrics."""
        if not numbers:
            return Severity.MEDIUM

        max_val = max(numbers)
        if max_val > 50:  # Very high failure/timeout counts
            return Severity.HIGH
        elif max_val > 10:
            return Severity.MEDIUM
        else:
            return Severity.LOW



