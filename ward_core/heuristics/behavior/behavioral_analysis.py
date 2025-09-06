"""
Behavioral Analysis Heuristic

Uses shared services for correlation and reduced false positives.
"""

import re
from typing import List, Dict, Any, Set, Tuple
from collections import defaultdict
from datetime import datetime, timedelta

from ward_core.heuristics.base import BaseHeuristic
from ward_core.heuristics.context.installation_context import InstallationContextHeuristic
from ward_core.logic.models import Detection, Evidence, EvidenceType, Severity, LogData

# JobScheduler thresholds - based on realistic Android patterns
MAX_JOBS_PER_APP = 15
SUSPICIOUS_JOB_TYPES = {"sync", "upload", "report", "collect", "monitor", "track", "log"}

# These patterns match real wakelock names found in Android batterystats
REALISTIC_WAKELOCK_PATTERNS = {
    "audio_wakelocks": re.compile(r'AudioMix', re.IGNORECASE),
    "power_manager_wakelocks": re.compile(r'PowerManagerService\.WakeLocks', re.IGNORECASE),
    "alarm_manager_wakelocks": re.compile(r'AlarmManager', re.IGNORECASE),
    "sync_wakelocks": re.compile(r'SyncManager', re.IGNORECASE),
    "network_wakelocks": re.compile(r'NetworkStats', re.IGNORECASE),
    "location_wakelocks": re.compile(r'LocationManagerService', re.IGNORECASE),
    "bluetooth_wakelocks": re.compile(r'BluetoothAdapter', re.IGNORECASE),
    "wifi_wakelocks": re.compile(r'WifiLock', re.IGNORECASE),
    "sensor_wakelocks": re.compile(r'SensorService', re.IGNORECASE),
}

SPYWARE_THRESHOLDS = {
    # High-frequency polling patterns (count, max_individual_duration_ms, time_window_hours)
    'high_frequency_abuse': (100, 30_000, 1),      # 100+ wakelocks under 30s in 1h (true polling behavior)
    'location_surveillance': (20, 300_000, 2),     # 20+ location wakelocks over 5min in 2h (stalking pattern)
    'background_exfiltration': (50, 60_000, 1),    # 50+ sync wakelocks under 1min in 1h (data theft)
    'scheduled_malware': (25, 180_000, 4),         # 25+ job wakelocks over 3min in 4h (persistence)
    'kernel_exploitation': (5, 600_000, 1),        # 5+ kernel wakelocks over 10min in 1h (privilege abuse)
    'stealth_networking': (30, 45_000, 1),         # 30+ network wakelocks under 45s in 1h (C2 communication)
    'sensor_spying': (10, 300_000, 2),             # 10+ sensor wakelocks over 5min in 2h (recording)

    # Total consumption thresholds (total_time_ms, count, time_window_hours)
    'excessive_total_time': (3_600_000, 50, 4),    # 60+ minutes total, 50+ instances in 4h
    'persistent_background': (1_800_000, 100, 2),  # 30+ minutes total, 100+ instances in 2h (aggressive polling)

    # Risk adjustment is now handled by installation_context heuristic
    # Sideloaded apps with suspicious behavior get higher risk scores
    # Play Store apps get baseline risk scores
}

# Fingerprinting permissions
CRITICAL_FINGERPRINTING_PERMS = {
    "android.permission.READ_PHONE_STATE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.GET_TASKS",
}

MULTIPLE_FINGERPRINTING_PERMS = {
    "android.permission.READ_PHONE_STATE",
    "android.permission.GET_ACCOUNTS", 
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.GET_TASKS",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.BLUETOOTH",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE"
}

# Battery drain thresholds
BATTERY_DRAIN_THRESHOLDS = {
    "high_cpu_usage": 1800,      # 30 minutes of CPU time
    "excessive_background": 0.6,  # 60% background usage
    "suspicious_network": 0.7,    # 70% network correlation
}

# Enhanced sensor thresholds for covert detection
COVERT_SENSOR_THRESHOLDS = {
    'CAMERA': {'high': 300, 'critical': 1800, 'bg_critical': 30},        # 5min/30min, any bg>30s
    'RECORD_AUDIO': {'high': 180, 'critical': 900, 'bg_critical': 20},   # 3min/15min, any bg>20s
    'COARSE_LOCATION': {'high': 3600, 'critical': 14400, 'bg_critical': 180}, # 1h/4h, bg>3min
    'FINE_LOCATION': {'high': 1800, 'critical': 7200, 'bg_critical': 180},   # 30min/2h, bg>3min
    'SYSTEM_ALERT_WINDOW': {'high': 180, 'critical': 900, 'bg_critical': 30}  # MediaProjection equivalent
}

class BehavioralAnalysisHeuristic(BaseHeuristic):
    """
    Analyzes Android app behavioral patterns to detect spyware-like activities.
    
    This heuristic looks for:
    - JobScheduler and background service abuse
    - Wakelock abuse patterns indicating surveillance
    - Device fingerprinting activities
    - Excessive resource consumption patterns
    - User interaction anomalies
    
    Follows zero-trust framework - never trusts package names alone.
    """
    
    def __init__(self, config=None):
        super().__init__(config)

        # Quality gate settings
        config_dict = self._extract_config_dict(config)
        self.min_risk_score = config_dict.get('min_risk_score', 2.0)
        self.require_log_evidence = config_dict.get('require_log_evidence', False)  # Behavioral analysis often relies on metadata
        self.max_detections_per_package = config_dict.get('max_detections_per_package', 3)

        # Initialize installation context heuristic for zero-trust verification
        self.installation_context_heuristic = InstallationContextHeuristic(config)

        # Configurable thresholds (can be overridden via config)
        self.spyware_thresholds = config_dict.get('spyware_thresholds', SPYWARE_THRESHOLDS)
        self.battery_drain_thresholds = config_dict.get('battery_drain_thresholds', BATTERY_DRAIN_THRESHOLDS)
        self.covert_sensor_thresholds = config_dict.get('covert_sensor_thresholds', COVERT_SENSOR_THRESHOLDS)

        # Temporal clustering windows (seconds) for enhanced analysis
        self.activity_cluster_window = config_dict.get('activity_cluster_window', 300)  # 5 minutes
        self.screen_off_window = config_dict.get('screen_off_window', 60)  # 1 minute for screen-off activity
    
    @property
    def name(self) -> str:
        """Get the name of this heuristic."""
        return "behavioral_analysis"
    
    @property
    def category(self) -> str:
        """Get the category of this heuristic."""
        return "Behavioral Analysis"
    
    @property
    def description(self) -> str:
        """Get description of what this heuristic detects."""
        return "Detects suspicious behavioral patterns indicating spyware or malicious activities"
    
    @property
    def max_score(self) -> float:
        """Maximum score this heuristic can produce."""
        return 10.0
    
    def analyze(self, log_data: LogData) -> List[Detection]:
        """
        Analyze log data for modern Android spyware behavioral patterns.

        Uses shared services for proper correlation and reduced false positives.

        Args:
            log_data: Parsed log data to analyze

        Returns:
            List of Detection objects with proper correlation
        """
        # Analyze different behavioral patterns using realistic ADB log patterns
        job_detections = self._analyze_jobscheduler_abuse(log_data)
        wakelock_detections = self._analyze_wakelock_abuse(log_data)
        fingerprint_detections = self._analyze_fingerprinting_activity(log_data)
        usage_detections = self._analyze_usage_statistics(log_data)

        # Enhanced behavioral analysis with realistic patterns
        # Accessibility service analysis is handled by permissions heuristic to avoid duplication
        notification_detections = self._analyze_notification_listener_abuse_realistic(log_data)
        stealth_detections = self._analyze_stealth_behaviors_realistic(log_data)

        # Merged resource analysis features
        battery_detections = self._analyze_battery_drain(log_data)
        foreground_detections = self._analyze_foreground_mismatch(log_data)
        # AppOps behavioral pattern analysis (focuses on behavior, not legitimacy)
        appops_behavior_detections = self._analyze_appops_behavioral_patterns(log_data)
        location_detections = self._analyze_location_misuse(log_data)
        persistent_detections = self._analyze_persistent_services(log_data)
        blocked_detections = self._analyze_blocked_operations(log_data)
        package_detections = self._analyze_package_characteristics(log_data)

        # Combine all detections (includes AppOps behavioral analysis)
        # Accessibility service analysis is handled by permissions heuristic
        all_detections = (job_detections + wakelock_detections + fingerprint_detections +
                         usage_detections + battery_detections + foreground_detections +
                         appops_behavior_detections + location_detections +
                         notification_detections + stealth_detections +
                         persistent_detections + blocked_detections + package_detections)
        
        # Smart detection limiting: prioritize by severity and confidence instead of truncating
        return self._prioritize_detections(all_detections)

    def _prioritize_detections(self, detections: List[Detection]) -> List[Detection]:
        """
        Detection prioritization instead of simple truncation.
        Prioritizes by severity and confidence, groups similar detections.
        """
        if len(detections) <= 50:
            return detections

        # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW) and confidence
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}

        sorted_detections = sorted(detections, key=lambda d: (
            severity_order.get(d.severity.name, 0),
            d.confidence,
            d.title  # Secondary sort for consistency
        ), reverse=True)

        # Group similar detections to avoid spam with more sophisticated grouping
        grouped_detections = {}
        for detection in sorted_detections:
            # Create more specific grouping to consolidate similar issues
            package = detection.technical_details.get('package', 'unknown')
            category = detection.category
            title_base = detection.title.split(':')[0]  # Group by base title

            # Special grouping for common redundant patterns
            if 'SELinux AVC' in detection.title:
                group_key = f"selinux_avc_{package}"
            elif 'Permission Usage' in detection.title:
                group_key = f"permission_{package}_{category}"
            elif 'Sensor' in detection.title or 'CAMERA' in detection.title or 'RECORD_AUDIO' in detection.title:
                group_key = f"sensor_{package}"
            else:
                group_key = f"{package}_{category}_{title_base}"

            if group_key not in grouped_detections:
                grouped_detections[group_key] = []
            grouped_detections[group_key].append(detection)

        # Consolidate detections from each group, creating summary detections for spam
        prioritized = []
        for group_key, group_detections in grouped_detections.items():
            if len(group_detections) == 1:
                # Single detection - add as is
                prioritized.append(group_detections[0])
            elif len(group_detections) <= 3:
                # Few detections - add the highest severity one
                prioritized.append(group_detections[0])
            else:
                # Many similar detections - create consolidated detection
                consolidated = self._create_consolidated_detection(group_key, group_detections)
                prioritized.append(consolidated)

        # If still too many, take top 50 by severity/confidence
        if len(prioritized) > 50:
            removed_count = len(prioritized) - 50
            # Log vital information removal for analyst followup
            print(f"WARNING: Behavioral analysis truncated {removed_count} detections due to volume limit. "
                  f"Consider reviewing full results or adjusting detection thresholds for comprehensive analysis.")
            prioritized = prioritized[:50]

        return prioritized

    def _create_consolidated_detection(self, group_key: str, detections: List[Detection]) -> Detection:
        """
        Create a consolidated detection from multiple similar detections to reduce noise.
        """
        from ward_core.logic.models import Detection, Evidence, EvidenceType

        # Use the highest severity detection as base
        base_detection = detections[0]
        count = len(detections)

        # Determine consolidated title and description
        if 'selinux_avc' in group_key:
            title = f"Multiple SELinux AVC Denials ({count} instances)"
            description = f"App generated {count} SELinux access denials - consolidated to reduce noise"
        elif 'permission' in group_key:
            title = f"Multiple Permission Issues ({count} instances)"
            description = f"App has {count} permission-related issues - consolidated to reduce noise"
        elif 'sensor' in group_key:
            title = f"Multiple Sensor Usage Issues ({count} instances)"
            description = f"App has {count} sensor usage issues - consolidated to reduce noise"
        else:
            title = f"Multiple Similar Issues ({count} instances)"
            description = f"App has {count} similar issues - consolidated to reduce noise"

        # Collect unique technical details
        consolidated_details = base_detection.technical_details.copy()
        consolidated_details.update({
            'consolidated_count': count,
            'original_titles': [d.title for d in detections[:5]],  # First 5 titles
            'consolidation_type': 'behavioral_analysis_grouping'
        })

        # Create consolidated detection
        return Detection(
            title=title,
            description=description,
            severity=base_detection.severity,
            confidence=min(0.95, base_detection.confidence + 0.1),  # Slightly higher confidence for patterns
            category=base_detection.category,
            technical_details=consolidated_details,
            evidence=[Evidence(
                type=EvidenceType.DERIVED,
                content=f"Consolidated from {count} similar detections",
                confidence=0.8
            )]
        )

    def _safe_parse_duration(self, duration_str: str) -> float:
        """
        Safely parse duration strings with fallback handling.
        Handles various Android duration formats and malformed entries.
        """
        if not duration_str:
            return 0.0

        try:
            # Handle common Android duration formats
            duration_str = duration_str.strip().lower()

            # Handle numeric values (seconds)
            if duration_str.replace('.', '').replace('-', '').isdigit():
                return max(0.0, float(duration_str))

            # Handle time formats like "1h2m3s", "30m", "45s"
            total_seconds = 0.0

            # Extract hours
            if 'h' in duration_str:
                hours_match = re.search(r'(\d+(?:\.\d+)?)h', duration_str)
                if hours_match:
                    total_seconds += float(hours_match.group(1)) * 3600

            # Extract minutes
            if 'm' in duration_str:
                minutes_match = re.search(r'(\d+(?:\.\d+)?)m', duration_str)
                if minutes_match:
                    total_seconds += float(minutes_match.group(1)) * 60

            # Extract seconds
            if 's' in duration_str:
                seconds_match = re.search(r'(\d+(?:\.\d+)?)s', duration_str)
                if seconds_match:
                    total_seconds += float(seconds_match.group(1))

            return max(0.0, total_seconds)

        except (ValueError, AttributeError):
            # Log warning for debugging but don't crash
            # In production, you might want to use proper logging
            return 0.0

    def _safe_parse_numeric(self, value: str, default: float = 0.0) -> float:
        """Safely parse numeric values with fallback."""
        if not value:
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            return default

    # Accessibility service analysis moved to permissions heuristic to avoid duplication

    def _analyze_persistent_services(self, log_data: LogData) -> List[Detection]:
        """
        Analyze for persistent foreground services indicating surveillance.

        Long-running foreground services (>4 hours) can indicate persistent
        surveillance or data collection activities.
        """
        detections = []

        # Parse AppOps data using the same method as working analysis
        appops_data = self._parse_appops_data(log_data.raw_lines)

        if not appops_data:
            return detections

        # Analyze each package for persistent services
        for package, operations in appops_data.items():
            if package == 'unknown' or self._is_system_app(package, log_data):
                continue

            # Check for START_FOREGROUND operation
            if 'START_FOREGROUND' not in operations:
                continue

            foreground_op = operations['START_FOREGROUND']
            if foreground_op.get('mode') != 'allow':
                continue

            # Parse duration
            duration_seconds = foreground_op.get('duration_secs', 0)
            if duration_seconds <= 0:
                continue

            # Thresholds for persistent services
            SUSPICIOUS_THRESHOLD = 4 * 3600  # 4 hours
            CRITICAL_THRESHOLD = 12 * 3600   # 12 hours

            if duration_seconds >= SUSPICIOUS_THRESHOLD:
                # Determine severity based on duration
                if duration_seconds >= CRITICAL_THRESHOLD:
                    severity = Severity.CRITICAL
                    confidence = 0.95
                    severity_desc = "extremely long"
                elif duration_seconds >= 8 * 3600:  # 8 hours
                    severity = Severity.HIGH
                    confidence = 0.9
                    severity_desc = "very long"
                else:
                    severity = Severity.HIGH
                    confidence = 0.8
                    severity_desc = "long"

                duration_hours = duration_seconds / 3600

                # Check for additional suspicious patterns
                suspicious_patterns = []
                if 'BIND_ACCESSIBILITY_SERVICE' in operations:
                    suspicious_patterns.append('Accessibility Service')
                if 'COARSE_LOCATION' in operations or 'FINE_LOCATION' in operations:
                    suspicious_patterns.append('Location Tracking')
                if 'CAMERA' in operations:
                    suspicious_patterns.append('Camera Access')
                if 'RECORD_AUDIO' in operations:
                    suspicious_patterns.append('Audio Recording')

                # Increase severity if combined with surveillance capabilities
                if suspicious_patterns and severity == Severity.HIGH:
                    severity = Severity.CRITICAL
                    confidence = min(confidence + 0.1, 0.95)

                detection = Detection(
                    category="Persistent Surveillance",
                    subcategory="Long-Running Service",
                    package=package,
                    severity=severity,
                    confidence=confidence,
                    title=f"Persistent Foreground Service: {package}",
                    description=f"App runs {severity_desc} foreground service: {duration_hours:.1f}h" +
                               (f" with {', '.join(suspicious_patterns)}" if suspicious_patterns else ""),
                    technical_details={
                        'service_duration_seconds': duration_seconds,
                        'service_duration_hours': duration_hours,
                        'threshold_hours': SUSPICIOUS_THRESHOLD / 3600,
                        'suspicious_patterns': suspicious_patterns,
                        'abuse_type': 'persistent_surveillance',
                        'heuristic_name': self.name,
                        'package_name': package
                    }
                )

                # Add evidence
                detection.evidence.append(Evidence(
                    type=EvidenceType.LOG_ANCHOR,
                    content=f"START_FOREGROUND: {self._format_operation_evidence(foreground_op)}",
                    confidence=0.8
                ))

                # Add evidence for suspicious patterns
                for pattern in suspicious_patterns:
                    if pattern == 'Accessibility Service' and 'BIND_ACCESSIBILITY_SERVICE' in operations:
                        detection.evidence.append(Evidence(
                            type=EvidenceType.LOG_ANCHOR,
                            content=f"BIND_ACCESSIBILITY_SERVICE: {self._format_operation_evidence(operations['BIND_ACCESSIBILITY_SERVICE'])}",
                            confidence=0.7
                        ))
                    elif pattern == 'Location Tracking':
                        for loc_op in ['COARSE_LOCATION', 'FINE_LOCATION']:
                            if loc_op in operations:
                                detection.evidence.append(Evidence(
                                    type=EvidenceType.LOG_ANCHOR,
                                    content=f"{loc_op}: {self._format_operation_evidence(operations[loc_op])}",
                                    confidence=0.7
                                ))
                                break

                detection.evidence.append(Evidence(
                    type=EvidenceType.METADATA_ONLY,
                    content=f"Behavioral pattern detected: persistent_surveillance",
                    confidence=0.8
                ))

                detections.append(detection)

        return detections

    def _analyze_blocked_operations(self, log_data: LogData) -> List[Detection]:
        """
        Analyze blocked/rejected AppOps operations to detect malicious intent.

        Even when operations are blocked, the attempts show malicious intent
        and help identify potentially dangerous applications.
        """
        detections = []

        # Parse AppOps data using the same method as working analysis
        appops_data = self._parse_appops_data(log_data.raw_lines)

        if not appops_data:
            return detections

        # Analyze each package for blocked operations
        for package, operations in appops_data.items():
            if package == 'unknown' or self._is_system_app(package, log_data):
                continue

            # Find blocked/rejected operations
            blocked_operations = []
            high_risk_blocks = []

            for operation, op_data in operations.items():
                if op_data.get('mode') in ['deny', 'ignore']:
                    blocked_operations.append(operation)

                    # High-risk blocked operations
                    if operation in ['WRITE_SMS', 'PROJECT_MEDIA', 'CAMERA', 'RECORD_AUDIO',
                                   'SYSTEM_ALERT_WINDOW', 'WRITE_SETTINGS', 'REQUEST_INSTALL_PACKAGES']:
                        high_risk_blocks.append(operation)

            # Determine if this indicates malicious intent
            if len(blocked_operations) >= 2:  # Multiple blocked attempts
                if high_risk_blocks:
                    severity = Severity.HIGH
                    confidence = 0.85
                    category = "Malicious Intent"
                    subcategory = "High-Risk Blocked Operations"
                    title_suffix = f"High-Risk Blocked Operations: {package}"
                    desc_suffix = f"attempted high-risk operations: {', '.join(high_risk_blocks[:3])}"
                elif len(blocked_operations) >= 4:
                    severity = Severity.MEDIUM
                    confidence = 0.75
                    category = "Suspicious Behavior"
                    subcategory = "Multiple Blocked Operations"
                    title_suffix = f"Multiple Blocked Operations: {package}"
                    desc_suffix = f"attempted {len(blocked_operations)} blocked operations"
                else:
                    continue  # Not enough evidence

                detection = Detection(
                    category=category,
                    subcategory=subcategory,
                    package=package,
                    severity=severity,
                    confidence=confidence,
                    title=title_suffix,
                    description=f"App {desc_suffix}, indicating potential malicious intent",
                    technical_details={
                        'blocked_operations_count': len(blocked_operations),
                        'blocked_operations': blocked_operations,
                        'high_risk_blocks': high_risk_blocks,
                        'abuse_type': 'malicious_intent_blocked',
                        'heuristic_name': self.name,
                        'package_name': package
                    }
                )

                # Add evidence for blocked operations
                for blocked_op in (high_risk_blocks if high_risk_blocks else blocked_operations[:3]):
                    if blocked_op in operations:
                        detection.evidence.append(Evidence(
                            type=EvidenceType.LOG_ANCHOR,
                            content=f"{blocked_op} (BLOCKED): {self._format_operation_evidence(operations[blocked_op])}",
                            confidence=0.7
                        ))

                detection.evidence.append(Evidence(
                    type=EvidenceType.METADATA_ONLY,
                    content=f"Behavioral pattern detected: malicious_intent_blocked",
                    confidence=0.8
                ))

                detections.append(detection)

        return detections

    def _analyze_package_characteristics(self, log_data: LogData) -> List[Detection]:
        """
        Analyze package characteristics for suspicious patterns.

        This includes Play Store disabled apps, old SDK versions with extensive
        permissions, and suspicious package naming patterns.
        """
        detections = []

        # Extract package entries
        package_entries = [
            entry for entry in log_data.parsed_events
            if entry.get('entry_type') == 'package_entry'
        ]

        if not package_entries:
            return detections

        # Analyze each package
        for entry in package_entries:
            content = entry.get('content', {})
            package = entry.get('package', 'unknown')

            if package == 'unknown' or self._is_system_app(package, log_data):
                continue

            # Check for Play Store disabled apps
            disabled_caller = content.get('lastDisabledCaller', '')
            if disabled_caller == 'com.android.vending':  # Play Store
                severity = Severity.HIGH
                confidence = 0.9

                detection = Detection(
                    category="Policy Violation",
                    subcategory="Play Store Disabled",
                    package=package,
                    severity=severity,
                    confidence=confidence,
                    title=f"Play Store Disabled App: {package}",
                    description=f"App was disabled by Google Play Store, indicating policy violations",
                    technical_details={
                        'disabled_by': 'com.android.vending',
                        'abuse_type': 'play_store_policy_violation',
                        'heuristic_name': self.name,
                        'package_name': package
                    }
                )

                detection.evidence.append(Evidence(
                    type=EvidenceType.METADATA_ONLY,
                    content=f"lastDisabledCaller: com.android.vending",
                    confidence=0.9
                ))

                detection.evidence.append(Evidence(
                    type=EvidenceType.METADATA_ONLY,
                    content=f"Behavioral pattern detected: play_store_policy_violation",
                    confidence=0.9
                ))

                detections.append(detection)

            # Check for old SDK + extensive permissions
            target_sdk = content.get('targetSdk', 0)
            permissions = content.get('permissions', [])

            if target_sdk > 0 and target_sdk <= 23 and len(permissions) >= 15:  # Android 6.0 or older
                dangerous_perms = [p for p in permissions if self._is_dangerous_permission(p)]

                if len(dangerous_perms) >= 8:  # Many dangerous permissions
                    severity = Severity.HIGH
                    confidence = 0.8

                    detection = Detection(
                        category="Security Risk",
                        subcategory="Old SDK + Extensive Permissions",
                        package=package,
                        severity=severity,
                        confidence=confidence,
                        title=f"Old SDK + Extensive Permissions: {package}",
                        description=f"App targets old Android SDK ({target_sdk}) with {len(dangerous_perms)} dangerous permissions",
                        technical_details={
                            'target_sdk': target_sdk,
                            'total_permissions': len(permissions),
                            'dangerous_permissions_count': len(dangerous_perms),
                            'dangerous_permissions': dangerous_perms[:10],  # Limit for readability
                            'abuse_type': 'old_sdk_extensive_permissions',
                            'heuristic_name': self.name,
                            'package_name': package
                        }
                    )

                    detection.evidence.append(Evidence(
                        type=EvidenceType.METADATA_ONLY,
                        content=f"Target SDK: {target_sdk} (Android 6.0 or older)",
                        confidence=0.8
                    ))

                    detection.evidence.append(Evidence(
                        type=EvidenceType.METADATA_ONLY,
                        content=f"Dangerous permissions: {len(dangerous_perms)} ({', '.join(dangerous_perms[:5])}...)",
                        confidence=0.7
                    ))

                    detection.evidence.append(Evidence(
                        type=EvidenceType.METADATA_ONLY,
                        content=f"Behavioral pattern detected: old_sdk_extensive_permissions",
                        confidence=0.8
                    ))

                    detections.append(detection)

            # Check for suspicious package names
            if self._is_suspicious_package_name(package):
                severity = Severity.MEDIUM
                confidence = 0.7

                detection = Detection(
                    category="Suspicious Naming",
                    subcategory="Random Package Name",
                    package=package,
                    severity=severity,
                    confidence=confidence,
                    title=f"Suspicious Package Name: {package}",
                    description=f"Package has suspicious naming pattern typical of malware",
                    technical_details={
                        'package_name_pattern': 'suspicious_random',
                        'abuse_type': 'suspicious_package_naming',
                        'heuristic_name': self.name,
                        'package_name': package
                    }
                )

                detection.evidence.append(Evidence(
                    type=EvidenceType.METADATA_ONLY,
                    content=f"Package name pattern: {package}",
                    confidence=0.7
                ))

                detection.evidence.append(Evidence(
                    type=EvidenceType.METADATA_ONLY,
                    content=f"Behavioral pattern detected: suspicious_package_naming",
                    confidence=0.7
                ))

                detections.append(detection)

        return detections

    # System package checking consolidated to use installation_context heuristic via _is_system_app method

    def _is_operation_allowed(self, operation_data: dict) -> bool:
        """Check if an AppOps operation is allowed."""
        mode = operation_data.get('mode', 'default')
        return mode == 'allow'

    def _is_operation_blocked(self, operation_data: dict) -> bool:
        """Check if an AppOps operation is blocked/rejected."""
        mode = operation_data.get('mode', 'default')
        raw_content = str(operation_data)
        return mode in ['deny', 'ignore', 'default'] or 'Reject:' in raw_content

    def _parse_duration_seconds(self, duration_str: str) -> float:
        """Parse duration string to seconds."""
        if not duration_str:
            return 0.0

        # Remove '+' prefix if present
        duration_str = duration_str.lstrip('+')

        # Parse format like "9h25m6s787ms"
        total_seconds = 0.0

        # Hours
        if 'h' in duration_str:
            hours_part = duration_str.split('h')[0]
            try:
                total_seconds += float(hours_part) * 3600
                duration_str = duration_str.split('h', 1)[1]
            except ValueError:
                pass

        # Minutes
        if 'm' in duration_str and 'ms' not in duration_str:
            minutes_part = duration_str.split('m')[0]
            try:
                total_seconds += float(minutes_part) * 60
                duration_str = duration_str.split('m', 1)[1]
            except ValueError:
                pass

        # Seconds
        if 's' in duration_str and 'ms' not in duration_str:
            seconds_part = duration_str.split('s')[0]
            try:
                total_seconds += float(seconds_part)
                duration_str = duration_str.split('s', 1)[1]
            except ValueError:
                pass

        # Milliseconds
        if 'ms' in duration_str:
            ms_part = duration_str.split('ms')[0]
            try:
                total_seconds += float(ms_part) / 1000
            except ValueError:
                pass

        return total_seconds

    def _format_operation_evidence(self, operation_data: dict) -> str:
        """Format operation data for evidence display."""
        mode = operation_data.get('mode', 'unknown')
        access_times = operation_data.get('access_times', [])
        duration = operation_data.get('duration', '')

        evidence_parts = [f"mode: {mode}"]

        if access_times:
            evidence_parts.append(f"recent access: {access_times[0] if access_times else 'none'}")

        if duration:
            evidence_parts.append(f"duration: {duration}")

        return ', '.join(evidence_parts)

    def _is_dangerous_permission(self, permission: str) -> bool:
        """Check if a permission is considered dangerous."""
        dangerous_permissions = {
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.WRITE_SMS',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.PROCESS_OUTGOING_CALLS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.GET_ACCOUNTS',
            'android.permission.READ_PHONE_STATE',
            'android.permission.READ_PHONE_NUMBERS',
            'android.permission.CALL_PHONE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.MANAGE_EXTERNAL_STORAGE',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.WRITE_SETTINGS',
            'android.permission.REQUEST_INSTALL_PACKAGES',
            'android.permission.BIND_ACCESSIBILITY_SERVICE'
        }
        return permission in dangerous_permissions

    def _is_suspicious_package_name(self, package: str) -> bool:
        """Check if a package name follows suspicious patterns."""
        # Skip empty or system packages - use installation context for zero-trust verification
        if not package or package in ['android', 'system']:
            return False

        # Use installation context heuristic for zero-trust system package verification
        # Note: This requires log_data parameter, but this method is called without it
        # For now, use basic system package prefixes as fallback
        system_prefixes = ['com.android.', 'android.', 'com.google.android.', 'com.samsung.android.']
        if any(package.startswith(prefix) for prefix in system_prefixes):
            return False

        # Split package into parts
        parts = package.split('.')

        # Single part packages are suspicious (but not system ones)
        if len(parts) < 2:
            return not package.startswith(('com.', 'org.', 'net.', 'android.'))

        # Check for specific suspicious patterns
        suspicious_patterns = 0

        # Pattern 1: Very short random parts (like "wws.mzrnbn")
        short_random_parts = 0
        for part in parts:
            if len(part) <= 6 and self._looks_random(part):
                short_random_parts += 1

        if short_random_parts >= 2:  # Multiple short random parts
            return True

        # Pattern 2: Single letter domains (like "a.b" or "x.y.z")
        single_letter_parts = sum(1 for part in parts if len(part) == 1)
        if single_letter_parts >= 2:
            return True

        # Pattern 3: All consonants or very few vowels in main parts
        main_parts = [part for part in parts if len(part) > 2]
        for part in main_parts:
            if self._has_suspicious_letter_pattern(part):
                suspicious_patterns += 1

        # Consider suspicious if multiple patterns match
        return suspicious_patterns >= 2

    def _looks_random(self, text: str) -> bool:
        """Check if text looks randomly generated."""
        if len(text) <= 2:
            return False

        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'

        vowel_count = sum(1 for c in text.lower() if c in vowels)
        consonant_count = sum(1 for c in text.lower() if c in consonants)

        # No vowels in text longer than 3 chars
        if len(text) > 3 and vowel_count == 0:
            return True

        # Very high consonant to vowel ratio
        if vowel_count > 0 and consonant_count / vowel_count > 4:
            return True

        # Check for common patterns that indicate real words
        common_endings = ['ing', 'tion', 'ness', 'ment', 'able', 'ible', 'ful', 'less']
        if any(text.lower().endswith(ending) for ending in common_endings):
            return False

        return False

    def _has_suspicious_letter_pattern(self, text: str) -> bool:
        """Check if text has suspicious letter patterns."""
        vowels = 'aeiou'
        vowel_count = sum(1 for c in text.lower() if c in vowels)

        # No vowels in text longer than 4 characters
        if len(text) > 4 and vowel_count == 0:
            return True

        # Very few vowels relative to length
        if len(text) > 6 and vowel_count <= 1:
            return True

        return False
    
    def _analyze_jobscheduler_abuse(self, log_data: LogData) -> List[Detection]:
        """Analyze JobScheduler and background service abuse using realistic Android patterns."""
        detections = []
        
        job_info = defaultdict(lambda: {'jobs': [], 'services': []})
        
        # Parse job scheduler information from logs - realistic Android patterns
        for line in log_data.raw_lines:
            line = line.strip()
            
            # Look for UID-based package identification (realistic Android pattern)
            uid_match = re.search(r'u(\d+):', line)
            if uid_match:
                # Extract package from subsequent lines or context
                continue
            
            # Look for realistic job patterns from Android logs
            if "Job " in line and ":" in line:
                # Pattern: "Job com.package.name/service.name: duration realtime (times), duration background (times)"
                job_match = re.search(r'Job\s+([^:]+):\s+(\d+[sm]\s+\d+ms)\s+realtime\s+\((\d+)\s+times\)', line)
                if job_match:
                    job_service = job_match.group(1)
                    duration = job_match.group(2)
                    times = int(job_match.group(3))
                    
                    # Extract package from job service path
                    pkg_match = re.search(r'([a-zA-Z0-9_.]+)/', job_service)
                    if pkg_match:
                        package = pkg_match.group(1)
                        if self._is_valid_package_name(package) and not self._is_system_app(package, log_data):
                            job_info[package]['jobs'].append({
                                'service': job_service,
                                'duration': duration,
                                'times': times,
                                'line': line
                            })
            
            # Look for realistic service patterns from Android logs
            if "Service " in line and "Created for:" in line:
                # Pattern: "Service com.package.service: Created for: duration uptime"
                service_match = re.search(r'Service\s+([^:]+):\s+Created for:', line)
                if service_match:
                    service_name = service_match.group(1)
                    pkg_match = re.search(r'([a-zA-Z0-9_.]+)\.', service_name)
                    if pkg_match:
                        package = pkg_match.group(1)
                        if self._is_valid_package_name(package) and not self._is_system_app(package, log_data):
                            job_info[package]['services'].append({
                                'service_name': service_name,
                                'line': line
                            })
        
        # Analyze job patterns for each package
        for package, info in job_info.items():
            if self._is_system_app(package, log_data):
                continue
            
            jobs = info['jobs']
            # services = info['services']  # Not used currently
            
            # Check for excessive jobs
            if len(jobs) > MAX_JOBS_PER_APP:
                detection = self._create_behavioral_detection(
                    package=package,
                    category="JobScheduler Abuse",
                    title=f"Excessive Background Jobs: {package}",
                    description=f"Package has {len(jobs)} background jobs (threshold: {MAX_JOBS_PER_APP})",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    technical_details={
                        'jobs_count': len(jobs),
                        'threshold': MAX_JOBS_PER_APP,
                        'abuse_type': 'excessive_jobs'
                    },
                    evidence_lines=[job['line'] for job in jobs[:3]]  # Limit evidence
                )
                detections.append(detection)
            
            # Check for suspicious job types based on service names
            suspicious_jobs = []
            for job in jobs:
                service_name = job['service'].lower()
                for job_type in SUSPICIOUS_JOB_TYPES:
                    if job_type in service_name:
                        suspicious_jobs.append(job)
                        break
            
            if suspicious_jobs:
                detection = self._create_behavioral_detection(
                    package=package,
                    category="JobScheduler Abuse",
                    title=f"Suspicious Job Types: {package}",
                    description=f"Package uses suspicious job types: {len(suspicious_jobs)} suspicious jobs",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    technical_details={
                        'suspicious_job_count': len(suspicious_jobs),
                        'abuse_type': 'suspicious_job_types'
                    },
                    evidence_lines=[job['line'] for job in suspicious_jobs[:2]]
                )
                detections.append(detection)
        
        return detections
    
    def _analyze_wakelock_abuse(self, log_data: LogData) -> List[Detection]:
        """Analyze wakelock abuse patterns using realistic Android log patterns."""
        detections = []
        
        # Parse wakelock information from logs - realistic Android patterns
        package_wakelocks = self._parse_realistic_wakelock_data(log_data.raw_lines)

        # Analyze each package's wakelock patterns
        for package, wakelocks in package_wakelocks.items():
            if self._is_system_app(package, log_data) or not wakelocks:
                continue
            
            # Calculate wakelock statistics
            total_wakelocks = len(wakelocks)
            total_time_ms = sum(wl.get('total_time_ms', 0) for wl in wakelocks)
            # total_count = sum(wl.get('count', 0) for wl in wakelocks) 
            # kernel_wakelocks = [wl for wl in wakelocks if wl.get('is_kernel', False)]  
            
            # Categorize wakelocks by realistic pattern
            categorized_wakelocks = defaultdict(list)
            for wl in wakelocks:
                wakelock_name = wl.get('name', '').lower()
                for pattern_name, pattern_regex in REALISTIC_WAKELOCK_PATTERNS.items():
                    if pattern_regex.search(wakelock_name):
                        categorized_wakelocks[pattern_name].append(wl)
            
            # Apply spyware detection algorithms with realistic thresholds
            package_detections = []
            
            # High-frequency background polling detection (app-category agnostic)
            if total_wakelocks >= SPYWARE_THRESHOLDS['high_frequency_abuse'][0]:
                avg_duration = total_time_ms / total_wakelocks if total_wakelocks > 0 else 0
                max_allowed_duration = SPYWARE_THRESHOLDS['high_frequency_abuse'][1]

                if avg_duration < max_allowed_duration:
                    # Get installation context for risk adjustment (zero-trust approach)
                    installation_context = self.installation_context_heuristic.get_installation_context(package, log_data)

                    # Base detection parameters
                    base_severity = Severity.HIGH
                    base_confidence = 0.8

                    # Adjust severity and confidence based on installation context
                    if installation_context.installer_source == 'sideloaded':
                        # Sideloaded apps with high-frequency abuse = critical risk
                        severity = Severity.CRITICAL
                        confidence = min(0.95, base_confidence * installation_context.risk_multiplier * 1.2)
                        risk_context = "sideloaded app with suspicious behavior"
                    elif installation_context.installer_source == 'play_store':
                        # Play Store apps still suspicious but lower confidence
                        severity = base_severity
                        confidence = base_confidence * installation_context.risk_multiplier * 0.9
                        risk_context = "Play Store app with suspicious behavior"
                    else:
                        # Unknown installation source
                        severity = base_severity
                        confidence = base_confidence * installation_context.risk_multiplier
                        risk_context = "app with unknown installation source"

                    detection = self._create_behavioral_detection(
                        package=package,
                        category="Wakelock Abuse",
                        title=f"High-Frequency Background Polling: {package}",
                        description=f"Suspicious high-frequency wakelock pattern: {total_wakelocks} wakelocks, avg {avg_duration:.0f}ms ({risk_context})",
                        severity=severity,
                        confidence=confidence,
                        technical_details={
                            'wakelock_count': total_wakelocks,
                            'avg_duration_ms': int(avg_duration),
                            'abuse_type': 'high_frequency_polling',
                            'total_time_minutes': total_time_ms // 60000,
                            'installation_source': installation_context.installer_source,
                            'risk_multiplier': installation_context.risk_multiplier
                        },
                        evidence_lines=[wl.get('raw_line', '') for wl in wakelocks[:3] if wl.get('raw_line')]
                    )
                    package_detections.append(detection)
            
            # Limit detections per package
            detections.extend(package_detections[:self.max_detections_per_package])
        
        return detections
    
    def _parse_realistic_wakelock_data(self, raw_lines: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Parse wakelock data from realistic Android log patterns."""
        package_wakelocks = defaultdict(list)
        current_uid = None
        
        # First pass: build UID to package mapping from realistic Android patterns
        for line in raw_lines:
            line = line.strip()
            
            # Look for UID patterns: "u0a42:" or "u1000:"
            uid_match = re.search(r'u(\d+):', line)
            if uid_match:
                current_uid = uid_match.group(1)
                continue
            
            # Look for package information in subsequent lines
            if current_uid and "Apk " in line:
                pkg_match = re.search(r'Apk\s+([a-zA-Z0-9_.]+):', line)
                if pkg_match:
                    # current_package = pkg_match.group(1)  # Not used currently
                    continue
        
        # Second pass: parse wakelocks with realistic Android patterns
        current_uid = None
        for line in raw_lines:
            line = line.strip()
            
            # Track current UID
            uid_match = re.search(r'u(\d+):', line)
            if uid_match:
                current_uid = uid_match.group(1)
                continue
            
            # Look for realistic wakelock patterns
            if "Wake lock " in line:
                # Pattern: "Wake lock *job*/package/service realtime"
                wl_match = re.search(r'Wake lock\s+([^\s]+)', line)
                if wl_match and current_uid:
                    wakelock_name = wl_match.group(1)
                    
                    # Extract package from wakelock name if possible
                    package = None
                    if '*job*/' in wakelock_name:
                        pkg_match = re.search(r'\*job\*/([^/]+)/', wakelock_name)
                        if pkg_match:
                            package = pkg_match.group(1)
                    elif '::' in wakelock_name:
                        pkg_match = re.search(r'([^:]+)::', wakelock_name)
                        if pkg_match:
                            package = pkg_match.group(1)
                    
                    if package and self._is_valid_package_name(package) and not (package == "android" or "com.android." in package.lower()):
                        package_wakelocks[package].append({
                            'name': wakelock_name,
                            'uid': current_uid,
                            'is_kernel': wakelock_name.startswith('*'),
                            'raw_line': line,
                            'total_time_ms': 0,  # Will be filled from job data if available
                            'count': 1
                        })
        
        return dict(package_wakelocks)
    
    def _analyze_fingerprinting_activity(self, log_data: LogData) -> List[Detection]:
        """Analyze device fingerprinting activity using realistic Android patterns."""
        detections = []
        
        package_permissions = defaultdict(set)
        
        # Extract permissions from package info (more reliable than parsing logs)
        for package_name, package_info in log_data.packages.items():
            permissions = getattr(package_info, 'permissions', set())
            if permissions:
                package_permissions[package_name].update(permissions)
        
        # Also look for permission patterns in realistic Android logs
        for line in log_data.raw_lines:
            line = line.strip()
            
            # Look for permission grants in realistic Android format
            perm_match = re.search(r'Permission\s+([a-zA-Z0-9_.]+)\s+granted\s+to\s+([a-zA-Z0-9_.]+)', line)
            if perm_match:
                permission = perm_match.group(1)
                package = perm_match.group(2)
                if self._is_valid_package_name(package):
                    package_permissions[package].add(permission)
        
        # Analyze fingerprinting patterns
        for package, permissions in package_permissions.items():
            if self._is_system_app(package, log_data):
                continue
            
            # Check for critical fingerprinting permissions
            critical_perms = permissions.intersection(CRITICAL_FINGERPRINTING_PERMS)
            if critical_perms:
                detection = self._create_behavioral_detection(
                    package=package,
                    category="Device Fingerprinting",
                    title=f"Critical Fingerprinting Permissions: {package}",
                    description=f"Package has critical fingerprinting permissions: {', '.join(critical_perms)}",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    technical_details={
                        'critical_fingerprinting_permissions': list(critical_perms),
                        'abuse_type': 'critical_fingerprinting_permissions'
                    },
                    evidence_lines=[]  # Permissions are metadata-only
                )
                detections.append(detection)
            
            # Check for multiple fingerprinting permissions
            fingerprint_perms = permissions.intersection(MULTIPLE_FINGERPRINTING_PERMS)
            if len(fingerprint_perms) >= 4:  # Threshold for suspicious combinations
                detection = self._create_behavioral_detection(
                    package=package,
                    category="Device Fingerprinting",
                    title=f"Multiple Fingerprinting Permissions: {package}",
                    description=f"Package has {len(fingerprint_perms)} fingerprinting permissions",
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    technical_details={
                        'fingerprinting_permissions': list(fingerprint_perms),
                        'permission_count': len(fingerprint_perms),
                        'abuse_type': 'multiple_fingerprinting_permissions'
                    },
                    evidence_lines=[]
                )
                detections.append(detection)
        
        return detections
    
    def _analyze_usage_statistics(self, log_data: LogData) -> List[Detection]:
        """Analyze usage statistics for suspicious patterns."""
        detections = []
        
        # Use parsed AppOps data from LogData if available, otherwise fall back to parsing raw lines
        appops_data = self._get_appops_data(log_data)
        
        # Analyze AppOps patterns for each package
        for package, ops_data in appops_data.items():
            if self._is_system_app(package, log_data):
                continue
            
            package_detections = self._analyze_appops_patterns(package, ops_data)
            detections.extend(package_detections[:self.max_detections_per_package])
        
        return detections
    
    def _get_appops_data(self, log_data: LogData) -> Dict[str, Dict[str, Any]]:
        """Get AppOps data from parsed events or fall back to parsing raw lines."""
        appops_data = {}
        
        # First, try to extract AppOps data from parsed events
        for event in log_data.parsed_events:
            if event.get('entry_type') == 'appops_entry':
                package = event.get('package')
                if package and not self._is_system_app(package, log_data):
                    if package not in appops_data:
                        appops_data[package] = {}
                    
                    operation = event.get('parsed_content', {}).get('operation')
                    if operation:
                        if operation not in appops_data[package]:
                            appops_data[package][operation] = {
                                'mode': event.get('parsed_content', {}).get('mode'),
                                'duration_secs': event.get('parsed_content', {}).get('duration_secs'),
                                'access_states': [],
                                'raw_line': event.get('raw_line', '')
                            }
                        
                        # Collect access states
                        access_type = event.get('parsed_content', {}).get('access_type')
                        if access_type:
                            appops_data[package][operation]['access_states'].append(access_type)
        
        # If no parsed AppOps data found, fall back to parsing raw lines
        if not appops_data:
            appops_data = self._parse_appops_data(log_data.raw_lines)
        
        # Calculate ratios for packages with access states
        for package, ops in appops_data.items():
            for operation, data in ops.items():
                access_states = data.get('access_states', [])
                if access_states:
                    total_states = len(access_states)
                    data['bg_ratio'] = access_states.count('bg') / total_states
                    data['fgsvc_ratio'] = access_states.count('fgsvc') / total_states
                    data['top_ratio'] = access_states.count('top') / total_states
                    data['cch_ratio'] = access_states.count('cch') / total_states
                    data['fg_ratio'] = access_states.count('fg') / total_states
        
        return appops_data
    
    def _create_behavioral_detection(self, package: str, category: str, title: str, 
                                   description: str, severity: Severity, confidence: float,
                                   technical_details: Dict[str, Any], 
                                   evidence_lines: List[str]) -> Detection:
        """Create a behavioral detection with proper evidence."""
        evidence_list = []
        
        # Add log evidence if available
        for line in evidence_lines[:3]:  # Limit evidence
            if line and line.strip():
                evidence_list.append(Evidence(
                    type=EvidenceType.LOG_ANCHOR,
                    content=line.strip(),
                    confidence=0.7
                ))
        
        # Add metadata evidence
        if technical_details:
            metadata_content = f"Behavioral pattern detected: {technical_details.get('abuse_type', 'unknown')}"
            evidence_list.append(Evidence(
                type=EvidenceType.METADATA_ONLY,
                content=metadata_content,
                confidence=0.8
            ))
        
        # Apply quality gates
        has_log_evidence = any(e.type == EvidenceType.LOG_ANCHOR for e in evidence_list)
        if self.require_log_evidence and not has_log_evidence:
            # For behavioral analysis, we often rely on patterns in logs
            # If no log evidence, lower the confidence
            confidence *= 0.7
        
        # Add heuristic name to technical details
        technical_details['heuristic_name'] = self.name
        technical_details['package_name'] = package
        
        return Detection(
            category=category,
            package=package,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            evidence=evidence_list,
            technical_details=technical_details
        )

    def _analyze_foreground_mismatch(self, log_data: LogData) -> List[Detection]:
        """Enhanced stealth behavior detection using realistic Android patterns."""
        detections = []
        
        # Parse usage statistics for foreground/background analysis
        usage_stats = self._parse_realistic_usage_statistics(log_data.raw_lines)
        
        # Parse battery statistics for background CPU correlation
        battery_stats = self._parse_battery_statistics(log_data.raw_lines)
        
        # Parse AppOps for foreground service correlation
        # Note: AppOps format may vary between OEMs but this handles common patterns
        appops_data = self._parse_appops_data(log_data.raw_lines)
        
        # Analyze stealth patterns for each package
        for package in set(list(usage_stats.keys()) + list(battery_stats.keys()) + list(appops_data.keys())):
            if self._is_system_app(package, log_data):
                continue
            
            # Get data for this package
            usage = usage_stats.get(package, {})
            battery = battery_stats.get(package, {})
            appops = appops_data.get(package, {})
            
            stealth_indicators = []
            stealth_score = 0
            
            # 1. Usage Statistics Analysis
            total_time = usage.get('total_time_ms', 0)
            fg_time = usage.get('foreground_time_ms', 0)
            launches = usage.get('launch_count', 0)
            
            if total_time > 300000:  # 5+ minutes total usage
                bg_time = total_time - fg_time
                bg_ratio = bg_time / total_time if total_time > 0 else 0
                
                if bg_ratio > 0.8:  # 80%+ background
                    stealth_score += 3
                    stealth_indicators.append(f"Background usage: {bg_ratio:.1%}")
                elif bg_ratio > 0.6:  # 60%+ background
                    stealth_score += 2
                    stealth_indicators.append(f"High background usage: {bg_ratio:.1%}")
            
            # 2. Launch Pattern Analysis (high usage, low launches = automated)
            if total_time > 600000 and launches < 5:  # 10+ minutes, <5 launches
                stealth_score += 2
                stealth_indicators.append(f"Automated behavior: {total_time//60000}min usage, {launches} launches")
            
            # 3. Battery Background CPU Correlation
            cpu_time = battery.get('cpu_time', 0)
            bg_cpu_time = battery.get('background_time', 0)
            if cpu_time > 0:
                cpu_bg_ratio = bg_cpu_time / cpu_time
                if cpu_bg_ratio > 0.7:  # 70%+ background CPU
                    stealth_score += 2
                    stealth_indicators.append(f"Background CPU: {cpu_bg_ratio:.1%}")
            
            # 4. Foreground Service Stealth Detection
            fgs_data = appops.get('START_FOREGROUND', {})
            if fgs_data:
                fgs_duration = fgs_data.get('duration_secs', 0)
                fgs_ratio = fgs_data.get('fgsvc_ratio', 0)
                
                if fgs_duration > 1800 and fgs_ratio > 0.8:  # 30+ min FGS, 80%+ FGS usage
                    stealth_score += 3
                    stealth_indicators.append(f"Persistent FGS: {fgs_duration//60}min ({fgs_ratio:.1%})")
            
            # 5. Service Persistence Detection
            if self._has_persistent_background_services(package, log_data.raw_lines):
                stealth_score += 2
                stealth_indicators.append("Long-running background services")
            
            # Generate detection if stealth behavior detected
            if stealth_score >= 4:  # Threshold for stealth behavior
                severity = self._calculate_stealth_severity(stealth_score, bg_ratio if 'bg_ratio' in locals() else 0)
                confidence = min(0.95, 0.6 + (stealth_score * 0.05))
                
                stealth_type = self._determine_stealth_type(stealth_indicators)
                
                detection = self._create_behavioral_detection(
                    package=package,
                    category="Stealth Behavior",
                    title=f"{stealth_type}: {package}",
                    description=f"App exhibits stealth behavior: {', '.join(stealth_indicators[:3])}",
                    severity=severity,
                    confidence=confidence,
                    technical_details={
                        'stealth_score': stealth_score,
                        'stealth_indicators': stealth_indicators,
                        'background_ratio': bg_ratio if 'bg_ratio' in locals() else 0,
                        'total_time_minutes': total_time // 60000,
                        'foreground_time_minutes': fg_time // 60000,
                        'launch_count': launches,
                        'stealth_type': stealth_type.lower().replace(' ', '_'),
                        'abuse_type': 'stealth_behavior'
                    },
                    evidence_lines=self._get_stealth_evidence_lines(package, log_data.raw_lines)
                )
                detections.append(detection)
        
        return detections
    
    def _analyze_appops_behavioral_patterns(self, log_data: LogData) -> List[Detection]:
        """
        Analyze AppOps data for behavioral patterns (not sensor legitimacy).
        Focuses on suspicious behavioral combinations and usage patterns.
        """
        detections = []

        # Parse AppOps data for behavioral analysis
        appops_data = self._parse_appops_data(log_data.raw_lines)

        # Debug logging to understand what's being parsed
        self.logger.info(f"AppOps behavioral analysis: Found {len(appops_data)} packages")
        for package, ops in appops_data.items():
            self.logger.info(f"Package {package}: {list(ops.keys())}")
            for op_name, op_data in ops.items():
                duration = op_data.get('duration_secs', 0)
                mode = op_data.get('mode', 'unknown')
                self.logger.info(f"  {op_name}: mode={mode}, duration={duration}s")

        # Analyze behavioral patterns for each package
        for package, ops_data in appops_data.items():
            is_system = self._is_system_app(package, log_data)
            self.logger.info(f"Analyzing package {package}: is_system={is_system}")
            if is_system:
                self.logger.info(f"Skipping system app: {package}")
                continue

            # Analyze suspicious behavioral combinations
            behavioral_score = 0
            suspicious_patterns = []

            # Pattern 1: Excessive sensor activity (background OR long duration)
            background_sensors = 0
            total_background_duration = 0
            long_duration_sensors = 0
            total_sensor_duration = 0

            for op_name in ['CAMERA', 'RECORD_AUDIO', 'COARSE_LOCATION', 'FINE_LOCATION']:
                if op_name in ops_data:
                    op_data = ops_data[op_name]
                    duration = op_data.get('duration_secs', 0)
                    bg_ratio = op_data.get('bg_ratio', 0)
                    mode = op_data.get('mode', 'unknown')

                    if mode == 'allow' and duration > 0:
                        total_sensor_duration += duration

                        # Background usage detection
                        if bg_ratio > 0.5 and duration > 60:  # 50%+ background for 1+ min
                            background_sensors += 1
                            total_background_duration += duration * bg_ratio

                        # Long duration detection (regardless of background/foreground)
                        if duration > 300:  # 5+ minutes of any sensor usage
                            long_duration_sensors += 1
                            suspicious_patterns.append(f"{op_name}: {duration/60:.1f}min duration")

            # Score for background sensors
            if background_sensors >= 2:  # Multiple sensors used in background
                behavioral_score += 3
                suspicious_patterns.append(f"Multiple background sensors: {background_sensors} sensors, {total_background_duration/60:.1f}min total")

            # Score for long duration sensors (major red flag)
            if long_duration_sensors >= 1:  # Any long-duration sensor usage
                behavioral_score += 2
                if total_sensor_duration > 3600:  # 1+ hour total
                    behavioral_score += 2  # Extra points for very long usage

            # Pattern 2: Critical stealth operations (major red flags)
            if 'BIND_ACCESSIBILITY_SERVICE' in ops_data and ops_data['BIND_ACCESSIBILITY_SERVICE'].get('mode') == 'allow':
                behavioral_score += 4  # Accessibility service is a major red flag
                suspicious_patterns.append("BIND_ACCESSIBILITY_SERVICE: Can intercept all user interactions")

            if 'GET_USAGE_STATS' in ops_data and ops_data['GET_USAGE_STATS'].get('mode') == 'allow':
                behavioral_score += 2  # Usage stats access
                suspicious_patterns.append("GET_USAGE_STATS: Can monitor app usage patterns")

            # Pattern 3: Stealth operation combinations
            stealth_ops = ['SYSTEM_ALERT_WINDOW', 'TOAST_WINDOW', 'PROJECT_MEDIA']
            active_stealth_ops = [op for op in stealth_ops if op in ops_data]

            if len(active_stealth_ops) >= 2:
                behavioral_score += 2
                suspicious_patterns.append(f"Stealth operation combination: {', '.join(active_stealth_ops)}")

            # Pattern 4: Data collection pattern (sensors + data access)
            data_collection_ops = ['GET_ACCOUNTS', 'OP_READ_PHONE_STATE', 'READ_EXTERNAL_STORAGE']
            sensor_ops = ['CAMERA', 'RECORD_AUDIO', 'COARSE_LOCATION', 'FINE_LOCATION']

            active_data_ops = [op for op in data_collection_ops if op in ops_data]
            active_sensor_ops = [op for op in sensor_ops if op in ops_data]

            if len(active_data_ops) >= 1 and len(active_sensor_ops) >= 2:
                behavioral_score += 2
                suspicious_patterns.append(f"Data collection pattern: {len(active_sensor_ops)} sensors + {len(active_data_ops)} data access")

            # Pattern 4: Persistent background execution
            if 'START_FOREGROUND' in ops_data and 'WAKE_LOCK' in ops_data:
                fgs_duration = ops_data['START_FOREGROUND'].get('duration_secs', 0)
                wakelock_duration = ops_data['WAKE_LOCK'].get('duration_secs', 0)

                if fgs_duration > 3600 or wakelock_duration > 1800:  # 1h FGS or 30min wakelock
                    behavioral_score += 1
                    suspicious_patterns.append(f"Persistent execution: FGS {fgs_duration/60:.1f}min, Wakelock {wakelock_duration/60:.1f}min")

            # Debug logging for scoring
            self.logger.info(f"Package {package} behavioral score: {behavioral_score}, patterns: {suspicious_patterns}")

            # Create detection if behavioral score is high enough (lowered threshold for better detection)
            if behavioral_score >= 2:
                # Get installation context for risk adjustment (zero-trust approach)
                installation_context = self.installation_context_heuristic.get_installation_context(package, log_data)

                # Base detection parameters
                base_severity = Severity.HIGH if behavioral_score >= 4 else Severity.MEDIUM
                base_confidence = min(0.8, 0.6 + (behavioral_score * 0.1))

                # Adjust severity and confidence based on installation context
                if installation_context.installer_source == 'sideloaded':
                    # Sideloaded apps with suspicious behavioral patterns = critical risk
                    severity = Severity.CRITICAL if behavioral_score >= 4 else Severity.HIGH
                    confidence = min(0.95, base_confidence * installation_context.risk_multiplier * 1.2)
                    risk_context = "sideloaded app with suspicious behavioral patterns"
                elif installation_context.installer_source == 'play_store':
                    # Play Store apps still concerning but lower risk
                    severity = base_severity
                    confidence = base_confidence * installation_context.risk_multiplier * 0.9
                    risk_context = "Play Store app with suspicious behavioral patterns"
                else:
                    # Unknown installation source
                    severity = base_severity
                    confidence = base_confidence * installation_context.risk_multiplier
                    risk_context = "app with unknown installation source"

                detection = self._create_behavioral_detection(
                    package=package,
                    category="Behavioral Pattern",
                    title=f"Suspicious AppOps Behavioral Pattern: {package}",
                    description=f"App shows suspicious behavioral patterns across multiple operations (score: {behavioral_score}) ({risk_context})",
                    severity=severity,
                    confidence=confidence,
                    technical_details={
                        'behavioral_score': behavioral_score,
                        'suspicious_patterns': suspicious_patterns,
                        'background_sensors': background_sensors,
                        'total_background_duration': total_background_duration,
                        'abuse_type': 'appops_behavioral_pattern',
                        'installation_source': installation_context.installer_source,
                        'risk_multiplier': installation_context.risk_multiplier
                    },
                    evidence_lines=[f"Pattern: {pattern}" for pattern in suspicious_patterns[:3]]
                )
                detections.append(detection)

        return detections

    def _analyze_location_misuse(self, log_data: LogData) -> List[Detection]:
        """Enhanced location tracking analysis with realistic Android patterns."""
        detections = []
        
        # Parse AppOps data for location usage (primary source)
        appops_data = self._parse_appops_data(log_data.raw_lines)
        
        # Get usage statistics for correlation
        usage_stats = self._parse_realistic_usage_statistics(log_data.raw_lines)
        
        # Analyze location patterns for each package
        for package, ops_data in appops_data.items():
            if self._is_system_app(package, log_data):
                continue
            
            package_detections = []
            
            for op_name in ['COARSE_LOCATION', 'FINE_LOCATION', 'MONITOR_LOCATION']:
                if op_name in ops_data:
                    op_data = ops_data[op_name]
                    duration = op_data.get('duration_secs', 0)
                    bg_ratio = op_data.get('bg_ratio', 0)
                    fgsvc_ratio = op_data.get('fgsvc_ratio', 0)
                    
                    # Enhanced location tracking detection
                    if duration > 3600:  # 1+ hour of location access
                        severity = self._calculate_location_severity(duration, bg_ratio, fgsvc_ratio, package, usage_stats)
                        confidence = self._calculate_location_confidence(duration, bg_ratio, fgsvc_ratio, package)
                        
                        # Determine tracking type
                        tracking_type = self._determine_location_tracking_type(duration, bg_ratio, fgsvc_ratio)
                        
                        detection = self._create_behavioral_detection(
                            package=package,
                            category="Location Tracking",
                            title=f"{tracking_type}: {package}",
                            description=f"App shows {tracking_type.lower()}: {duration/3600:.1f}h location access ({bg_ratio*100:.0f}% background)",
                            severity=severity,
                            confidence=confidence,
                            technical_details={
                                'location_operation': op_name,
                                'duration_hours': duration / 3600,
                                'background_ratio': bg_ratio,
                                'foreground_service_ratio': fgsvc_ratio,
                                'tracking_type': tracking_type.lower().replace(' ', '_'),
                                'abuse_type': 'location_tracking'
                            },
                            evidence_lines=[op_data.get('raw_line', '')]
                        )
                        package_detections.append(detection)
            
            # Limit detections per package
            detections.extend(package_detections[:self.max_detections_per_package])
        
        return detections
    
    def _parse_realistic_usage_statistics(self, raw_lines: List[str]) -> Dict[str, Dict[str, Any]]:
        """Parse usage statistics for foreground/background analysis."""
        usage_stats = defaultdict(lambda: {
            'total_time_ms': 0, 'foreground_time_ms': 0, 'launch_count': 0
        })
        
        for line in raw_lines:
            line = line.strip()
            
            # Parse realistic usage statistics format from Android logs
            # Pattern: "Total running: 2h 21m 22s 649ms"
            if "Total running:" in line:
                # This would need context to associate with package
                continue
            
            # Parse realistic launch count patterns
            if "starts" in line and "Proc " in line:
                proc_match = re.search(r'Proc\s+([a-zA-Z0-9_.]+):', line)
                if proc_match:
                    package = proc_match.group(1)
                    if not (package == "android" or "com.android." in package.lower()):
                        starts_match = re.search(r'(\d+)\s+starts', line)
                        if starts_match:
                            starts = int(starts_match.group(1))
                            usage_stats[package]['launch_count'] = max(usage_stats[package]['launch_count'], starts)
        
        return dict(usage_stats)
    
    # Duplicate battery statistics parsing method removed - using centralized _parse_battery_statistics instead
    
    def _calculate_location_severity(self, duration: float, bg_ratio: float, fgsvc_ratio: float,
                                   package: str, usage_stats: Dict) -> Severity:
        """Calculate severity for location tracking based on multiple factors."""
        # Consider foreground service ratio for legitimate use cases
        legitimate_fgsvc_threshold = 0.3  # 30%+ foreground service usage suggests legitimate use

        # Check if app has low user interaction (suspicious for location tracking)
        app_usage = usage_stats.get(package, {})
        user_interaction_time = app_usage.get('foreground_time', 0)

        # System apps get different treatment (use zero-trust verification)
        # Note: Using basic system package check as fallback since log_data not available in this context
        if package == "android" or "com.android." in package.lower():
            # System apps can legitimately use location in background
            if bg_ratio > 0.9 and duration > 21600:  # 90%+ background for 6+ hours
                return Severity.HIGH
            else:
                return Severity.MEDIUM

        # For user apps, high background usage with low user interaction is suspicious
        if bg_ratio > 0.7 and fgsvc_ratio < legitimate_fgsvc_threshold:
            if user_interaction_time < 300:  # Less than 5 minutes user interaction
                return Severity.CRITICAL
            else:
                return Severity.HIGH
        elif duration > 14400:  # 4+ hours
            return Severity.CRITICAL
        elif bg_ratio > 0.5 or duration > 7200:  # 50%+ background or 2+ hours
            return Severity.HIGH
        else:
            return Severity.MEDIUM
    
    def _calculate_location_confidence(self, duration: float, bg_ratio: float, fgsvc_ratio: float,
                                     package: str) -> float:
        """Calculate confidence for location tracking detection."""
        confidence = 0.7

        # Factor in foreground service usage for confidence
        if fgsvc_ratio > 0.5:
            confidence += 0.1  # Higher confidence if using foreground services
        
        # Higher confidence for longer duration
        if duration > 14400:  # 4+ hours
            confidence += 0.2
        elif duration > 7200:  # 2+ hours
            confidence += 0.1
        
        # Higher confidence for background usage
        if bg_ratio > 0.7:
            confidence += 0.2
        elif bg_ratio > 0.5:
            confidence += 0.1
        
        # Lower confidence for legitimate location apps
        legitimate_apps = ['maps', 'navigation', 'uber', 'lyft', 'waze', 'gps']
        if any(app in package.lower() for app in legitimate_apps):
            confidence *= 0.7
        
        return min(0.95, confidence)
    
    def _determine_location_tracking_type(self, duration: float, bg_ratio: float, fgsvc_ratio: float) -> str:
        """Determine the type of location tracking behavior."""
        if bg_ratio > 0.8:
            return "Background Location Stalking"
        elif fgsvc_ratio > 0.6 and bg_ratio > 0.4:
            return "Stealth Location Tracking"
        elif duration > 14400:  # 4+ hours
            return "Excessive Location Monitoring"
        else:
            return "Suspicious Location Access"
    
    def _calculate_stealth_severity(self, stealth_score: int, bg_ratio: float) -> Severity:
        """Calculate severity for stealth behavior."""
        if stealth_score >= 8 or bg_ratio > 0.9:
            return Severity.CRITICAL
        elif stealth_score >= 6 or bg_ratio > 0.8:
            return Severity.HIGH
        else:
            return Severity.MEDIUM
    
    def _determine_stealth_type(self, indicators: List[str]) -> str:
        """Determine the type of stealth behavior."""
        indicator_text = ' '.join(indicators).lower()
        
        if 'persistent fgs' in indicator_text or 'background services' in indicator_text:
            return "Persistent Background Execution"
        elif 'automated behavior' in indicator_text:
            return "Automated Background Activity"
        elif 'background cpu' in indicator_text:
            return "Covert Resource Consumption"
        else:
            return "Stealth Background Operation"
    
    def _has_persistent_background_services(self, package: str, raw_lines: List[str]) -> bool:
        """Check if package has long-running background services."""
        service_lines = 0
        for line in raw_lines:
            if package in line and ("Service " in line or "Created for:" in line):
                service_lines += 1
                if service_lines >= 3:  # Multiple service references suggest persistence
                    return True
        return False
    
    def _get_stealth_evidence_lines(self, package: str, raw_lines: List[str]) -> List[str]:
        """Get evidence lines for stealth behavior detection using realistic Android patterns."""
        evidence_lines = []
        for line in raw_lines:
            if package in line and any(keyword in line.lower() for keyword in 
                                     ['total running', 'cpu:', 'background for', 'service ']):
                evidence_lines.append(line)
                if len(evidence_lines) >= 3:
                    break
        return evidence_lines
    
    def _is_system_app(self, package: str, log_data: LogData) -> bool:
        """
        Check if package is a system app using zero-trust verification.
        Uses installation_context heuristic instead of trusting package names.
        """
        if not package:
            return False

        # Explicitly exclude the base android package from being flagged
        if package == "android":
            return True

        # Use installation context heuristic for zero-trust verification
        installation_context = self.installation_context_heuristic.get_installation_context(package, log_data)

        # Handle case where installation context returns string instead of boolean
        is_system = installation_context.is_system_app
        if isinstance(is_system, str):
            # If it's a string like 'Unable to determine', treat as False (not system app)
            return False

        return bool(is_system)
    
    def _is_valid_package_name(self, name: str) -> bool:
        """Check if a string is a valid Android package name format."""
        if not name or len(name) < 3:
            return False
        
        core_system_names = {"android", "system", "kernel", "init", "zygote"}
        if name in core_system_names:
            return True
        
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$', name):
            return False
        
        invalid_patterns = [r'^\d+$', r'^[a-zA-Z]{1,4}$', r'^\w{1,2}$', r'^u\d+a\d+$']
        for pattern in invalid_patterns:
            if re.match(pattern, name):
                return False
        
        return True
    
    def _extract_config_dict(self, config) -> Dict[str, Any]:
        """Extract configuration dictionary from various config formats."""
        if config and hasattr(config, 'settings'):
            return config.settings
        elif config and hasattr(config, '__dict__'):
            return config.__dict__
        else:
            return config or {}
    
    def _parse_appops_data(self, raw_lines: List[str]) -> Dict[str, Dict[str, Any]]:
        """Parse AppOps data from raw log lines for behavioral analysis."""
        appops_data = defaultdict(lambda: defaultdict(dict))
        current_package = None
        current_operation = None
        
        # OEM-specific duration parsing patterns 
        # Different OEMs use different AppOps output formats
        OEM_DURATION_PATTERNS = {
            'samsung': re.compile(r'duration=\+(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?'),
            'xiaomi': re.compile(r'time_used=(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?'),
            'huawei': re.compile(r'usage_time=(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?'),
            'oppo': re.compile(r'duration=(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?'),  # No + prefix
            'vivo': re.compile(r'time=(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?'),
            'oneplus': re.compile(r'duration=\+(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?'),
            'generic': re.compile(r'(?:duration|time|usage)[=:].*?(\d+).*?(?:h|hour|m|min|s|sec|ms)')
        }

        access_state_pattern = re.compile(r'(?:Access:\s*)?(top|fgsvc|bg|cch|fg)\s*=')
        
        for line in raw_lines:
            line = line.strip()
            
            # Package detection
            pkg_match = re.search(r'Package ([a-zA-Z0-9_.]+):', line)
            if pkg_match:
                current_package = pkg_match.group(1)
                continue
            
            if not current_package or (current_package == "android" or "com.android." in current_package.lower()):
                continue
            
            # Operation detection with mode - fixed to match actual AppOps format
            # Format: "      CAMERA (allow):" or "      CAMERA (allow / switch COARSE_LOCATION=allow):"
            op_match = re.search(r'(COARSE_LOCATION|FINE_LOCATION|CAMERA|RECORD_AUDIO|WAKE_LOCK|GET_ACCOUNTS|OP_READ_PHONE_STATE|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|BIND_ACCESSIBILITY_SERVICE|START_FOREGROUND|TOAST_WINDOW|GET_USAGE_STATS|RUN_IN_BACKGROUND|CHANGE_WIFI_STATE|PROJECT_MEDIA|WIFI_SCAN|WRITE_SMS)\s*\((allow|ignore|deny)(?:[^)]*)\)\s*:', line)
            if op_match:
                current_operation = op_match.group(1)
                mode = op_match.group(2)
                appops_data[current_package][current_operation]['mode'] = mode
                continue
            
            if not current_operation:
                continue
            
            # Access pattern detection
            if 'Access:' in line or any(state in line for state in ['top', 'fgsvc', 'bg', 'cch', 'fg']):
                access_states = access_state_pattern.findall(line)
                if access_states:
                    # Initialize access_states list if not exists
                    if 'access_states' not in appops_data[current_package][current_operation]:
                        appops_data[current_package][current_operation]['access_states'] = []
                    
                    # Add new access states to the list
                    appops_data[current_package][current_operation]['access_states'].extend(access_states)
                    
                    # Calculate background vs foreground ratios from all collected states
                    all_states = appops_data[current_package][current_operation]['access_states']
                    total_states = len(all_states)
                    bg_ratio = all_states.count('bg') / total_states
                    top_ratio = all_states.count('top') / total_states
                    fgsvc_ratio = all_states.count('fgsvc') / total_states
                    cch_ratio = all_states.count('cch') / total_states
                    
                    appops_data[current_package][current_operation]['bg_ratio'] = bg_ratio
                    appops_data[current_package][current_operation]['top_ratio'] = top_ratio
                    appops_data[current_package][current_operation]['fgsvc_ratio'] = fgsvc_ratio
                    appops_data[current_package][current_operation]['cch_ratio'] = cch_ratio
            
            # Duration parsing with OEM-specific patterns
            duration_seconds = self._parse_duration_with_oem_patterns(line, OEM_DURATION_PATTERNS)
            if duration_seconds > 0 and current_package and current_operation:
                appops_data[current_package][current_operation]['duration_secs'] = duration_seconds
                appops_data[current_package][current_operation]['raw_line'] = line
            
            # Reject detection
            if 'Reject:' in line:
                appops_data[current_package][current_operation]['has_rejects'] = True
        
        return dict(appops_data)
    
    def _analyze_appops_patterns(self, package: str, ops_data: Dict[str, Any]) -> List[Detection]:
        """Analyze AppOps data for spyware behavioral patterns."""
        detections = []
        
        # Analyze different types of suspicious AppOps patterns
        surveillance_ops = ['CAMERA', 'RECORD_AUDIO', 'COARSE_LOCATION', 'FINE_LOCATION']
        data_ops = ['GET_ACCOUNTS', 'OP_READ_PHONE_STATE', 'READ_EXTERNAL_STORAGE']
        
        # 1. Covert surveillance detection
        covert_surveillance_score = 0
        surveillance_evidence = []
        
        for op in surveillance_ops:
            if op in ops_data:
                op_data = ops_data[op]
                duration = op_data.get('duration_secs', 0) or 0  # Convert None to 0
                bg_ratio = op_data.get('bg_ratio', 0) or 0  # Convert None to 0
                
                # Detect covert usage patterns with realistic thresholds
                if duration > 7200:  # 2+ hours - CRITICAL
                    covert_surveillance_score += 5
                    surveillance_evidence.append(f"{op}: {duration/3600:.1f}h ({bg_ratio*100:.0f}% background)")
                elif duration > 1800 and bg_ratio > 0.5:  # 30+ minutes with 50%+ background
                    covert_surveillance_score += 4
                    surveillance_evidence.append(f"{op}: {duration/60:.1f}min ({bg_ratio*100:.0f}% background)")
                elif duration > 300 and bg_ratio > 0.6:  # 5+ minutes with 60%+ background usage
                    covert_surveillance_score += 3
                    surveillance_evidence.append(f"{op}: {duration/60:.1f}min ({bg_ratio*100:.0f}% background)")
                elif duration > 60 and bg_ratio > 0.8:  # 1+ minute with 80%+ background usage
                    covert_surveillance_score += 2
                    surveillance_evidence.append(f"{op}: {duration/60:.1f}min ({bg_ratio*100:.0f}% background)")
        
        if covert_surveillance_score >= 3:
            detection = self._create_behavioral_detection(
                package=package,
                category="Covert Surveillance",
                title=f"Covert Surveillance Pattern: {package}",
                description=f"App shows covert surveillance behavior: {', '.join(surveillance_evidence)}",
                severity=Severity.CRITICAL,
                confidence=0.9,
                technical_details={
                    'surveillance_score': covert_surveillance_score,
                    'surveillance_operations': surveillance_evidence,
                    'abuse_type': 'covert_surveillance'
                },
                evidence_lines=[ops_data[op].get('raw_line', '') for op in surveillance_ops if op in ops_data]
            )
            detections.append(detection)
        
        # 2. Excessive foreground service abuse
        foreground_abuse_score = 0
        fgs_evidence = []
        
        # Check specifically for START_FOREGROUND operations
        if 'START_FOREGROUND' in ops_data:
            op_data = ops_data['START_FOREGROUND']
            fgsvc_ratio = op_data.get('fgsvc_ratio', 0) or 0  # Convert None to 0
            duration = op_data.get('duration_secs', 0) or 0  # Convert None to 0
            
            # Detect excessive FGS usage with realistic thresholds
            if duration > 14400:  # 4+ hours - CRITICAL
                foreground_abuse_score += 5
                fgs_evidence.append(f"START_FOREGROUND: {duration/3600:.1f}h FGS")
            elif fgsvc_ratio > 0.5 and duration > 7200:  # 50%+ FGS usage for 2+ hours
                foreground_abuse_score += 4
                fgs_evidence.append(f"START_FOREGROUND: {duration/60:.1f}min FGS")
            elif fgsvc_ratio > 0.5 and duration > 1800:  # 50%+ FGS usage for 30+ minutes
                foreground_abuse_score += 3
                fgs_evidence.append(f"START_FOREGROUND: {duration/60:.1f}min FGS")
            elif fgsvc_ratio > 0.3 and duration > 3600:  # 30%+ FGS usage for 1+ hour
                foreground_abuse_score += 2
                fgs_evidence.append(f"START_FOREGROUND: {duration/60:.1f}min FGS")
        
        if foreground_abuse_score >= 2:
            detection = self._create_behavioral_detection(
                package=package,
                category="Foreground Service Abuse",
                title=f"Excessive Foreground Service Usage: {package}",
                description=f"App abuses foreground services: {', '.join(fgs_evidence)}",
                severity=Severity.HIGH,
                confidence=0.85,
                technical_details={
                    'fgs_abuse_score': foreground_abuse_score,
                    'fgs_operations': fgs_evidence,
                    'abuse_type': 'foreground_service_abuse'
                },
                evidence_lines=[ops_data[op].get('raw_line', '') for op in ops_data if ops_data[op].get('fgsvc_ratio', 0) > 0.3]
            )
            detections.append(detection)
        
        # 3. Data collection pattern detection
        data_collection_score = 0
        data_evidence = []
        
        for op in data_ops:
            if op in ops_data:
                op_data = ops_data[op]
                mode = op_data.get('mode', 'unknown')
                has_rejects = op_data.get('has_rejects', False)
                
                if mode == 'allow':
                    data_collection_score += 1
                    data_evidence.append(f"{op}: allowed")
                elif has_rejects:
                    data_collection_score += 0.5  # Attempted access
                    data_evidence.append(f"{op}: attempted (rejected)")
        
        # Accessibility service analysis is handled by permissions heuristic to avoid duplication
        
        if data_collection_score >= 3:
            detection = self._create_behavioral_detection(
                package=package,
                category="Data Collection",
                title=f"Extensive Data Collection: {package}",
                description=f"App shows extensive data collection patterns: {', '.join(data_evidence)}",
                severity=Severity.HIGH,
                confidence=0.8,
                technical_details={
                    'data_collection_score': data_collection_score,
                    'data_operations': data_evidence,
                    'abuse_type': 'data_collection'
                },
                evidence_lines=[ops_data[op].get('raw_line', '') for op in data_ops if op in ops_data]
            )
            detections.append(detection)
        
        # 4. Wake lock abuse detection
        if 'WAKE_LOCK' in ops_data:
            wakelock_data = ops_data['WAKE_LOCK']
            duration = wakelock_data.get('duration_secs', 0) or 0  # Convert None to 0
            bg_ratio = wakelock_data.get('bg_ratio', 0) or 0  # Convert None to 0
            
            if duration > 1800 and bg_ratio > 0.7:  # 30+ minutes with 70%+ background
                detection = self._create_behavioral_detection(
                    package=package,
                    category="Wakelock Abuse",
                    title=f"Excessive Wakelock Usage: {package}",
                    description=f"App holds wakelocks for {duration/60:.1f} minutes ({bg_ratio*100:.0f}% background)",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    technical_details={
                        'wakelock_duration_minutes': duration / 60,
                        'background_ratio': bg_ratio,
                        'abuse_type': 'wakelock_abuse'
                    },
                    evidence_lines=[wakelock_data.get('raw_line', '')]
                )
                detections.append(detection)
        
        # 5. Combined spyware pattern detection
        combined_score = covert_surveillance_score + foreground_abuse_score + data_collection_score
        suspicious_ops = []
        
        # Count suspicious operations (excluding accessibility service - handled by permissions heuristic)
        for op in ops_data:
            op_data = ops_data[op]
            mode = op_data.get('mode', 'unknown')
            duration = op_data.get('duration_secs', 0) or 0  # Convert None to 0
            
            if mode == 'allow':
                if op in ['CAMERA', 'RECORD_AUDIO', 'COARSE_LOCATION', 'FINE_LOCATION'] and duration > 300:
                    suspicious_ops.append(f"{op} ({duration/60:.1f}min)")
                elif op in ['START_FOREGROUND']:  # FGS abuse is behavioral
                    suspicious_ops.append(f"{op}")
                elif op in ['WRITE_SMS', 'GET_ACCOUNTS', 'OP_READ_PHONE_STATE']:
                    suspicious_ops.append(f"{op}")
        
        # Detect combined spyware patterns
        if len(suspicious_ops) >= 4 and combined_score >= 6:
            detection = self._create_behavioral_detection(
                package=package,
                category="Spyware Pattern",
                title=f"Multiple Spyware Behaviors: {package}",
                description=f"App shows multiple spyware behaviors: {', '.join(suspicious_ops)}",
                severity=Severity.CRITICAL,
                confidence=0.9,
                technical_details={
                    'combined_score': combined_score,
                    'suspicious_operations': suspicious_ops,
                    'surveillance_score': covert_surveillance_score,
                    'fgs_score': foreground_abuse_score,
                    'data_score': data_collection_score,
                    'abuse_type': 'combined_spyware_pattern'
                },
                evidence_lines=[ops_data[op].get('raw_line', '') for op in ops_data if ops_data[op].get('mode') == 'allow']
            )
            detections.append(detection)
        
        return detections
    
    def _analyze_battery_drain(self, log_data: LogData) -> List[Detection]:
        """Analyze battery drain patterns from batterystats data."""
        detections = []
        
        # Use centralized battery statistics parsing (supports both regular and checkin formats)
        package_battery = self._parse_battery_statistics(log_data.raw_lines)
        
        # Analyze battery patterns
        for package, stats in package_battery.items():
            cpu_time = stats['cpu_time']
            bg_time = stats['background_time']
            total_time = cpu_time + bg_time
            
            if total_time == 0:
                continue
            
            package_detections = []
        
            # Check for excessive background usage (app-category agnostic)
            bg_ratio = bg_time / total_time if total_time > 0 else 0
            if bg_ratio > self.battery_drain_thresholds["excessive_background"]:
                # Get installation context for risk adjustment 
                installation_context = self.installation_context_heuristic.get_installation_context(package, log_data)

                # Base detection parameters
                base_severity = Severity.MEDIUM
                base_confidence = 0.7

                # Adjust severity and confidence based on installation context
                if installation_context.installer_source == 'sideloaded':
                    # Sideloaded apps with excessive background usage = higher risk
                    severity = Severity.HIGH
                    confidence = min(0.9, base_confidence * installation_context.risk_multiplier * 1.3)
                    risk_context = "sideloaded app with excessive background usage"
                elif installation_context.installer_source == 'play_store':
                    # Play Store apps still concerning but lower risk
                    severity = base_severity
                    confidence = base_confidence * installation_context.risk_multiplier
                    risk_context = "Play Store app with excessive background usage"
                else:
                    # Unknown installation source
                    severity = base_severity
                    confidence = base_confidence * installation_context.risk_multiplier
                    risk_context = "app with unknown installation source"

                detection = self._create_behavioral_detection(
                    package=package,
                    category="Battery Drain",
                    title=f"Excessive Background Usage: {package}",
                    description=f"App shows excessive background usage: {bg_ratio:.1%} (>{self.battery_drain_thresholds['excessive_background']:.1%}) ({risk_context})",
                    severity=severity,
                    confidence=confidence,
                    technical_details={
                        'background_ratio': bg_ratio,
                        'background_time_seconds': bg_time,
                        'total_time_seconds': total_time,
                        'threshold': self.battery_drain_thresholds["excessive_background"],
                        'abuse_type': 'excessive_background_usage',
                        'installation_source': installation_context.installer_source,
                        'risk_multiplier': installation_context.risk_multiplier
                    },
                    evidence_lines=[]
                )
                package_detections.append(detection)
            
            # Limit detections per package
            detections.extend(package_detections[:self.max_detections_per_package])
        
        return detections

    def _analyze_enhanced_sensor_abuse(self, log_data: LogData) -> List[Detection]:
        """Enhanced sensor abuse analysis with covert detection."""
        detections = []
        
        # Parse AppOps data for sensor usage patterns
        appops_data = self._parse_appops_data(log_data.raw_lines)
        
        # Analyze sensor operations from AppOps
        for package, ops_data in appops_data.items():
            if package == "android" or "com.android." in package.lower():
                continue
            
            for op_name, op_data in ops_data.items():
                if op_name in COVERT_SENSOR_THRESHOLDS:
                    duration = op_data.get('duration_secs', 0)
                    bg_ratio = op_data.get('bg_ratio', 0)
                    thresholds = COVERT_SENSOR_THRESHOLDS[op_name]
                    
                    severity = None
                    confidence = 0.5
                    
                    # Critical detection for background usage OR excessive duration
                    if (bg_ratio > 0 and duration > thresholds['bg_critical']) or duration > thresholds['critical']:
                        severity = Severity.CRITICAL
                        confidence = 0.95
                    elif duration > thresholds['high']:
                        severity = Severity.HIGH
                        confidence = 0.8
                    
                    if severity:
                        detection = self._create_behavioral_detection(
                            package=package,
                            category="Sensor Abuse",
                            title=f"Covert {op_name} Usage: {package}",
                            description=f"App shows covert {op_name.lower()} usage: {duration:.0f}s ({duration/60:.1f}min), {bg_ratio*100:.0f}% background",
                            severity=severity,
                            confidence=confidence,
                            technical_details={
                                'sensor_operation': op_name,
                                'duration_seconds': duration,
                                'background_ratio': bg_ratio,
                                'threshold_high': thresholds['high'],
                                'threshold_critical': thresholds['critical'],
                                'abuse_type': 'covert_sensor_usage'
                            },
                            evidence_lines=[op_data.get('raw_line', '')]
                        )
                        detections.append(detection)
        
        return detections
    
    def _analyze_location_misuse(self, log_data: LogData) -> List[Detection]:
        """Enhanced location tracking analysis with multiple data sources."""
        detections = []
        
        # Parse LocationManagerService logs for request patterns
        location_requests = self._parse_location_requests(log_data.raw_lines)
        
        # Analyze AppOps location data (primary source)
        appops_data = self._parse_appops_data(log_data.raw_lines)
        
        # Get usage statistics for correlation
        usage_stats = self._parse_usage_statistics(log_data.raw_lines)
        
        # Analyze location patterns for each package
        for package, ops_data in appops_data.items():
            if package == "android" or "com.android." in package.lower():
                continue
            
            package_detections = []
            
            for op_name in ['COARSE_LOCATION', 'FINE_LOCATION', 'MONITOR_LOCATION']:
                if op_name in ops_data:
                    op_data = ops_data[op_name]
                    duration = op_data.get('duration_secs', 0)
                    bg_ratio = op_data.get('bg_ratio', 0)
                    fgsvc_ratio = op_data.get('fgsvc_ratio', 0)
                    
                    # Enhanced location tracking detection
                    if duration > 3600:  # 1+ hour of location access
                        severity = self._calculate_location_severity(duration, bg_ratio, fgsvc_ratio, package, usage_stats)
                        confidence = self._calculate_location_confidence(duration, bg_ratio, fgsvc_ratio, package)
                        
                        # Determine tracking type
                        tracking_type = self._determine_location_tracking_type(duration, bg_ratio, fgsvc_ratio)
                        
                        detection = self._create_behavioral_detection(
                            package=package,
                            category="Location Tracking",
                            title=f"{tracking_type}: {package}",
                            description=f"App shows {tracking_type.lower()}: {duration/3600:.1f}h location access ({bg_ratio*100:.0f}% background)",
                            severity=severity,
                            confidence=confidence,
                            technical_details={
                                'location_operation': op_name,
                                'duration_hours': duration / 3600,
                                'background_ratio': bg_ratio,
                                'foreground_service_ratio': fgsvc_ratio,
                                'tracking_type': tracking_type.lower().replace(' ', '_'),
                                'abuse_type': 'location_tracking'
                            },
                            evidence_lines=[op_data.get('raw_line', '')]
                        )
                        package_detections.append(detection)
            
            # Check for high-frequency location requests
            request_data = location_requests.get(package, {})
            if request_data.get('total_requests', 0) > 1000:  # 1000+ requests
                bg_request_ratio = request_data.get('background_requests', 0) / request_data['total_requests']
                
                detection = self._create_behavioral_detection(
                    package=package,
                    category="Location Tracking",
                    title=f"High-Frequency Location Requests: {package}",
                    description=f"App made {request_data['total_requests']} location requests ({bg_request_ratio*100:.0f}% background)",
                    severity=Severity.HIGH if bg_request_ratio > 0.8 else Severity.MEDIUM,
                    confidence=0.85,
                    technical_details={
                        'total_requests': request_data['total_requests'],
                        'background_request_ratio': bg_request_ratio,
                        'abuse_type': 'high_frequency_location_requests'
                    },
                    evidence_lines=request_data.get('evidence_lines', [])[:3]
                )
                package_detections.append(detection)
            
            # Limit detections per package
            detections.extend(package_detections[:self.max_detections_per_package])
        
        return detections
    
    def _parse_location_requests(self, raw_lines: List[str]) -> Dict[str, Dict[str, Any]]:
        """Parse LocationManagerService logs for location request patterns."""
        location_requests = defaultdict(lambda: {
            'total_requests': 0, 'background_requests': 0, 'passive_requests': 0, 'evidence_lines': []
        })
        
        for line in raw_lines:
            line = line.strip()
            
            # Look for LocationManagerService entries
            if "LocationManagerService" in line or "requestLocationUpdates" in line:
                # Extract package name
                pkg_match = re.search(r'([a-zA-Z0-9_.]+)\s+requestLocationUpdates', line)
                if pkg_match:
                    package = pkg_match.group(1)
                    if not (package == "android" or "com.android." in package.lower()):
                        location_requests[package]['total_requests'] += 1
                        location_requests[package]['evidence_lines'].append(line)
                        
                        # Check for background requests
                        if "background" in line.lower():
                            location_requests[package]['background_requests'] += 1
                        
                        # Check for passive requests
                        if "passive" in line.lower():
                            location_requests[package]['passive_requests'] += 1
        
        return dict(location_requests)
    
    def _parse_usage_statistics(self, raw_lines: List[str]) -> Dict[str, Dict[str, Any]]:
        """Parse usage statistics for foreground/background analysis."""
        usage_stats = defaultdict(lambda: {
            'total_time_ms': 0, 'foreground_time_ms': 0, 'launch_count': 0
        })
        
        for line in raw_lines:
            line = line.strip()
            
            # Parse usage statistics format: package=com.example totalTime="01:23:45" appLaunchCount=5
            if 'package=' in line and 'totalTime=' in line:
                pkg_match = re.search(r'package=([a-zA-Z0-9_.]+)', line)
                if pkg_match:
                    package = pkg_match.group(1)
                    if not (package == "android" or "com.android." in package.lower()):
                        # Parse total time (format: "HH:MM:SS" or milliseconds)
                        time_match = re.search(r'totalTime="([^"]+)"', line)
                        if time_match:
                            time_str = time_match.group(1)
                            total_ms = self._parse_time_to_ms(time_str)
                            usage_stats[package]['total_time_ms'] = max(usage_stats[package]['total_time_ms'], total_ms)
                        
                        # Parse launch count
                        launch_match = re.search(r'appLaunchCount=(\d+)', line)
                        if launch_match:
                            launches = int(launch_match.group(1))
                            usage_stats[package]['launch_count'] = max(usage_stats[package]['launch_count'], launches)
            
            # Parse foreground time if available
            fg_match = re.search(r'Package ([a-zA-Z0-9_.]+).*foregroundTime=(\d+)', line)
            if fg_match:
                package = fg_match.group(1)
                fg_time = int(fg_match.group(2))
                if not (package == "android" or "com.android." in package.lower()):
                    usage_stats[package]['foreground_time_ms'] = max(usage_stats[package]['foreground_time_ms'], fg_time)
        
        return dict(usage_stats)
    
    def _parse_battery_statistics(self, raw_lines: List[str]) -> Dict[str, Dict[str, Any]]:
        """Parse battery statistics for CPU usage analysis using both regular and checkin formats."""
        battery_stats = defaultdict(lambda: {'cpu_time': 0, 'background_time': 0})
        
        # Build UID-to-package mapping from checkin format if available
        uid_to_package = {}
        
        for line in raw_lines:
            line = line.strip()
            
            # Parse UID-to-package mapping from checkin format
            # Format: 9,0,i,uid,10004,com.google.android.gms
            if line.startswith('9,0,i,uid,'):
                parts = line.split(',')
                if len(parts) >= 6:
                    uid = parts[4]
                    package = parts[5]
                    uid_to_package[uid] = package
            
            # Parse CPU usage from checkin format
            # Format: 9,10004,l,cpu,90241,33660,0
            elif line.startswith('9,') and ',l,cpu,' in line:
                parts = line.split(',')
                if len(parts) >= 7:
                    uid = parts[1]
                    user_cpu = int(parts[4]) if parts[4].isdigit() else 0
                    system_cpu = int(parts[5]) if parts[5].isdigit() else 0
                    total_cpu = user_cpu + system_cpu
                    
                    # Get package name from UID mapping
                    package = uid_to_package.get(uid, f"uid_{uid}")
                    
                    if not (package == "android" or "com.android." in package.lower()) and self._is_valid_package_name(package):
                        battery_stats[package]['cpu_time'] += total_cpu
                        battery_stats[package]['background_time'] += system_cpu
            
            # Look for CPU time entries in regular batterystats format
            elif "u" in line and "cpu=" in line:
                cpu_match = re.search(r'u(\d+)\s+([^\s]+)\s+cpu=(\d+)', line)
                if cpu_match:
                    package = cpu_match.group(2)
                    cpu_time = int(cpu_match.group(3))
                    if not (package == "android" or "com.android." in package.lower()) and self._is_valid_package_name(package):
                        battery_stats[package]['cpu_time'] += cpu_time
            
            # Look for background time entries in regular format
            elif "u" in line and "bg=" in line:
                bg_match = re.search(r'u(\d+)\s+([^\s]+)\s+bg=(\d+)', line)
                if bg_match:
                    package = bg_match.group(2)
                    bg_time = int(bg_match.group(3))
                    if not (package == "android" or "com.android." in package.lower()) and self._is_valid_package_name(package):
                        battery_stats[package]['background_time'] += bg_time
        
        return dict(battery_stats)
    
    def _parse_time_to_ms(self, time_str: str) -> int:
        """Convert time string to milliseconds."""
        try:
            if ":" in time_str:
                # Format: "HH:MM:SS" or "MM:SS"
                parts = time_str.split(":")
                if len(parts) == 3:  # HH:MM:SS
                    hours, minutes, seconds = map(int, parts)
                    return (hours * 3600 + minutes * 60 + seconds) * 1000
                elif len(parts) == 2:  # MM:SS
                    minutes, seconds = map(int, parts)
                    return (minutes * 60 + seconds) * 1000
            else:
                # Assume milliseconds
                return int(time_str)
        except (ValueError, TypeError):
            return 0
    

    
    def _calculate_location_confidence(self, duration: float, bg_ratio: float, fgsvc_ratio: float,
                                     package: str) -> float:
        """Calculate confidence for location tracking detection."""
        confidence = 0.7

        # Increase confidence for longer duration and higher background ratio
        if duration > 7200:  # 2+ hours
            confidence += 0.1
        if bg_ratio > 0.8:  # 80%+ background
            confidence += 0.1
        if fgsvc_ratio < 0.1:  # Very low foreground service usage
            confidence += 0.05

        # System apps get lower confidence (could be legitimate)
        if package == "android" or "com.android." in package.lower():
            confidence -= 0.2
        
        # Higher confidence for longer duration
        if duration > 14400:  # 4+ hours
            confidence += 0.2
        elif duration > 7200:  # 2+ hours
            confidence += 0.1
        
        # Higher confidence for background usage
        if bg_ratio > 0.7:
            confidence += 0.2
        elif bg_ratio > 0.5:
            confidence += 0.1
        
        # Lower confidence for legitimate location apps
        legitimate_apps = ['maps', 'navigation', 'uber', 'lyft', 'waze', 'gps']
        if any(app in package.lower() for app in legitimate_apps):
            confidence *= 0.7
        
        return min(0.95, confidence)
    
    def _determine_location_tracking_type(self, duration: float, bg_ratio: float, fgsvc_ratio: float) -> str:
        """Determine the type of location tracking behavior."""
        if bg_ratio > 0.8:
            return "Background Location Stalking"
        elif fgsvc_ratio > 0.6 and bg_ratio > 0.4:
            return "Stealth Location Tracking"
        elif duration > 14400:  # 4+ hours
            return "Excessive Location Monitoring"
        else:
            return "Suspicious Location Access"
    
    def _calculate_stealth_severity(self, stealth_score: int, bg_ratio: float) -> Severity:
        """Calculate severity for stealth behavior."""
        if stealth_score >= 8 or bg_ratio > 0.9:
            return Severity.CRITICAL
        elif stealth_score >= 6 or bg_ratio > 0.8:
            return Severity.HIGH
        else:
            return Severity.MEDIUM
    
    def _determine_stealth_type(self, indicators: List[str]) -> str:
        """Determine the type of stealth behavior."""
        indicator_text = ' '.join(indicators).lower()
        
        if 'persistent fgs' in indicator_text or 'background services' in indicator_text:
            return "Persistent Background Execution"
        elif 'automated behavior' in indicator_text:
            return "Automated Background Activity"
        elif 'background cpu' in indicator_text:
            return "Covert Resource Consumption"
        else:
            return "Stealth Background Operation"
    
    def _has_persistent_background_services(self, package: str, raw_lines: List[str]) -> bool:
        """Check if package has long-running background services."""
        service_lines = 0
        for line in raw_lines:
            if package in line and ("ServiceRecord" in line or "service=" in line):
                service_lines += 1
                if service_lines >= 3:  # Multiple service references suggest persistence
                    return True
        return False
    
    def _get_stealth_evidence_lines(self, package: str, raw_lines: List[str]) -> List[str]:
        """Get evidence lines for stealth behavior detection."""
        evidence_lines = []
        for line in raw_lines:
            if package in line and any(keyword in line.lower() for keyword in 
                                     ['totaltime', 'foregroundtime', 'cpu=', 'bg=', 'servicerecord']):
                evidence_lines.append(line)
                if len(evidence_lines) >= 3:
                    break
        return evidence_lines
    
    def _extract_config_dict(self, config) -> Dict[str, Any]:
        """Extract configuration dictionary from various config formats."""
        if config and hasattr(config, 'settings'):
            return config.settings
        elif config and hasattr(config, '__dict__'):
            return config.__dict__
        else:
            return config or {}

    def _parse_duration_with_oem_patterns(self, line: str, oem_patterns: Dict) -> float:
        """
        Parse duration from AppOps line using OEM-specific patterns.

        Args:
            line: AppOps log line
            oem_patterns: Dictionary of OEM-specific regex patterns

        Returns:
            Duration in seconds, or 0 if no match found
        """
        # Try each OEM pattern in order of likelihood
        pattern_priority = ['samsung', 'xiaomi', 'huawei', 'oppo', 'vivo', 'oneplus', 'generic']

        for oem in pattern_priority:
            if oem not in oem_patterns:
                continue

            pattern = oem_patterns[oem]
            match = pattern.search(line)

            if match:
                try:
                    if oem == 'generic':
                        # Generic pattern just extracts first number found
                        duration_str = match.group(1)
                        # Assume seconds if no unit specified
                        return float(duration_str)
                    else:
                        # Standard h/m/s/ms pattern
                        hours = int(match.group(1) or 0)
                        minutes = int(match.group(2) or 0)
                        seconds = int(match.group(3) or 0)
                        milliseconds = int(match.group(4) or 0)

                        return hours * 3600 + minutes * 60 + seconds + milliseconds / 1000
                except (ValueError, IndexError):
                    continue

        return 0.0

    # Accessibility service analysis moved to permissions heuristic to avoid duplication

    def _analyze_notification_listener_abuse_realistic(self, log_data: LogData) -> List[Detection]:
        """Analyze notification listener abuse using realistic ADB log patterns."""
        detections = []

        # Look for actual notification listener patterns in Android logs
        notification_patterns = [
            re.compile(r'NotificationListenerService.*bind.*([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)', re.IGNORECASE),
            re.compile(r'BIND_NOTIFICATION_LISTENER_SERVICE.*([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)', re.IGNORECASE),
            re.compile(r'NotificationManager.*registerListener.*([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)', re.IGNORECASE)
        ]

        for line in log_data.raw_lines:
            for pattern in notification_patterns:
                match = pattern.search(line)
                if match:
                    package_name = match.group(1)

                    # Skip system packages - use basic check since log_data not available in this context
                    system_prefixes = ['com.android.', 'android.', 'com.google.android.', 'com.samsung.android.']
                    if not any(package_name.startswith(prefix) for prefix in system_prefixes):
                        detection = Detection(
                            category="Notification Listener Abuse",
                            package=package_name,
                            severity=Severity.HIGH,
                            confidence=0.85,
                            title=f"Notification Listener Service: {package_name}",
                            description=f"Package {package_name} bound notification listener service for message interception",
                            technical_details={
                                'package_name': package_name,
                                'service_type': 'NotificationListenerService',
                                'threat_type': 'message_interception'
                            },
                            evidence=[Evidence(
                                type=EvidenceType.LOG_ANCHOR,
                                content=line.strip(),
                                confidence=0.85
                            )]
                        )
                        detections.append(detection)
                        break

        return detections

    def _build_uid_to_package_mapping(self, raw_lines: List[str]) -> Dict[str, str]:
        """Build UID to package mapping from Android log data."""
        uid_to_package = {}

        for line in raw_lines:
            line = line.strip()

            # Parse UID-to-package mapping from checkin format
            # Format: 9,0,i,uid,10004,com.google.android.gms
            if line.startswith('9,0,i,uid,'):
                parts = line.split(',')
                if len(parts) >= 6:
                    uid = parts[4]
                    package = parts[5]
                    uid_to_package[uid] = package

            # Also look for other UID mapping patterns in logs
            # Format: "u0a42:" followed by package name
            uid_match = re.search(r'u(\d+)a(\d+).*?([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)', line, re.IGNORECASE)
            if uid_match:
                user_id = uid_match.group(1)
                app_id = uid_match.group(2)
                package = uid_match.group(3)
                # Convert to standard UID format
                uid = str(int(user_id) * 100000 + int(app_id))
                uid_to_package[uid] = package

        return uid_to_package

    def _analyze_stealth_behaviors_realistic(self, log_data: LogData) -> List[Detection]:
        """Analyze stealth behaviors using realistic ADB log patterns."""
        detections = []

        # Look for realistic stealth behavior patterns in Android logs
        # Based on actual AppOps and ActivityManager log patterns
        stealth_patterns = [
            # AppOps patterns for background sensor access
            re.compile(r'AppOpsService.*CAMERA.*uid=(\d+).*mode=allow.*background', re.IGNORECASE),
            re.compile(r'AppOpsService.*RECORD_AUDIO.*uid=(\d+).*mode=allow.*background', re.IGNORECASE),
            re.compile(r'AppOpsService.*COARSE_LOCATION.*uid=(\d+).*mode=allow.*background', re.IGNORECASE),
            re.compile(r'AppOpsService.*FINE_LOCATION.*uid=(\d+).*mode=allow.*background', re.IGNORECASE),
            # ActivityManager patterns for background activity
            re.compile(r'ActivityManager.*START.*([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+).*from background', re.IGNORECASE),
            # PowerManager wakelock patterns during screen off
            re.compile(r'PowerManagerService.*WakeLock.*([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+).*screen_off', re.IGNORECASE)
        ]

        package_activity = defaultdict(int)
        uid_to_package = self._build_uid_to_package_mapping(log_data.raw_lines)

        for line in log_data.raw_lines:
            for i, pattern in enumerate(stealth_patterns):
                match = pattern.search(line)
                if match:
                    if i < 4:  # UID-based patterns (AppOps)
                        uid = match.group(1)
                        package_name = uid_to_package.get(uid, 'unknown')
                    else:  # Package name patterns (ActivityManager, PowerManager)
                        package_name = match.group(1)

                    # Skip system packages - use basic check since log_data not available in this context
                    system_prefixes = ['com.android.', 'android.', 'com.google.android.', 'com.samsung.android.']
                    if (package_name != 'unknown' and
                        not any(package_name.startswith(prefix) for prefix in system_prefixes)):
                        package_activity[package_name] += 1

        # Create detections for packages with high stealth activity
        for package_name, count in package_activity.items():
            if count >= 5:  # Threshold for suspicious stealth activity
                detection = Detection(
                    category="Stealth Behavior",
                    package=package_name,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    title=f"Background Stealth Activity: {package_name}",
                    description=f"Package {package_name} showed {count} stealth behavior indicators",
                    technical_details={
                        'package_name': package_name,
                        'stealth_activities': count,
                        'threat_type': 'stealth_behavior'
                    },
                    evidence=[Evidence(
                        type=EvidenceType.LOG_ANCHOR,
                        content=f"Stealth activity count: {count}",
                        confidence=0.8
                    )]
                )
                detections.append(detection)

        return detections
