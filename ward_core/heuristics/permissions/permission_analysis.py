"""
Permission Analysis Heuristic
#TODO:Document this properly
"""

import re
from typing import List, Dict, Any, Set, Tuple
from collections import defaultdict

from ward_core.heuristics.base import BaseHeuristic
from ward_core.heuristics.context.installation_context import InstallationContextHeuristic
from ward_core.logic.models import Detection, Evidence, EvidenceType, Severity, LogData


# Critical permissions that require special attention
CRITICAL_PERMISSIONS = {
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "weight": 5,
        "description": "Can draw over other apps (overlay attacks)"
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "weight": 5,
        "description": "Device administrator privileges"
    },
    "android.permission.WRITE_SECURE_SETTINGS": {
        "weight": 4,
        "description": "Can modify secure system settings"
    },
    "android.permission.WRITE_SETTINGS": {
        "weight": 3,
        "description": "Can modify system settings"
    },
    "android.permission.INSTALL_PACKAGES": {
        "weight": 5,
        "description": "Can install other apps"
    },
    "android.permission.DELETE_PACKAGES": {
        "weight": 5,
        "description": "Can uninstall apps"
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "weight": 4,
        "description": "Accessibility service binding"
    },
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": {
        "weight": 4,
        "description": "Can read all notifications"
    },
    "android.permission.CAPTURE_AUDIO_OUTPUT": {
        "weight": 5,
        "description": "Can capture audio output"
    },
    "android.permission.REBOOT": {
        "weight": 4,
        "description": "Can reboot device"
    },
    # Modern Android permissions (Android 11+)
    "android.permission.QUERY_ALL_PACKAGES": {
        "weight": 4,
        "description": "Can query all installed packages (Android 11+)"
    },
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "weight": 3,
        "description": "Full external storage access (Android 11+)"
    },
    "android.permission.SCHEDULE_EXACT_ALARM": {
        "weight": 2,
        "description": "Can schedule exact alarms (Android 12+)"
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "weight": 4,
        "description": "Can request package installation (Android 8+)"
    },
    "android.permission.BIND_VPN_SERVICE": {
        "weight": 5,
        "description": "VPN service binding (traffic interception)"
    },
    "android.permission.CAPTURE_SECURE_VIDEO_OUTPUT": {
        "weight": 5,
        "description": "Can capture secure video content"
    },
}

# High-risk permissions
HIGH_RISK_PERMISSIONS = {
    "android.permission.RECORD_AUDIO": {
        "weight": 3,
        "description": "Microphone access"
    },
    "android.permission.CAMERA": {
        "weight": 3,
        "description": "Camera access"
    },
    "android.permission.READ_SMS": {
        "weight": 3,
        "description": "SMS reading"
    },
    "android.permission.SEND_SMS": {
        "weight": 3,
        "description": "SMS sending"
    },
    "android.permission.READ_CALL_LOG": {
        "weight": 3,
        "description": "Call log access"
    },
    "android.permission.CALL_PHONE": {
        "weight": 2,
        "description": "Phone calling"
    },
    "android.permission.READ_CONTACTS": {
        "weight": 2,
        "description": "Contacts access"
    },
    "android.permission.WRITE_CONTACTS": {
        "weight": 2,
        "description": "Contacts modification"
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "weight": 2,
        "description": "Precise location access"
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "weight": 1,
        "description": "Approximate location access"
    },
    "android.permission.READ_PHONE_STATE": {
        "weight": 2,
        "description": "Phone state access"
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "weight": 1,
        "description": "External storage read"
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "weight": 2,
        "description": "External storage write"
    },
    # Modern Android high-risk permissions
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "weight": 3,
        "description": "Background location access (Android 10+)"
    },
    "android.permission.ACTIVITY_RECOGNITION": {
        "weight": 2,
        "description": "Physical activity recognition (Android 10+)"
    },
    "android.permission.ANSWER_PHONE_CALLS": {
        "weight": 3,
        "description": "Can answer phone calls (Android 8+)"
    },
    "android.permission.READ_PHONE_NUMBERS": {
        "weight": 2,
        "description": "Can read phone numbers (Android 8+)"
    },
    "android.permission.USE_BIOMETRIC": {
        "weight": 2,
        "description": "Biometric authentication access"
    },
    "android.permission.FOREGROUND_SERVICE": {
        "weight": 1,
        "description": "Can run foreground services (Android 9+)"
    },
}

# Suspicious permission combinations
SUSPICIOUS_COMBINATIONS = [
    ({"android.permission.RECORD_AUDIO", "android.permission.CAMERA"}, "Audio and camera access"),
    ({"android.permission.READ_SMS", "android.permission.SEND_SMS"}, "SMS read and send"),
    ({"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"}, "Both location permissions"),
    ({"android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG"}, "Contacts and call log"),
    ({"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"}, "Overlay and accessibility"),
    ({"android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION"}, "Audio recording and precise location"),
    ({"android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION"}, "Camera and precise location"),
    ({"android.permission.READ_SMS", "android.permission.READ_CONTACTS"}, "SMS and contacts access"),
    # Modern suspicious combinations
    ({"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION"}, "Foreground and background location"),
    ({"android.permission.QUERY_ALL_PACKAGES", "android.permission.SYSTEM_ALERT_WINDOW"}, "Package enumeration and overlay"),
    ({"android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.QUERY_ALL_PACKAGES"}, "Full storage and package access"),
    ({"android.permission.BIND_VPN_SERVICE", "android.permission.QUERY_ALL_PACKAGES"}, "VPN and package enumeration"),
    ({"android.permission.RECORD_AUDIO", "android.permission.ACTIVITY_RECOGNITION"}, "Audio recording and activity tracking"),
    ({"android.permission.CAMERA", "android.permission.ACTIVITY_RECOGNITION"}, "Camera and activity tracking"),
    ({"android.permission.ANSWER_PHONE_CALLS", "android.permission.READ_PHONE_STATE"}, "Call control and phone state"),
]


class PermissionAnalysisHeuristic(BaseHeuristic):
    """
    Analyzes Android permission usage patterns to detect potential spyware behavior.
    
    This heuristic looks for:
    - Critical system permissions on non-system apps
    - Excessive high-risk permission combinations
    - Suspicious permission patterns indicating surveillance
    - Permission denials indicating attempted abuse
    - Accessibility service abuse patterns
    
    Follows zero-trust framework - never trusts package names alone.
    """
    
    def __init__(self, config=None):
        super().__init__(config)

        # Quality gate settings
        config_dict = self._extract_config_dict(config)
        self.min_risk_score = config_dict.get('min_risk_score', 3.0)
        self.require_log_evidence = config_dict.get('require_log_evidence', False)  # Permissions are often metadata-only
        self.max_detections_per_package = config_dict.get('max_detections_per_package', 5)

        # Initialize installation context heuristic for zero-trust verification
        self.installation_context_heuristic = InstallationContextHeuristic(config)
    
    @property
    def name(self) -> str:
        """Get the name of this heuristic."""
        return "permission_analysis"
    
    @property
    def category(self) -> str:
        """Get the category of this heuristic."""
        return "Permission Analysis"
    
    @property
    def description(self) -> str:
        """Get description of what this heuristic detects."""
        return "Detects abuse of sensitive Android permissions and suspicious permission patterns"
    
    @property
    def max_score(self) -> float:
        """Maximum score this heuristic can produce."""
        return 10.0
    
    def analyze(self, log_data: LogData) -> List[Detection]:
        """
        Analyze log data for permission abuse patterns.
        
        Args:
            log_data: Parsed log data to analyze
            
        Returns:
            List of Detection objects
        """
        detections = []
        
        # Extract permission data from logs and packages
        app_permissions, permission_denials = self._extract_permissions(log_data)
        
        # Analyze each package for permission abuse
        for package_name, permissions in app_permissions.items():
            if not permissions:
                continue
                
            package_detections = self._analyze_package_permissions(
                package_name, permissions, permission_denials.get(package_name, set()), log_data
            )
            
            # Limit detections per package to avoid spam
            detections.extend(package_detections[:self.max_detections_per_package])
        
        # Analyze accessibility service abuse
        accessibility_detections = self._analyze_accessibility_abuse(log_data)
        detections.extend(accessibility_detections)
        
        return detections
    
    def _extract_permissions(self, log_data: LogData) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        """Extract permissions from log data and package information."""
        app_permissions = defaultdict(set)
        permission_denials = defaultdict(set)
        
        # Get permissions from package info (already parsed by our improved parser)
        for package_name, package_info in log_data.packages.items():
            permissions = getattr(package_info, 'permissions', set())
            if permissions:
                app_permissions[package_name].update(permissions)
        
        # Extract additional permissions and denials from raw logs
        permission_pattern = re.compile(r'android\.permission\.([A-Z_]+)')
        current_package = None
        
        for line in log_data.raw_lines:
            if not line or not isinstance(line, str):
                continue
                
            line = line.strip()
            
            # Look for package declarations
            pkg_match = re.search(r'Package \[([a-zA-Z0-9_.]+)\]', line)
            if pkg_match:
                current_package = pkg_match.group(1)
                continue
            
            if not current_package:
                continue
            
            # Extract permissions
            perm_match = permission_pattern.search(line)
            if perm_match:
                permission = f"android.permission.{perm_match.group(1)}"
                app_permissions[current_package].add(permission)
            
            # Extract permission denials
            if "Permission Denial" in line or "SecurityException" in line:
                perm_match = permission_pattern.search(line)
                if perm_match:
                    permission = f"android.permission.{perm_match.group(1)}"
                    permission_denials[current_package].add(permission)
        
        return dict(app_permissions), dict(permission_denials)
    
    def _analyze_package_permissions(self, package_name: str, permissions: Set[str],
                                   denials: Set[str], log_data: LogData) -> List[Detection]:
        """Analyze permissions for a single package with zero-trust installation context verification."""
        detections = []

        # Whitelist the core Android system package - this is an exception to zero-trust
        # The "android" package represents the core Android system, not a third-party app
        # TODO: Reasearch if there are possible risks associated with whitelisting "android" package
        if package_name == "android":
            return detections  # Skip analysis for core Android system

        # Get installation context for zero-trust verification
        installation_context = self.installation_context_heuristic.get_installation_context(package_name, log_data)

        # Calculate risk score and findings
        risk_score, findings = self._calculate_permission_risk(package_name, permissions, denials)

        # Apply installation context risk multiplier (zero-trust framework)
        adjusted_risk_score = risk_score * installation_context.risk_multiplier

        # Lower threshold for system apps (they legitimately need more permissions)
        effective_threshold = self.min_risk_score
        if installation_context.is_system_app:
            effective_threshold = self.min_risk_score * 1.5  # Higher threshold for system apps

        if adjusted_risk_score < effective_threshold:
            return detections
        
        # Create evidence
        evidence_list = []
        
        # Add permission evidence
        if permissions:
            evidence_list.append(Evidence(
                type=EvidenceType.METADATA_ONLY,
                content=f"Permissions: {', '.join(sorted(permissions))}",
                confidence=0.8
            ))
        
        # Add denial evidence if any
        if denials:
            evidence_list.append(Evidence(
                type=EvidenceType.METADATA_ONLY,
                content=f"Permission denials: {', '.join(sorted(denials))}",
                confidence=0.9
            ))
        
        # Add installation context evidence
        evidence_list.append(Evidence(
            type=EvidenceType.METADATA_ONLY,
            content=f"Installation: {installation_context.installation_method}, Source: {installation_context.installer_source}, Risk multiplier: {installation_context.risk_multiplier:.1f}",
            confidence=0.8
        ))

        # Add log evidence if available
        log_evidence = self._find_permission_log_evidence(package_name, log_data)
        if log_evidence:
            evidence_list.extend(log_evidence[:3])  # Limit to avoid spam

        # Apply quality gates
        has_log_evidence = any(e.type == EvidenceType.LOG_ANCHOR for e in evidence_list)
        if self.require_log_evidence and not has_log_evidence:
            return detections

        # Calculate severity (adjusted for installation context)
        severity = self._calculate_severity(adjusted_risk_score, findings)

        # Adjust confidence based on installation context
        base_confidence = min(0.95, 0.6 + (adjusted_risk_score * 0.05))
        if installation_context.is_system_app:
            base_confidence *= 0.8  # Lower confidence for system apps

        # Create detection
        detection = Detection(
            category=self.category,
            package=package_name,
            title=f"Permission Abuse: {package_name}",
            description=f"Package exhibits suspicious permission patterns (adjusted risk: {adjusted_risk_score:.1f}, source: {installation_context.installer_source})",
            severity=severity,
            confidence=base_confidence,
            evidence=evidence_list,
            technical_details={
                'heuristic_name': self.name,
                'package_name': package_name,
                'risk_score': risk_score,
                'adjusted_risk_score': adjusted_risk_score,
                'installation_context': {
                    'installer_source': installation_context.installer_source,
                    'is_system_app': installation_context.is_system_app,
                    'risk_multiplier': installation_context.risk_multiplier
                },
                'findings': findings,
                'permissions': list(permissions),
                'denials': list(denials)
            }
        )
        
        detections.append(detection)
        return detections
    
    def _calculate_permission_risk(self, package_name: str, permissions: Set[str], 
                                 denials: Set[str]) -> Tuple[float, List[str]]:
        """Calculate risk score and findings for a package's permissions."""
        score = 0.0
        findings = []
        
        # Check for critical permissions
        critical_perms = permissions.intersection(CRITICAL_PERMISSIONS.keys())
        if critical_perms:
            for perm in critical_perms:
                weight = CRITICAL_PERMISSIONS[perm]["weight"]
                score += weight
                findings.append(f"Critical permission: {perm}")
        
        # Check for high-risk permissions
        high_risk_perms = permissions.intersection(HIGH_RISK_PERMISSIONS.keys())
        if len(high_risk_perms) >= 3:
            score += 2.0
            findings.append(f"Multiple high-risk permissions: {len(high_risk_perms)} permissions")
        elif len(high_risk_perms) >= 1:
            score += 1.0
            findings.append(f"High-risk permissions: {', '.join(high_risk_perms)}")
        
        # Check for permission denials (indicates attempted abuse)
        if denials:
            denial_score = len(denials) * 0.5
            score += denial_score
            findings.append(f"Permission denials detected: {len(denials)} permissions")
        
        # Check for suspicious permission combinations
        for combo, description in SUSPICIOUS_COMBINATIONS:
            if combo.issubset(permissions):
                score += 1.5
                findings.append(f"Suspicious combination: {description}")

        # Note: Removed zero-trust breaking system-like package name check
        # Installation context verification is now handled by installation_context heuristic

        return score, findings
    
    def _analyze_accessibility_abuse(self, log_data: LogData) -> List[Detection]:
        """Analyze for accessibility service abuse patterns."""
        detections = []
        
        # Look for accessibility service patterns in logs
        accessibility_patterns = [
            r'AccessibilityService.*enabled',
            r'BIND_ACCESSIBILITY_SERVICE',
            r'accessibility.*service.*started',
            r'AccessibilityManager.*service'
        ]
        
        found_services = {}
        
        for line in log_data.raw_lines:
            if not line or not isinstance(line, str):
                continue
                
            for pattern in accessibility_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Extract package name if possible
                    pkg_match = re.search(r'([a-zA-Z0-9_.]+)/[a-zA-Z0-9_.]+Service', line)
                    if pkg_match:
                        package_name = pkg_match.group(1)
                        if package_name not in found_services:
                            found_services[package_name] = []
                        found_services[package_name].append(line.strip())
        
        # Create detections for accessibility service abuse
        for package_name, evidence_lines in found_services.items():
            # Whitelist the core Android system package - exception to zero-trust
            if package_name == "android":
                continue  # Skip core Android system

            if self.installation_context_heuristic.get_installation_context(package_name, log_data).is_system_app:
                continue  # Skip system packages for accessibility services
                
            evidence_list = []
            for line in evidence_lines[:2]:  # Limit evidence
                evidence_list.append(Evidence(
                    type=EvidenceType.LOG_ANCHOR,
                    content=line,
                    confidence=0.7
                ))
            
            detection = Detection(
                category="Accessibility Abuse",
                package=package_name,
                title=f"Accessibility Service Abuse: {package_name}",
                description="Package uses accessibility services which can be abused for surveillance",
                severity=Severity.HIGH,
                confidence=0.8,
                evidence=evidence_list,
                technical_details={
                    'heuristic_name': self.name,
                    'package_name': package_name,
                    'abuse_type': 'accessibility_service'
                }
            )
            
            detections.append(detection)
        
        return detections
    
    def _find_permission_log_evidence(self, package_name: str, log_data: LogData) -> List[Evidence]:
        """Find log evidence related to permission usage for a package."""
        evidence = []
        
        # Look for permission-related log entries
        permission_keywords = ['permission', 'Permission', 'denied', 'granted', 'SecurityException']
        
        for line in log_data.raw_lines[:1000]:  # Limit search for performance
            if not line or not isinstance(line, str):
                continue
                
            if package_name in line and any(keyword in line for keyword in permission_keywords):
                evidence.append(Evidence(
                    type=EvidenceType.LOG_ANCHOR,
                    content=line.strip(),
                    confidence=0.6
                ))
                
                if len(evidence) >= 3:  # Limit evidence to avoid spam
                    break
        
        return evidence
    
    def _calculate_severity(self, risk_score: float, findings: List[str]) -> Severity:
        """Calculate severity based on risk score and findings."""
        # Escalate severity if critical findings are present
        critical_findings = [f for f in findings if 'SYSTEM_ALERT_WINDOW' in f or 'BIND_DEVICE_ADMIN' in f or 'VPN' in f]

        if risk_score >= 8.0 or len(critical_findings) > 0:
            return Severity.CRITICAL
        elif risk_score >= 5.0:
            return Severity.HIGH
        elif risk_score >= 3.0:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _extract_config_dict(self, config) -> Dict[str, Any]:
        """Extract configuration dictionary from various config formats."""
        if config and hasattr(config, 'settings'):
            return config.settings
        elif config and hasattr(config, '__dict__'):
            return config.__dict__
        else:
            return config or {}
