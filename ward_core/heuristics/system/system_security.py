"""
System Security Heuristic - Comprehensive Android Security Analysis

This heuristic detects system security issues, privilege escalation attempts,
and advanced Android security violations including SELinux AVC analysis.
Implements sophisticated logic with quality gates to prevent false positives.
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from collections import defaultdict
from enum import Enum
from datetime import datetime

from ward_core.heuristics.base import BaseHeuristic, HeuristicResult
from ward_core.heuristics.context.installation_context import InstallationContextHeuristic
from ward_core.logic.models import Detection, Evidence, EvidenceType, Severity, LogData


class SecurityThreatType(Enum):
    """Types of security threats detected by this heuristic."""
    SELINUX_VIOLATION = "selinux_violation"
    SYSTEM_INTEGRITY = "system_integrity"
    ROOT_TAMPERING = "root_tampering"
    ATTACK_CORRELATION = "attack_correlation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SURVEILLANCE = "surveillance"


# Android UID classification (multi-user aware)
# Formula: uid = userId * 100000 + appId
# System appIds: 0-9999, App appIds: 10000-98999, Isolated appIds: 99000+

def extract_app_id(uid: int) -> int:
    """Extract appId from multi-user UID. Formula: uid = userId*100000 + appId"""
    return uid % 100000

def extract_user_id(uid: int) -> int:
    """Extract userId from multi-user UID. Formula: uid = userId*100000 + appId"""
    return uid // 100000

def is_system_uid(uid_str: str) -> bool:
    """Check if UID is a system UID, accounting for multi-user (appId 0-9999, excluding shell=2000)."""
    try:
        uid = int(uid_str)
        app_id = extract_app_id(uid)
        user_id = extract_user_id(uid)
        # System appIds are < 10000, but shell (2000) can be legitimate for debugging
        # Also check for reasonable user_id (0-999 are typical)
        return app_id < 10000 and app_id != 2000 and user_id < 1000
    except (ValueError, TypeError):
        return False

def is_app_uid(uid_str: str) -> bool:
    """Check if UID is an app UID, accounting for multi-user (appId 10000-98999)."""
    try:
        uid = int(uid_str)
        app_id = extract_app_id(uid)
        user_id = extract_user_id(uid)
        # App appIds: 10000-98999 (isolated appIds are 99000+)
        # Check for reasonable user_id
        return 10000 <= app_id <= 98999 and user_id < 1000
    except (ValueError, TypeError):
        return False

def is_isolated_uid(uid_str: str) -> bool:
    """Check if UID is an isolated process UID, accounting for multi-user (appId 99000+)."""
    try:
        uid = int(uid_str)
        app_id = extract_app_id(uid)
        user_id = extract_user_id(uid)
        # Isolated appIds are 99000+
        # Check for reasonable user_id
        return app_id >= 99000 and user_id < 1000
    except (ValueError, TypeError):
        return False

# Installation context analysis is now handled by the dedicated installation_context heuristic


class AdvancedSecurityPatterns:
    """Advanced Android security patterns for comprehensive analysis."""

    # Flexible AVC pattern that captures the main structure and remaining fields
    AVC_PATTERN = re.compile(
        r'(?:audit\([^)]*\):\s*)?'  # Optional audit prefix
        r'avc:\s+denied\s+\{\s*([^}]+)\s*\}(.+)',  # Capture permissions and remaining fields
        re.IGNORECASE
    )

    # Key-value extraction patterns for flexible AVC field parsing
    AVC_FIELD_PATTERNS = {
        'pid': re.compile(r'pid=(\d+)', re.IGNORECASE),
        'uid': re.compile(r'uid=(\d+)', re.IGNORECASE),
        'comm': re.compile(r'comm="([^"]*)"', re.IGNORECASE),
        'path': re.compile(r'path="([^"]*)"', re.IGNORECASE),
        'name': re.compile(r'name="([^"]*)"', re.IGNORECASE),  # Fallback for unlabeled sockets
        'dev': re.compile(r'dev=([^\s]+)', re.IGNORECASE),
        'ino': re.compile(r'ino=([^\s]+)', re.IGNORECASE),
        'scontext': re.compile(r'scontext=([^\s]+)', re.IGNORECASE),
        'tcontext': re.compile(r'tcontext=([^\s]+)', re.IGNORECASE),
        'tclass': re.compile(r'tclass=([^\s]+)', re.IGNORECASE),
        'permissive': re.compile(r'permissive=([01])', re.IGNORECASE),
    }

    # Cross-app data access patterns (real data exfiltration)
    DATA_EXFILTRATION_PATTERNS = [
        # Untrusted app accessing other app's private data
        re.compile(r'avc:\s+denied.*\{\s*(?:read|open)\s*\}.*scontext=u:r:untrusted_app.*tcontext=u:object_r:app_data_file.*path="/data/data/([^/]+)', re.IGNORECASE),
        # System app accessing user data inappropriately
        re.compile(r'avc:\s+denied.*\{\s*(?:read|open|getattr)\s*\}.*scontext=u:r:system_app.*tcontext=u:object_r:app_data_file.*path="/data/data/([^/]+)', re.IGNORECASE),
        # Platform app accessing private app data
        re.compile(r'avc:\s+denied.*\{\s*(?:read|open)\s*\}.*scontext=u:r:platform_app.*tcontext=u:object_r:app_data_file.*path="/data/data/([^/]+)', re.IGNORECASE),
    ]

    # Real privilege escalation patterns (capability attempts)
    PRIVILEGE_ESCALATION_PATTERNS = [
        # Untrusted app attempting dangerous capabilities
        re.compile(r'avc:\s+denied.*\{\s*(?:setuid|setgid|dac_override|sys_admin|sys_module)\s*\}.*scontext=u:r:untrusted_app.*tclass=capability', re.IGNORECASE),
        re.compile(r'avc:\s+denied.*\{\s*(?:mac_admin|mac_override)\s*\}.*scontext=u:r:untrusted_app.*tclass=capability2', re.IGNORECASE),
        # Process manipulation attempts
        re.compile(r'avc:\s+denied.*\{\s*ptrace\s*\}.*scontext=u:r:untrusted_app.*tclass=process', re.IGNORECASE),
    ]

    # Device access patterns (surveillance-related hardware)
    SURVEILLANCE_DEVICE_PATTERNS = [
        # Camera device access
        re.compile(r'avc:\s+denied.*\{\s*(?:read|write|open)\s*\}.*path="/dev/video[0-9]+".*scontext=u:r:untrusted_app', re.IGNORECASE),
        # Audio device access
        re.compile(r'avc:\s+denied.*\{\s*(?:read|write|open)\s*\}.*path="/dev/snd/.*".*scontext=u:r:untrusted_app', re.IGNORECASE),
        # Location/GPS access
        re.compile(r'avc:\s+denied.*\{\s*(?:read|write|open)\s*\}.*path="/dev/gnss.*".*scontext=u:r:untrusted_app', re.IGNORECASE),
    ]

    # System integrity violation patterns - comprehensive OEM variants
    SYSTEM_INTEGRITY_PATTERNS = [
        # dm-verity variants
        re.compile(r'dm-verity.*(?:verification.*failed|corruption|data corruption)', re.IGNORECASE),
        re.compile(r'verity.*(?:corruption.*detected|error|failed)', re.IGNORECASE),
        # fs-verity (file-based)
        re.compile(r'fs-verity.*(?:verification failed|invalid)', re.IGNORECASE),
        # AVB (Android Verified Boot) failures
        re.compile(r'avb.*(?:verification.*failed|vbmeta.*invalid)', re.IGNORECASE),
        re.compile(r'vbmeta.*(?:digest mismatch|invalid.*signature|verification failed)', re.IGNORECASE),
        # Legacy android-verity
        re.compile(r'android-verity.*(?:failed|error)', re.IGNORECASE),
        # Generic verified boot failures
        re.compile(r'verified boot.*(?:failed|error|disabled)', re.IGNORECASE),
        re.compile(r'boot.*verification.*failed', re.IGNORECASE),
    ]

    # REMOUNT/FILESYSTEM tampering patterns (context-aware)
    REMOUNT_PATTERNS = [
        # Suspicious remounts outside of expected contexts
        re.compile(r'fs_mgr.*remount.*rw.*(?:/system|/vendor)', re.IGNORECASE),
        re.compile(r'init.*remount.*(?:/system|/vendor).*rw', re.IGNORECASE),
        # Overlayfs usage outside of A/B updates (suspicious on user builds)
        re.compile(r'overlayfs:.*mount.*(?:/system|/vendor)', re.IGNORECASE),
        # Manual mount commands (highly suspicious)
        re.compile(r'mount.*-o.*rw.*remount.*(?:/system|/vendor)', re.IGNORECASE),
    ]

    # KERNEL MODULE loading patterns (GKI-aware with context)
    MODULE_LOAD_PATTERNS = [
        # High confidence suspicious patterns
        re.compile(r'kernel.*tainted.*flags.*0x[0-9a-f]+', re.IGNORECASE),
        re.compile(r'livepatch.*module.*loaded', re.IGNORECASE),
        re.compile(r'module.*signature.*verification.*failed', re.IGNORECASE),
        re.compile(r'Unknown symbol.*module', re.IGNORECASE),
        re.compile(r'module verification failed', re.IGNORECASE),
        # Generic module activity (context-dependent)
        re.compile(r'module.*(?:loaded|loading)', re.IGNORECASE),
    ]

    # Legitimate module loader contexts (zero-trust: still investigate but lower confidence)
    LEGITIMATE_MODULE_LOADERS = [
        'init', 'update_engine', 'vold', 'vendor_init'
    ]

    # Legitimate module paths (zero-trust: verify but lower confidence)
    LEGITIMATE_MODULE_PATHS = [
        '/vendor/lib/modules/', '/vendor/lib64/modules/',
        '/system/lib/modules/', '/system/lib64/modules/',
        'initramfs'
    ]

    # Standard Linux kernel modules that are legitimate during boot/initialization
    # These are core kernel components, not third-party modules
    STANDARD_KERNEL_MODULES = {
        # Block device modules
        'brd',          # Block RAM disk
        'loop',         # Loopback device
        'dm_mod',       # Device mapper
        'dm_crypt',     # Device mapper crypto
        'dm_verity',    # Device mapper verity (Android verified boot)

        # Network modules
        'bridge',       # Network bridge
        'tun',          # TUN/TAP device
        'xt_qtaguid',   # Android network quota/tag
        'xt_quota2',    # Network quota v2

        # Filesystem modules
        'fuse',         # FUSE filesystem
        'ext4',         # EXT4 filesystem
        'f2fs',         # F2FS filesystem (common on Android)
        'squashfs',     # SquashFS (read-only compressed filesystem)

        # Android-specific legitimate modules
        'wlan',         # WiFi driver (generic)
        'cfg80211',     # WiFi configuration
        'mac80211',     # WiFi MAC layer
        'bluetooth',    # Bluetooth stack
        'hid',          # Human Interface Device
        'usbcore',      # USB core
        'usb_storage',  # USB storage

        # Security modules
        'selinux',      # SELinux security module
        'capability',   # POSIX capabilities

        # Memory/performance modules
        'zram',         # Compressed RAM
        'lz4',          # LZ4 compression
        'lz4_compress', # LZ4 compression
        'lzo',          # LZO compression
    }



    # SELinux mode detection patterns
    SELINUX_MODE_PATTERNS = [
        re.compile(r'setenforce\s+0', re.IGNORECASE),  # Permissive mode
        re.compile(r'SELinux:\s*Disabled', re.IGNORECASE),
        re.compile(r'SELinux:\s*Permissive', re.IGNORECASE),
        re.compile(r'SELinux:\s*Enforcing', re.IGNORECASE),
    ]

    # MAGISK/ROOT detection patterns (updated for modern versions)
    # These patterns detect actual root activity, not package queries or app names
    MAGISK_PATTERNS = [
        # Generic magisk/zygisk patterns (avoid deprecated MagiskHide)
        re.compile(r'magisk.*(?:daemon|service)', re.IGNORECASE),
        re.compile(r'zygisk.*(?:inject|hook|loaded)', re.IGNORECASE),
        # Su daemon variants
        re.compile(r'(?:su|supersu).*daemon.*(?:started|running)', re.IGNORECASE),
        # Property spoofing (key indicator of root hiding)
        re.compile(r'(?:resetprop|setprop).*ro\.(?:build|product|system)', re.IGNORECASE),
        re.compile(r'ro\.product\..*(?:changed|modified)', re.IGNORECASE),
        re.compile(r'ro\.build\..*(?:changed|modified)', re.IGNORECASE),
        # Mount namespace manipulation
        re.compile(r'mount.*(?:bind|tmpfs).*(?:magisk|xposed)', re.IGNORECASE),
        re.compile(r'mount.*namespace.*manipulation', re.IGNORECASE),
    ]


class SystemSecurityHeuristic(BaseHeuristic):
    """
    Comprehensive Android System Security Analysis.

    This heuristic detects:
    - Advanced SELinux AVC violations and privilege escalation
    - Cross-app data access attempts (data exfiltration)
    - System integrity violations (dm-verity, AVB failures)
    - Root/Magisk detection and system tampering
    - Surveillance device access attempts
    - Apps using system UIDs inappropriately
    - Suspicious installer sources and package security issues
    - Attack chain correlation and burst detection

    Quality gates prevent false positives through context-aware analysis,
    build type awareness, and multi-signal correlation.
    """

    def __init__(self, config = None):
        super().__init__(config)
        self.max_detections_per_category = 15
        self.attack_correlation_window = 300  # 5 minutes for attack correlation
        self.avc_burst_threshold = 10  # Multiple AVCs in short time
        self.avc_burst_window = 60  # 1 minute window for burst detection
        
        # Quality gate settings - handle both dict and HeuristicConfig
        if config and hasattr(config, 'settings'):
            config_dict = config.settings
        elif config and hasattr(config, '__dict__'):
            config_dict = config.__dict__
        else:
            config_dict = config or {}
            
        self.min_suspicious_indicators = config_dict.get('min_suspicious_indicators', 2)  # Require 2+ indicators to reduce noise

        # Track SELinux mode for severity adjustment
        self.selinux_enforcing = True  # Default assumption
        self.selinux_mode_detected = False
        self.require_log_evidence = config_dict.get('require_log_evidence', False)  # Keep disabled for now

        # Initialize installation context heuristic for enrichment
        self.installation_context_heuristic = InstallationContextHeuristic()
    
    @property
    def name(self) -> str:
        """Get the name of this heuristic."""
        return "system_security"
    
    @property
    def category(self) -> str:
        """Get the category of this heuristic."""
        return "System Security"
    
    @property
    def description(self) -> str:
        """Get description of what this heuristic detects."""
        return "Detects privilege escalation and system security issues"
    
    def analyze(self, log_data: LogData) -> List[Detection]:
        """
        Analyze log data for system security issues.
        
        Args:
            log_data: Parsed log data to analyze
            
        Returns:
            List of Detection objects
        """
        detections = []
        analyzed_packages = set()  # Track packages to avoid duplicates
        
        # Debug logging
        self.logger.info(f"System security analysis: analyzing {len(log_data.packages)} packages")
        
        # Analyze each package for security issues
        for package_name, package_info in log_data.packages.items():
            # Skip if we've already analyzed this package
            if package_name in analyzed_packages:
                self.logger.debug(f"Skipping duplicate package: {package_name}")
                continue
                
            self.logger.debug(f"Analyzing package: {package_name}")
            package_detections = self._analyze_package(package_name, package_info, log_data)
            detections.extend(package_detections)
            analyzed_packages.add(package_name)
        
        # Security-specific data sources are now handled by dedicated heuristics
        
        # Look for system-level security issues in logs
        system_detections = self._analyze_system_logs(log_data)
        detections.extend(system_detections)

        # Advanced Security Analysis - collect all log lines
        all_lines = log_data.raw_lines

        # Detect SELinux mode transitions and create detections for runtime changes
        selinux_analysis = self._detect_selinux_mode_transitions(all_lines)
        selinux_detections = self._create_selinux_transition_detections(selinux_analysis)
        detections.extend(selinux_detections)

        # Advanced SELinux AVC Analysis
        advanced_selinux_detections = self._analyze_advanced_selinux_violations(all_lines, log_data)
        detections.extend(advanced_selinux_detections)

        # System Integrity Analysis
        integrity_detections = self._analyze_system_integrity_violations(all_lines)
        detections.extend(integrity_detections)

        # Root/Tampering Detection
        tampering_detections = self._analyze_root_tampering(all_lines)
        detections.extend(tampering_detections)

        # Apply attack correlation and burst detection
        detections = self._correlate_attack_patterns(detections)

        self.logger.info(f"System security analysis: found {len(detections)} detections")
        return detections
    
    def _analyze_package(self, package_name: str, package_info, log_data: LogData) -> List[Detection]:
        """Analyze a single package for security issues."""
        detections = []
        suspicious_indicators = 0
        findings = []
        evidence_list = []
        
        # Extract package information
        uid = getattr(package_info, 'uid', None)
        installer = getattr(package_info, 'installer', 'unknown')
        permissions = getattr(package_info, 'permissions', set())
        # Get installation context for enrichment
        installation_context = self.installation_context_heuristic.get_installation_context(package_name, log_data)
        
        self.logger.debug(f"Package {package_name}: uid={uid}, installer={installer}, permissions={len(permissions)}")

        # Zero-trust: ANY package using system UIDs requires investigation
        # Never whitelist based on package names - spyware can spoof system package names
        if uid and is_system_uid(str(uid)):
            app_id = extract_app_id(int(uid))
            user_id = extract_user_id(int(uid))
            suspicious_indicators += 1
            findings.append(f"System UID usage detected: UID {uid} (appId={app_id}, userId={user_id})")
            self.logger.debug(f"  -> Zero-trust violation: Package claims system UID {uid} (appId={app_id}, userId={user_id}, name: {package_name})")
            evidence_list.append(Evidence(
                type=EvidenceType.METADATA_ONLY,
                content=f"Package: {package_name}, UID: {uid}",
                confidence=0.6  # Lower confidence since system UIDs can be legitimate
            ))
        
        # Use installation context to enrich system security analysis
        if installation_context.risk_multiplier > 1.5:  # High risk installation
            suspicious_indicators += 1
            findings.append(f"High-risk installation context: {installation_context.installer_source} (risk: {installation_context.risk_multiplier:.1f})")
            self.logger.debug(f"  -> High-risk installation: {package_name} via {installation_context.installer_source}")
            evidence_list.append(Evidence(
                type=EvidenceType.METADATA_ONLY,
                content=f"Installation: {installation_context.installation_method}, Source: {installation_context.installer_source}, Risk: {installation_context.risk_multiplier:.1f}",
                confidence=0.8
            ))
    
        # Dangerous permission analysis is handled by the dedicated permission_analysis heuristic

        # Performance optimization: Skip log evidence collection for system apps with low risk
        # This significantly improves performance when analyzing hundreds of system packages
        if not installation_context.is_system_app or suspicious_indicators >= 2:
            # Find log evidence for this package using optimized matching
            log_evidence = self._find_log_evidence_precise(log_data.raw_lines, package_name, max_evidence=3)
            for evidence_line in log_evidence:
                evidence_list.append(Evidence(
                    type=EvidenceType.LOG_ANCHOR,
                    content=evidence_line,
                    confidence=0.7
                ))
        
        self.logger.debug(f"  -> Total suspicious indicators for {package_name}: {suspicious_indicators}")
        
        # Zero-trust quality gates with installation context verification
        critical_single_indicators = [
            'integrity failure', 'system remount on user', 'permissive→enforcing flip',
            'magisk', 'zygisk', 'setenforce 0', 'system uid usage detected'
        ]

        has_critical_indicator = any(
            any(critical in finding.lower() for critical in critical_single_indicators)
            for finding in findings
        )

        # Use installation context heuristic for zero-trust verification (no code duplication)
        is_verified_system_app = installation_context.is_system_app

        # Allow detection if:
        # 1. Multiple indicators (≥2), OR
        # 2. Single critical indicator, OR
        # 3. System UID usage by unverified package (zero-trust)
        should_detect = (
            suspicious_indicators >= self.min_suspicious_indicators or
            has_critical_indicator or
            (uid and is_system_uid(str(uid)) and not is_verified_system_app)
        )

        if should_detect:
            # Check if we have real log evidence when required
            has_log_evidence = any(e.type == EvidenceType.LOG_ANCHOR for e in evidence_list)

            if not self.require_log_evidence or has_log_evidence:
                # Create detection
                severity = self._calculate_severity(suspicious_indicators, findings)
                
                detection = Detection(
                    category=self.category,
                    package=package_name,
                    title=f"Zero-Trust Security Violation: {package_name}",
                    description=f"Package {package_name} exhibits {suspicious_indicators} suspicious indicators (zero-trust analysis)",
                    severity=severity,
                    confidence=min(0.9, 0.5 + (suspicious_indicators * 0.1)),
                    evidence=evidence_list,
                    technical_details={
                        'heuristic_name': self.name,
                        'package_name': package_name,
                        'suspicious_indicators': suspicious_indicators,
                        'findings': findings,
                        'uid': uid,
                        'installer': installer,
                        'zero_trust_analysis': True,
                        'installation_context': {
                            'installer_source': installation_context.installer_source,
                            'is_system_app': installation_context.is_system_app,
                            'risk_multiplier': installation_context.risk_multiplier
                        },
                        'verified_system_app': is_verified_system_app,
                        'threat_type': SecurityThreatType.ROOT_TAMPERING.value
                    }
                )
                
                detections.append(detection)
                self.logger.info(f"  -> Created detection for {package_name} with {suspicious_indicators} indicators")
        
        return detections
    
    def _analyze_appops_violations(self, log_data: LogData) -> List[Detection]:
        """Analyze AppOps for permission violations."""
        detections = []
        
        # Look for AppOps violations in logs
        appops_patterns = [
            r'appops.*denied',
            r'appops.*violation',
            r'permission.*denied.*appops',
            r'operation.*denied.*appops'
        ]
        
        for line in log_data.raw_lines:
            for pattern in appops_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    detection = Detection(
                        category="AppOps Violation",
                        title="AppOps Permission Violation",
                        description="AppOps permission enforcement violation detected",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        evidence=[Evidence(
                            type=EvidenceType.LOG_ANCHOR,
                            content=line.strip(),
                            confidence=0.8
                        )],
                        technical_details={
                            'heuristic_name': self.name,
                            'pattern_matched': pattern,
                            'log_line': line.strip()
                        }
                    )
                    detections.append(detection)
                    break
        
        return detections
    
    def _analyze_activity_services(self, log_data: LogData) -> List[Detection]:
        """Analyze activity services for security issues."""
        detections = []
        
        # Look for suspicious service patterns
        service_patterns = [
            r'service.*crash.*count.*[2-9]',  # Multiple service crashes
            r'ANR.*service',  # Application Not Responding services
            r'service.*restart.*count.*[3-9]',  # Multiple service restarts
            r'background.*service.*abuse',
            r'service.*permission.*escalation'
        ]
        
        for line in log_data.raw_lines:
            for pattern in service_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    detection = Detection(
                        category="Service Security Issue",
                        title="Suspicious Service Activity",
                        description="Suspicious service behavior detected",
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        evidence=[Evidence(
                            type=EvidenceType.LOG_ANCHOR,
                            content=line.strip(),
                            confidence=0.7
                        )],
                        technical_details={
                            'heuristic_name': self.name,
                            'pattern_matched': pattern,
                            'log_line': line.strip()
                        }
                    )
                    detections.append(detection)
                    break
        
        return detections
    
    def _analyze_system_logs(self, log_data: LogData) -> List[Detection]:
        """Analyze system logs for security issues with proper context awareness."""
        detections = []

        # SELinux AVC analysis is now handled by the comprehensive advanced method

        # Look for actual privilege escalation attempts (not normal enforcement)
        escalation_patterns = [
            # Root access attempts
            r'su:\s+.*failed\.',
            r'su:\s+.*(?:permission denied|not found|access denied)',

            # Actual capability violations (not normal denials)
            r'audit.*denied.*capability.*cap_(?:sys_admin|dac_override|setuid|setgid)',

            # System service access violations (actual attacks)
            r'permission\s+denied.*system_server.*(?:exploit|attack|malicious)',
            r'seccomp.*violation.*syscall',

            # Binder security violations (actual attacks, not normal denials)
            r'binder.*denied.*permission.*(?:exploit|attack|escalation)'
        ]

        for line in log_data.raw_lines:
            for pattern in escalation_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Found potential privilege escalation attempt
                    detection = Detection(
                        category="Privilege Escalation",
                        title="Potential Privilege Escalation Attempt",
                        description="System logs show potential privilege escalation activity",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        evidence=[Evidence(
                            type=EvidenceType.LOG_ANCHOR,
                            content=line.strip(),
                            confidence=0.8
                        )],
                        technical_details={
                            'heuristic_name': self.name,
                            'pattern_matched': pattern,
                            'log_line': line.strip(),
                            'threat_type': SecurityThreatType.PRIVILEGE_ESCALATION.value,
                            'abuse_type': 'system_log_privilege_escalation'
                        }
                    )
                    detections.append(detection)
                    break  # Only one detection per line

        return detections



    def _find_log_evidence(self, package_name: str, log_data: LogData) -> List[Evidence]:
        """Find relevant log evidence for a package."""
        evidence = []
        seen_content = set()  # Track unique content to avoid duplicates
        
        # Look for mentions of the package in logs
        for line in log_data.raw_lines[:100]:  # Limit to first 100 lines for performance
            if package_name in line:
                content = line.strip()
                # Only add if we haven't seen this content before
                if content not in seen_content:
                    evidence.append(Evidence(
                        type=EvidenceType.LOG_ANCHOR,
                        content=content,
                        confidence=0.6
                    ))
                    seen_content.add(content)
                    if len(evidence) >= 3:  # Limit evidence to avoid spam
                        break
        
        return evidence
    
    def _calculate_severity(self, suspicious_indicators: int, findings: List[str], permissive: bool = False) -> Severity:
        """Calculate severity based on indicators, findings, and SELinux mode."""
        base_severity = Severity.LOW

        if suspicious_indicators >= 4:
            base_severity = Severity.CRITICAL
        elif suspicious_indicators >= 3:
            base_severity = Severity.HIGH
        elif suspicious_indicators >= 2:
            base_severity = Severity.MEDIUM
        else:
            base_severity = Severity.LOW

        # Adjust severity based on SELinux mode
        if permissive or not self.selinux_enforcing:
            # Lower severity when in permissive mode (denials don't actually block)
            if base_severity == Severity.CRITICAL:
                base_severity = Severity.HIGH
            elif base_severity == Severity.HIGH:
                base_severity = Severity.MEDIUM
        elif self.selinux_enforcing and self.selinux_mode_detected:
            # Raise severity when in enforcing mode (actual security violations)
            if base_severity == Severity.MEDIUM:
                base_severity = Severity.HIGH

        return base_severity

    def _create_evidence(self, line: str, confidence: float, line_number: Optional[int] = None,
                        timestamp: Optional[datetime] = None, metadata: Optional[Dict[str, Any]] = None) -> Evidence:
        """Create evidence object from log line with optional context."""
        # Convert timestamp if needed
        parsed_timestamp = timestamp
        if timestamp is None:
            # Parse timestamp from line and convert float to datetime if needed
            raw_timestamp = self._parse_timestamp(line)
            parsed_timestamp = self._convert_timestamp_to_datetime(raw_timestamp) if raw_timestamp else None

        return Evidence(
            type=EvidenceType.LOG_ANCHOR,
            content=line.strip(),
            confidence=confidence,
            source_line_number=line_number,
            timestamp=parsed_timestamp,
            metadata=metadata or {}
        )

    def _parse_avc_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse AVC line with flexible key=value ordering and edge case handling."""
        match = AdvancedSecurityPatterns.AVC_PATTERN.search(line)
        if not match:
            return None

        perms, remaining_fields = match.groups()

        # Extract fields using flexible patterns
        parsed = {'permissions': perms.strip() if perms else '', 'raw_line': line}

        for field_name, pattern in AdvancedSecurityPatterns.AVC_FIELD_PATTERNS.items():
            field_match = pattern.search(remaining_fields)
            if field_match:
                value = field_match.group(1)
                if field_name == 'permissive':
                    parsed[field_name] = value == '1'
                else:
                    parsed[field_name] = value
            else:
                parsed[field_name] = None

        # Handle edge cases: fallback to name= when path= is missing
        if not parsed.get('path') and parsed.get('name'):
            parsed['path'] = parsed['name']
            parsed['path_source'] = 'name_fallback'
        elif not parsed.get('path') and parsed.get('dev') and parsed.get('ino'):
            parsed['path'] = f"dev={parsed['dev']},ino={parsed['ino']}"
            parsed['path_source'] = 'dev_ino_fallback'
        else:
            parsed['path_source'] = 'path_direct'

        # WARNING: comm is truncated to 15 chars - NEVER trust as reliable package identifier
        if parsed.get('comm'):
            parsed['comm_warning'] = 'truncated_15_chars_unreliable'

        return parsed

    def _build_pid_to_package_map(self, lines: List[str]) -> Dict[str, str]:
        """Build PID to package mapping from ActivityManager and process snapshots."""
        pid_to_pkg = {}

        # ActivityManager process start patterns
        am_patterns = [
            re.compile(r'am_proc_start.*uid=(\d+).*pid=(\d+).*process=([^\s,]+)', re.IGNORECASE),
            re.compile(r'Process started for.*uid=(\d+).*pid=(\d+).*package=([^\s,]+)', re.IGNORECASE),
            re.compile(r'Start proc (\d+):([^/\s]+)', re.IGNORECASE),  # Start proc PID:package
        ]

        # Process snapshot patterns (ps, /proc listings)
        proc_patterns = [
            re.compile(r'^\s*\d+\s+(\d+)\s+\d+\s+\d+\s+[^\s]+\s+[^\s]+\s+[^\s]+\s+[^\s]+\s+([^\s]+)', re.MULTILINE),  # ps output
        ]

        for line in lines:
            # Try ActivityManager patterns first (most reliable)
            for pattern in am_patterns:
                match = pattern.search(line)
                if match:
                    if len(match.groups()) == 3:
                        uid, pid, package = match.groups()
                        pid_to_pkg[pid] = package
                        self.logger.debug(f"PID mapping: {pid} -> {package} (from AM, uid={uid})")
                    elif len(match.groups()) == 2:  # Start proc pattern
                        pid, package = match.groups()
                        pid_to_pkg[pid] = package
                        self.logger.debug(f"PID mapping: {pid} -> {package} (from proc start)")

            # Try process snapshot patterns as fallback
            for pattern in proc_patterns:
                match = pattern.search(line)
                if match and len(match.groups()) == 2:
                    pid, process_name = match.groups()
                    # Only use if we don't have a better mapping
                    if pid not in pid_to_pkg:
                        pid_to_pkg[pid] = process_name
                        self.logger.debug(f"PID mapping: {pid} -> {process_name} (from proc snapshot)")

        self.logger.info(f"Built PID->package mapping with {len(pid_to_pkg)} entries")
        return pid_to_pkg

    def _resolve_package_from_avc(self, avc_data: Dict[str, Any], pid_to_pkg: Dict[str, str]) -> str:
        """Resolve actual package name from AVC data, preferring PID mapping over comm."""
        # First try PID mapping (most reliable)
        if avc_data.get('pid') and avc_data['pid'] in pid_to_pkg:
            package = pid_to_pkg[avc_data['pid']]
            self.logger.debug(f"Resolved package via PID {avc_data['pid']}: {package}")
            return package

        # Fallback to comm but warn about truncation
        if avc_data.get('comm'):
            comm = avc_data['comm']
            self.logger.warning(f"Using truncated comm as package (unreliable): {comm} (PID {avc_data.get('pid', 'unknown')})")
            return f"{comm}[truncated]"

        # Last resort: extract from scontext if it contains app info
        if avc_data.get('scontext'):
            scontext = avc_data['scontext']
            if ':untrusted_app:' in scontext or ':platform_app:' in scontext:
                return f"app_from_scontext[{scontext.split(':')[2] if len(scontext.split(':')) > 2 else 'unknown'}]"

        return "unknown_package"

    def _detect_selinux_mode_transitions(self, lines: List[str]) -> Dict[str, Any]:
        """Detect SELinux mode and track transitions with timestamps."""
        selinux_states = []
        mode_transitions = []

        # Timestamp patterns for different log formats
        timestamp_patterns = [
            re.compile(r'audit\((\d+\.\d+):\d+\):', re.IGNORECASE),  # audit(173013.123:456):
            re.compile(r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})', re.IGNORECASE),  # MM-DD HH:MM:SS.mmm
            re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})', re.IGNORECASE),  # YYYY-MM-DD HH:MM:SS.mmm
        ]

        for line in lines:
            # Extract timestamp
            timestamp = None
            for ts_pattern in timestamp_patterns:
                ts_match = ts_pattern.search(line)
                if ts_match:
                    timestamp = ts_match.group(1)
                    break

            # Check for SELinux mode indicators
            for pattern in AdvancedSecurityPatterns.SELINUX_MODE_PATTERNS:
                if pattern.search(line):
                    current_mode = None
                    is_runtime_change = False

                    if 'setenforce 0' in line.lower():
                        current_mode = 'permissive'
                        is_runtime_change = True  # Runtime change is more suspicious
                        self.logger.warning(f"Runtime SELinux disable detected (non-rooted device): {line.strip()}")
                    elif 'setenforce 1' in line.lower():
                        current_mode = 'enforcing'
                        is_runtime_change = True
                        self.logger.info(f"Runtime SELinux enable detected (rooted device): {line.strip()}")
                    elif 'permissive' in line.lower():
                        current_mode = 'permissive'
                        self.logger.info(f"SELinux permissive mode detected (rooted device): {line.strip()}")
                    elif 'enforcing' in line.lower():
                        current_mode = 'enforcing'
                        self.logger.info(f"SELinux enforcing mode detected (rooted device): {line.strip()}")
                    elif 'disabled' in line.lower():
                        current_mode = 'disabled'
                        self.logger.warning(f"SELinux disabled detected: {line.strip()}")

                    if current_mode:
                        state_entry = {
                            'mode': current_mode,
                            'timestamp': timestamp,
                            'is_runtime_change': is_runtime_change,
                            'line': line.strip()
                        }
                        selinux_states.append(state_entry)

                        # Detect transitions
                        if len(selinux_states) > 1:
                            prev_mode = selinux_states[-2]['mode']
                            if prev_mode != current_mode:
                                transition = {
                                    'from': prev_mode,
                                    'to': current_mode,
                                    'timestamp': timestamp,
                                    'is_runtime': is_runtime_change,
                                    'line': line.strip()
                                }
                                mode_transitions.append(transition)
                                self.logger.warning(f"SELinux mode transition: {prev_mode} -> {current_mode}")
                    break

        # Set final state
        if selinux_states:
            final_state = selinux_states[-1]
            self.selinux_enforcing = final_state['mode'] == 'enforcing'
            self.selinux_mode_detected = True

        return {
            'states': selinux_states,
            'transitions': mode_transitions,
            'final_mode': selinux_states[-1]['mode'] if selinux_states else 'unknown',
            'has_runtime_changes': any(s['is_runtime_change'] for s in selinux_states)
        }

    def _create_selinux_transition_detections(self, selinux_analysis: Dict[str, Any]) -> List[Detection]:
        """Create detections for suspicious SELinux mode transitions."""
        detections = []

        for transition in selinux_analysis.get('transitions', []):
            # Focus on runtime changes (more suspicious than boot-time)
            if transition['is_runtime']:
                if transition['to'] == 'permissive' or transition['to'] == 'disabled':
                    severity = Severity.CRITICAL
                    confidence = 0.95
                    title = f"Runtime SELinux Disable: {transition['from']} → {transition['to']}"
                    description = f"SELinux was disabled at runtime via {transition['to']} - critical security bypass"
                elif transition['from'] == 'permissive' and transition['to'] == 'enforcing':
                    severity = Severity.MEDIUM
                    confidence = 0.8
                    title = f"Runtime SELinux Enable: {transition['from']} → {transition['to']}"
                    description = f"SELinux was enabled at runtime - possible evasion cleanup"
                else:
                    continue  # Skip other transitions

                detection = Detection(
                    category="SELinux Security Bypass",
                    package="system",
                    severity=severity,
                    confidence=confidence,
                    title=title,
                    description=description,
                    technical_details={
                        'threat_type': SecurityThreatType.ROOT_TAMPERING.value,
                        'violation_type': 'selinux_runtime_transition',
                        'from_mode': transition['from'],
                        'to_mode': transition['to'],
                        'timestamp': transition.get('timestamp'),
                        'is_runtime_change': True,
                        'abuse_type': 'selinux_security_bypass'
                    },
                    evidence=[Evidence(
                        type=EvidenceType.LOG_ANCHOR,
                        content=transition['line'],
                        confidence=confidence
                    )]
                )
                detections.append(detection)

        return detections

    def _parse_timestamp(self, line: str) -> Optional[float]:
        """Parse timestamp from log line and convert to epoch seconds."""
        # Timestamp patterns with conversion logic
        patterns = [
            # audit(173013.123:456): -> epoch seconds
            (re.compile(r'audit\((\d+\.\d+):\d+\):', re.IGNORECASE), lambda m: float(m.group(1))),
            # MM-DD HH:MM:SS.mmm -> approximate epoch (assume current year)
            (re.compile(r'(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3})', re.IGNORECASE),
             lambda m: self._convert_mmdd_to_epoch(m.groups())),
            # YYYY-MM-DD HH:MM:SS.mmm -> epoch
            (re.compile(r'(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3})', re.IGNORECASE),
             lambda m: self._convert_full_date_to_epoch(m.groups())),
        ]

        for pattern, converter in patterns:
            match = pattern.search(line)
            if match:
                try:
                    return converter(match)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to parse timestamp from {line[:50]}: {e}")
                    continue

        return None

    def _convert_timestamp_to_datetime(self, timestamp_float: float) -> datetime:
        """Convert float timestamp (epoch seconds) to datetime object."""
        return datetime.fromtimestamp(timestamp_float)

    def _convert_mmdd_to_epoch(self, groups) -> float:
        """Convert MM-DD HH:MM:SS.mmm to approximate epoch seconds."""
        import datetime
        mm, dd, hh, min_val, ss, ms = groups
        # Assume current year (rough approximation)
        year = datetime.datetime.now().year
        dt = datetime.datetime(year, int(mm), int(dd), int(hh), int(min_val), int(ss), int(ms) * 1000)
        return dt.timestamp()

    def _convert_full_date_to_epoch(self, groups) -> float:
        """Convert YYYY-MM-DD HH:MM:SS.mmm to epoch seconds."""
        import datetime
        yyyy, mm, dd, hh, min_val, ss, ms = groups
        dt = datetime.datetime(int(yyyy), int(mm), int(dd), int(hh), int(min_val), int(ss), int(ms) * 1000)
        return dt.timestamp()

    def _is_within_time_window(self, timestamp1: Optional[float], timestamp2: Optional[float], window_seconds: float) -> bool:
        """Check if two timestamps are within the specified time window."""
        if timestamp1 is None or timestamp2 is None:
            return False
        return abs(timestamp1 - timestamp2) <= window_seconds

    def _find_correlated_events(self, events: List[Dict], window_seconds: float) -> List[List[Dict]]:
        """Group events that occur within the correlation window."""
        if not events:
            return []

        # Sort events by timestamp
        sorted_events = sorted([e for e in events if e.get('timestamp')], key=lambda x: x['timestamp'])

        if not sorted_events:
            return [events]  # Return all events as one group if no timestamps

        correlated_groups = []
        current_group = [sorted_events[0]]

        for event in sorted_events[1:]:
            if self._is_within_time_window(current_group[-1]['timestamp'], event['timestamp'], window_seconds):
                current_group.append(event)
            else:
                correlated_groups.append(current_group)
                current_group = [event]

        if current_group:
            correlated_groups.append(current_group)

        return correlated_groups

    def _find_log_evidence_precise(self, lines: List[str], package_name: str, max_evidence: int = 3) -> List[str]:
        """Find log evidence with optimized package name matching."""
        evidence = []

        # Performance optimization: sampling across the entire log
        # Sample from beginning, middle, and end to capture different phases of activity
        if len(lines) > 2000:
            # Sample from different sections: early boot, mid-session, recent activity
            early_section = lines[:500]
            mid_section = lines[len(lines)//2-250:len(lines)//2+250]
            recent_section = lines[-500:]
            search_lines = early_section + mid_section + recent_section
        else:
            search_lines = lines

        # Simple string containment check first (much faster than regex)
        for line in search_lines:
            if len(evidence) >= max_evidence:
                break

            # Quick containment check first
            if package_name in line:
                # More precise check to avoid substring matches
                # Use word boundaries but with simpler logic
                line_lower = line.lower()
                package_lower = package_name.lower()

                # Find all occurrences of the package name
                start = 0
                while True:
                    pos = line_lower.find(package_lower, start)
                    if pos == -1:
                        break

                    # Check if it's a word boundary match
                    before_ok = pos == 0 or line_lower[pos-1] in ' \t\n\r()[]{}:;,="\'<>|&'
                    after_pos = pos + len(package_lower)
                    after_ok = after_pos >= len(line_lower) or line_lower[after_pos] in ' \t\n\r()[]{}:;,="\'<>|&'

                    if before_ok and after_ok:
                        evidence.append(line.strip())
                        break

                    start = pos + 1

        return evidence

    def _is_privileged_target_app(self, package_name: str, log_data: LogData) -> bool:
        """Check if target app is privileged using zero-trust installation context verification."""
        # Use installation context heuristic for zero-trust verification
        installation_context = self.installation_context_heuristic.get_installation_context(package_name, log_data)
        return installation_context.is_privileged

    def _analyze_improved_kernel_modules(self, lines: List[str], build_type: str) -> List[Detection]:
        """Improved kernel module analysis with GKI awareness and zero-trust context filtering."""
        detections = []
        module_events = []

        for i, line in enumerate(lines):
            # Apply zero-trust framework: analyze ALL module activity
            # Only skip if it's clearly not a kernel module (e.g., application modules)
            if self._is_application_module_activity(line):
                continue

            for pattern in AdvancedSecurityPatterns.MODULE_LOAD_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Determine confidence level based on GKI context and build type
                    confidence_level = self._assess_module_confidence_gki_aware(line, build_type)

                    if confidence_level != 'ignore':
                        timestamp = self._parse_timestamp(line)
                        module_events.append({
                            'line_number': i,
                            'line': line,
                            'confidence_level': confidence_level,
                            'timestamp': timestamp
                        })
                    break

        # Group correlated events
        if module_events:
            correlated_groups = self._find_correlated_events(module_events, self.attack_correlation_window)

            for group in correlated_groups:
                # Create detection for each group
                highest_confidence = max(group, key=lambda x: {'critical': 3, 'high': 2, 'medium': 1, 'low': 0}[x['confidence_level']])

                detection = self._create_module_detection(group, highest_confidence, build_type)
                if detection:
                    detections.append(detection)

        return detections[:self.max_detections_per_category]



    def _is_application_module_activity(self, line: str) -> bool:
        """Check if this is application module activity (not kernel modules) using zero-trust analysis."""
        line_lower = line.lower()

        # Only skip if it's clearly application-level module activity
        # Look for specific patterns that indicate non-kernel modules
        app_module_indicators = [
            'dynamite',  # Google Play Services dynamic modules
            'chimera',   # Google Play Services modules
            'split_config',  # App bundle split configs
            'feature_module',  # Android App Bundle feature modules
        ]

        # Only skip if it contains app module indicators AND doesn't contain kernel indicators
        has_app_indicators = any(indicator in line_lower for indicator in app_module_indicators)
        has_kernel_indicators = any(indicator in line_lower for indicator in ['kernel', 'ko', '/lib/modules/', 'insmod', 'modprobe'])

        # Zero-trust: only skip if clearly app-level AND no kernel indicators
        return has_app_indicators and not has_kernel_indicators

    def _assess_module_confidence_gki_aware(self, line: str, build_type: str) -> str:
        """Assess confidence level for kernel module activity with GKI awareness."""
        line_lower = line.lower()

        # Critical: Always suspicious regardless of context
        critical_patterns = [
            re.compile(r'tainted', re.IGNORECASE),
            re.compile(r'signature.*verification.*failed', re.IGNORECASE),
            re.compile(r'unknown symbol', re.IGNORECASE),
            re.compile(r'verification failed', re.IGNORECASE)
        ]
        if any(pattern.search(line) for pattern in critical_patterns):
            return 'critical'

        # High: Suspicious patterns
        if 'livepatch' in line_lower:
            return 'high'

        # Check if this is a standard kernel module (legitimate)
        module_name = self._extract_module_name_from_line(line)
        if module_name and module_name.lower() in AdvancedSecurityPatterns.STANDARD_KERNEL_MODULES:
            # Standard kernel modules are legitimate, especially during boot
            return 'ignore'

        # GKI-specific analysis: Generic Kernel Image should have limited module loading
        gki_indicators = [
            'gki', 'generic kernel', 'android-mainline', 'android-common'
        ]
        is_gki_system = any(indicator in line_lower for indicator in gki_indicators)

        # On GKI systems, any non-vendor module loading is more suspicious
        if is_gki_system and 'module' in line_lower and ('loaded' in line_lower or 'loading' in line_lower):
            # Check if it's from vendor partition (more legitimate on GKI)
            if '/vendor/' not in line_lower and '/system/' not in line_lower:
                return 'high'  # Non-vendor modules on GKI are suspicious

        # Check for legitimate contexts
        has_legitimate_loader = any(loader in line_lower for loader in AdvancedSecurityPatterns.LEGITIMATE_MODULE_LOADERS)
        has_legitimate_path = any(path in line_lower for path in AdvancedSecurityPatterns.LEGITIMATE_MODULE_PATHS)
        has_signature_ok = 'signature ok' in line_lower or 'signed' in line_lower

        # Module path missing or outside legitimate locations
        if 'module' in line_lower and not has_legitimate_path and '/vendor' not in line_lower:
            return 'high'

        # Generic module loading
        if 'module' in line_lower and ('loaded' in line_lower or 'loading' in line_lower):
            if build_type == 'user' and not (has_legitimate_loader and has_legitimate_path):
                return 'medium'
            elif build_type in ['userdebug', 'eng'] and has_legitimate_loader and has_legitimate_path and has_signature_ok:
                return 'low'
            elif build_type in ['userdebug', 'eng']:
                return 'low'

        return 'ignore'

    def _extract_module_name_from_line(self, line: str) -> Optional[str]:
        """Extract module name from log line for standard module checking."""
        # Android kernel log format: MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG : message
        # Example: "09-03 13:00:06.482  root     0     0 I brd     : module loaded"

        # Pattern 1: TAG field contains module name (most common in Android logs)
        tag_match = re.search(r'\d+\s+[VDIWEF]\s+(\w+)\s*:\s*module\s+loaded', line, re.IGNORECASE)
        if tag_match:
            return tag_match.group(1)

        # Pattern 2: Explicit module name in message
        module_patterns = [
            r'module\s+([^\s]+)\s+loaded',
            r'loading\s+module\s+([^\s]+)',
            r'insmod\s+([^\s/]+)',
            r'modprobe\s+([^\s/]+)',
            r'([^\s/]+):\s*module\s+loaded'  # TAG: module loaded format
        ]

        for pattern in module_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                module_name = match.group(1)
                # Clean up common suffixes
                if module_name.endswith('.ko'):
                    module_name = module_name[:-3]
                return module_name

        return None

    def _extract_module_info(self, log_line: str) -> Dict[str, Optional[str]]:
        """Extract module information from log line for better context."""
        module_info = {
            'name': None,
            'path': None,
            'loader': None
        }

        line_lower = log_line.lower()

        # Extract module name from common patterns
        module_patterns = [
            r'module\s+([^\s]+)\s+loaded',
            r'loading\s+module\s+([^\s]+)',
            r'insmod\s+([^\s]+)',
            r'modprobe\s+([^\s]+)'
        ]

        for pattern in module_patterns:
            match = re.search(pattern, line_lower)
            if match:
                module_info['name'] = match.group(1)
                break

        # Extract module path
        path_patterns = [
            r'(/[^\s]+\.ko)',
            r'(/vendor/lib[^\s]+)',
            r'(/system/lib[^\s]+)'
        ]

        for pattern in path_patterns:
            match = re.search(pattern, log_line)
            if match:
                module_info['path'] = match.group(1)
                break

        # Extract loader process from log format (if available)
        # Common Android log format: MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG : message
        log_format_match = re.match(r'^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+(\w+)\s+\d+\s+\d+\s+[VDIWEF]\s+(\w+)\s*:', log_line)
        if log_format_match:
            module_info['loader'] = log_format_match.group(1)

        return module_info

    def _create_module_detection(self, event_group: List[Dict], highest_confidence_event: Dict, build_type: str) -> Optional[Detection]:
        """Create detection for kernel module activity group."""
        confidence_level = highest_confidence_event['confidence_level']

        if confidence_level == 'critical':
            severity = Severity.CRITICAL
            confidence = 0.95
            title = "Critical Kernel Module Security Violation"
        elif confidence_level == 'high':
            severity = Severity.HIGH
            confidence = 0.85
            title = "Suspicious Kernel Module Activity"
        elif confidence_level == 'medium':
            severity = Severity.MEDIUM
            confidence = 0.7
            title = "Kernel Module Activity (Investigation Required)"
        else:  # low
            severity = Severity.LOW
            confidence = 0.5
            title = "Kernel Module Activity (Monitoring)"

        # Create evidence from event group with enhanced context
        evidence = []
        for event in event_group[:3]:  # Limit evidence
            # Extract module name and path from the log line for better context
            line_content = event['line'].strip()
            module_info = self._extract_module_info(line_content)

            # Convert timestamp from float to datetime if needed
            raw_timestamp = event.get('timestamp')
            converted_timestamp = self._convert_timestamp_to_datetime(raw_timestamp) if raw_timestamp else None

            evidence.append(Evidence(
                type=EvidenceType.LOG_ANCHOR,
                content=line_content,
                confidence=confidence,
                source_line_number=event.get('line_number'),
                timestamp=converted_timestamp,
                metadata={
                    'confidence_level': event.get('confidence_level', 'unknown'),
                    'module_name': module_info.get('name'),
                    'module_path': module_info.get('path'),
                    'loader_process': module_info.get('loader'),
                    'analysis_context': f"Build type: {build_type}, Zero-trust analysis enabled"
                }
            ))

        return Detection(
            category="Kernel Module Activity",
            package="kernel",
            severity=severity,
            confidence=confidence,
            title=title,
            description=f"Kernel module activity detected: {len(event_group)} related events",
            technical_details={
                'threat_type': SecurityThreatType.ROOT_TAMPERING.value,
                'violation_type': 'kernel_module_load',
                'confidence_level': confidence_level,
                'event_count': len(event_group),
                'build_type': build_type,
                'zero_trust_analysis': True,
                'time_window': f"{event_group[0].get('timestamp', 'unknown')} - {event_group[-1].get('timestamp', 'unknown')}",
                'abuse_type': 'kernel_module_tampering'
            },
            evidence=evidence
        )

    def _is_cross_app_access(self, avc_data: Dict[str, Any]) -> bool:
        """Check if AVC represents cross-app data access."""
        if not avc_data.get('path') or not avc_data.get('scontext') or not avc_data.get('tcontext'):
            return False

        # Check for untrusted app accessing other app's data
        if ('untrusted_app' in avc_data['scontext'] and
            'app_data_file' in avc_data['tcontext'] and
            '/data/data/' in avc_data['path']):
            return True

        return False

    def _extract_target_app_from_path(self, path: str) -> str:
        """Extract target app package name from path."""
        if '/data/data/' in path:
            parts = path.split('/data/data/')
            if len(parts) > 1:
                return parts[1].split('/')[0]
        return 'unknown'

    def _get_build_type(self, lines: List[str]) -> str:
        """Extract build type from system properties with proper precedence."""
        for line in lines:
            if 'ro.build.type' in line:
                # Check userdebug/eng before user to avoid substring matches
                if 'userdebug' in line:
                    return 'userdebug'
                elif 'eng' in line:
                    return 'eng'
                elif 'user' in line:
                    return 'user'
        return 'unknown'

    def _analyze_advanced_selinux_violations(self, lines: List[str], log_data: LogData) -> List[Detection]:
        """Comprehensive SELinux AVC analysis with proper context parsing and PID mapping."""
        detections = []

        # Build PID to package mapping for accurate package identification
        pid_to_pkg = self._build_pid_to_package_map(lines)

        # Data exfiltration detection
        cross_app_accesses = []
        capability_attempts = []
        device_accesses = []

        for i, line in enumerate(lines):
            avc_data = self._parse_avc_line(line)
            if not avc_data:
                continue

            # Parse timestamp for burst detection
            timestamp = self._parse_timestamp(line)
            avc_data['timestamp'] = timestamp
            avc_data['line_number'] = i

            # Resolve actual package name using PID mapping
            actual_package = self._resolve_package_from_avc(avc_data, pid_to_pkg)
            avc_data['resolved_package'] = actual_package

            # Check for cross-app data access
            if self._is_cross_app_access(avc_data):
                cross_app_accesses.append((i, avc_data))

            # Check for dangerous capability attempts by untrusted apps
            if (avc_data.get('scontext') and 'untrusted_app' in avc_data['scontext'] and
                avc_data.get('tclass') in ['capability', 'capability2'] and
                avc_data.get('permissions')):

                dangerous_caps = {'setuid', 'setgid', 'dac_override', 'sys_admin', 'sys_module', 'mac_admin', 'mac_override'}
                requested_perms = set(avc_data['permissions'].split())

                if dangerous_caps.intersection(requested_perms):
                    capability_attempts.append((i, avc_data, requested_perms.intersection(dangerous_caps)))

            # Check for ptrace attempts (process manipulation)
            if (avc_data.get('scontext') and 'untrusted_app' in avc_data['scontext'] and
                avc_data.get('tclass') == 'process' and
                'ptrace' in avc_data.get('permissions', '')):
                capability_attempts.append((i, avc_data, {'ptrace'}))

            # Check for surveillance device access
            if (avc_data.get('scontext') and 'untrusted_app' in avc_data['scontext'] and
                avc_data.get('path') and avc_data.get('permissions')):

                device_type = None
                if '/dev/video' in avc_data['path']:
                    device_type = 'camera'
                elif '/dev/snd/' in avc_data['path']:
                    device_type = 'audio'
                elif '/dev/gnss' in avc_data['path'] or '/dev/gps' in avc_data['path']:
                    device_type = 'location'

                if device_type and any(perm in avc_data['permissions'] for perm in ['read', 'write', 'open']):
                    device_accesses.append((i, avc_data, device_type))

        # Apply burst detection and enhanced cross-app access logic
        cross_app_events_with_metadata = [
            {'timestamp': avc_data.get('timestamp'), 'line_number': line_num, 'avc_data': avc_data}
            for line_num, avc_data in cross_app_accesses
        ]

        cross_app_bursts = self._find_correlated_events(cross_app_events_with_metadata, self.avc_burst_window)

        # Create detections for cross-app access (≥3 events, privileged targets, or permissive mode)
        for burst_group in cross_app_bursts:
            for event in burst_group[:self.max_detections_per_category]:
                line_num, avc_data = event['line_number'], event['avc_data']
                target_app = self._extract_target_app_from_path(avc_data.get('path', ''))

                # Enhanced severity logic
                is_privileged_target = self._is_privileged_target_app(target_app, log_data)
                is_permissive = avc_data.get('permissive', False)

                # Only create detection if: multiple attempts, privileged target, or permissive mode
                if len(burst_group) >= 3 or is_privileged_target or is_permissive:
                    # Adjust severity based on context
                    severity = Severity.CRITICAL if is_privileged_target else Severity.HIGH

                    detection = Detection(
                    category="Cross-App Data Access",
                    package=avc_data.get('comm', 'unknown'),
                    severity=Severity.HIGH,
                    confidence=0.92,
                    title=f"Cross-App Data Access: {avc_data.get('comm', 'unknown')} → {target_app}",
                    description=f"Process attempted unauthorized access to {target_app}'s private data",
                    technical_details={
                        'threat_type': SecurityThreatType.SELINUX_VIOLATION.value,
                        'violation_type': 'cross_app_data_access',
                        'target_app': target_app,
                        'source_context': avc_data.get('scontext'),
                        'target_context': avc_data.get('tcontext'),
                        'permissions': avc_data.get('permissions'),
                        'line_number': line_num,
                        'abuse_type': 'selinux_cross_app_access'
                    },
                    evidence=[self._create_evidence(avc_data['raw_line'], 0.92)]
                )
                detections.append(detection)

        # Create detections for capability attempts
        for line_num, avc_data, dangerous_perms in capability_attempts[:self.max_detections_per_category]:
            severity = Severity.CRITICAL if any(cap in dangerous_perms for cap in ['sys_admin', 'sys_module', 'mac_admin']) else Severity.HIGH

            detection = Detection(
                category="Privilege Escalation Attempt",
                package=avc_data.get('comm', 'unknown'),
                severity=severity,
                confidence=0.95,
                title=f"Capability Escalation: {', '.join(dangerous_perms)}",
                description=f"Untrusted app attempted dangerous capabilities: {', '.join(dangerous_perms)}",
                technical_details={
                    'threat_type': SecurityThreatType.PRIVILEGE_ESCALATION.value,
                    'violation_type': 'capability_escalation',
                    'dangerous_capabilities': list(dangerous_perms),
                    'source_context': avc_data.get('scontext'),
                    'target_class': avc_data.get('tclass'),
                    'line_number': line_num,
                    'abuse_type': 'selinux_capability_escalation'
                },
                evidence=[self._create_evidence(avc_data['raw_line'], 0.95)]
            )
            detections.append(detection)

        # Create detections for device access attempts
        for line_num, avc_data, device_type in device_accesses[:self.max_detections_per_category]:
            detection = Detection(
                category="Surveillance Device Access",
                package=avc_data.get('comm', 'unknown'),
                severity=Severity.HIGH,
                confidence=0.88,
                title=f"Unauthorized {device_type.title()} Device Access",
                description=f"Untrusted app attempted direct access to {device_type} device: {avc_data.get('path')}",
                technical_details={
                    'threat_type': SecurityThreatType.SURVEILLANCE.value,
                    'violation_type': 'surveillance_device_access',
                    'device_type': device_type,
                    'device_path': avc_data.get('path'),
                    'permissions': avc_data.get('permissions'),
                    'source_context': avc_data.get('scontext'),
                    'line_number': line_num,
                    'abuse_type': 'selinux_surveillance_device_access'
                },
                evidence=[self._create_evidence(avc_data['raw_line'], 0.88)]
            )
            detections.append(detection)

        return detections

    def _analyze_system_integrity_violations(self, lines: List[str]) -> List[Detection]:
        """Analyze system integrity violations (dm-verity, AVB failures) with proper success/failure distinction."""
        detections = []

        for i, line in enumerate(lines):
            # Check if this is actually a success message (not a failure)
            if self._is_integrity_success_message(line):
                continue  # Skip success messages

            for pattern in AdvancedSecurityPatterns.SYSTEM_INTEGRITY_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Critical severity for integrity violations
                    severity = Severity.CRITICAL
                    confidence = 0.98

                    violation_type = 'dm_verity' if 'verity' in line.lower() else 'avb_verification'

                    detection = Detection(
                        category="System Integrity Violation",
                        package="system",
                        severity=severity,
                        confidence=confidence,
                        title=f"System Integrity Failure: {violation_type.replace('_', ' ').title()}",
                        description=f"System integrity verification failed - possible tampering detected",
                        technical_details={
                            'threat_type': SecurityThreatType.SYSTEM_INTEGRITY.value,
                            'violation_type': violation_type,
                            'line_number': i,
                            'abuse_type': 'system_integrity_violation'
                        },
                        evidence=[self._create_evidence(line, confidence)]
                    )
                    detections.append(detection)

                    if len(detections) >= self.max_detections_per_category:
                        return detections
                    break

        return detections

    def _is_integrity_success_message(self, line: str) -> bool:
        """Check if a line indicates successful integrity verification (not a failure)."""
        line_lower = line.lower()

        # Success indicators
        success_indicators = [
            'verifiedbootstate=green',
            'veritymode=enforcing',
            'verification.*success',
            'integrity.*ok',
            'verity.*enabled',
            'avb.*success',
            'boot.*verified'
        ]

        # If line contains success indicators, it's not a failure
        for indicator in success_indicators:
            if re.search(indicator, line_lower):
                return True

        return False

    def _analyze_root_tampering(self, lines: List[str]) -> List[Detection]:
        """Analyze root/tampering activities with build type awareness."""
        detections = []
        build_type = self._get_build_type(lines)

        # Analyze remount events
        remount_events = []
        for i, line in enumerate(lines):
            for pattern in AdvancedSecurityPatterns.REMOUNT_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Skip overlayfs on userdebug/eng builds (normal for A/B updates)
                    if 'overlayfs' in line.lower() and build_type in ['userdebug', 'eng']:
                        continue

                    remount_events.append((i, line))

        # Create detections for remount events
        for line_num, line in remount_events[:self.max_detections_per_category]:
            # Higher severity on user builds
            severity = Severity.CRITICAL if build_type == 'user' else Severity.HIGH
            confidence = 0.96 if build_type == 'user' else 0.75

            detection = Detection(
                category="System Tampering",
                package="system",
                severity=severity,
                confidence=confidence,
                title=f"System Remount on {build_type.title()} Build",
                description=f"System partition remounted on {build_type} build - {'critical tampering' if build_type == 'user' else 'development activity'}",
                technical_details={
                    'threat_type': SecurityThreatType.ROOT_TAMPERING.value,
                    'violation_type': 'system_remount',
                    'build_type': build_type,
                    'line_number': line_num,
                    'abuse_type': 'system_remount_tampering'
                },
                evidence=[self._create_evidence(
                    line,
                    confidence,
                    line_number=line_num,
                    metadata={
                        'detection_type': 'system_remount',
                        'build_type': build_type,
                        'severity_reason': 'critical tampering' if build_type == 'user' else 'development activity',
                        'analysis_context': 'Zero-trust system tampering analysis'
                    }
                )]
            )
            detections.append(detection)

        # Use improved kernel module analysis (avoid duplication)
        module_detections = self._analyze_improved_kernel_modules(lines, build_type)
        detections.extend(module_detections)

        # Analyze Magisk/root indicators - exclude package name lists
        magisk_events = []
        for i, line in enumerate(lines):
            # Skip lines that are clearly package name lists or queries
            if self._is_package_name_list(line):
                continue

            for pattern in AdvancedSecurityPatterns.MAGISK_PATTERNS:
                match = pattern.search(line)
                if match:
                    magisk_events.append((i, line))

        # Create detections for Magisk/root activity
        for line_num, line in magisk_events[:self.max_detections_per_category]:
            detection = Detection(
                category="Root Activity Detected",
                package="root",
                severity=Severity.CRITICAL,
                confidence=0.94,
                title="Magisk/Root Activity Detected",
                description="Root management tools detected - device may be compromised",
                technical_details={
                    'threat_type': SecurityThreatType.ROOT_TAMPERING.value,
                    'violation_type': 'magisk_root_activity',
                    'build_type': build_type,
                    'line_number': line_num,
                    'abuse_type': 'magisk_root_detection'
                },
                evidence=[self._create_evidence(
                    line,
                    0.94,
                    line_number=line_num,
                    metadata={
                        'detection_type': 'magisk_root_activity',
                        'build_type': build_type,
                        'analysis_context': 'Zero-trust root detection analysis'
                    }
                )]
            )
            detections.append(detection)

        return detections

    def _is_package_name_list(self, line: str) -> bool:
        """
        Check if a line contains package names in a list/array context.
        This prevents false positives when package names appear in queries or lists.
        """
        line_lower = line.lower().strip()

        # Skip lines that are clearly package name lists or queries
        package_list_indicators = [
            'queriespackages=',
            'packagequeries=',
            'getinstalledpackages',
            'pm list packages',
            'dumpsys package',
            # Lines that contain multiple comma-separated package names
            'com.' in line_lower and ',' in line_lower and line_lower.count('com.') > 2,
            # Lines that are just package names with brackets/commas
            line_lower.startswith('com.') and (',' in line_lower or ']' in line_lower),
            # Lines that contain package names in array format
            '[com.' in line_lower or ', com.' in line_lower
        ]

        return any(indicator if isinstance(indicator, bool) else indicator in line_lower
                  for indicator in package_list_indicators)

    def _correlate_attack_patterns(self, detections: List[Detection]) -> List[Detection]:
        """Apply multi-signal correlation for attack chain detection."""
        if len(detections) < 2:
            return detections

        # Group detections by type for correlation analysis
        detection_groups = defaultdict(list)
        for detection in detections:
            threat_type = detection.technical_details.get('threat_type', 'unknown')
            detection_groups[threat_type].append(detection)

        # Look for attack chain patterns
        correlated_detections = list(detections)  # Start with all detections

        # Pattern 1: System integrity failure → Remount → Root activity
        integrity_failures = detection_groups.get(SecurityThreatType.SYSTEM_INTEGRITY.value, [])
        remount_events = [d for d in detection_groups.get(SecurityThreatType.ROOT_TAMPERING.value, [])
                         if 'remount' in d.technical_details.get('violation_type', '')]
        root_activities = [d for d in detection_groups.get(SecurityThreatType.ROOT_TAMPERING.value, [])
                          if 'magisk' in d.technical_details.get('violation_type', '')]

        if integrity_failures and remount_events and root_activities:
            # Create correlation detection
            correlation_detection = Detection(
                category="Attack Chain Detected",
                package="system",
                severity=Severity.CRITICAL,
                confidence=0.98,
                title="Complete System Compromise Chain",
                description="Detected full attack chain: integrity bypass → system modification → root installation",
                technical_details={
                    'threat_type': SecurityThreatType.ATTACK_CORRELATION.value,
                    'attack_chain': 'integrity_bypass_to_root',
                    'chain_components': ['system_integrity', 'system_remount', 'root_activity'],
                    'component_count': len(integrity_failures) + len(remount_events) + len(root_activities),
                    'abuse_type': 'attack_chain_correlation'
                },
                evidence=[
                    self._create_evidence(f"Correlated {len(integrity_failures)} integrity failures, {len(remount_events)} remounts, {len(root_activities)} root activities", 0.98)
                ]
            )
            correlated_detections.append(correlation_detection)

        # Pattern 2: Multiple privilege escalation attempts (burst detection)
        priv_esc_detections = detection_groups.get(SecurityThreatType.PRIVILEGE_ESCALATION.value, [])
        selinux_priv_esc = [d for d in detection_groups.get(SecurityThreatType.SELINUX_VIOLATION.value, [])
                           if 'escalation' in d.technical_details.get('violation_type', '')]
        all_priv_esc = priv_esc_detections + selinux_priv_esc

        if len(all_priv_esc) >= self.avc_burst_threshold:
            burst_detection = Detection(
                category="Privilege Escalation Burst",
                package="multiple",
                severity=Severity.HIGH,
                confidence=0.94,
                title=f"Burst of {len(all_priv_esc)} Privilege Escalation Attempts",
                description=f"Detected {len(all_priv_esc)} privilege escalation attempts - possible automated attack",
                technical_details={
                    'threat_type': SecurityThreatType.ATTACK_CORRELATION.value,
                    'attack_pattern': 'privilege_escalation_burst',
                    'attempt_count': len(all_priv_esc),
                    'abuse_type': 'privilege_escalation_burst'
                },
                evidence=[
                    self._create_evidence(f"Burst of {len(all_priv_esc)} privilege escalation attempts detected", 0.94)
                ]
            )
            correlated_detections.append(burst_detection)

        return correlated_detections



    def _extract_target_app_from_path(self, path: str) -> str:
        """Extract target app package name from file path."""
        if not path:
            return 'unknown'

        # Extract from /data/data/package.name/ paths
        if '/data/data/' in path:
            parts = path.split('/data/data/')
            if len(parts) > 1:
                app_part = parts[1].split('/')[0]
                return app_part

        # Extract from /data/user/0/package.name/ paths
        if '/data/user/' in path:
            parts = path.split('/data/user/')
            if len(parts) > 1:
                user_parts = parts[1].split('/')
                if len(user_parts) > 1:
                    return user_parts[1]

        return 'unknown'
