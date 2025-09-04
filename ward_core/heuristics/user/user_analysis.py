"""
User Analysis Heuristic - Hidden User and Shared User Detection

Detects hidden users, shared user violations, and UID range anomalies
that may indicate system compromise or unauthorized modifications.

Focuses on realistic ADB log patterns from:
- dumpsys package for hidden users
- pm list-users for user enumeration
- UID mapping analysis
"""

import re
from typing import List, Dict, Any, Set
from collections import defaultdict

from ward_core.heuristics.base import BaseHeuristic
from ward_core.logic.models import Detection, Evidence, EvidenceType, Severity, LogData


class UserAnalysisHeuristic(BaseHeuristic):
    """Detects hidden users and shared user violations."""
    
    # User patterns from realistic ADB output (based on actual dumpsys package output)
    USER_PATTERNS = {
        'dumpsys_user': re.compile(r'User\s+(\d+):\s+.*?hidden=([^\s]+)', re.IGNORECASE),
        'pm_user': re.compile(r'UserInfo\{(\d+):([^:]+):([^\}]+)\}', re.IGNORECASE),
        'shared_user': re.compile(r'SharedUser\s+\[([^\]]+)\]', re.IGNORECASE),
        'package_uid': re.compile(r'userId=(\d+)', re.IGNORECASE),
    }
    
    # Normal user ID ranges
    NORMAL_USER_RANGES = {
        'system': (0, 9999),
        'app_users': (10000, 19999),
        'isolated_apps': (90000, 99999),
    }
    
    # Suspicious shared user patterns
    SUSPICIOUS_SHARED_USERS = {
        'android.uid.system',
        'android.uid.phone',
        'android.uid.shell',
        'android.uid.root',
    }
    
    def __init__(self, config=None):
        super().__init__(config)
        self.min_suspicious_indicators = 1
    
    @property
    def name(self) -> str:
        return "user_analysis"
    
    @property
    def category(self) -> str:
        return "System Analysis"
    
    @property
    def description(self) -> str:
        return "Detects hidden users and shared user violations"
    
    def analyze(self, log_data: LogData) -> List[Detection]:
        """Analyze log data for user anomalies."""
        detections = []
        
        # Detect hidden users
        hidden_user_detections = self._detect_hidden_users(log_data)
        detections.extend(hidden_user_detections)
        
        # Analyze shared users
        shared_user_detections = self._analyze_shared_users(log_data)
        detections.extend(shared_user_detections)
        
        # Detect UID anomalies
        uid_detections = self._detect_uid_anomalies(log_data)
        detections.extend(uid_detections)
        
        return detections
    
    def _detect_hidden_users(self, log_data: LogData) -> List[Detection]:
        """Detect hidden users in dumpsys package output."""
        detections = []
        hidden_users = set()  # Use set to track unique hidden users

        # Look for user information in raw lines (realistic approach)
        for line in log_data.raw_lines:
            line = line.strip()
            if not line:
                continue

            # Look for hidden user indicators in actual dumpsys package output
            user_match = self.USER_PATTERNS['dumpsys_user'].search(line)
            if user_match:
                user_id = user_match.group(1)
                hidden_flag = user_match.group(2).lower()

                # Only create detection if hidden and not already found
                if hidden_flag == 'true' and user_id not in hidden_users:
                    hidden_users.add(user_id)  # Mark as found to avoid duplicates

                    evidence = [
                        Evidence(
                            type=EvidenceType.LOG_ANCHOR,
                            content=f"Hidden user detected: {line.strip()}",
                            confidence=0.9
                        )
                    ]

                    detections.append(Detection(
                        category="User Analysis",
                        package="system",
                        title="Hidden User Detected",
                        description=f"Hidden user ID {user_id} found in system",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        technical_details={'user_id': user_id, 'hidden_flag': hidden_flag},
                        evidence=evidence
                    ))

        return detections
    
    def _analyze_shared_users(self, log_data: LogData) -> List[Detection]:
        """Analyze shared user assignments for violations."""
        detections = []
        found_shared_users = {}  # Track found shared users to avoid duplicates

        # Look for shared user information in raw lines
        for line in log_data.raw_lines:
            line = line.strip()
            if not line:
                continue

            # Look for shared user assignments in actual dumpsys package output
            shared_match = self.USER_PATTERNS['shared_user'].search(line)
            if shared_match:
                shared_user = shared_match.group(1)

                # Check if this is a suspicious shared user and we haven't seen it before
                if shared_user in self.SUSPICIOUS_SHARED_USERS and shared_user not in found_shared_users:
                    found_shared_users[shared_user] = line  # Store first occurrence

                    evidence = [
                        Evidence(
                            type=EvidenceType.LOG_ANCHOR,
                            content=f"Suspicious shared user assignment: {line.strip()}",
                            confidence=0.8
                        )
                    ]

                    detections.append(Detection(
                        category="User Analysis",
                        package="system",
                        title="Suspicious Shared User Assignment",
                        description=f"Package using suspicious shared user: {shared_user}",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        technical_details={'shared_user': shared_user},
                        evidence=evidence
                    ))

        return detections
    
    def _detect_uid_anomalies(self, log_data: LogData) -> List[Detection]:
        """Detect UID range anomalies and suspicious assignments."""
        detections = []
        
        # Collect UID assignments from packages
        uid_assignments = {}
        
        # Look for package UID information in raw lines
        current_package = None
        for line in log_data.raw_lines:
            line = line.strip()
            if not line:
                continue

            # Extract package and UID from actual dumpsys package output
            pkg_match = re.search(r'Package \[([^\]]+)\]', line)
            if pkg_match:
                current_package = pkg_match.group(1)
                continue

            uid_match = self.USER_PATTERNS['package_uid'].search(line)
            if uid_match and current_package:
                uid = int(uid_match.group(1))
                uid_assignments[current_package] = uid
        
        # Check for UID range violations (already deduplicated by using dict)
        for package, uid in uid_assignments.items():
            if self._is_suspicious_uid(uid):
                evidence = [
                    Evidence(
                        type=EvidenceType.METADATA_ONLY,
                        content=f"Package {package} assigned suspicious UID {uid}",
                        confidence=0.7
                    )
                ]

                detections.append(Detection(
                    category="User Analysis",
                    package=package,
                    title="Suspicious UID Assignment",
                    description=f"Package {package} assigned UID {uid} outside normal ranges",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    technical_details={'package': package, 'uid': uid},
                    evidence=evidence
                ))
        
        return detections
    
    def _is_suspicious_uid(self, uid: int) -> bool:
        """Check if a UID is suspicious."""
        # Check if UID is in normal ranges
        for (min_uid, max_uid) in self.NORMAL_USER_RANGES.values():
            if min_uid <= uid <= max_uid:
                return False
        
        # Check for system UIDs (0-9999) assigned to non-system packages
        if 0 <= uid <= 9999:
            return True
        
        # Check for very high UIDs (potential overflow or manipulation)
        if uid > 99999:
            return True
        
        return False
