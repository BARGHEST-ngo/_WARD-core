"""
Log data domain models.

Contains the data structures for representing collected log data and device information.
There's a hell of a lot of special case handling needed for various different bits in ADB logs. 
_is_valid_package_name is used to sort this stuff out. 
THis also needs massive cleanup. And also additional OEM-specific handling. 
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Set, Any, Optional


@dataclass
class PackageInfo:
    """Information about an Android package."""
    name: str
    uid: Optional[int] = None
    installer: str = "unknown"
    code_path: Optional[str] = None
    is_system: bool = False
    is_enabled: bool = True
    is_debuggable: bool = False
    
    # Permissions and capabilities
    permissions: Set[str] = field(default_factory=set)
    appops: Dict[str, Any] = field(default_factory=dict)
    
    # Activity information
    has_launcher_intent: bool = False
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    
    # Security information
    apk_signing_version: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    signers: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate package info after initialization."""
        if not self.name:
            raise ValueError("Package name cannot be empty")
        
        # Validate package name format
        if not self._is_valid_package_name(self.name):
            raise ValueError(f"Invalid package name format: {self.name}")
    
    def _is_valid_package_name(self, name: str) -> bool:
        """Check if package name follows valid Android package naming conventions."""
        if not name:
            return False
        
        # Allow single-character package names (like "U", "A", etc.)
        if len(name) == 1:
            return name.isalnum()
        
        # Allow system package names that don't have dots (like "android", "system", etc.)
        system_packages = {
            'android', 'system', 'shell', 'root', 'media', 'bluetooth', 
            'nfc', 'se', 'keystore', 'credstore', 'vold', 'recovery',
            'u', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
        }
        
        if name.lower() in system_packages:
            return True
        
        # Standard validation for regular packages
        if not (name[0].isalpha() or name[0] == '_'):
            return False
        # Allow @, -, and : for Android HAL services and shared components like com.android.vending:instant_app_installer
        if not all(c.isalnum() or c in '._@-:' for c in name):
            return False
        
        # Special handling for Android HAL services (contain @)
        if '@' in name:
            # Android HAL service format: android.hidl.service@1.0-service
            base_parts = name.split('@')
            if len(base_parts) == 2:
                service_name, version_part = base_parts
                # Validate service name part (before @)
                if '.' in service_name:
                    segments = service_name.split('.')
                    for segment in segments:
                        if not segment or not segment[0].isalpha():
                            return False
                    return True
        
        # Special handling for Android shared components (contain :)
        if ':' in name:
            # Android component format: com.android.vending:instant_app_installer
            base_parts = name.split(':')
            if len(base_parts) == 2:
                package_name, component_name = base_parts
                # Validate package name part (before :)
                if '.' in package_name:
                    segments = package_name.split('.')
                    for segment in segments:
                        if not segment or not segment[0].isalpha():
                            return False
                    # Validate component name part (after :) - allow alphanumeric with underscores
                    return component_name and (component_name[0].isalpha() or component_name[0] == '_')
        
        # Require dots for non-system packages
        if '.' in name:
            segments = name.split('.')
            for segment in segments:
                if not segment or not segment[0].isalpha():
                    return False
            return True
        
        # Allow single-word names that start with letters (for system components)
        return name.isalnum() and name[0].isalpha()
    
    def is_suspicious_installer(self) -> bool:
        """Check if the installer source is suspicious."""
        suspicious_installers = {
            'unknown', '', 'null', 'sideloaded', 'adb', 
            'packageinstaller', 'com.android.packageinstaller', 'com.android.shell'
        }
        return self.installer in suspicious_installers
    
    def has_sensitive_permissions(self) -> bool:
        """Check if package has sensitive permissions."""
        sensitive_permissions = {
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA", 
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.READ_PHONE_STATE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.WRITE_SECURE_SETTINGS",
            "android.permission.WRITE_SETTINGS"
        }
        return bool(self.permissions.intersection(sensitive_permissions))


@dataclass
class DeviceInfo:
    """Information about the Android device being analyzed."""
    device_id: str = "Unknown Device"
    device_model: str = "Unknown Model"
    android_version: str = "Unknown"
    build_fingerprint: str = ""
    build_type: str = "user"
    security_patch: str = ""
    
    # Device properties
    device_props: Dict[str, str] = field(default_factory=dict)
    
    def is_debug_build(self) -> bool:
        """Check if this is a debug/development build."""
        return self.build_type in ['eng', 'userdebug']
    
    def is_rooted_indicators(self) -> bool:
        """Check for basic rooting indicators in device properties."""
        rooting_indicators = ['ro.debuggable=1', 'ro.secure=0', 'ro.build.tags=test-keys']
        return any(indicator in str(self.device_props) for indicator in rooting_indicators)


@dataclass
class LogData:
    """
    Container for all collected log data and parsed information.
    
    This represents the raw and processed data that will be analyzed by heuristics.
    """
    
    # Raw data
    raw_lines: List[str] = field(default_factory=list)
    log_directory: str = ""
    data_format: str = "shell_commands"  # or "bugreport"
    
    # Device information
    device_info: DeviceInfo = field(default_factory=DeviceInfo)
    
    # Package information
    packages: Dict[str, PackageInfo] = field(default_factory=dict)
    
    # Parsed structured data
    parsed_events: List[Dict[str, Any]] = field(default_factory=list)
    
    # Efficient lookups (preprocessed data)
    package_lines: Dict[str, List[int]] = field(default_factory=dict)
    permission_lines: Dict[str, List[int]] = field(default_factory=dict)
    battery_lines: List[int] = field(default_factory=list)
    network_lines: List[int] = field(default_factory=list)
    
    # Legacy compatibility fields (will be phased out)
    package_uids: Dict[str, int] = field(default_factory=dict)
    installer_info: Dict[str, str] = field(default_factory=dict)
    package_permissions: Dict[str, Set[str]] = field(default_factory=dict)
    appops: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Collection metadata
    timestamp: Optional[datetime] = None
    missing_sections: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize computed fields after data loading."""
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def get_package_count(self) -> int:
        """Get total number of packages."""
        return len(self.packages)
    
    def get_line_count(self) -> int:
        """Get total number of raw log lines."""
        return len(self.raw_lines)
    
    def get_suspicious_packages(self) -> List[PackageInfo]:
        """Get packages with suspicious characteristics."""
        suspicious = []
        for package in self.packages.values():
            if (package.is_suspicious_installer() or 
                package.has_sensitive_permissions() or 
                package.is_debuggable):
                suspicious.append(package)
        return suspicious
    
    def get_system_packages(self) -> List[PackageInfo]:
        """Get packages identified as system packages."""
        return [pkg for pkg in self.packages.values() if pkg.is_system]
    
    def get_user_packages(self) -> List[PackageInfo]:
        """Get packages identified as user-installed packages."""
        return [pkg for pkg in self.packages.values() if not pkg.is_system]


