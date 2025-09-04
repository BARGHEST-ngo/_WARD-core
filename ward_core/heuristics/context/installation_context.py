"""
Installation Context Heuristic - Context-Aware Analysis

This heuristic analyzes installation sources and provides context for security analysis.
It determines whether apps were installed via Play Store or sideloaded, which affects
risk assessment and detection interpretation.
Note that when analysing emulators, this will be completely messed up since installation sources are always unknown. 
"""

import re
from typing import List, Dict, Any, Set
from dataclasses import dataclass

from ward_core.heuristics.base import BaseHeuristic, HeuristicResult
from ward_core.logic.models import Detection, Evidence, EvidenceType, Severity, LogData


@dataclass
class InstallationContext:
    """Context information about app installation."""
    package_name: str
    installer_source: str  # 'play_store', 'sideloaded', 'system', 'unknown'
    installer_package: str
    installation_method: str  # 'adb', 'package_installer', 'play_store', 'system'
    is_system_app: bool
    is_privileged: bool
    risk_multiplier: float  # Risk multiplier based on installation context


class InstallationContextHeuristic(BaseHeuristic):
    """
    Context-aware heuristic for analyzing installation sources.
    
    This heuristic provides context about how apps were installed, which is crucial
    for interpreting security findings. Sideloaded apps are inherently more risky
    than Play Store apps.
    """
    
    def __init__(self, config = None):
        super().__init__(config)
        
        # Installation source patterns
        self.installer_patterns = {
            'play_store': [
                'com.android.vending',  # Google Play Store
                'com.google.android.packageinstaller',  # Google package installer
                'com.android.packageinstaller'  # System package installer (Play Store)
            ],
            'sideloaded': [
                'adb',  # ADB installation
                'shell',  # Shell installation
                'unknown',  # Unknown installer
                'sideload',  # Direct sideload
                'package_installer',  # Generic package installer
                'com.android.packageinstaller.permission.ui.GrantPermissionsActivity'  # Manual install
            ],
            'system': [
                'system',  # System installation
                'com.android.shell',  # System shell
                'com.android.settings',  # Settings app
                'com.android.provision'  # Device provisioning
            ]
        }
        
        # Risk multipliers for different installation sources
        self.risk_multipliers = {
            'play_store': 1.0,  # Baseline risk
            'system': 0.8,  # System apps are generally trusted
            'sideloaded': 2.5,  # Sideloaded apps are inherently more risky
            'unknown': 2.0  # Unknown source is risky
        }
    
    @property
    def name(self) -> str:
        """Get the name of this heuristic."""
        return "installation_context"
    
    @property
    def category(self) -> str:
        """Get the category of this heuristic."""
        return "Context Analysis"
    
    @property
    def description(self) -> str:
        """Get description of what this heuristic detects."""
        return "Analyzes installation sources to provide context for security analysis"
    
    def analyze(self, log_data: LogData) -> List[Detection]:
        """
        Analyze installation context for all packages.
        
        Args:
            log_data: Parsed log data to analyze
            
        Returns:
            List of Detection objects with installation context
        """
        detections = []
        installation_contexts = {}
        
        # Analyze each package for installation context
        for package_name, package_info in log_data.packages.items():
            context = self._analyze_package_installation_context(package_name, package_info, log_data)
            installation_contexts[package_name] = context
            
            # Create detection for high-risk installation contexts
            if context.risk_multiplier > 1.5:
                detection = self._create_installation_context_detection(package_name, context)
                detections.append(detection)
        
        # Store installation contexts in log_data for other heuristics to use
        self._store_installation_contexts(log_data, installation_contexts)
        
        return detections
    
    def _analyze_package_installation_context(self, package_name: str, package_info, log_data: LogData) -> InstallationContext:
        """Analyze installation context for a single package."""
        
        # Extract installer information
        installer_package = getattr(package_info, 'installer', 'unknown')
        installer_source = self._determine_installer_source(installer_package)
        installation_method = self._determine_installation_method(installer_package, log_data)
        
        # Check if it's a system app
        is_system_app = self._is_system_app(package_name, package_info)
        
        # Check if it's privileged
        is_privileged = self._is_privileged_app(package_name, package_info)
        
        # Calculate risk multiplier
        risk_multiplier = self._calculate_risk_multiplier(
            installer_source, is_system_app, is_privileged, package_name
        )
        
        return InstallationContext(
            package_name=package_name,
            installer_source=installer_source,
            installer_package=installer_package,
            installation_method=installation_method,
            is_system_app=is_system_app,
            is_privileged=is_privileged,
            risk_multiplier=risk_multiplier
        )
    
    def _determine_installer_source(self, installer_package: str) -> str:
        """Determine the installer source based on installer package."""
        installer_lower = installer_package.lower()
        
        for source, patterns in self.installer_patterns.items():
            for pattern in patterns:
                if pattern.lower() in installer_lower:
                    return source
        
        return 'unknown'
    
    def _determine_installation_method(self, installer_package: str, log_data: LogData) -> str:
        """Determine the specific installation method used."""
        installer_lower = installer_package.lower()
        
        if 'vending' in installer_lower:
            return 'play_store'
        elif 'adb' in installer_lower or 'shell' in installer_lower:
            return 'adb'
        elif 'packageinstaller' in installer_lower:
            return 'package_installer'
        elif 'system' in installer_lower:
            return 'system'
        else:
            return 'unknown'
    
    def _is_system_app(self, package_name: str, package_info) -> bool:
        """Check if the app is a system app."""
        # Check system package prefixes
        system_prefixes = {
            'com.android.',
            'android.',
            'com.google.android.',
            'com.samsung.android.',
            'com.sec.android.',
            'com.qualcomm.',
            'com.mediatek.'
        }
        
        # Check if package name starts with system prefix
        if any(package_name.startswith(prefix) for prefix in system_prefixes):
            return True
        
        # Check if installed in system directory
        base_dir = getattr(package_info, 'base_dir', '')
        if '/system/' in base_dir or '/vendor/' in base_dir:
            return True
        
        return False
    
    def _is_privileged_app(self, package_name: str, package_info) -> bool:
        """Check if the app is privileged."""
        # Check if installed in privileged directory
        base_dir = getattr(package_info, 'base_dir', '')
        if '/system/priv-app/' in base_dir:
            return True
        
        # Check for privileged permissions
        permissions = getattr(package_info, 'permissions', set())
        privileged_permissions = {
            'android.permission.WRITE_SECURE_SETTINGS',
            'android.permission.INSTALL_PACKAGES',
            'android.permission.DELETE_PACKAGES',
            'android.permission.MOUNT_UNMOUNT_FILESYSTEMS',
            'android.permission.CHANGE_CONFIGURATION'
        }
        
        if any(perm in permissions for perm in privileged_permissions):
            return True
        
        return False
    
    def _calculate_risk_multiplier(self, installer_source: str, is_system_app: bool, is_privileged: bool, package_name: str) -> float:
        """Calculate risk multiplier based on installation context."""
        base_multiplier = self.risk_multipliers.get(installer_source, 1.0)
        
        # Adjust for system apps
        if is_system_app:
            base_multiplier *= 0.8
        
        # Adjust for privileged apps (higher risk)
        if is_privileged:
            base_multiplier *= 1.2
        
        # Special cases for known risky packages
        risky_packages = {
            'com.estrongs.android.pop',  # ES File Explorer (known for abuse)
            'com.bluestacks',  # BlueStacks (emulator, can be abused)
            'com.uncube.launcher3'  # Custom launcher (potential for abuse)
        }
        
        if package_name in risky_packages:
            base_multiplier *= 1.5
        
        return base_multiplier
    
    def _create_installation_context_detection(self, package_name: str, context: InstallationContext) -> Detection:
        """Create a detection for high-risk installation context."""
        
        # Determine severity based on risk multiplier
        if context.risk_multiplier >= 2.5:
            severity = Severity.HIGH
        elif context.risk_multiplier >= 1.8:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        # Create evidence
        evidence = [
            Evidence(
                type=EvidenceType.METADATA_ONLY,
                content=f"Package: {package_name}, Installer: {context.installer_package}",
                confidence=0.9
            ),
            Evidence(
                type=EvidenceType.METADATA_ONLY,
                content=f"Installation Method: {context.installation_method}, Risk Multiplier: {context.risk_multiplier:.1f}",
                confidence=0.8
            )
        ]
        
        # Add context about system/privileged status
        if context.is_system_app:
            evidence.append(Evidence(
                type=EvidenceType.METADATA_ONLY,
                content="System App: True",
                confidence=0.9
            ))
        
        if context.is_privileged:
            evidence.append(Evidence(
                type=EvidenceType.METADATA_ONLY,
                content="Privileged App: True",
                confidence=0.9
            ))
        
        return Detection(
            category="Installation Context",
            package=package_name,
            title=f"High-Risk Installation Context: {package_name}",
            description=f"App installed via {context.installation_method} with risk multiplier {context.risk_multiplier:.1f}",
            severity=severity,
            confidence=0.8,
            evidence=evidence,
            technical_details={
                'heuristic_name': self.name,
                'package_name': package_name,
                'installer_source': context.installer_source,
                'installer_package': context.installer_package,
                'installation_method': context.installation_method,
                'is_system_app': context.is_system_app,
                'is_privileged': context.is_privileged,
                'risk_multiplier': context.risk_multiplier
            }
        )
    
    def _store_installation_contexts(self, log_data: LogData, contexts: Dict[str, InstallationContext]):
        """Store installation contexts in log_data for other heuristics to use."""
        # Add installation contexts to log_data metadata
        if not hasattr(log_data, 'metadata'):
            log_data.metadata = {}
        
        if 'installation_contexts' not in log_data.metadata:
            log_data.metadata['installation_contexts'] = {}
        
        # Convert contexts to dictionaries for storage
        for package_name, context in contexts.items():
            log_data.metadata['installation_contexts'][package_name] = {
                'installer_source': context.installer_source,
                'installer_package': context.installer_package,
                'installation_method': context.installation_method,
                'is_system_app': context.is_system_app,
                'is_privileged': context.is_privileged,
                'risk_multiplier': context.risk_multiplier
            }
    
    def get_installation_context(self, package_name: str, log_data: LogData) -> InstallationContext:
        """Get installation context for a specific package."""
        if hasattr(log_data, 'metadata') and 'installation_contexts' in log_data.metadata:
            context_data = log_data.metadata['installation_contexts'].get(package_name)
            if context_data:
                return InstallationContext(
                    package_name=package_name,
                    installer_source=context_data['installer_source'],
                    installer_package=context_data['installer_package'],
                    installation_method=context_data['installation_method'],
                    is_system_app=context_data['is_system_app'],
                    is_privileged=context_data['is_privileged'],
                    risk_multiplier=context_data['risk_multiplier']
                )
        
        # Return default context if not found - use proper boolean values
        return InstallationContext(
            package_name=package_name,
            installer_source='unknown',
            installer_package='unknown',
            installation_method='unknown',
            is_system_app=False,  # Default to False for unknown packages
            is_privileged=False,  # Default to False for unknown packages
            risk_multiplier=1.0
        )
