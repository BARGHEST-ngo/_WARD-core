"""
Collection profiles for different analysis scenarios.

This module provides predefined collection configurations optimized for
different use cases and analysis requirements.
"""

from dataclasses import dataclass, field
from typing import Dict, Any
from pathlib import Path

from .base_collector import CollectionConfig


@dataclass
class CollectionProfile:
    """Represents a named collection profile with specific settings."""
    
    name: str
    description: str
    config: CollectionConfig
    use_cases: list[str] = field(default_factory=list)
    estimated_time: str = "Unknown"
    data_volume: str = "Unknown"


class CollectionProfiles:
    """
    Predefined collection profiles for different analysis scenarios.
    
    These profiles optimize collection settings for specific use cases,
    balancing thoroughness with time and resource constraints.
    """
    
    @staticmethod
    def get_quick_analysis() -> CollectionProfile:
        """
        Quick analysis profile for rapid assessment.
        
        - Minimal data collection
        - Focus on critical security indicators
        - Fast execution (2-5 minutes)
        """
        config = CollectionConfig(
            # Collection methods - prioritize speed
            collect_bugreport=False,
            collect_adb_commands=True,
            collect_system_logs=False,
            supplement_with_adb=False,
            
            # Timeouts - shorter for quick analysis
            adb_timeout_seconds=120,
            bugreport_timeout_seconds=300,
            max_logcat_lines=10000,
            
            # Output settings
            preserve_temp_files=False,
            compress_output=True,
            
            # Security focus
            prioritize_security_data=True,
            skip_redundant_sources=True,
            
            # Enabled command groups - minimal set
            enabled_command_groups={
                'system_info': True,
                'package_management': True,
                'dumpsys_core': True,
                'dumpsys_security': True,
                'dumpsys_power_performance': False,
                'dumpsys_system': False,
                'system_logs': False,
                'filesystem_analysis': False,
                'additional_forensics': False
            }
        )
        
        return CollectionProfile(
            name="quick",
            description="Rapid security assessment with minimal data collection",
            config=config,
            use_cases=[
                "Initial threat assessment",
                "Quick security screening",
                "Triage analysis",
                "Resource-constrained environments"
            ],
            estimated_time="2-5 minutes",
            data_volume="10-50 MB"
        )
    
    @staticmethod
    def get_standard_analysis() -> CollectionProfile:
        """
        Standard analysis profile for balanced forensic examination.
        
        - Comprehensive data collection
        - Bug report + ADB commands
        - Moderate execution time (10-15 minutes)
        """
        config = CollectionConfig(
            # Collection methods - balanced approach
            collect_bugreport=True,
            collect_adb_commands=True,
            collect_system_logs=True,
            supplement_with_adb=True,
            
            # Standard timeouts
            adb_timeout_seconds=300,
            bugreport_timeout_seconds=600,
            max_logcat_lines=50000,
            
            # Output settings
            preserve_temp_files=False,
            compress_output=True,
            
            # Security and coverage
            prioritize_security_data=True,
            skip_redundant_sources=False,
            
            # Most command groups enabled
            enabled_command_groups={
                'system_info': True,
                'package_management': True,
                'dumpsys_core': True,
                'dumpsys_power_performance': True,
                'dumpsys_security': True,
                'dumpsys_system': True,
                'system_logs': True,
                'filesystem_analysis': True,
                'additional_forensics': False  # Optional
            }
        )
        
        return CollectionProfile(
            name="standard",
            description="Balanced forensic analysis with comprehensive data collection",
            config=config,
            use_cases=[
                "Standard forensic examination",
                "Malware analysis",
                "Security incident investigation",
                "Compliance auditing"
            ],
            estimated_time="10-15 minutes",
            data_volume="50-200 MB"
        )
    
    @staticmethod
    def get_forensic_deep_dive() -> CollectionProfile:
        """
        Forensic deep dive profile for thorough investigation.
        
        - Maximum data collection
        - All available sources
        - Extended timeouts
        - No data volume limits
        - Note deep forensics potentialy captures PII. This is to be used with caution.
        - This aims to be able to recover SMS/MMS messages for correlation with MVT down the line.
        - TODO: Add SMS stuff.
        - Collects userland APKs for forensic evidence
        """
        config = CollectionConfig(
            # Collection methods - everything
            collect_bugreport=True,
            collect_adb_commands=True,
            collect_system_logs=True,
            supplement_with_adb=True,

            # Extended timeouts for comprehensive collection
            adb_timeout_seconds=600,
            bugreport_timeout_seconds=1200,
            max_logcat_lines=100000,
            max_file_size_mb=1000,

            # APK collection for forensic evidence
            collect_userland_apks=True,
            collect_all_apks=False,
            
            # Preservation settings
            preserve_temp_files=True,
            compress_output=False,  # Keep uncompressed for analysis
            
            # Maximum coverage
            prioritize_security_data=True,
            skip_redundant_sources=False,
            include_sensitive_data=True,
            
            # All command groups enabled
            enabled_command_groups={
                'system_info': True,
                'package_management': True,
                'dumpsys_core': True,
                'dumpsys_power_performance': True,
                'dumpsys_security': True,
                'dumpsys_system': True,
                'system_logs': True,
                'filesystem_analysis': True,
                'additional_forensics': True  # Include everything
            }
        )
        
        return CollectionProfile(
            name="forensic",
            description="Comprehensive forensic investigation with maximum data collection",
            config=config,
            use_cases=[
                "Advanced persistent threat investigation",
                "MVT correlation",
                "Legal forensic examination",
                "Research and malware analysis",
                "Incident response deep dive"
            ],
            estimated_time="20-45 minutes",
            data_volume="200-500 MB"
        )
    
    @staticmethod
    def get_stealth_collection() -> CollectionProfile:
        """
        Stealth collection profile for minimal device impact.
        
        - Minimal system disruption
        - No bug report generation
        - Focused on passive data collection
        - Quick and quiet
        """
        config = CollectionConfig(
            # Collection methods - minimal impact
            collect_bugreport=False,  # No bug report (generates notifications)
            collect_adb_commands=True,
            collect_system_logs=False,  # No real-time log collection
            supplement_with_adb=False,
            
            # Fast timeouts
            adb_timeout_seconds=60,
            bugreport_timeout_seconds=0,  # Disabled
            max_logcat_lines=5000,
            
            # Stealth settings
            preserve_temp_files=False,
            compress_output=True,
            anonymize_data=True,
            
            # Minimal coverage
            prioritize_security_data=True,
            skip_redundant_sources=True,
            include_sensitive_data=False,
            
            # Limited command groups
            enabled_command_groups={
                'system_info': True,
                'package_management': True,
                'dumpsys_core': False,  # Some dumpsys commands are visible
                'dumpsys_power_performance': False,
                'dumpsys_security': True,
                'dumpsys_system': False,
                'system_logs': False,
                'filesystem_analysis': False,
                'additional_forensics': False
            }
        )
        
        return CollectionProfile(
            name="stealth",
            description="Minimal-impact collection for covert analysis",
            config=config,
            use_cases=[
                "Covert monitoring",
                "Suspicious device analysis",
                "Minimal disruption assessment",
                "Quick stealth check"
            ],
            estimated_time="1-3 minutes",
            data_volume="5-20 MB"
        )
    
    @staticmethod
    def get_network_focused() -> CollectionProfile:
        """
        Network-focused collection profile for network behavior analysis.
        
        - Emphasis on network-related data
        - Traffic analysis optimization
        - Communication pattern detection
        """
        config = CollectionConfig(
            # Collection methods - network focused
            collect_bugreport=True,
            collect_adb_commands=True,
            collect_system_logs=True,
            supplement_with_adb=True,
            
            # Standard timeouts
            adb_timeout_seconds=300,
            bugreport_timeout_seconds=600,
            max_logcat_lines=75000,  # More logs for network analysis
            
            # Output settings
            preserve_temp_files=False,
            compress_output=True,
            
            # Network priority
            prioritize_security_data=True,
            skip_redundant_sources=False,
            
            # Network-optimized command groups
            enabled_command_groups={
                'system_info': True,
                'package_management': True,
                'dumpsys_core': True,  # Includes netstats, connectivity
                'dumpsys_power_performance': False,
                'dumpsys_security': True,
                'dumpsys_system': False,
                'system_logs': True,  # Network events in logs
                'filesystem_analysis': True,  # Network connections
                'additional_forensics': False
            }
        )
        
        return CollectionProfile(
            name="network",
            description="Network-focused collection for communication analysis",
            config=config,
            use_cases=[
                "Network behavior analysis",
                "Data exfiltration detection",
                "C2 communication analysis",
                "Traffic pattern investigation"
            ],
            estimated_time="8-12 minutes",
            data_volume="30-150 MB"
        )
    
    @staticmethod
    def get_all_profiles() -> Dict[str, CollectionProfile]:
        """Get all available collection profiles."""
        return {
            "quick": CollectionProfiles.get_quick_analysis(),
            "standard": CollectionProfiles.get_standard_analysis(), 
            "forensic": CollectionProfiles.get_forensic_deep_dive(),
            "stealth": CollectionProfiles.get_stealth_collection(),
            "network": CollectionProfiles.get_network_focused()
        }
    
    @staticmethod
    def get_profile(profile_name: str) -> CollectionProfile:
        """
        Get a specific collection profile by name.
        
        Args:
            profile_name: Name of the profile to retrieve
            
        Returns:
            CollectionProfile instance
            
        Raises:
            ValueError: If profile name is not found
        """
        profiles = CollectionProfiles.get_all_profiles()
        
        if profile_name not in profiles:
            available = list(profiles.keys())
            raise ValueError(f"Unknown profile '{profile_name}'. Available: {available}")
        
        return profiles[profile_name]
    
    @staticmethod
    def create_custom_profile(
        name: str,
        description: str,
        base_profile: str = "standard",
        **config_overrides
    ) -> CollectionProfile:
        """
        Create a custom profile based on an existing profile.
        
        Args:
            name: Name for the custom profile
            description: Description of the custom profile
            base_profile: Name of profile to use as base
            **config_overrides: Configuration values to override
            
        Returns:
            Custom CollectionProfile instance
        """
        base = CollectionProfiles.get_profile(base_profile)
        
        # Create new config with overrides
        config_dict = base.config.__dict__.copy()
        config_dict.update(config_overrides)
        
        custom_config = CollectionConfig(**config_dict)
        
        return CollectionProfile(
            name=name,
            description=description,
            config=custom_config,
            use_cases=[f"Custom profile based on {base_profile}"]
        )
    
    @staticmethod
    def save_profile_to_file(profile: CollectionProfile, file_path: Path):
        """
        Save a collection profile to YAML file.
        
        Args:
            profile: Profile to save
            file_path: Path to save profile
        """
        import yaml
        
        profile_data = {
            'name': profile.name,
            'description': profile.description,
            'use_cases': profile.use_cases,
            'estimated_time': profile.estimated_time,
            'data_volume': profile.data_volume,
            'config': {
                # Convert config to dict (simplified for YAML)
                'collect_bugreport': profile.config.collect_bugreport,
                'collect_adb_commands': profile.config.collect_adb_commands,
                'collect_system_logs': profile.config.collect_system_logs,
                'adb_timeout_seconds': profile.config.adb_timeout_seconds,
                'bugreport_timeout_seconds': profile.config.bugreport_timeout_seconds,
                'max_logcat_lines': profile.config.max_logcat_lines,
                'enabled_command_groups': profile.config.enabled_command_groups,
                'prioritize_security_data': profile.config.prioritize_security_data,
                'skip_redundant_sources': profile.config.skip_redundant_sources,
            }
        }
        
        with open(file_path, 'w') as f:
            yaml.dump(profile_data, f, default_flow_style=False, indent=2)
    
    @staticmethod
    def load_profile_from_file(file_path: Path) -> CollectionProfile:
        """
        Load a collection profile from YAML file.
        
        Args:
            file_path: Path to profile file
            
        Returns:
            Loaded CollectionProfile instance
        """
        import yaml
        
        with open(file_path, 'r') as f:
            profile_data = yaml.safe_load(f)
        
        # Create config from loaded data
        config_data = profile_data.get('config', {})
        config = CollectionConfig(**config_data)
        
        return CollectionProfile(
            name=profile_data['name'],
            description=profile_data['description'],
            config=config,
            use_cases=profile_data.get('use_cases', []),
            estimated_time=profile_data.get('estimated_time', 'Unknown'),
            data_volume=profile_data.get('data_volume', 'Unknown')
        )
