"""
Base collector interface for data collection.

Defines the contract that all data collectors must implement.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path


class CollectionError(Exception):
    """Exception raised during data collection."""
    pass


@dataclass
class DataSource:
    """Represents a single data source collected during the process."""
    type: str  # "bugreport", "adb_command", "logcat", etc.
    path: Path
    size_bytes: int = 0
    created_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization to set default values."""
        if isinstance(self.path, str):
            self.path = Path(self.path)
            
        if self.path.exists():
            self.size_bytes = self.path.stat().st_size
            if not self.created_at:
                self.created_at = datetime.fromtimestamp(self.path.stat().st_mtime)


@dataclass 
class CollectionConfig:
    """Configuration for data collection operations."""
    
    # Collection methods
    collect_bugreport: bool = True
    collect_adb_commands: bool = True
    collect_system_logs: bool = True
    supplement_with_adb: bool = True
    
    # Timeouts and limits
    adb_timeout_seconds: int = 300
    bugreport_timeout_seconds: int = 600
    max_logcat_lines: int = 100000
    max_file_size_mb: int = 500
    
    # Output settings
    preserve_temp_files: bool = False
    compress_output: bool = False
    output_directory: Optional[Path] = None
    
    # Security and privacy
    include_sensitive_data: bool = True
    anonymize_data: bool = False

    # APK collection settings (for forensic evidence)
    collect_userland_apks: bool = False
    collect_all_apks: bool = False
    
    # Coverage optimization
    prioritize_security_data: bool = True
    skip_redundant_sources: bool = True
    
    # Command group configuration
    enabled_command_groups: Dict[str, bool] = field(default_factory=lambda: {
        'system_info': True,
        'package_management': True,
        'dumpsys_core': True,
        'dumpsys_power_performance': True,
        'dumpsys_security': True,
        'dumpsys_system': True,
        'system_logs': True,
        'filesystem_analysis': True,
        'additional_forensics': False,  # Optional group
        'apk_collection': False         # APK collection group (controlled by APK settings)
    })
    
    def __post_init__(self):
        """Convert string paths to Path objects and validate configuration."""
        if self.output_directory and isinstance(self.output_directory, str):
            self.output_directory = Path(self.output_directory)

        # Validate APK collection settings - both cannot be true
        if self.collect_userland_apks and self.collect_all_apks:
            raise ValueError("Cannot enable both collect_userland_apks and collect_all_apks simultaneously")

        # Enable APK collection group if either APK collection option is enabled
        if self.collect_userland_apks or self.collect_all_apks:
            self.enabled_command_groups['apk_collection'] = True
    
    def get_command_group_enabled(self, group_name: str) -> bool:
        """Check if a command group is enabled."""
        return self.enabled_command_groups.get(group_name, True)


@dataclass
class CollectionResult:
    """Result from a data collection operation."""
    
    sources: List[DataSource] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    collection_time: Optional[datetime] = None
    
    def __post_init__(self):
        """Set collection time if not provided."""
        if not self.collection_time:
            self.collection_time = datetime.now()
    
    def get_total_size_mb(self) -> float:
        """Get total size of all collected sources in MB."""
        total_bytes = sum(source.size_bytes for source in self.sources)
        return total_bytes / (1024 * 1024)
    
    def get_source_by_type(self, source_type: str) -> List[DataSource]:
        """Get all sources of a specific type."""
        return [source for source in self.sources if source.type == source_type]
    
    def has_errors(self) -> bool:
        """Check if collection had any errors."""
        return len(self.errors) > 0
    
    def get_coverage_score(self) -> float:
        """
        Calculate data coverage score (0.0-1.0).
        
        This gives a rough estimate of how complete the data collection was.
        """
        # Essential source types for Android forensic analysis
        essential_types = {
            'package_info', 'appops', 'accessibility', 'netstats', 
            'batterystats', 'device_info', 'logcat'
        }
        
        available_types = {source.type for source in self.sources}
        coverage = len(available_types.intersection(essential_types)) / len(essential_types)
        
        # Reduce score for errors
        error_penalty = min(0.3, len(self.errors) * 0.1)
        return max(0.0, coverage - error_penalty)


class BaseCollector(ABC):
    """
    Base interface for all data collectors.
    
    This defines the contract that all collectors must implement, providing
    a consistent interface for different collection strategies.
    """
    
    def __init__(self, config: Optional[CollectionConfig] = None):
        """Initialize collector with configuration."""
        self.config = config or CollectionConfig()
        self.logger = self._setup_logger()
    
    def _setup_logger(self):
        """Setup logging for the collector."""
        import logging
        return logging.getLogger(f"collector.{self.__class__.__name__}")
    
    @property
    @abstractmethod
    def collector_type(self) -> str:
        """Get the type identifier for this collector."""
        pass
    
    @abstractmethod
    def can_collect_from(self, target: str) -> bool:
        """
        Check if this collector can collect from the given target.
        
        Args:
            target: Target identifier (device ID, path, etc.)
            
        Returns:
            True if this collector can handle the target
        """
        pass
    
    @abstractmethod
    def collect(self, target: str) -> CollectionResult:
        """
        Collect data from the specified target.
        
        Args:
            target: Target to collect from (device, directory, etc.)
            
        Returns:
            Collection result with all collected data sources
            
        Raises:
            CollectionError: If collection fails
        """
        pass
    
    @abstractmethod
    def get_supported_sources(self) -> List[str]:
        """
        Get list of data source types this collector supports.
        
        Returns:
            List of supported source types
        """
        pass
    
    def validate_target(self, target: str) -> None:
        """
        Validate that the target is accessible and valid.
        
        Args:
            target: Target to validate
            
        Raises:
            CollectionError: If target is invalid or inaccessible
        """
        if not self.can_collect_from(target):
            raise CollectionError(f"Cannot collect from target: {target}")
    
    def cleanup(self, result: CollectionResult) -> None:
        """
        Clean up temporary files and resources after collection.
        
        Args:
            result: Collection result to clean up
        """
        if not self.config.preserve_temp_files:
            for source in result.sources:
                if source.metadata.get('is_temporary', False):
                    try:
                        if source.path.exists():
                            source.path.unlink()
                            self.logger.debug(f"Cleaned up temporary file: {source.path}")
                    except Exception as e:
                        self.logger.warning(f"Failed to cleanup {source.path}: {e}")
