"""
Coverage analysis for Android forensic data collection.

This module analyzes data coverage and completeness for forensic analysis.
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import Counter, defaultdict
from enum import Enum
from pathlib import Path
import logging

from ward_core.infrastructure.parsers.base_parser import ParsedLogEntry


class CoverageCategory(Enum):
    """Categories of forensic data coverage."""
    SYSTEM_INFO = "system_info"
    PACKAGE_DATA = "package_data"
    PERMISSIONS = "permissions"
    NETWORK_DATA = "network_data"
    SYSTEM_LOGS = "system_logs"
    ACCESSIBILITY = "accessibility" 
    SECURITY_EVENTS = "security_events"
    PERFORMANCE_DATA = "performance_data"


@dataclass
class CoverageMetric:
    """Represents a coverage metric for a specific category."""
    
    category: CoverageCategory
    score: float  # 0.0 - 1.0
    expected_sources: Set[str]
    found_sources: Set[str]
    missing_sources: Set[str]
    entry_count: int = 0
    quality_indicators: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def completeness_ratio(self) -> float:
        """Calculate completeness as ratio of found to expected sources."""
        if not self.expected_sources:
            return 1.0
        return len(self.found_sources) / len(self.expected_sources)
    
    @property
    def coverage_level(self) -> str:
        """Get human-readable coverage level."""
        if self.score >= 0.9:
            return "Excellent"
        elif self.score >= 0.7:
            return "Good"
        elif self.score >= 0.5:
            return "Fair"
        elif self.score >= 0.3:
            return "Poor"
        else:
            return "Insufficient"


@dataclass
class CoverageReport:
    """Comprehensive coverage analysis report."""
    
    overall_score: float
    category_metrics: Dict[CoverageCategory, CoverageMetric]
    total_entries: int
    unique_sources: int
    analysis_timestamp: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    
    def get_category_score(self, category: CoverageCategory) -> float:
        """Get score for a specific category."""
        metric = self.category_metrics.get(category)
        return metric.score if metric else 0.0
    
    def get_missing_critical_sources(self) -> List[str]:
        """Get list of missing critical data sources."""
        missing = []
        for category, metric in self.category_metrics.items():
            if metric.score < 0.5:  # Poor coverage threshold
                missing.extend(metric.missing_sources)
        return sorted(set(missing))
    
    def get_summary(self) -> str:
        """Get human-readable coverage summary."""
        excellent_count = sum(1 for m in self.category_metrics.values() if m.score >= 0.9)
        poor_count = sum(1 for m in self.category_metrics.values() if m.score < 0.5)
        
        return (f"Coverage: {self.overall_score:.1%} overall "
               f"({excellent_count} excellent, {poor_count} poor categories)")


class CoverageAnalyzer:
    """
    Analyzer for forensic data coverage and completeness.
    
    This class evaluates how complete the collected data is for forensic analysis
    and identifies gaps that could affect detection accuracy.
    """
    
    # Define expected sources for each coverage category (UPDATED to match actual collector output)
    EXPECTED_SOURCES = {
        CoverageCategory.SYSTEM_INFO: {
            'shell_getprop.txt',           # ✓ Already correct
            'shell_build_info.txt',        # Fixed: was 'build.prop'
            'shell_version_info.txt',      # Fixed: was 'version.txt'  
            'shell_deviceidle.txt',        # Fixed: was 'shell_dumpsys_deviceidle.txt'
            'shell_uptime.txt',            # Additional: system uptime
            'shell_date.txt'               # Additional: system date
        },
        
        CoverageCategory.PACKAGE_DATA: {
            'shell_package.txt',           # Fixed: was 'shell_dumpsys_package.txt'
            'shell_packages_full.txt',     # Fixed: was 'shell_pm_list_packages__f.txt'
            'shell_packages_system.txt',   # Additional: system packages
            'shell_packages_third_party.txt', # Additional: third party packages
            'shell_packages_enabled.txt',  # Additional: enabled packages
            'shell_packages_disabled.txt'  # Additional: disabled packages
        },
        
        CoverageCategory.PERMISSIONS: {
            'shell_package.txt',           # Fixed: Contains permission info
            'shell_appops.txt',            # Fixed: was 'shell_dumpsys_appops.txt'
            'shell_permissions_list.txt',  # Additional: all permissions
            'shell_permissions_dangerous.txt', # Additional: dangerous permissions
            'shell_permission.txt'         # Additional: permission manager data
        },
        
        CoverageCategory.NETWORK_DATA: {
            'shell_netstats.txt',          # Fixed: was 'shell_dumpsys_netstats.txt'
            'shell_connectivity.txt',      # Fixed: was 'shell_dumpsys_connectivity.txt'
            'shell_network_connections.txt', # Additional: netstat output
            'shell_network_policy.txt'     # Additional: network policy data
        },
        
        CoverageCategory.SYSTEM_LOGS: {
            'shell_logcat_main.txt',       # Fixed: was 'logcat__v_threadtime__d.txt'
            'shell_logcat_system.txt',     # Fixed: was 'system.txt'
            'shell_logcat_events.txt',     # Fixed: was 'events.txt'
            'shell_logcat_crash.txt',      # Additional: crash logs
            'shell_dmesg.txt',             # Additional: kernel logs
            'shell_activity_services.txt', # Additional: service logs and ANR data
            'main.txt',                    # Bug report: main logcat
            'system.txt',                  # Bug report: system logcat
            'events.txt',                  # Bug report: events logcat
            'radio.txt',                   # Bug report: radio logcat
            'kernel.txt'                   # Bug report: kernel logs
        },
        
        CoverageCategory.ACCESSIBILITY: {
            'shell_accessibility.txt'      # Fixed: was 'shell_dumpsys_accessibility.txt'
        },
        
        CoverageCategory.SECURITY_EVENTS: {
            'shell_device_policy.txt',     # Fixed: was 'shell_dumpsys_device_policy.txt'
            'shell_deviceidle.txt',        # Fixed: was 'shell_dumpsys_deviceidle.txt'
            'shell_logcat_main.txt',       # Fixed: For security-related log entries
            'shell_activity_services.txt', # Critical: Service bindings, ANR data, crash info
            'shell_binder.txt',            # Additional: Binder IPC security data
            'shell_logcat_crash.txt',      # Critical: Crash buffer logs
            'shell_logcat_events.txt',     # Critical: DropBox references
            'tombstone_00.txt',            # Bug report: crash dumps
            'tombstone_01.txt',            # Bug report: additional crash dumps
            'dropbox.txt',                 # Bug report: system error reports
            'anr.txt',                     # Bug report: application not responding
            'traces.txt'                   # Bug report: ANR trace files
        },
        
        CoverageCategory.PERFORMANCE_DATA: {
            'shell_batterystats.txt',           # Fixed: was 'shell_dumpsys_batterystats.txt'
            'shell_batterystats_checkin.txt',   # Fixed: was 'shell_dumpsys_batterystats__checkin.txt'  
            'shell_alarm.txt',                  # Fixed: was 'shell_dumpsys_alarm.txt'
            'shell_usagestats.txt',             # Fixed: was 'shell_dumpsys_usagestats.txt'
            'shell_meminfo.txt',                # Additional: memory information
            'shell_cpuinfo.txt',                # Additional: CPU information
            'shell_power.txt',                  # Additional: power management data
            'shell_jobscheduler.txt',           # Additional: job scheduler data
            'batterystats.txt',                 # Bug report: battery statistics
            'batterystats-checkin.txt',         # Bug report: battery checkin data
            'power.txt',                        # Bug report: power management
            'alarm.txt',                        # Bug report: alarm manager
            'usagestats.txt',                   # Bug report: usage statistics
            'meminfo.txt',                      # Bug report: memory information
            'cpuinfo.txt'                       # Bug report: CPU information
        }
    }
    
    # Entry types that indicate good coverage for each category
    EXPECTED_ENTRY_TYPES = {
        CoverageCategory.SYSTEM_INFO: {
            'device_info', 'build_info', 'system_property'
        },
        
        CoverageCategory.PACKAGE_DATA: {
            'package_info', 'installer_info', 'package_signature'
        },
        
        CoverageCategory.PERMISSIONS: {
            'permission', 'appops_entry', 'permission_grant'
        },
        
        CoverageCategory.NETWORK_DATA: {
            'network_stats', 'network_interface', 'connection_info'
        },
        
        CoverageCategory.SYSTEM_LOGS: {
            'system_log', 'app_log', 'crash_log', 'event_log',
            'service_record', 'anr_service', 'service_crash'
        },
        
        CoverageCategory.ACCESSIBILITY: {
            'accessibility_service', 'accessibility_event'
        },
        
        CoverageCategory.SECURITY_EVENTS: {
            'security_event', 'policy_violation', 'admin_action',
            'anr_service', 'service_crash', 'service_binding'
        },
        
        CoverageCategory.PERFORMANCE_DATA: {
            'battery_stats', 'wakelock', 'alarm', 'job', 'usage_stats'
        }
    }
    
    # Minimum entry counts for good coverage
    MIN_ENTRY_COUNTS = {
        CoverageCategory.SYSTEM_INFO: 10,
        CoverageCategory.PACKAGE_DATA: 50,  # Expect many packages
        CoverageCategory.PERMISSIONS: 20,   # Expect many permissions
        CoverageCategory.NETWORK_DATA: 5,
        CoverageCategory.SYSTEM_LOGS: 100,  # Expect many log entries
        CoverageCategory.ACCESSIBILITY: 1,   # May be zero on some devices
        CoverageCategory.SECURITY_EVENTS: 1,
        CoverageCategory.PERFORMANCE_DATA: 20
    }
    
    def __init__(self):
        """Initialize the coverage analyzer."""
        self.logger = logging.getLogger("coverage.analyzer")
    
    def analyze(self, entries: List[ParsedLogEntry], collection_directory: Optional[str] = None) -> CoverageReport:
        """
        Analyze coverage of parsed log entries.
        
        Args:
            entries: List of parsed entries to analyze
            collection_directory: Optional path to collection directory for file-based coverage
            
        Returns:
            Comprehensive coverage report
        """
        if not entries:
            return CoverageReport(
                overall_score=0.0,
                category_metrics={},
                total_entries=0,
                unique_sources=0
            )
        
        self.logger.info(f"Starting coverage analysis of {len(entries)} entries")
        
        # Collect basic statistics
        # Extract just filenames from full paths for proper matching
        source_files = set(Path(entry.source_file).name for entry in entries)
        
        # Also check actual files in collection directory if provided
        if collection_directory:
            collection_path = Path(collection_directory)
            if collection_path.exists():
                raw_data_dir = collection_path / "raw_data"
                if raw_data_dir.exists():
                    actual_files = set(f.name for f in raw_data_dir.glob("*.txt"))
                    # Merge with parsed source files
                    source_files.update(actual_files)
                    self.logger.info(f"Found {len(actual_files)} actual files in collection directory")
        
        entry_types_by_category = self._categorize_entries(entries)
        
        # Calculate metrics for each category
        category_metrics = {}
        for category in CoverageCategory:
            metric = self._analyze_category_coverage(
                category, entries, source_files, entry_types_by_category
            )
            category_metrics[category] = metric
        
        # Calculate overall score
        overall_score = self._calculate_overall_score(category_metrics)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(category_metrics, source_files)
        
        report = CoverageReport(
            overall_score=overall_score,
            category_metrics=category_metrics,
            total_entries=len(entries),
            unique_sources=len(source_files),
            recommendations=recommendations
        )
        
        self.logger.info(report.get_summary())
        return report
    
    def _categorize_entries(self, entries: List[ParsedLogEntry]) -> Dict[CoverageCategory, List[ParsedLogEntry]]:
        """Categorize entries by coverage category."""
        categorized = defaultdict(list)
        
        for entry in entries:
            # Match entry types to categories
            for category, expected_types in self.EXPECTED_ENTRY_TYPES.items():
                if entry.entry_type in expected_types:
                    categorized[category].append(entry)
                    
            # Special categorization based on content
            if entry.package and 'system' not in entry.source_file.lower():
                categorized[CoverageCategory.PACKAGE_DATA].append(entry)
                
            if entry.has_tag('suspicious') or entry.has_tag('security_relevant'):
                categorized[CoverageCategory.SECURITY_EVENTS].append(entry)
        
        return dict(categorized)
    
    def _analyze_category_coverage(
        self,
        category: CoverageCategory,
        all_entries: List[ParsedLogEntry],
        source_files: Set[str],
        categorized_entries: Dict[CoverageCategory, List[ParsedLogEntry]]
    ) -> CoverageMetric:
        """Analyze coverage for a specific category."""
        
        expected_sources = self.EXPECTED_SOURCES.get(category, set())
        found_sources = set()
        
        # Find which expected sources we have
        for source_file in source_files:
            for expected_source in expected_sources:
                # Exact match or source file contains expected source name
                if source_file == expected_source or expected_source in source_file:
                    found_sources.add(expected_source)
        
        missing_sources = expected_sources - found_sources
        
        # Get entries for this category
        category_entries = categorized_entries.get(category, [])
        entry_count = len(category_entries)
        
        # Calculate base score from source completeness
        source_score = len(found_sources) / len(expected_sources) if expected_sources else 1.0
        
        # Adjust score based on entry count
        min_entries = self.MIN_ENTRY_COUNTS.get(category, 1)
        entry_score = min(1.0, entry_count / min_entries) if min_entries > 0 else 1.0
        
        # Calculate quality indicators
        quality_indicators = self._calculate_quality_indicators(category, category_entries)
        
        # Combine scores with quality adjustment
        quality_multiplier = quality_indicators.get('quality_multiplier', 1.0)
        final_score = (source_score * 0.6 + entry_score * 0.4) * quality_multiplier
        
        return CoverageMetric(
            category=category,
            score=min(1.0, final_score),
            expected_sources=expected_sources,
            found_sources=found_sources,
            missing_sources=missing_sources,
            entry_count=entry_count,
            quality_indicators=quality_indicators
        )
    
    def _calculate_quality_indicators(
        self, 
        category: CoverageCategory,
        entries: List[ParsedLogEntry]
    ) -> Dict[str, Any]:
        """Calculate quality indicators for a category."""
        
        if not entries:
            return {'quality_multiplier': 0.0}
        
        indicators = {}
        
        # Calculate average confidence
        confidences = [e.confidence for e in entries]
        avg_confidence = sum(confidences) / len(confidences)
        indicators['average_confidence'] = avg_confidence
        
        # Count entries with timestamps
        timestamped_count = sum(1 for e in entries if e.timestamp)
        indicators['timestamp_coverage'] = timestamped_count / len(entries)
        
        # Count entries with package information
        package_count = sum(1 for e in entries if e.package)
        indicators['package_coverage'] = package_count / len(entries)
        
        # Count entries with parsed content
        parsed_content_count = sum(1 for e in entries if e.parsed_content)
        indicators['parsed_content_coverage'] = parsed_content_count / len(entries)
        
        # Category-specific quality metrics
        if category == CoverageCategory.PACKAGE_DATA:
            # For package data, diversity of packages is important
            unique_packages = set(e.package for e in entries if e.package)
            indicators['package_diversity'] = len(unique_packages)
            
        elif category == CoverageCategory.NETWORK_DATA:
            # For network data, look for upload/download statistics
            stats_count = sum(1 for e in entries if 'bytes' in str(e.parsed_content).lower())
            indicators['network_stats_coverage'] = stats_count / len(entries) if entries else 0
            
        elif category == CoverageCategory.PERMISSIONS:
            # For permissions, diversity of permission types matters
            permissions = set()
            for entry in entries:
                if entry.parsed_content and 'permissions' in entry.parsed_content:
                    perms = entry.parsed_content['permissions']
                    if isinstance(perms, list):
                        permissions.update(perms)
                    elif isinstance(perms, str):
                        permissions.add(perms)
            indicators['permission_diversity'] = len(permissions)
        
        # Calculate quality multiplier based on indicators
        quality_multiplier = 1.0
        
        # Reduce quality for low confidence
        if avg_confidence < 0.7:
            quality_multiplier *= 0.8
        
        # Reduce quality for poor timestamp coverage
        if indicators['timestamp_coverage'] < 0.3:
            quality_multiplier *= 0.9
            
        # Reduce quality for poor parsed content coverage
        if indicators['parsed_content_coverage'] < 0.5:
            quality_multiplier *= 0.9
        
        indicators['quality_multiplier'] = quality_multiplier
        
        return indicators
    
    def _calculate_overall_score(self, category_metrics: Dict[CoverageCategory, CoverageMetric]) -> float:
        """Calculate overall coverage score."""
        if not category_metrics:
            return 0.0
        
        # Weight categories by importance for forensic analysis
        category_weights = {
            CoverageCategory.SYSTEM_INFO: 0.15,
            CoverageCategory.PACKAGE_DATA: 0.25,      # Very important
            CoverageCategory.PERMISSIONS: 0.20,       # Very important
            CoverageCategory.NETWORK_DATA: 0.15,
            CoverageCategory.SYSTEM_LOGS: 0.10,
            CoverageCategory.ACCESSIBILITY: 0.05,
            CoverageCategory.SECURITY_EVENTS: 0.05,
            CoverageCategory.PERFORMANCE_DATA: 0.05
        }
        
        weighted_score = 0.0
        total_weight = 0.0
        
        for category, metric in category_metrics.items():
            weight = category_weights.get(category, 0.1)
            weighted_score += metric.score * weight
            total_weight += weight
        
        return weighted_score / total_weight if total_weight > 0 else 0.0
    
    def _generate_recommendations(
        self,
        category_metrics: Dict[CoverageCategory, CoverageMetric],
        source_files: Set[str]
    ) -> List[str]:
        """Generate recommendations for improving coverage."""
        
        recommendations = []
        
        # Check for missing critical sources
        critical_missing = []
        for category, metric in category_metrics.items():
            if metric.score < 0.5 and metric.missing_sources:
                critical_missing.extend(metric.missing_sources)
        
        if critical_missing:
            recommendations.append(
                f"Critical data sources missing: {', '.join(sorted(set(critical_missing)))}. "
                "Consider re-collecting data with these sources included."
            )
        
        # Check for low entry counts in important categories
        low_coverage_categories = []
        for category, metric in category_metrics.items():
            if category in [CoverageCategory.PACKAGE_DATA, CoverageCategory.PERMISSIONS]:
                if metric.entry_count < self.MIN_ENTRY_COUNTS.get(category, 0):
                    low_coverage_categories.append(category.value)
        
        if low_coverage_categories:
            recommendations.append(
                f"Low entry counts in critical categories: {', '.join(low_coverage_categories)}. "
                "This may limit detection accuracy."
            )
        
        # Check for missing system logs
        system_log_metric = category_metrics.get(CoverageCategory.SYSTEM_LOGS)
        if system_log_metric and system_log_metric.score < 0.3:
            recommendations.append(
                "System logs coverage is poor. Consider collecting logcat data for better analysis."
            )
        
        # Check for missing network data
        network_metric = category_metrics.get(CoverageCategory.NETWORK_DATA)
        if network_metric and network_metric.score < 0.4:
            recommendations.append(
                "Network data coverage is limited. Consider collecting dumpsys netstats for traffic analysis."
            )

        # Check for missing crash analysis data
        security_metric = category_metrics.get(CoverageCategory.SECURITY_EVENTS)
        if security_metric:
            missing_crash_sources = []
            crash_sources = {'tombstone_00.txt', 'tombstone_01.txt', 'dropbox.txt', 'anr.txt', 'traces.txt'}

            for crash_source in crash_sources:
                if crash_source in security_metric.missing_sources:
                    missing_crash_sources.append(crash_source)

            if missing_crash_sources:
                recommendations.append(
                    f"Crash analysis fidelity reduced - missing: {', '.join(missing_crash_sources)}. "
                    "For complete crash analysis, enable bug report collection to include tombstone and ANR data."
                )

        # General recommendation based on overall score
        overall_score = self._calculate_overall_score(category_metrics)
        if overall_score < 0.6:
            recommendations.append(
                "Overall coverage is below recommended levels. Consider using hybrid collection "
                "strategy combining bug reports with individual ADB commands."
            )

        return recommendations
