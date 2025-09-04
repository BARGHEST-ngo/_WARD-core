"""
Correlation service for cross-referencing detections.

This service handles correlation between different types of detections.
"""

from typing import List, Dict, Set, Any
import logging

from ward_core.logic.models import Detection, LogData, PackageInfo


class CorrelationService:
    """
    Service for correlating detections across different heuristics.
    
    This replaces the correlation logic from the old correlate.py.
    """
    
    def __init__(self):
        """Initialize the correlation service."""
        self.logger = logging.getLogger("correlation.service")
    
    def correlate_detections(
        self, 
        detections: List[Detection], 
        log_data: LogData
    ) -> Dict[str, Any]:
        """
        Correlate detections to find relationships and patterns.
        
        Args:
            detections: List of all detections
            log_data: Original log data for context
            
        Returns:
            Correlation analysis results
        """
        correlation_result = {
            'package_correlations': self._correlate_by_package(detections),
            'category_correlations': self._correlate_by_category(detections),
            'temporal_correlations': self._correlate_by_time(detections),
            'severity_distribution': self._analyze_severity_distribution(detections),
            'suspicious_packages': self._identify_suspicious_packages(detections, log_data)
        }
        
        return correlation_result
    
    def _correlate_by_package(self, detections: List[Detection]) -> Dict[str, Any]:
        """Correlate detections by package."""
        package_detections = {}
        
        for detection in detections:
            if detection.package:
                if detection.package not in package_detections:
                    package_detections[detection.package] = []
                package_detections[detection.package].append(detection)
        
        # Analyze packages with multiple detections
        multi_detection_packages = {
            package: detections_list 
            for package, detections_list in package_detections.items() 
            if len(detections_list) > 1
        }
        
        return {
            'total_packages_with_detections': len(package_detections),
            'packages_with_multiple_detections': len(multi_detection_packages),
            'multi_detection_packages': {
                package: {
                    'detection_count': len(detections_list),
                    'categories': list(set(d.category for d in detections_list)),
                    'max_severity': self._get_max_severity(detections_list)
                }
                for package, detections_list in multi_detection_packages.items()
            }
        }
    
    def _correlate_by_category(self, detections: List[Detection]) -> Dict[str, Any]:
        """Correlate detections by category."""
        category_counts = {}
        category_packages = {}
        
        for detection in detections:
            category = detection.category
            
            # Count detections per category
            category_counts[category] = category_counts.get(category, 0) + 1
            
            # Track packages per category
            if category not in category_packages:
                category_packages[category] = set()
            if detection.package:
                category_packages[category].add(detection.package)
        
        return {
            'category_counts': category_counts,
            'category_package_counts': {
                category: len(packages) 
                for category, packages in category_packages.items()
            },
            'cross_category_packages': self._find_cross_category_packages(detections)
        }
    
    def _correlate_by_time(self, detections: List[Detection]) -> Dict[str, Any]:
        """Correlate detections by time."""
        detections_with_time = [
            d for d in detections 
            if d.timestamp or d.window_start
        ]
        
        if not detections_with_time:
            return {'temporal_patterns': None}
        
        # Group by time windows (already done by TimeWindowGrouper)
        grouped_detections = [d for d in detections_with_time if d.window_start]
        
        return {
            'detections_with_timestamps': len(detections_with_time),
            'grouped_detections': len(grouped_detections),
            'temporal_clustering': len(grouped_detections) < len(detections_with_time)
        }
    
    def _analyze_severity_distribution(self, detections: List[Detection]) -> Dict[str, Any]:
        """Analyze the distribution of severity levels."""
        severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        for detection in detections:
            severity = detection.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        total = len(detections)
        
        return {
            'severity_counts': severity_counts,
            'severity_percentages': {
                severity: (count / total * 100) if total > 0 else 0
                for severity, count in severity_counts.items()
            },
            'has_critical': severity_counts['critical'] > 0,
            'has_high': severity_counts['high'] > 0
        }
    
    def _identify_suspicious_packages(
        self, 
        detections: List[Detection], 
        log_data: LogData
    ) -> List[Dict[str, Any]]:
        """Identify the most suspicious packages based on detections."""
        package_suspicion = {}
        
        # Score packages based on their detections
        for detection in detections:
            if not detection.package:
                continue
                
            package = detection.package
            if package not in package_suspicion:
                package_suspicion[package] = {
                    'package': package,
                    'detection_count': 0,
                    'severity_score': 0,
                    'categories': set(),
                    'detections': []
                }
            
            # Add to package suspicion
            package_data = package_suspicion[package]
            package_data['detection_count'] += 1
            package_data['categories'].add(detection.category)
            package_data['detections'].append(detection.id)
            
            # Add severity score
            severity_weights = {'low': 1, 'medium': 3, 'high': 6, 'critical': 10}
            package_data['severity_score'] += severity_weights.get(detection.severity.value, 3)
        
        # Convert sets to lists for JSON serialization
        for package_data in package_suspicion.values():
            package_data['categories'] = list(package_data['categories'])
        
        # Add package metadata if available
        for package_name, package_data in package_suspicion.items():
            package_info = log_data.packages.get(package_name)
            if package_info:
                package_data.update({
                    'installer': package_info.installer,
                    'is_system': package_info.is_system,
                    'has_sensitive_permissions': package_info.has_sensitive_permissions(),
                    'is_suspicious_installer': package_info.is_suspicious_installer()
                })
        
        # Sort by suspicion score (severity_score * detection_count)
        suspicious_packages = sorted(
            package_suspicion.values(),
            key=lambda x: x['severity_score'] * x['detection_count'],
            reverse=True
        )
        
        return suspicious_packages[:10]  # Top 10 most suspicious
    
    def _find_cross_category_packages(self, detections: List[Detection]) -> Dict[str, List[str]]:
        """Find packages that appear in multiple categories."""
        package_categories = {}
        
        for detection in detections:
            if detection.package:
                if detection.package not in package_categories:
                    package_categories[detection.package] = set()
                package_categories[detection.package].add(detection.category)
        
        # Find packages with multiple categories
        cross_category = {
            package: list(categories)
            for package, categories in package_categories.items()
            if len(categories) > 1
        }
        
        return cross_category
    
    def _get_max_severity(self, detections: List[Detection]) -> str:
        """Get the maximum severity from a list of detections."""
        severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        
        max_severity = 'low'
        max_value = 0
        
        for detection in detections:
            severity = detection.severity.value
            value = severity_order.get(severity, 0)
            if value > max_value:
                max_value = value
                max_severity = severity
        
        return max_severity
