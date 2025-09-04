"""
Data validation for parsed and enriched log entries.

This module validates data quality, consistency, and completeness.
"""

from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import logging

from ward_core.infrastructure.parsers.base_parser import ParsedLogEntry
from ward_core.infrastructure.shared.validation_utils import ValidationUtils, ValidationIssue, ValidationSeverity


@dataclass
class ValidationResult:
    """Result of data validation process."""
    
    total_entries: int
    valid_entries: int
    issues: List[ValidationIssue] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def validation_score(self) -> float:
        """Calculate validation score (0.0-1.0)."""
        if self.total_entries == 0:
            return 0.0
        
        # Base score from valid entries
        base_score = self.valid_entries / self.total_entries
        
        # Penalty for errors (but not warnings)
        error_count = len([i for i in self.issues if i.severity == ValidationSeverity.ERROR])
        error_penalty = min(0.5, error_count * 0.1)

        return max(0.0, base_score - error_penalty)

    @property
    def has_errors(self) -> bool:
        """Check if validation found any errors."""
        return any(issue.severity == ValidationSeverity.ERROR for issue in self.issues)

    def get_issues_by_severity(self, severity: ValidationSeverity) -> List[ValidationIssue]:
        """Get all issues of a specific severity."""
        return [issue for issue in self.issues if issue.severity == severity]
    
    def get_summary(self) -> str:
        """Get human-readable validation summary."""
        error_count = len(self.get_issues_by_severity(ValidationSeverity.ERROR))
        warning_count = len(self.get_issues_by_severity(ValidationSeverity.WARNING))

        return (f"Validation: {self.valid_entries}/{self.total_entries} valid entries "
               f"(score: {self.validation_score:.2f}) - "
               f"{error_count} errors, {warning_count} warnings")


class DataValidator:
    """
    Data validator for parsed log entries.
    
    This class validates data quality, consistency, and completeness
    of parsed Android forensic log data.
    """
    
    # Expected entry types for different file sources
    EXPECTED_ENTRY_TYPES = {
        'package': {'package_info', 'installer_info', 'permission'},
        'appops': {'appops_entry', 'permission'},
        'accessibility': {'accessibility_service', 'accessibility_event'},
        'netstats': {'network_stats', 'network_interface'},
        'logcat': {'system_log', 'app_log', 'crash_log'},
        'batterystats': {'battery_stats', 'wakelock', 'alarm', 'job'}
    }
    
    # Valid log levels
    VALID_LOG_LEVELS = {'V', 'D', 'I', 'W', 'E', 'F', 'S'}
    
    # Maximum reasonable values for validation
    MAX_REASONABLE_VALUES = {
        'confidence': 1.0,
        'line_number': 10000000,  # 10M lines max
        'network_bytes': 10 * 1024 * 1024 * 1024,  # 10GB max
        'duration_seconds': 24 * 60 * 60,  # 24 hours max
    }
    
    def __init__(self):
        """Initialize the data validator."""
        self.logger = logging.getLogger("data.validator")
        self.validation_utils = ValidationUtils()
        
        # Track validation statistics
        self._validation_stats = Counter()
    
    def validate(self, entries: List[ParsedLogEntry]) -> ValidationResult:
        """
        Validate a list of parsed log entries.
        
        Args:
            entries: List of entries to validate
            
        Returns:
            Validation result with issues and statistics
        """
        if not entries:
            return ValidationResult(total_entries=0, valid_entries=0)
        
        self.logger.info(f"Starting validation of {len(entries)} entries")
        self._validation_stats.clear()
        
        issues = []
        valid_count = 0
        
        # Group entries by source file for contextual validation
        entries_by_file = defaultdict(list)
        for entry in entries:
            entries_by_file[entry.source_file].append(entry)
        
        # Validate individual entries
        for entry in entries:
            entry_issues = self._validate_single_entry(entry)
            issues.extend(entry_issues)
            
            if not any(issue.severity == ValidationSeverity.ERROR for issue in entry_issues):
                valid_count += 1
                self._validation_stats['valid_entries'] += 1
            else:
                self._validation_stats['invalid_entries'] += 1
        
        # Validate file-level consistency
        for file_name, file_entries in entries_by_file.items():
            file_issues = self._validate_file_consistency(file_name, file_entries)
            issues.extend(file_issues)
        
        # Validate cross-file consistency
        cross_file_issues = self._validate_cross_file_consistency(entries_by_file)
        issues.extend(cross_file_issues)
        
        # Aggregate duplicate issues
        aggregated_issues = self._aggregate_issues(issues)
        
        # Generate validation statistics
        statistics = self._generate_statistics(entries, aggregated_issues)
        
        result = ValidationResult(
            total_entries=len(entries),
            valid_entries=valid_count,
            issues=aggregated_issues,
            statistics=statistics
        )
        
        self.logger.info(result.get_summary())
        return result
    
    def _validate_single_entry(self, entry: ParsedLogEntry) -> List[ValidationIssue]:
        """Validate a single log entry."""
        issues = []
        
        # Required fields validation
        if not entry.source_file:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="completeness",
                message="Missing source file",
                source=f"line_{entry.line_number}"
            ))

        if not entry.entry_type:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="completeness",
                message="Missing entry type",
                source=f"{entry.source_file}_line_{entry.line_number}" if entry.source_file else f"line_{entry.line_number}"
            ))

        if entry.line_number <= 0:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="quality",
                message=f"Invalid line number: {entry.line_number}",
                source=f"{entry.source_file}_line_{entry.line_number}" if entry.source_file else f"line_{entry.line_number}"
            ))

        # Confidence validation
        if not (0.0 <= entry.confidence <= 1.0):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category="quality",
                message=f"Invalid confidence value: {entry.confidence}",
                source=f"{entry.source_file}_line_{entry.line_number}" if entry.source_file else f"line_{entry.line_number}"
            ))
        
        # Log level validation
        if entry.log_level and entry.log_level not in self.VALID_LOG_LEVELS:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="quality",
                message=f"Unknown log level: {entry.log_level}",
                source=f"{entry.source_file}_line_{entry.line_number}" if entry.source_file else f"line_{entry.line_number}"
            ))

        # Content validation
        if not entry.raw_line and not entry.parsed_content:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="completeness",
                message="Entry has no content (empty raw_line and parsed_content)",
                source=f"{entry.source_file}_line_{entry.line_number}" if entry.source_file else f"line_{entry.line_number}"
            ))

        # Timestamp validation
        if entry.timestamp:
            # Check if timestamp is reasonable (not too far in past/future)
            now = datetime.now()
            if entry.timestamp > now + timedelta(days=1):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="quality",
                    message="Timestamp in future",
                    source=f"{entry.source_file}_line_{entry.line_number}" if entry.source_file else f"line_{entry.line_number}"
                ))
            elif entry.timestamp < datetime(2010, 1, 1):  # Before Android was popular
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="quality",
                    message="Timestamp too old (before 2010)",
                    source=f"{entry.source_file}_line_{entry.line_number}" if entry.source_file else f"line_{entry.line_number}"
                ))
        
        # Package name validation
        if entry.package:
            if not self._is_valid_package_name(entry.package):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="quality",
                    message=f"Suspicious package name format: {entry.package}",
                    source=f"{entry.source_file}_line_{entry.line_number}" if entry.source_file else f"line_{entry.line_number}"
                ))
        
        # Parsed content validation
        if entry.parsed_content:
            content_issues = self._validate_parsed_content(entry)
            issues.extend(content_issues)
        
        return issues
    
    def _validate_file_consistency(self, file_name: str, entries: List[ParsedLogEntry]) -> List[ValidationIssue]:
        """Validate consistency within a single file."""
        issues = []
        
        if not entries:
            return issues
        
        # Check for expected entry types based on file name
        file_type = self._detect_file_type(file_name)
        if file_type and file_type in self.EXPECTED_ENTRY_TYPES:
            expected_types = self.EXPECTED_ENTRY_TYPES[file_type]
            actual_types = set(entry.entry_type for entry in entries)
            
            # Warn if no expected types found
            if not expected_types.intersection(actual_types):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="consistency",
                    message=f"No expected entry types found for {file_type} file. "
                           f"Expected: {expected_types}, Got: {actual_types}",
                    source=file_name
                ))

        # Check line number sequence
        line_numbers = [entry.line_number for entry in entries]
        if len(set(line_numbers)) != len(line_numbers):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="consistency",
                message="Duplicate line numbers found",
                source=file_name
            ))
        
        # Check timestamp ordering (if timestamps exist)
        timestamped_entries = [(e.line_number, e.timestamp) for e in entries if e.timestamp]
        if len(timestamped_entries) > 1:
            # Sort by line number and check if timestamps are roughly in order
            timestamped_entries.sort(key=lambda x: x[0])
            
            out_of_order_count = 0
            for i in range(1, len(timestamped_entries)):
                if timestamped_entries[i][1] < timestamped_entries[i-1][1]:
                    out_of_order_count += 1
            
            if out_of_order_count > len(timestamped_entries) * 0.1:  # More than 10% out of order
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    category="consistency",
                    message=f"Many timestamps out of chronological order ({out_of_order_count} out of {len(timestamped_entries)})",
                    source=file_name
                ))
        
        return issues
    
    def _validate_cross_file_consistency(self, entries_by_file: Dict[str, List[ParsedLogEntry]]) -> List[ValidationIssue]:
        """Validate consistency across multiple files."""
        issues = []
        
        # Check for overlapping package information
        packages_by_file = defaultdict(set)
        for file_name, entries in entries_by_file.items():
            for entry in entries:
                if entry.package:
                    packages_by_file[file_name].add(entry.package)
        
        # Check for completeness - warn if important files are missing
        file_types = set()
        for file_name in entries_by_file.keys():
            file_type = self._detect_file_type(file_name)
            if file_type:
                file_types.add(file_type)
        
        important_missing = set(['package', 'appops']) - file_types
        if important_missing:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category="completeness",
                message=f"Important file types missing: {important_missing}",
                source="cross_file_validation"
            ))
        
        return issues
    
    def _validate_parsed_content(self, entry: ParsedLogEntry) -> List[ValidationIssue]:
        """Validate parsed content fields."""
        issues = []
        
        for key, value in entry.parsed_content.items():
            # Check for reasonable numeric values
            if isinstance(value, (int, float)):
                max_reasonable = self.MAX_REASONABLE_VALUES.get(key)
                if max_reasonable and value > max_reasonable:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        category="quality",
                        message=f"Unusually large value for {key}: {value}",
                        source=f"{entry.source_file}_line_{entry.line_number}" if entry.source_file else f"line_{entry.line_number}"
                    ))

            # Check for empty string values that should have content
            elif isinstance(value, str) and not value and key in ['package', 'process', 'component']:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    category="completeness",
                    message=f"Empty {key} field",
                    source=f"{entry.source_file}_line_{entry.line_number}" if entry.source_file else f"line_{entry.line_number}"
                ))
        
        return issues
    
    def _detect_file_type(self, file_name: str) -> Optional[str]:
        """Detect file type from filename."""
        file_name_lower = file_name.lower()
        
        if 'package' in file_name_lower:
            return 'package'
        elif 'appops' in file_name_lower:
            return 'appops' 
        elif 'accessibility' in file_name_lower:
            return 'accessibility'
        elif 'netstats' in file_name_lower:
            return 'netstats'
        elif 'logcat' in file_name_lower:
            return 'logcat'
        elif 'batterystats' in file_name_lower:
            return 'batterystats'
        
        return None
    
    def _is_valid_package_name(self, package: str) -> bool:
        """Check if package name follows valid Android package naming conventions."""
        if not package:
            return False
        
        # Basic Android package naming rules
        parts = package.split('.')
        
        # Should have at least 2 parts
        if len(parts) < 2:
            return False
        
        # Each part should be a valid identifier
        for part in parts:
            if not part or not part.replace('_', '').isalnum() or part[0].isdigit():
                return False
        
        return True
    
    def _aggregate_issues(self, issues: List[ValidationIssue]) -> List[ValidationIssue]:
        """Aggregate duplicate issues using shared validation utilities."""
        return self.validation_utils.aggregate_issues(issues)
    
    def _generate_statistics(self, entries: List[ParsedLogEntry], issues: List[ValidationIssue]) -> Dict[str, Any]:
        """Generate validation statistics."""
        stats = {}
        
        # Basic counts
        stats['total_entries'] = len(entries)
        stats['total_issues'] = len(issues)
        stats['error_count'] = len([i for i in issues if i.severity == ValidationSeverity.ERROR])
        stats['warning_count'] = len([i for i in issues if i.severity == ValidationSeverity.WARNING])
        stats['info_count'] = len([i for i in issues if i.severity == ValidationSeverity.INFO])
        
        # Entry type distribution
        entry_types = Counter(entry.entry_type for entry in entries)
        stats['entry_type_distribution'] = dict(entry_types)
        
        # Source file distribution
        source_files = Counter(entry.source_file for entry in entries)
        stats['source_file_distribution'] = dict(source_files)
        
        # Completeness statistics
        stats['entries_with_timestamp'] = sum(1 for e in entries if e.timestamp)
        stats['entries_with_package'] = sum(1 for e in entries if e.package)
        stats['entries_with_parsed_content'] = sum(1 for e in entries if e.parsed_content)
        
        # Quality statistics  
        confidence_scores = [e.confidence for e in entries]
        if confidence_scores:
            stats['average_confidence'] = sum(confidence_scores) / len(confidence_scores)
            stats['min_confidence'] = min(confidence_scores)
            stats['max_confidence'] = max(confidence_scores)
        
        return stats


