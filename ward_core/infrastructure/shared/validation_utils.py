"""
Shared Validation Utilities - Centralized validation and aggregation logic.

Consolidates validation functionality from multiple processors and services
to eliminate redundancy and provide consistent validation across the system.

This utility replaces duplicate logic found in:
- data_validator.py (_aggregate_issues)
- parser_registry.py (compatibility caching)
- hybrid_collector.py (source merging validation)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, TypeVar, Generic, Callable
from collections import defaultdict
from enum import Enum
import logging

T = TypeVar('T')


class ValidationSeverity(Enum):
    """Severity levels for validation issues."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ValidationIssue:
    """Represents a validation issue."""
    severity: ValidationSeverity
    category: str
    message: str
    source: Optional[str] = None
    count: int = 1
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ValidationResult:
    """Result of a validation operation."""
    total_items: int
    valid_items: int
    issues: List[ValidationIssue]
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    @property
    def success_rate(self) -> float:
        """Get the validation success rate."""
        if self.total_items == 0:
            return 1.0
        return self.valid_items / self.total_items
    
    @property
    def has_errors(self) -> bool:
        """Check if there are any error-level issues."""
        return any(issue.severity in [ValidationSeverity.ERROR, ValidationSeverity.CRITICAL] 
                  for issue in self.issues)
    
    def get_summary(self) -> str:
        """Get a summary of the validation results."""
        error_count = sum(1 for issue in self.issues 
                         if issue.severity in [ValidationSeverity.ERROR, ValidationSeverity.CRITICAL])
        warning_count = sum(1 for issue in self.issues 
                           if issue.severity == ValidationSeverity.WARNING)
        
        return (f"Validation: {self.valid_items}/{self.total_items} valid items "
                f"(score: {self.success_rate:.2f}) - {error_count} errors, {warning_count} warnings")


class ValidationUtils:
    """
    Centralized utility class for validation operations.
    
    This class provides consistent validation functionality that was
    previously duplicated across multiple processors and services.
    """
    
    def __init__(self):
        """Initialize the validation utilities."""
        self.logger = logging.getLogger("validation.utils")
    
    def aggregate_issues(self, issues: List[ValidationIssue]) -> List[ValidationIssue]:
        """
        Aggregate duplicate issues to reduce noise.
        
        Args:
            issues: List of validation issues to aggregate
            
        Returns:
            List of aggregated issues
        """
        if not issues:
            return []
        
        issue_groups = defaultdict(list)
        
        # Group similar issues
        for issue in issues:
            # Handle ValidationIssue objects that might not have source attribute (backward compatibility)
            source = getattr(issue, 'source', None)
            key = (issue.severity, issue.category, issue.message, source)
            issue_groups[key].append(issue)
        
        aggregated = []
        for (severity, category, message, source), group in issue_groups.items():
            if len(group) == 1:
                aggregated.append(group[0])
            else:
                # Create aggregated issue
                total_count = sum(issue.count for issue in group)
                merged_metadata = {}
                for issue in group:
                    merged_metadata.update(issue.metadata)
                
                aggregated_issue = ValidationIssue(
                    severity=severity,
                    category=category,
                    message=message,
                    source=source,
                    count=total_count,
                    metadata=merged_metadata
                )
                aggregated.append(aggregated_issue)
        
        return aggregated
    
    def validate_items(self, items: List[T], 
                      validator_func: Callable[[T], List[ValidationIssue]],
                      item_name: str = "item") -> ValidationResult:
        """
        Validate a list of items using a validator function.
        
        Args:
            items: List of items to validate
            validator_func: Function that validates a single item
            item_name: Name for the items being validated
            
        Returns:
            Validation result
        """
        if not items:
            return ValidationResult(
                total_items=0,
                valid_items=0,
                issues=[],
                metadata={'item_type': item_name}
            )
        
        all_issues = []
        valid_count = 0
        
        for i, item in enumerate(items):
            try:
                item_issues = validator_func(item)
                if not item_issues:
                    valid_count += 1
                else:
                    # Add source information to issues
                    for issue in item_issues:
                        if not issue.source:
                            issue.source = f"{item_name}_{i}"
                    all_issues.extend(item_issues)
            except Exception as e:
                # Handle validation errors
                error_issue = ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    category="validation_error",
                    message=f"Failed to validate {item_name} {i}: {str(e)}",
                    source=f"{item_name}_{i}"
                )
                all_issues.append(error_issue)
        
        # Aggregate similar issues
        aggregated_issues = self.aggregate_issues(all_issues)
        
        return ValidationResult(
            total_items=len(items),
            valid_items=valid_count,
            issues=aggregated_issues,
            metadata={
                'item_type': item_name,
                'validation_errors': len([i for i in aggregated_issues 
                                        if i.severity in [ValidationSeverity.ERROR, ValidationSeverity.CRITICAL]])
            }
        )
    
    def validate_cross_references(self, items: List[T],
                                get_references: Callable[[T], List[str]],
                                reference_exists: Callable[[str], bool],
                                item_name: str = "item") -> List[ValidationIssue]:
        """
        Validate cross-references between items.
        
        Args:
            items: List of items to validate
            get_references: Function to extract references from an item
            reference_exists: Function to check if a reference exists
            item_name: Name for the items being validated
            
        Returns:
            List of validation issues
        """
        issues = []
        
        for i, item in enumerate(items):
            try:
                references = get_references(item)
                for ref in references:
                    if not reference_exists(ref):
                        issue = ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            category="missing_reference",
                            message=f"Reference '{ref}' not found",
                            source=f"{item_name}_{i}"
                        )
                        issues.append(issue)
            except Exception as e:
                error_issue = ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    category="reference_validation_error",
                    message=f"Failed to validate references for {item_name} {i}: {str(e)}",
                    source=f"{item_name}_{i}"
                )
                issues.append(error_issue)
        
        return issues
    
    def validate_consistency(self, items: List[T],
                           get_key: Callable[[T], str],
                           get_value: Callable[[T], Any],
                           item_name: str = "item") -> List[ValidationIssue]:
        """
        Validate consistency of values across items with the same key.
        
        Args:
            items: List of items to validate
            get_key: Function to extract grouping key from item
            get_value: Function to extract value to check consistency
            item_name: Name for the items being validated
            
        Returns:
            List of validation issues
        """
        issues = []
        value_groups = defaultdict(list)
        
        # Group items by key
        for i, item in enumerate(items):
            try:
                key = get_key(item)
                value = get_value(item)
                value_groups[key].append((i, value))
            except Exception as e:
                error_issue = ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    category="consistency_validation_error",
                    message=f"Failed to extract key/value for {item_name} {i}: {str(e)}",
                    source=f"{item_name}_{i}"
                )
                issues.append(error_issue)
        
        # Check consistency within each group
        for key, value_list in value_groups.items():
            if len(value_list) > 1:
                # Check if all values are the same
                first_value = value_list[0][1]
                inconsistent_items = []
                
                for item_index, value in value_list[1:]:
                    if value != first_value:
                        inconsistent_items.append(item_index)
                
                if inconsistent_items:
                    issue = ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        category="inconsistent_values",
                        message=f"Inconsistent values for key '{key}' in {item_name}s: {inconsistent_items}",
                        source=f"{item_name}_consistency_check",
                        metadata={
                            'key': key,
                            'inconsistent_items': inconsistent_items,
                            'expected_value': str(first_value)
                        }
                    )
                    issues.append(issue)
        
        return issues
    
    def create_compatibility_cache(self) -> Dict[str, Any]:
        """Create a new compatibility cache for validation operations."""
        return {
            'cache': {},
            'hits': 0,
            'misses': 0,
            'created_at': None  # Would be set to current time in real implementation
        }
    
    def get_cached_result(self, cache: Dict[str, Any], key: str) -> Optional[Any]:
        """Get a cached validation result."""
        if key in cache['cache']:
            cache['hits'] += 1
            return cache['cache'][key]
        else:
            cache['misses'] += 1
            return None
    
    def set_cached_result(self, cache: Dict[str, Any], key: str, result: Any) -> None:
        """Set a cached validation result."""
        cache['cache'][key] = result
    
    def get_cache_stats(self, cache: Dict[str, Any]) -> Dict[str, Any]:
        """Get statistics about cache usage."""
        total_requests = cache['hits'] + cache['misses']
        hit_rate = cache['hits'] / total_requests if total_requests > 0 else 0.0
        
        return {
            'total_requests': total_requests,
            'cache_hits': cache['hits'],
            'cache_misses': cache['misses'],
            'hit_rate': hit_rate,
            'cache_size': len(cache['cache'])
        }
