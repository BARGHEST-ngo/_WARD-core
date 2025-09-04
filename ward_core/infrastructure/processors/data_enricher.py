"""
Data enrichment pipeline for parsed log data.

This module adds derived data, correlations, and context to parsed log entries.
"""

import re
from typing import Dict, List, Set, Optional, Any, Iterator
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import logging

from ward_core.infrastructure.parsers.base_parser import ParsedLogEntry


@dataclass
class EnrichmentConfig:
    """Configuration for data enrichment."""
    
    # Package enrichment
    extract_package_relationships: bool = True
    resolve_package_names: bool = True
    identify_system_packages: bool = True
    
    # Temporal enrichment
    add_time_context: bool = True
    group_related_events: bool = True
    calculate_durations: bool = True
    
    # Security enrichment
    flag_suspicious_patterns: bool = True
    add_security_context: bool = True
    correlate_permissions: bool = True
    
    # Performance settings
    max_entries_for_correlation: int = 100000
    enable_caching: bool = True


@dataclass
class EnrichmentResult:
    """Result of data enrichment process."""
    
    enriched_entries: List[ParsedLogEntry]
    metadata: Dict[str, Any] = field(default_factory=dict)
    statistics: Dict[str, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    
    def get_enrichment_summary(self) -> str:
        """Get human-readable enrichment summary."""
        total = len(self.enriched_entries)
        enriched = self.statistics.get('enriched_count', 0)
        
        return (f"Enriched {enriched}/{total} entries "
               f"({enriched/total*100:.1f}% enrichment rate)")


class DataEnricher:
    """
    Data enrichment pipeline that adds context and derived data to parsed entries.
    
    This class transforms raw parsed entries into enriched entries with additional
    context, correlations, and security-relevant metadata.
    """
    
    # Known system packages (partial list for Android)
    SYSTEM_PACKAGES = {
        'android', 'com.android.systemui', 'com.android.settings',
        'com.android.phone', 'com.android.bluetooth', 'system_server',
        'com.google.android.gms', 'com.android.vending'
    }
    
    # Suspicious patterns to flag
    SUSPICIOUS_PATTERNS = {
        'privilege_escalation': [
            re.compile(r'su\s+', re.IGNORECASE),
            re.compile(r'root.*exploit', re.IGNORECASE),
            re.compile(r'setuid.*0', re.IGNORECASE),
        ],
        'data_exfiltration': [
            re.compile(r'upload.*\d+\s*mb', re.IGNORECASE),
            re.compile(r'send.*data.*server', re.IGNORECASE),
            re.compile(r'POST.*binary.*data', re.IGNORECASE),
        ],
        'persistence': [
            re.compile(r'boot.*receiver', re.IGNORECASE),
            re.compile(r'install.*\.(apk|dex)', re.IGNORECASE),
            re.compile(r'service.*persistent', re.IGNORECASE),
        ],
        'anti_analysis': [
            re.compile(r'debugger.*detect', re.IGNORECASE),
            re.compile(r'emulator.*check', re.IGNORECASE),
            re.compile(r'anti.*virus', re.IGNORECASE),
        ]
    }
    
    def __init__(self, config: Optional[EnrichmentConfig] = None):
        """Initialize the data enricher."""
        self.config = config or EnrichmentConfig()
        self.logger = logging.getLogger("data.enricher")
        
        # Caches for performance
        self._package_cache: Dict[str, Dict[str, Any]] = {}
        self._pattern_cache: Dict[str, bool] = {}
        
        # Statistics tracking
        self._stats = Counter()
    
    def enrich(self, entries: List[ParsedLogEntry]) -> EnrichmentResult:
        """
        Enrich a list of parsed log entries.
        
        Args:
            entries: List of parsed entries to enrich
            
        Returns:
            Enrichment result with enriched entries and metadata
        """
        if not entries:
            return EnrichmentResult(enriched_entries=[], statistics={'total_entries': 0})
        
        self.logger.info(f"Starting enrichment of {len(entries)} entries")
        self._stats.clear()
        
        try:
            # Phase 1: Individual entry enrichment
            enriched_entries = []
            for entry in entries:
                enriched_entry = self._enrich_single_entry(entry)
                enriched_entries.append(enriched_entry)
                self._stats['total_processed'] += 1
            
            # Phase 2: Cross-entry correlation and context
            if self.config.group_related_events and len(enriched_entries) <= self.config.max_entries_for_correlation:
                enriched_entries = self._add_correlation_context(enriched_entries)
            
            # Phase 3: Temporal analysis
            if self.config.add_time_context:
                enriched_entries = self._add_temporal_context(enriched_entries)
            
            # Phase 4: Security analysis
            if self.config.add_security_context:
                enriched_entries = self._add_security_context(enriched_entries)
            
            # Calculate final statistics
            enriched_count = sum(1 for e in enriched_entries if e.metadata.get('enriched', False))
            self._stats['enriched_count'] = enriched_count
            
            result = EnrichmentResult(
                enriched_entries=enriched_entries,
                metadata={
                    'enrichment_config': self.config,
                    'processing_time': datetime.now(),
                    'cache_hits': self._stats.get('cache_hits', 0)
                },
                statistics=dict(self._stats)
            )
            
            self.logger.info(result.get_enrichment_summary())
            return result
            
        except Exception as e:
            self.logger.error(f"Enrichment failed: {e}")
            raise
    
    def _enrich_single_entry(self, entry: ParsedLogEntry) -> ParsedLogEntry:
        """Enrich a single log entry."""
        # Create enriched copy
        enriched = ParsedLogEntry(
            line_number=entry.line_number,
            source_file=entry.source_file,
            entry_type=entry.entry_type,
            timestamp=entry.timestamp,
            log_level=entry.log_level,
            raw_line=entry.raw_line,
            parsed_content=entry.parsed_content.copy(),
            package=entry.package,
            process=entry.process,
            component=entry.component,
            confidence=entry.confidence,
            tags=entry.tags.copy(),
            metadata=entry.metadata.copy()
        )
        
        # Add enrichment markers
        enriched.metadata['enriched'] = True
        enriched.metadata['enrichment_timestamp'] = datetime.now()
        
        # Package enrichment
        if self.config.extract_package_relationships and entry.package:
            package_info = self._enrich_package_info(entry.package)
            enriched.metadata.update(package_info)
        
        # Content enrichment
        if entry.raw_line:
            content_enrichment = self._enrich_content(entry.raw_line, entry.entry_type)
            enriched.metadata.update(content_enrichment)
        
        # Pattern matching
        if self.config.flag_suspicious_patterns:
            suspicious_flags = self._check_suspicious_patterns(entry.raw_line)
            if suspicious_flags:
                enriched.add_tag('suspicious')
                enriched.metadata['suspicious_patterns'] = suspicious_flags
        
        self._stats['enriched_entries'] += 1
        return enriched
    
    def _enrich_package_info(self, package: str) -> Dict[str, Any]:
        """Enrich package-related information."""
        # Check cache first
        if self.config.enable_caching and package in self._package_cache:
            self._stats['cache_hits'] += 1
            return self._package_cache[package]
        
        enrichment = {}
        
        # Identify system packages
        if self.config.identify_system_packages:
            is_system = any(sys_pkg in package for sys_pkg in self.SYSTEM_PACKAGES)
            enrichment['is_system_package'] = is_system
            if is_system:
                enrichment['package_category'] = 'system'
            else:
                enrichment['package_category'] = 'user'
        
        # Extract package hierarchy
        if '.' in package:
            parts = package.split('.')
            enrichment['package_domain'] = parts[0] if len(parts) > 1 else package
            enrichment['package_hierarchy_depth'] = len(parts)
            
            # Flag suspicious package naming patterns
            if len(parts) > 6:  # Unusually deep hierarchy
                enrichment['suspicious_naming'] = 'deep_hierarchy'
            elif any(part.isdigit() for part in parts):  # Numbers in package name
                enrichment['suspicious_naming'] = 'contains_numbers'
        
        # Cache result
        if self.config.enable_caching:
            self._package_cache[package] = enrichment
        
        return enrichment
    
    def _enrich_content(self, raw_line: str, entry_type: str) -> Dict[str, Any]:
        """Enrich content-specific information."""
        enrichment = {}
        
        # Extract numeric values and patterns
        numbers = re.findall(r'\b\d+\b', raw_line)
        if numbers:
            enrichment['numeric_values'] = [int(n) for n in numbers[:5]]  # Limit to first 5
        
        # Extract file paths
        file_paths = re.findall(r'/[\w/.-]+', raw_line)
        if file_paths:
            enrichment['file_paths'] = file_paths[:3]  # Limit to first 3
        
        # Extract network-related information
        ip_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_line)
        if ip_addresses:
            enrichment['ip_addresses'] = ip_addresses
        
        urls = re.findall(r'https?://[^\s]+', raw_line)
        if urls:
            enrichment['urls'] = urls
        
        # Entry-type specific enrichment
        if entry_type == 'permission':
            permissions = re.findall(r'android\.permission\.[\w_]+', raw_line)
            if permissions:
                enrichment['permissions'] = permissions
        
        elif entry_type == 'appops':
            operations = re.findall(r'op=(\w+)', raw_line)
            if operations:
                enrichment['appops_operations'] = operations
        
        elif entry_type == 'network':
            # Extract network statistics
            rx_match = re.search(r'rx.*?(\d+)', raw_line, re.IGNORECASE)
            tx_match = re.search(r'tx.*?(\d+)', raw_line, re.IGNORECASE)
            
            if rx_match:
                enrichment['rx_bytes'] = int(rx_match.group(1))
            if tx_match:
                enrichment['tx_bytes'] = int(tx_match.group(1))
        
        return enrichment
    
    def _check_suspicious_patterns(self, content: str) -> List[str]:
        """Check content against suspicious patterns."""
        cache_key = hash(content)
        if self.config.enable_caching and cache_key in self._pattern_cache:
            self._stats['cache_hits'] += 1
            return self._pattern_cache[cache_key] if self._pattern_cache[cache_key] else []
        
        suspicious_flags = []
        
        for category, patterns in self.SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(content):
                    suspicious_flags.append(category)
                    break  # Only flag each category once per entry
        
        # Cache result
        if self.config.enable_caching:
            self._pattern_cache[cache_key] = suspicious_flags if suspicious_flags else False
        
        if suspicious_flags:
            self._stats['suspicious_entries'] += 1
        
        return suspicious_flags
    
    def _add_correlation_context(self, entries: List[ParsedLogEntry]) -> List[ParsedLogEntry]:
        """Add cross-entry correlation context."""
        # Group entries by package
        package_groups = defaultdict(list)
        for entry in entries:
            if entry.package:
                package_groups[entry.package].append(entry)
        
        # Add package-level statistics
        for package, package_entries in package_groups.items():
            entry_types = Counter(entry.entry_type for entry in package_entries)
            
            # Add package context to each entry
            for entry in package_entries:
                entry.metadata.setdefault('package_context', {})
                entry.metadata['package_context'].update({
                    'total_entries': len(package_entries),
                    'entry_type_distribution': dict(entry_types),
                    'dominant_entry_type': entry_types.most_common(1)[0][0] if entry_types else None
                })
        
        self._stats['correlation_groups'] = len(package_groups)
        return entries
    
    def _add_temporal_context(self, entries: List[ParsedLogEntry]) -> List[ParsedLogEntry]:
        """Add temporal analysis context."""
        # Sort entries by timestamp
        timestamped_entries = [(e, e.timestamp) for e in entries if e.timestamp]
        timestamped_entries.sort(key=lambda x: x[1])
        
        if len(timestamped_entries) < 2:
            return entries  # Not enough timestamped entries
        
        # Add temporal context
        for i, (entry, timestamp) in enumerate(timestamped_entries):
            temporal_context = {}
            
            # Add position in timeline
            temporal_context['timeline_position'] = i / len(timestamped_entries)
            
            # Add time gaps to previous/next entries
            if i > 0:
                prev_timestamp = timestamped_entries[i-1][1]
                time_gap = (timestamp - prev_timestamp).total_seconds()
                temporal_context['time_since_previous'] = time_gap
            
            if i < len(timestamped_entries) - 1:
                next_timestamp = timestamped_entries[i+1][1]
                time_gap = (next_timestamp - timestamp).total_seconds()
                temporal_context['time_until_next'] = time_gap
            
            entry.metadata['temporal_context'] = temporal_context
        
        self._stats['timestamped_entries'] = len(timestamped_entries)
        return entries
    
    def _add_security_context(self, entries: List[ParsedLogEntry]) -> List[ParsedLogEntry]:
        """Add security-focused context."""
        # Count security-relevant events by package
        security_events = defaultdict(list)
        
        for entry in entries:
            if entry.has_tag('suspicious') or entry.entry_type in ['permission', 'appops', 'accessibility']:
                if entry.package:
                    security_events[entry.package].append(entry)
        
        # Add security context to entries from packages with multiple security events
        for package, events in security_events.items():
            if len(events) >= 2:  # Multiple security events from same package
                for entry in events:
                    entry.add_tag('security_relevant')
                    entry.metadata.setdefault('security_context', {})
                    entry.metadata['security_context'].update({
                        'package_security_event_count': len(events),
                        'security_event_types': list(set(e.entry_type for e in events))
                    })
        
        self._stats['security_relevant_packages'] = len([p for p, events in security_events.items() if len(events) >= 2])
        return entries


