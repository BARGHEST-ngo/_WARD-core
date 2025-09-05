"""
Clean Data Loader Service replacing the monolithic data_loader.py

This service orchestrates collection, parsing, and processing of Android log data
using the new modular architecture.
"""

from typing import Dict, Any, List, Optional
from pathlib import Path
import logging
from datetime import datetime

from ward_core.logic.models import LogData, PackageInfo, DeviceInfo
from .collectors import CollectorRegistry, CollectionProfiles, CollectionConfig
from .parsers import ParserRegistry, FormatDetector
from .processors import DataEnricher, DataValidator, CoverageAnalyzer


class DataLoaderService:
    """
    Clean data loading service that replaces the monolithic data_loader.py
    
    This service orchestrates collection, parsing, and processing of Android log data
    using clean architecture principles.
    """
    
    def __init__(self, collection_config: Optional[CollectionConfig] = None):
        """Initialize the data loader service."""
        self.collection_config = collection_config or CollectionConfig()
        self.logger = logging.getLogger("data.loader")
        
        # Initialize registries
        self.collector_registry = CollectorRegistry()
        self.parser_registry = ParserRegistry()
        self.format_detector = FormatDetector()
        
        # Initialize processors
        self.enricher = DataEnricher()
        self.validator = DataValidator()
        self.coverage_analyzer = CoverageAnalyzer()
        
        # Register collectors
        self._register_collectors()
        
        # Auto-discover parsers
        self.parser_registry.auto_discover()
        self._register_specialized_parsers()
    
    def load_data(
        self, 
        source: str, 
        source_type: str = "auto", 
        profile_name: Optional[str] = None
    ) -> LogData:
        """
        Load and process data from source using new architecture.
        
        Args:
            source: Path to data source (directory, device, etc.)
            source_type: Type of source ("auto", "bugreport", "adb", "hybrid")
            profile_name: Collection profile to use ("quick", "standard", "forensic", etc.)
            
        Returns:
            Clean LogData domain model
        """
        try:
            self.logger.info(f"Starting data loading from: {source}")
            
            # Apply collection profile if specified
            if profile_name:
                profile = CollectionProfiles.get_profile(profile_name)
                # Preserve existing output_directory configuration when applying profile
                current_output_dir = self.collection_config.output_directory
                self.collection_config = profile.config
                if current_output_dir:
                    self.collection_config.output_directory = current_output_dir
                    self.logger.info(f"Preserved output directory: {current_output_dir}")
                self.logger.info(f"Using collection profile: {profile_name}")
            
            # Step 1: Detect source type if auto
            if source_type == "auto":
                source_type = self._detect_source_type(source)
                self.logger.info(f"Detected source type: {source_type}")
            
            # Step 2: Collect raw data
            collection_result = self._collect_data(source, source_type)
            
            # Step 3: Parse collected data
            parsed_entries = self._parse_collected_data(collection_result)
            
            # Step 4: Enrich parsed data
            enrichment_result = self.enricher.enrich(parsed_entries)
            enriched_entries = enrichment_result.enriched_entries
            
            # Step 5: Validate enriched data
            validation_result = self.validator.validate(enriched_entries)
            
            # Step 6: Analyze coverage
            # Pass collection directory for file-based coverage analysis
            collection_directory = None
            if hasattr(collection_result, 'metadata') and 'source_directory' in collection_result.metadata:
                collection_directory = collection_result.metadata['source_directory']
            
            coverage_report = self.coverage_analyzer.analyze(enriched_entries, collection_directory)
            
            # Step 7: Create clean LogData model
            log_data = self._create_log_data_model(
                enriched_entries, 
                collection_result, 
                validation_result,
                coverage_report
            )
            
            self.logger.info(f"Successfully loaded {log_data.get_line_count()} entries "
                           f"from {log_data.get_package_count()} packages")
            
            return log_data
            
        except Exception as e:
            self.logger.error(f"Failed to load data from {source}: {e}")
            raise
    
    def _load_raw_file_content(self, collection_result):
        """Load raw file content from all sources."""
        raw_lines = []
        
        for source in collection_result.sources:
            try:
                if source.path.is_file():
                    with open(source.path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_lines = f.readlines()
                        raw_lines.extend(file_lines)
                        self.logger.debug(f"Loaded {len(file_lines)} lines from {source.path.name}")
            except Exception as e:
                self.logger.warning(f"Failed to load raw content from {source.path}: {e}")
                continue
        
        return raw_lines
    
    def load_data_with_profile(self, source: str, profile_name: str) -> LogData:
        """
        Convenience method to load data with a specific collection profile.
        
        Args:
            source: Data source path or device
            profile_name: Name of collection profile to use
            
        Returns:
            Processed LogData
        """
        return self.load_data(source, source_type="auto", profile_name=profile_name)
    
    def get_available_profiles(self) -> Dict[str, str]:
        """Get available collection profiles with descriptions."""
        profiles = CollectionProfiles.get_all_profiles()
        return {name: profile.description for name, profile in profiles.items()}
    
    def _detect_source_type(self, source: str) -> str:
        """Detect the optimal collection/parsing strategy for source."""

        # Check if source is a directory first (prioritize existing directories)
        try:
            if Path(source).is_dir():
                # For existing directories, bypass collectors and parse directly
                return "directory"
        except (OSError, ValueError):
            # Path is invalid or inaccessible
            pass

        # Check if source looks like a device identifier (contains : or is IP address)
        # But only if it's not a valid directory path
        if ':' in source or source.replace('.', '').isdigit():
            # This looks like a device identifier (IP:port or device ID)
            return "hybrid"

        # Default to hybrid collector for comprehensive data
        return "hybrid"
    
    def _collect_data(self, source: str, source_type: str):
        """Collect data using appropriate collector or direct file processing."""
        
        # Handle directory source type with direct file processing (no collection needed)
        if source_type == "directory":
            self.logger.info(f"Processing directory directly: {source}")
            return self._process_directory_directly(source)
        
        # Get collector based on source type or auto-select for non-directory sources
        if source_type == "auto":
            collector = self.collector_registry.get_collector_for_target(source, self.collection_config)
        else:
            collector = self.collector_registry.get_collector(source_type, self.collection_config)
        
        self.logger.info(f"Using collector: {collector.collector_type}")
        
        # Execute collection
        collection_result = collector.collect(source)
        
        # Log collection summary
        self.logger.info(f"Collection completed: {len(collection_result.sources)} sources, "
                        f"{collection_result.get_total_size_mb():.1f} MB")
        
        if collection_result.errors:
            self.logger.warning(f"Collection had {len(collection_result.errors)} errors")
        
        return collection_result
    
    def _process_directory_directly(self, directory_path: str):
        """
        Process existing files in a directory directly without collection.
        Creates a mock CollectionResult from existing files.
        """
        from .collectors.base_collector import CollectionResult, DataSource
        from pathlib import Path
        import os
        
        directory = Path(directory_path)
        sources = []
        total_size = 0
        
        # Files to exclude from processing (analysis results, metadata, etc.)
        excluded_files = {
            'risk_assessment.json',
            'metadata.json',
            'collection_info.json',
            'analysis_log_info.json'
        }

        # File extensions to exclude
        excluded_extensions = {'.log'}  # Analysis log files

        # Find all log files in the directory and subdirectories
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                try:
                    # Skip excluded files
                    if file_path.name in excluded_files:
                        self.logger.debug(f"Skipping excluded file: {file_path.name}")
                        continue

                    # Skip excluded extensions
                    if file_path.suffix.lower() in excluded_extensions:
                        self.logger.debug(f"Skipping excluded extension: {file_path.name}")
                        continue

                    file_size = file_path.stat().st_size
                    total_size += file_size

                    # Create DataSource for each file
                    data_source = DataSource(
                        type="file",
                        path=file_path,
                        size_bytes=file_size,
                        metadata={'original_path': str(file_path), 'filename': file_path.name}
                    )
                    sources.append(data_source)

                except Exception as e:
                    self.logger.warning(f"Error processing file {file_path}: {e}")
                    continue
        
        self.logger.info(f"Found {len(sources)} files in directory, total size: {total_size/1024/1024:.1f} MB")
        
        # Create mock CollectionResult
        collection_result = CollectionResult(
            sources=sources,
            errors=[],
            metadata={'source_directory': str(directory), 'total_files': len(sources)}
        )
        
        return collection_result
    
    def _parse_collected_data(self, collection_result):
        """Parse collected data sources into structured entries."""
        all_entries = []
        parsing_stats = {'parsed_files': 0, 'total_entries': 0, 'errors': 0, 'no_parser': 0}
        unparsed_files = []

        self.logger.info(f"Starting to parse {len(collection_result.sources)} discovered files")

        for source in collection_result.sources:
            try:
                self.logger.debug(f"Parsing {source.path.name} (path: {source.path})...")

                # Get parser for this source
                parser = self.parser_registry.get_parser_for_file(source.path)
                if not parser:
                    self.logger.warning(f"No suitable parser found for {source.path.name} (full path: {source.path})")
                    parsing_stats['no_parser'] += 1
                    unparsed_files.append(str(source.path))

                    # CRITICAL: Don't skip files without parsers - add them as raw content
                    # This ensures tombstone files and other critical data isn't lost
                    try:
                        with open(source.path, 'r', encoding='utf-8', errors='ignore') as f:
                            raw_content = f.read()

                        # Create a basic parsed entry for unparsed files
                        from ward_core.infrastructure.parsers.base_parser import ParsedLogEntry
                        raw_entry = ParsedLogEntry(
                            entry_type='raw_file',
                            source_file=str(source.path),
                            line_number=1,
                            raw_line=raw_content,
                            parsed_content={
                                'file_type': 'unparsed',
                                'filename': source.path.name,
                                'full_path': str(source.path),
                                'content': raw_content
                            },
                            tags={'unparsed', 'raw_file'},
                            confidence=0.5
                        )
                        all_entries.append(raw_entry)
                        self.logger.info(f"Added unparsed file as raw content: {source.path.name}")

                    except Exception as read_error:
                        self.logger.error(f"Failed to read unparsed file {source.path.name}: {read_error}")
                        parsing_stats['errors'] += 1

                    continue

                # Parse file with parser
                entries = list(parser.parse_file(source.path))
                all_entries.extend(entries)

                parsing_stats['parsed_files'] += 1
                parsing_stats['total_entries'] += len(entries)

                self.logger.debug(f"✓ Parsed {len(entries)} entries from {source.path.name} using {parser.__class__.__name__}")

            except Exception as e:
                self.logger.error(f"Failed to parse {source.path.name}: {e}")
                parsing_stats['errors'] += 1
        
        # Log comprehensive parsing summary
        self.logger.info(f"Parsing completed: {parsing_stats['parsed_files']} files parsed with parsers, "
                        f"{parsing_stats['no_parser']} files added as raw content, "
                        f"{parsing_stats['total_entries']} total entries, {parsing_stats['errors']} errors")

        if unparsed_files:
            self.logger.warning(f"Files without parsers (added as raw content): {unparsed_files[:10]}{'...' if len(unparsed_files) > 10 else ''}")

        return all_entries
    
    def _create_log_data_model(
        self, 
        entries, 
        collection_result, 
        validation_result,
        coverage_report
    ) -> LogData:
        """Create LogData domain model from processed entries."""
        
        # Extract device information
        device_info = self._extract_device_info(collection_result, entries)
        
        # Extract package information
        packages = self._extract_package_info(entries)
        
        # Create LogData model
        # Load actual file content as raw lines, not just parsed lines
        raw_lines = self._load_raw_file_content(collection_result)
        
        log_data = LogData(
            raw_lines=raw_lines,
            packages=packages,
            device_info=device_info,
            parsed_events=[entry.__dict__ for entry in entries],  # Store parsed events
            missing_sections=coverage_report.get_missing_critical_sources(),
            timestamp=datetime.now()
        )
        
        # Add processing metadata
        log_data.metadata = {
            'processing_info': {
                'total_entries': len(entries),
                'validation_score': validation_result.validation_score,
                'coverage_score': coverage_report.overall_score,
                'collection_type': collection_result.metadata.get('collector_type', 'unknown'),
                'processing_time': datetime.now().isoformat()
            },
            'collection_metadata': collection_result.metadata,
            'validation_summary': validation_result.get_summary(),
            'coverage_summary': coverage_report.get_summary()
        }
        
        return log_data
    
    def _extract_device_info(self, collection_result, entries) -> DeviceInfo:
        """Extract device information from collection result and entries."""
        
        # Start with collection metadata
        metadata = collection_result.metadata
        
        device_info = DeviceInfo(
            device_id=metadata.get('device_id', 'Unknown'),
            device_model=metadata.get('device_model', 'Unknown'),
            android_version=metadata.get('android_version', 'Unknown'),
            build_fingerprint=metadata.get('build_fingerprint', 'Unknown')
        )
        
        # Try to extract additional info from parsed entries
        for entry in entries:
            if entry.entry_type == 'device_info':
                content = entry.parsed_content
                if 'device_model' in content and device_info.device_model == 'Unknown':
                    device_info.device_model = content['device_model']
                if 'android_version' in content and device_info.android_version == 'Unknown':
                    device_info.android_version = content['android_version']
        
        return device_info
    
    def _extract_package_info(self, entries) -> Dict[str, PackageInfo]:
        """Extract package information from parsed entries."""
        packages = {}
        
        # Group entries by package
        package_entries = {}
        for entry in entries:
            if entry.package:
                if entry.package not in package_entries:
                    package_entries[entry.package] = []
                package_entries[entry.package].append(entry)
        
        # Create PackageInfo objects
        for package_name, package_entry_list in package_entries.items():
            
            # Skip invalid package names
            clean_package_name = package_name.strip()
            if not clean_package_name:
                self.logger.warning(f"Skipping empty package name")
                continue
            
            # Log problematic package names for debugging
            if len(clean_package_name) == 1 or not clean_package_name.replace('.', '').replace('_', '').replace('-', '').replace('@', '').replace(':', '').isalnum():
                self.logger.debug(f"Processing potentially problematic package name: '{clean_package_name}'")
            
            # Extract package details from entries
            permissions = set()
            installer = None
            uid = None
            
            for entry in package_entry_list:
                if entry.entry_type == 'permission' and entry.parsed_content:
                    if 'permissions' in entry.parsed_content:
                        perms = entry.parsed_content['permissions']
                        if isinstance(perms, list):
                            permissions.update(perms)
                        elif isinstance(perms, str):
                            permissions.add(perms)
                
                elif entry.entry_type == 'package_info' and entry.parsed_content:
                    if 'installer' in entry.parsed_content:
                        installer = entry.parsed_content['installer']
                    if 'uid' in entry.parsed_content:
                        uid = entry.parsed_content['uid']
            
            try:
                packages[clean_package_name] = PackageInfo(
                    name=clean_package_name,
                    permissions=permissions,
                    installer=installer,
                    uid=uid
                )
            except ValueError as e:
                self.logger.warning(f"Failed to create PackageInfo for '{clean_package_name}': {e}")
                # Skip this package instead of failing the entire process
                continue
        
        return packages
    
    def _register_collectors(self):
        """Register all available collectors."""
        try:
            # Import and register collectors
            from .collectors import AdbShellCollector, BugreportCollector, HybridCollector
            
            self.collector_registry.register(AdbShellCollector)
            self.collector_registry.register(BugreportCollector) 
            self.collector_registry.register(HybridCollector)
            
            self.logger.info("Registered data collectors")
            
        except Exception as e:
            self.logger.error(f"Failed to register collectors: {e}")
    
    def _register_specialized_parsers(self):
        """Register all specialized parsers."""
        try:
            # Import and register specialized parsers
            from .parsers.specialized import (
                PackageParser, AppOpsParser, AccessibilityParser,
                NetworkStatsParser, BatteryStatsParser, LogcatParser,
                SystemPropertiesParser, DumpsysGenericParser,
                # New parsers for complete forensic coverage
                SimpleTextParser, PackageListParser, ProcessListParser,
                NetworkConnectionParser, DmesgParser, BinderParser,
                SensorServiceParser, NetworkPolicyParser, ActivityServicesParser,
                FallbackParser,
                # Crash analysis parsers
                TombstoneParser, ANRTraceParser, DropBoxParser
            )
            
            # Import new forensic parsers
            from .parsers import ProcessParser, DexParser, UserParser
            
            # Import and register context-aware heuristics
            from ward_core.heuristics.context.installation_context import InstallationContextHeuristic
            
            parsers = [
                PackageParser, AppOpsParser, AccessibilityParser,
                NetworkStatsParser, BatteryStatsParser, LogcatParser,
                SystemPropertiesParser, DumpsysGenericParser,
                # New parsers for complete forensic coverage
                SimpleTextParser, PackageListParser, ProcessListParser,
                NetworkConnectionParser, DmesgParser, BinderParser,
                SensorServiceParser, NetworkPolicyParser, ActivityServicesParser,
                FallbackParser,
                # Crash analysis parsers
                TombstoneParser, ANRTraceParser, DropBoxParser,
                # New forensic parsers
                ProcessParser, DexParser, UserParser
            ]
            
            # Register context-aware heuristics
            context_heuristics = [
                InstallationContextHeuristic
            ]
            
            for parser_class in parsers:
                self.parser_registry.register(parser_class)
            
            self.logger.info(f"Registered {len(parsers)} specialized parsers")
            
            # Register context-aware heuristics
            for heuristic_class in context_heuristics:
                # Note: Context heuristics are registered with the analysis service, not parser registry
                self.logger.debug(f"Context heuristic available: {heuristic_class.__name__}")
            
            self.logger.info(f"Registered {len(context_heuristics)} context-aware heuristics")
            
        except Exception as e:
            self.logger.debug(f"Failed to register specialized parsers: {e}")
    
    def get_collection_statistics(self) -> Dict[str, Any]:
        """Get statistics about available collectors and parsers."""
        return {
            'available_collectors': self.collector_registry.get_available_collectors(),
            'available_parsers': len(self.parser_registry.get_available_parsers()),
            'collection_profiles': list(CollectionProfiles.get_all_profiles().keys())
        }


# Compatibility function to maintain interface with existing code
def load_collected_logs(log_dir: str, profile: str = "standard") -> Dict[str, Any]:
    """
    Legacy compatibility function for existing code.
    
    Args:
        log_dir: Directory containing logs
        profile: Collection profile to use
        
    Returns:
        Dictionary compatible with old data format
    """
    try:
        # Create data loader with profile
        data_loader = DataLoaderService()
        log_data = data_loader.load_data_with_profile(log_dir, profile)
        
        # Convert to legacy format for compatibility
        return {
            "parsed": [],  # Would need conversion from LogData format
            "raw_lines": log_data.raw_lines,
            "log_dir": log_dir,
            "data_format": "refactored",
            "timestamp": log_data.timestamp.isoformat() if log_data.timestamp else None,
            "device_id": log_data.device_info.device_id,
            "device_model": log_data.device_info.device_model,
            "android_version": log_data.device_info.android_version,
            "build_fingerprint": log_data.device_info.build_fingerprint,
            "packages": {name: pkg.__dict__ for name, pkg in log_data.packages.items()},
            "missing_sections": log_data.missing_sections,
            "metadata": getattr(log_data, 'metadata', {})
        }
        
    except Exception as e:
        logging.error(f"Legacy load_collected_logs failed: {e}")
        # Return error-compatible structure
        return {
            "parsed": [],
            "raw_lines": [],
            "error": str(e),
            "log_dir": log_dir,
            "data_format": "error"
        }
