"""
Bug Report Collector for Android forensic analysis.

This collector generates and processes Android bug reports primarily to aquire Tombestone and other crash/memory data.
"""

import subprocess
import tempfile
import zipfile
import time
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime
import logging
import re

from .base_collector import BaseCollector, CollectionResult, DataSource, CollectionError


class BugreportCollector(BaseCollector):
    """
    Bug Report collector for comprehensive Android system analysis.
    
    This collector generates Android bug reports which contain extensive system
    information, logs, and diagnostics in a structured format.
    """
    
    # Known bug report sections and their importance for forensic analysis
    BUGREPORT_SECTIONS = {
        'critical': [
            'PACKAGE MANAGER',
            'APP OPS MANAGER',
            'ACCESSIBILITY MANAGER',
            'ACTIVITY MANAGER',
            'BATTERY HISTORY',
            'NETWORK STATS',
            # Memory and crash analysis - CRITICAL for exploitation detection
            'TOMBSTONES',
            'ANR TRACES',
            'NATIVE CRASH DUMPS',
            'MEMINFO',
            'PROCRANK',
            'SHOWMAP',
        ],
        'important': [
            'CONNECTIVITY MANAGER',
            'POWER MANAGER',
            'DEVICE IDLE CONTROLLER',
            'USAGE STATS',
            'ALARM MANAGER',
            'JOB SCHEDULER',
            'WINDOW MANAGER',
            'LOCATION MANAGER',
            # Memory exploitation indicators
            'KERNEL LOG',
            'SYSTEM LOG',
            'CRASH LOG',
            'DROPBOX ENTRIES',
            'MEMORY MAPS',
            'PROCESS MEMORY',
        ],
        'supplementary': [
            'SENSOR SERVICE',
            'BINDER STATS',
            'DEVICE POLICY MANAGER',
            'NOTIFICATION MANAGER',
            'CPUINFO',
            'VMSTAT',
            'SLABINFO',
            'BUDDYINFO',
            'PAGETYPEINFO',
        ]
    }
    
    # Files typically found in extracted bug reports
    EXPECTED_BUGREPORT_FILES = {
        'main.txt',           # Main bug report content
        'version.txt',        # Bug report version
        'system.txt',         # System logs
        'events.txt',         # Event logs
        'radio.txt',          # Radio logs (if available)
        'kernel.txt',         # Kernel logs
        'bugreport-*.txt',    # Timestamped bug report
        'dumpstate.txt',      # System state dump
        # Memory and crash analysis files - CRITICAL for exploitation detection
        'tombstone_*.txt',    # Native crash dumps
        'tombstone_*.pb',     # Protobuf tombstone files (Android 11+)
        'anr_*.txt',          # ANR traces
        'traces.txt',         # System traces
        'dropbox_*.txt',      # System dropbox entries
        'meminfo.txt',        # Memory information
        'procrank.txt',       # Process memory ranking
        'showmap_*.txt',      # Memory maps
        'vmstat.txt',         # Virtual memory statistics
        'slabinfo.txt',       # Kernel slab allocator info
        'buddyinfo.txt',      # Memory fragmentation info
        'pagetypeinfo.txt',   # Page type information
    }
    
    @property
    def collector_type(self) -> str:
        """Get collector type identifier."""
        return "bugreport"
    
    def can_collect_from(self, target: str) -> bool:
        """Check if we can collect bug report from target."""
        if Path(target).is_dir():
            # Check if directory contains existing bug report
            return self._is_bugreport_directory(Path(target))
        else:
            # Check if we can generate bug report from device
            try:
                if not target or target == "auto":
                    result = subprocess.run(['adb', 'devices'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        devices = self._parse_adb_devices(result.stdout)
                        return len(devices) > 0
                else:
                    result = subprocess.run(['adb', '-s', target, 'get-state'], 
                                          capture_output=True, text=True, timeout=10)
                    return result.returncode == 0 and result.stdout.strip() == 'device'
                    
            except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                return False
    
    def collect(self, target: str) -> CollectionResult:
        """
        Collect bug report data from target.
        
        Args:
            target: Device ID or path to existing bug report directory
            
        Returns:
            Collection result with bug report data
        """
        self.logger.info(f"Starting bug report collection from: {target}")
        
        result = CollectionResult(metadata={
            'collector_type': self.collector_type,
            'collection_start': datetime.now()
        })
        
        try:
            if Path(target).is_dir():
                # Process existing bug report directory
                result = self._collect_from_directory(Path(target))
            else:
                # Generate new bug report from device
                result = self._collect_from_device(target)
            
            result.metadata['collection_end'] = datetime.now()
            self.logger.info(f"Bug report collection completed: {len(result.sources)} sources")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Bug report collection failed: {e}")
            raise CollectionError(f"Bug report collection failed: {e}")
    
    def get_supported_sources(self) -> List[str]:
        """Get list of supported data source types."""
        return [
            'bugreport', 'system_logs', 'package_info', 'dumpsys_output',
            'battery_history', 'network_stats', 'activity_info',
            # Memory and crash analysis sources - CRITICAL for exploitation detection
            'tombstones', 'anr_traces', 'native_crashes', 'memory_info',
            'memory_maps', 'kernel_logs', 'crash_logs', 'dropbox_entries',
            'process_memory', 'memory_stats', 'kernel_memory'
        ]
    
    def _collect_from_directory(self, directory: Path) -> CollectionResult:
        """Collect from existing bug report directory."""
        self.logger.info(f"Processing existing bug report in: {directory}")
        
        result = CollectionResult(metadata={
            'source_type': 'existing_directory',
            'source_path': str(directory)
        })
        
        # Look for bug report files
        bugreport_files = self._find_bugreport_files(directory)
        
        for file_path in bugreport_files:
            try:
                source = DataSource(
                    type='bugreport_file',
                    path=file_path,
                    metadata={
                        'file_type': self._classify_bugreport_file(file_path),
                        'source': 'existing_file'
                    }
                )
                result.sources.append(source)
                
            except Exception as e:
                error_msg = f"Error processing {file_path.name}: {e}"
                result.errors.append(error_msg)
                self.logger.error(error_msg)
        
        # Check for extracted directory
        extracted_dir = directory / 'extracted'
        if extracted_dir.exists():
            self.logger.info("Processing extracted bug report content")
            extracted_sources = self._process_extracted_content(extracted_dir)
            result.sources.extend(extracted_sources)
        
        # Validate completeness
        self._validate_bugreport_completeness(result, directory)
        
        return result
    
    def _collect_from_device(self, device_id: str) -> CollectionResult:
        """Generate and collect bug report from device."""
        device_id = self._resolve_device_id(device_id)
        if not device_id:
            raise CollectionError(f"No accessible device found: {device_id}")
        
        self.logger.info(f"Generating bug report from device: {device_id}")
        
        # Use configured output directory or create temporary one
        if self.config.output_directory:
            output_dir = self.config.output_directory / "raw_data" 
            output_dir.mkdir(parents=True, exist_ok=True)
            temp_dir = output_dir
            self.logger.info(f"Using permanent output directory: {output_dir}")
        else:
            temp_dir = Path(tempfile.mkdtemp(prefix="barghest_bugreport_"))
            self.logger.info(f"Using temporary directory: {temp_dir}")
        
        result = CollectionResult(metadata={
            'device_id': device_id,
            'source_type': 'generated',
            'temp_directory': str(temp_dir)
        })
        
        try:
            # Generate bug report
            bugreport_path = self._generate_bugreport(device_id, temp_dir)
            
            if bugreport_path and bugreport_path.exists():
                # Add the bug report as a source
                source = DataSource(
                    type='bugreport_archive',
                    path=bugreport_path,
                    metadata={
                        'generated': True,
                        'device_id': device_id,
                        'is_temporary': True
                    }
                )
                result.sources.append(source)
                
                # Extract if it's a zip file
                if bugreport_path.suffix.lower() == '.zip':
                    extracted_sources = self._extract_bugreport_archive(bugreport_path, temp_dir)
                    result.sources.extend(extracted_sources)
            
            return result
            
        except Exception as e:
            # Cleanup on failure (only if using temp directory)
            if not self.config.preserve_temp_files and not self.config.output_directory:
                shutil.rmtree(temp_dir, ignore_errors=True)
            raise
    
    def _generate_bugreport(self, device_id: str, output_dir: Path) -> Optional[Path]:
        """Generate bug report from device."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"bugreport_{device_id}_{timestamp}.zip"
        
        # Prepare bug report command
        cmd = ['adb', '-s', device_id, 'bugreport', str(output_file)]
        
        self.logger.info("Generating bug report (this may take several minutes)...")
        start_time = time.time()
        
        try:
            # Execute bug report generation with extended timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.bugreport_timeout_seconds,
                cwd=str(output_dir)
            )
            
            execution_time = time.time() - start_time
            self.logger.info(f"Bug report generation completed in {execution_time:.1f}s")
            
            if result.returncode != 0:
                error_msg = f"Bug report generation failed: {result.stderr}"
                self.logger.error(error_msg)
                raise CollectionError(error_msg)
            
            if output_file.exists():
                self.logger.info(f"Bug report generated: {output_file} ({output_file.stat().st_size / (1024*1024):.1f} MB)")
                return output_file
            else:
                # Some Android versions create different filename formats
                possible_files = list(output_dir.glob("bugreport*.zip")) + list(output_dir.glob("bugreport*.txt"))
                if possible_files:
                    return possible_files[0]
                
                raise CollectionError("Bug report file was not created")
                
        except subprocess.TimeoutExpired:
            error_msg = f"Bug report generation timed out after {self.config.bugreport_timeout_seconds}s"
            self.logger.error(error_msg)
            raise CollectionError(error_msg)
    
    def _extract_bugreport_archive(self, archive_path: Path, extract_dir: Path) -> List[DataSource]:
        """Extract bug report archive and return sources."""
        self.logger.info(f"Extracting bug report archive: {archive_path.name}")
        
        extraction_dir = extract_dir / 'extracted'
        extraction_dir.mkdir(exist_ok=True)
        
        sources = []
        
        try:
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                # Extract all files
                zip_ref.extractall(extraction_dir)
                
                # Create sources for extracted files
                for extracted_file in extraction_dir.rglob('*'):
                    if extracted_file.is_file():
                        source = DataSource(
                            type='bugreport_extracted',
                            path=extracted_file,
                            metadata={
                                'extracted_from': archive_path.name,
                                'file_type': self._classify_bugreport_file(extracted_file),
                                'is_temporary': True
                            }
                        )
                        sources.append(source)
                
                self.logger.info(f"Extracted {len(sources)} files from bug report archive")
                
        except zipfile.BadZipFile as e:
            self.logger.error(f"Invalid zip archive: {e}")
            # Try to treat as text file
            if archive_path.suffix == '.zip':
                # Sometimes ADB creates .zip files that are actually text
                text_source = DataSource(
                    type='bugreport_text',
                    path=archive_path,
                    metadata={
                        'extracted_from': 'direct',
                        'file_type': 'main_report',
                        'is_temporary': True
                    }
                )
                sources.append(text_source)
        
        return sources
    
    def _find_bugreport_files(self, directory: Path) -> List[Path]:
        """Find bug report files in directory."""
        bugreport_files = []
        
        # Look for common bug report file patterns including memory/crash data
        patterns = [
            'bugreport*.txt',
            'bugreport*.zip',
            'main.txt',
            'version.txt',
            'system.txt',
            'events.txt',
            'radio.txt',
            'kernel.txt',
            'dumpstate.txt',
            # Memory and crash analysis files - CRITICAL for exploitation detection
            'tombstone*',        # Android tombstone files often have no extension
            'tombstone*.txt',    # Some may have .txt extension
            'tombstone*.pb',     # Protobuf tombstone files (Android 11+)
            'anr*.txt',
            'traces.txt',
            'dropbox*.txt',
            'meminfo*.txt',
            'procrank*.txt',
            'showmap*.txt',
            'vmstat*.txt',
            'slabinfo*.txt'
        ]
        
        for pattern in patterns:
            bugreport_files.extend(directory.glob(pattern))
        
        # Also check subdirectories for extracted content
        for subdir in directory.iterdir():
            if subdir.is_dir() and subdir.name in ['extracted', 'FS']:
                for pattern in patterns:
                    bugreport_files.extend(subdir.glob(pattern))

                # Look for system files in extracted content
                bugreport_files.extend(subdir.glob('**/build.prop'))
                bugreport_files.extend(subdir.glob('**/packages.xml'))

                # Look for memory and crash files in extracted content - CRITICAL
                # Android tombstone files are typically in /data/tombstones/ without extensions
                bugreport_files.extend(subdir.glob('**/tombstones/tombstone*'))
                bugreport_files.extend(subdir.glob('**/tombstone*'))
                bugreport_files.extend(subdir.glob('**/anr/*'))
                bugreport_files.extend(subdir.glob('**/dropbox/*'))
                bugreport_files.extend(subdir.glob('**/proc/meminfo'))
                bugreport_files.extend(subdir.glob('**/proc/vmstat'))
                bugreport_files.extend(subdir.glob('**/proc/*/maps'))
                bugreport_files.extend(subdir.glob('**/proc/*/smaps'))
        
        return sorted(set(bugreport_files))
    
    def _process_extracted_content(self, extracted_dir: Path) -> List[DataSource]:
        """Process extracted bug report content including memory and crash data."""
        sources = []

        # Process system files
        system_files = [
            'system/build.prop',
            'data/system/packages.xml',
            'data/system/appops.xml',
            'data/system/device_policies.xml'
        ]

        for sys_file in system_files:
            file_path = extracted_dir / sys_file
            if file_path.exists():
                source = DataSource(
                    type='system_file',
                    path=file_path,
                    metadata={
                        'file_type': sys_file.split('/')[-1],
                        'source_path': sys_file
                    }
                )
                sources.append(source)

        # Process memory and crash data - CRITICAL for exploitation detection
        memory_crash_files = [
            # Tombstone files (native crashes)
            'data/tombstones/tombstone_*.txt',
            'data/tombstones/tombstone_*',
            'data/tombstones/tombstone_*.pb',
            # ANR traces
            'data/anr/traces.txt',
            'data/anr/anr_*.txt',
            'data/anr/anr_*',
            # System crash logs
            'data/system/dropbox/*',
            # Memory information
            'proc/meminfo',
            'proc/vmstat',
            'proc/slabinfo',
            'proc/buddyinfo',
            'proc/pagetypeinfo',
            # Process memory maps
            'proc/*/maps',
            'proc/*/smaps',
            'proc/*/status',
        ]

        for pattern in memory_crash_files:
            if '*' in pattern:
                # Handle glob patterns
                for file_path in extracted_dir.glob(pattern):
                    if file_path.is_file():
                        source = DataSource(
                            type=self._classify_memory_crash_file(file_path),
                            path=file_path,
                            metadata={
                                'file_type': self._get_memory_crash_type(file_path),
                                'source_path': str(file_path.relative_to(extracted_dir)),
                                'is_memory_related': True
                            }
                        )
                        sources.append(source)
            else:
                # Handle direct file paths
                file_path = extracted_dir / pattern
                if file_path.exists():
                    source = DataSource(
                        type=self._classify_memory_crash_file(file_path),
                        path=file_path,
                        metadata={
                            'file_type': self._get_memory_crash_type(file_path),
                            'source_path': pattern,
                            'is_memory_related': True
                        }
                    )
                    sources.append(source)

        return sources

    def _classify_memory_crash_file(self, file_path: Path) -> str:
        """Classify memory and crash related files."""
        """TODO: Crosscheck against different OEMs"""
        name_lower = file_path.name.lower()
        path_str = str(file_path).lower()

        if 'tombstone' in name_lower:
            return 'tombstone'
        elif 'anr' in name_lower or 'traces.txt' in name_lower:
            return 'anr_trace'
        elif 'dropbox' in path_str:
            return 'dropbox_entry'
        elif 'meminfo' in name_lower:
            return 'memory_info'
        elif 'vmstat' in name_lower:
            return 'memory_stats'
        elif 'slabinfo' in name_lower:
            return 'kernel_memory'
        elif 'maps' in name_lower or 'smaps' in name_lower:
            return 'memory_map'
        elif 'buddyinfo' in name_lower or 'pagetypeinfo' in name_lower:
            return 'memory_fragmentation'
        elif '/proc/' in path_str:
            return 'process_info'
        else:
            return 'memory_related'

    def _get_memory_crash_type(self, file_path: Path) -> str:
        """Get specific type for memory/crash files."""
        name_lower = file_path.name.lower()
        path_str = str(file_path).lower()

        if 'tombstone' in name_lower:
            if name_lower.endswith('.pb'):
                return 'tombstone_protobuf'
            else:
                return 'tombstone_text'
        elif 'anr' in name_lower:
            return 'anr_trace'
        elif 'traces.txt' in name_lower:
            return 'system_traces'
        elif 'dropbox' in path_str:
            return 'system_dropbox'
        elif 'meminfo' in name_lower:
            return 'memory_information'
        elif 'vmstat' in name_lower:
            return 'virtual_memory_stats'
        elif 'slabinfo' in name_lower:
            return 'kernel_slab_info'
        elif 'maps' in name_lower:
            return 'process_memory_map'
        elif 'smaps' in name_lower:
            return 'process_memory_detailed'
        elif 'buddyinfo' in name_lower:
            return 'memory_buddy_info'
        elif 'pagetypeinfo' in name_lower:
            return 'memory_page_info'
        else:
            return 'memory_other'

    def _classify_bugreport_file(self, file_path: Path) -> str:
        """Classify bug report file type including memory and crash files."""
        name_lower = file_path.name.lower()
        path_str = str(file_path).lower()

        # Memory and crash files - CRITICAL for exploitation detection
        if 'tombstone' in name_lower:
            return 'tombstone'
        elif 'anr' in name_lower or 'traces.txt' in name_lower:
            return 'anr_trace'
        elif 'dropbox' in path_str:
            return 'dropbox_entry'
        elif 'meminfo' in name_lower:
            return 'memory_info'
        elif 'vmstat' in name_lower or 'slabinfo' in name_lower:
            return 'memory_stats'
        elif 'maps' in name_lower or 'smaps' in name_lower:
            return 'memory_map'
        # Standard bugreport files
        elif 'main' in name_lower or 'bugreport' in name_lower:
            return 'main_report'
        elif 'system' in name_lower:
            return 'system_logs'
        elif 'event' in name_lower:
            return 'event_logs'
        elif 'kernel' in name_lower or 'dmesg' in name_lower:
            return 'kernel_logs'
        elif 'radio' in name_lower:
            return 'radio_logs'
        elif 'version' in name_lower:
            return 'version_info'
        elif 'build.prop' in name_lower:
            return 'build_properties'
        elif 'packages.xml' in name_lower:
            return 'package_manifest'
        else:
            return 'other'
    
    def _validate_bugreport_completeness(self, result: CollectionResult, source_dir: Path):
        """Validate bug report completeness."""
        found_types = set()
        for source in result.sources:
            file_type = source.metadata.get('file_type', 'unknown')
            found_types.add(file_type)
        
        # Check for critical missing components
        critical_missing = []
        if 'main_report' not in found_types:
            critical_missing.append('main bug report')
        if 'system_logs' not in found_types:
            critical_missing.append('system logs')
        if 'package_manifest' not in found_types and 'build_properties' not in found_types:
            critical_missing.append('system configuration')

        # Check for memory and crash analysis components - CRITICAL for exploitation detection
        memory_crash_missing = []
        if 'tombstone' not in found_types:
            memory_crash_missing.append('tombstone files (native crashes)')
        if 'anr_trace' not in found_types:
            memory_crash_missing.append('ANR traces')
        if 'memory_info' not in found_types:
            memory_crash_missing.append('memory information')
        if 'dropbox_entry' not in found_types:
            memory_crash_missing.append('system dropbox entries')

        if memory_crash_missing:
            warning = f"Memory/crash analysis data missing: {', '.join(memory_crash_missing)}"
            result.warnings.append(warning)
            self.logger.warning(warning)
        
        if critical_missing:
            warning = f"Bug report may be incomplete. Missing: {', '.join(critical_missing)}"
            result.warnings.append(warning)
            self.logger.warning(warning)
        
        # Add completeness metrics
        expected_files = len(self.EXPECTED_BUGREPORT_FILES)
        found_files = len([s for s in result.sources if s.type in ['bugreport_file', 'bugreport_extracted']])
        completeness_ratio = min(1.0, found_files / expected_files)
        
        result.metadata['completeness'] = {
            'expected_files': expected_files,
            'found_files': found_files,
            'completeness_ratio': completeness_ratio,
            'missing_critical': critical_missing
        }
    
    def _is_bugreport_directory(self, directory: Path) -> bool:
        """Check if directory contains a bug report."""
        if not directory.is_dir():
            return False
        
        # Look for bug report indicators
        bugreport_indicators = [
            'bugreport*.txt',
            'bugreport*.zip',
            'main.txt',
            'version.txt'
        ]
        
        for pattern in bugreport_indicators:
            if list(directory.glob(pattern)):
                return True
        
        # Check for extracted directory
        extracted_dir = directory / 'extracted'
        if extracted_dir.exists() and extracted_dir.is_dir():
            return True
        
        return False
    
    def _resolve_device_id(self, target: str) -> Optional[str]:
        """Resolve target to device ID for bug report generation."""
        try:
            if not target or target == "auto":
                # Get first available device
                result = subprocess.run(['adb', 'devices'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    devices = self._parse_adb_devices(result.stdout)
                    return devices[0] if devices else None
            else:
                # Validate specific device
                result = subprocess.run(['adb', '-s', target, 'get-state'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip() == 'device':
                    return target
                
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        
        return None
    
    def _parse_adb_devices(self, devices_output: str) -> List[str]:
        """Parse ADB devices command output."""
        devices = []
        for line in devices_output.split('\n'):
            line = line.strip()
            if line and '\tdevice' in line:
                device_id = line.split('\t')[0]
                devices.append(device_id)
        return devices
