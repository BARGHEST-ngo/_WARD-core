"""
Hybrid Collector for comprehensive Android forensic data collection.

This collector combines ADB shell commands with bug report generation to ensure
complete coverage of all forensic data sources including tombstone files,
dropbox data, and other critical artifacts.
"""

import subprocess
import tempfile
import time
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
import logging
import zipfile

from .base_collector import BaseCollector, CollectionResult, DataSource, CollectionError
from .adb_shell_collector import AdbShellCollector
from .bugreport_collector import BugreportCollector


class HybridCollector(BaseCollector):
    """
    Hybrid collector that combines ADB shell commands and bug report generation.
    
    This collector ensures comprehensive data collection by:
    1. Generating a bug report for tombstone files, dropbox data, and other artifacts
    2. Executing targeted ADB shell commands for specific data points
    3. Merging both data sources before parsing
    """
    
    def __init__(self, config=None):
        super().__init__(config)
        self.adb_collector = AdbShellCollector(config)
        self.bugreport_collector = BugreportCollector(config)
        
        # Configuration for hybrid collection
        self.config.bugreport_timeout_seconds = getattr(self.config, 'bugreport_timeout_seconds', 300)  # 5 minutes
        self.config.enable_bugreport = getattr(self.config, 'enable_bugreport', True)
        self.config.enable_adb_shell = getattr(self.config, 'enable_adb_shell', True)
        self.config.merge_strategy = getattr(self.config, 'merge_strategy', 'prefer_adb')  # 'prefer_adb', 'prefer_bugreport', 'merge_all'
    
    @property
    def collector_type(self) -> str:
        """Get collector type identifier."""
        return "hybrid"
    
    def get_supported_sources(self) -> List[str]:
        """Get list of supported data source types."""
        return [
            'hybrid_merged', 'bugreport', 'adb_shell', 'system_logs', 
            'package_info', 'dumpsys_output', 'battery_history', 
            'network_stats', 'activity_info', 'tombstone', 'dropbox', 'anr'
        ]
    
    def can_collect_from(self, target: str) -> bool:
        """Check if we can collect from the target via hybrid method."""
        # Check if either collector can work
        adb_can_collect = self.adb_collector.can_collect_from(target)
        bugreport_can_collect = self.bugreport_collector.can_collect_from(target)
        
        return adb_can_collect or bugreport_can_collect
    
    def collect(self, target: str) -> CollectionResult:
        """
        Collect comprehensive data using hybrid approach.
        
        Args:
            target: Device ID or "auto" for first available device
            
        Returns:
            Collection result with merged data from both sources
        """
        self.logger.info(f"Starting hybrid collection from target: {target}")
        
        # Validate target device
        device_id = self._resolve_device_id(target)
        if not device_id:
            raise CollectionError(f"No accessible device found for target: {target}")
        
        # Use configured output directory or create temporary one
        if self.config.output_directory:
            output_dir = self.config.output_directory / "raw_data" 
            output_dir.mkdir(parents=True, exist_ok=True)
            temp_dir = output_dir
            self.logger.info(f"Using permanent output directory: {output_dir}")
        else:
            temp_dir = Path(tempfile.mkdtemp(prefix="barghest_hybrid_"))
            self.logger.info(f"Using temporary directory: {temp_dir}")
        
        result = CollectionResult(metadata={
            'device_id': device_id,
            'collector_type': self.collector_type,
            'collection_start': datetime.now(),
            'collection_methods': []
        })
        
        try:
            # Step 1: Generate bug report (if enabled)
            bugreport_sources = []
            if self.config.enable_bugreport:
                self.logger.info("Step 1: Generating bug report...")
                bugreport_sources = self._collect_bugreport(device_id, temp_dir)
                result.metadata['collection_methods'].append('bugreport')
                self.logger.info(f"Bug report collection completed: {len(bugreport_sources)} sources")
            
            # Step 2: Execute ADB shell commands (if enabled)
            adb_sources = []
            if self.config.enable_adb_shell:
                self.logger.info("Step 2: Executing ADB shell commands...")
                adb_sources = self._collect_adb_shell(device_id, temp_dir)
                result.metadata['collection_methods'].append('adb_shell')
                self.logger.info(f"ADB shell collection completed: {len(adb_sources)} sources")
            
            # Step 3: Merge data sources
            self.logger.info("Step 3: Merging data sources...")
            merged_sources = self._merge_data_sources(bugreport_sources, adb_sources, temp_dir)
            result.sources = merged_sources
            
            # Step 4: Validate collection completeness
            self._validate_collection_completeness(result, temp_dir)
            
            result.metadata['collection_end'] = datetime.now()
            result.metadata['total_sources'] = len(result.sources)
            result.metadata['bugreport_sources'] = len(bugreport_sources)
            result.metadata['adb_sources'] = len(adb_sources)
            
            self.logger.info(f"Hybrid collection completed: {len(result.sources)} total sources")
            return result
            
        except Exception as e:
            self.logger.error(f"Hybrid collection failed: {e}")
            # Clean up temporary directory
            if not self.config.output_directory and temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
            raise CollectionError(f"Hybrid collection failed: {e}")
    
    def _collect_bugreport(self, device_id: str, output_dir: Path) -> List[DataSource]:
        """Collect bug report data."""
        sources = []
        
        try:
            # Generate bug report
            bugreport_file = self._generate_bugreport(device_id, output_dir)
            if bugreport_file:
                # Extract bug report
                extracted_dir = output_dir / "bugreport_extracted"
                extracted_dir.mkdir(exist_ok=True)
                
                self._extract_bugreport(bugreport_file, extracted_dir)
                
                # Process extracted files
                for file_path in extracted_dir.rglob('*'):
                    if file_path.is_file():
                        source = DataSource(
                            type='bugreport_file',
                            path=file_path,
                            size_bytes=file_path.stat().st_size,
                            metadata={
                                'source': 'bugreport',
                                'original_bugreport': str(bugreport_file),
                                'file_type': self._classify_bugreport_file(file_path)
                            }
                        )
                        sources.append(source)
                
                # Clean up original bug report file to save space
                if bugreport_file.exists():
                    bugreport_file.unlink()
        
        except Exception as e:
            self.logger.error(f"Bug report collection failed: {e}")
            # Continue with ADB shell collection even if bug report fails
        
        return sources
    
    def _collect_adb_shell(self, device_id: str, output_dir: Path) -> List[DataSource]:
        """Collect ADB shell command data."""
        sources = []
        
        try:
            # Use the ADB shell collector's command execution logic
            for group_name, commands in self.adb_collector.ADB_COMMAND_GROUPS.items():
                if not self.config.get_command_group_enabled(group_name):
                    continue
                
                self.logger.debug(f"Executing {group_name} commands...")
                group_sources = self._execute_command_group(device_id, group_name, commands, output_dir)
                sources.extend(group_sources)
        
        except Exception as e:
            self.logger.error(f"ADB shell collection failed: {e}")
            # Continue with bug report collection even if ADB shell fails
        
        return sources
    
    def _merge_data_sources(self, bugreport_sources: List[DataSource], adb_sources: List[DataSource], output_dir: Path) -> List[DataSource]:
        """Merge data sources based on merge strategy."""
        merged_sources = []
        source_map = {}  # filename -> DataSource mapping
        
        # Process bug report sources first
        for source in bugreport_sources:
            filename = source.path.name
            source_map[filename] = source
            merged_sources.append(source)
        
        # Process ADB shell sources
        for source in adb_sources:
            filename = source.path.name
            
            if filename in source_map:
                # File exists in both sources - apply merge strategy
                existing_source = source_map[filename]
                merged_source = self._merge_duplicate_sources(existing_source, source)
                if merged_source:
                    # Replace existing source with merged one
                    merged_sources.remove(existing_source)
                    merged_sources.append(merged_source)
                    source_map[filename] = merged_source
            else:
                # New file from ADB shell
                source_map[filename] = source
                merged_sources.append(source)
        
        return merged_sources
    
    def _merge_duplicate_sources(self, bugreport_source: DataSource, adb_source: DataSource) -> Optional[DataSource]:
        """Merge duplicate sources based on merge strategy."""
        if self.config.merge_strategy == 'prefer_adb':
            # Prefer ADB shell version (usually more targeted and recent)
            adb_source.metadata['merged_from'] = ['bugreport', 'adb_shell']
            adb_source.metadata['merge_strategy'] = 'prefer_adb'
            return adb_source
        
        elif self.config.merge_strategy == 'prefer_bugreport':
            # Prefer bug report version (usually more comprehensive)
            bugreport_source.metadata['merged_from'] = ['bugreport', 'adb_shell']
            bugreport_source.metadata['merge_strategy'] = 'prefer_bugreport'
            return bugreport_source
        
        elif self.config.merge_strategy == 'merge_all':
            # Keep both sources with different names
            adb_source.path = adb_source.path.parent / f"{adb_source.path.stem}_adb{adb_source.path.suffix}"
            adb_source.metadata['merged_from'] = ['adb_shell']
            bugreport_source.metadata['merged_from'] = ['bugreport']
            return None  # Return None to keep both sources
        
        else:
            # Default: prefer ADB shell
            adb_source.metadata['merged_from'] = ['bugreport', 'adb_shell']
            adb_source.metadata['merge_strategy'] = 'prefer_adb'
            return adb_source
    
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
                cwd=str(output_dir),
                encoding='utf-8',
                errors='ignore'  # Handle encoding issues gracefully
            )
            
            execution_time = time.time() - start_time
            self.logger.info(f"Bug report generation completed in {execution_time:.1f}s")
            
            if result.returncode != 0:
                error_msg = f"Bug report generation failed: {result.stderr}"
                self.logger.error(error_msg)
                return None
            
            if output_file.exists():
                self.logger.info(f"Bug report generated: {output_file} ({output_file.stat().st_size / (1024*1024):.1f} MB)")
                return output_file
            else:
                # Some Android versions create different filename formats
                possible_files = list(output_dir.glob("bugreport*.zip")) + list(output_dir.glob("bugreport*.txt"))
                if possible_files:
                    return possible_files[0]
                
                self.logger.error("Bug report file was not created")
                return None
                
        except subprocess.TimeoutExpired:
            error_msg = f"Bug report generation timed out after {self.config.bugreport_timeout_seconds}s"
            self.logger.error(error_msg)
            return None
        except Exception as e:
            self.logger.error(f"Bug report generation failed: {e}")
            return None
    
    def _extract_bugreport(self, bugreport_file: Path, extract_dir: Path):
        """Extract bug report archive."""
        try:
            if bugreport_file.suffix.lower() == '.zip':
                with zipfile.ZipFile(bugreport_file, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                self.logger.info(f"Extracted bug report to: {extract_dir}")
            else:
                # If it's a text file, copy it directly
                shutil.copy2(bugreport_file, extract_dir / bugreport_file.name)
                self.logger.info(f"Copied bug report text file to: {extract_dir}")
        
        except Exception as e:
            self.logger.error(f"Failed to extract bug report: {e}")
            raise
    
    def _classify_bugreport_file(self, file_path: Path) -> str:
        """Classify bug report file type."""
        filename = file_path.name.lower()
        
        if 'tombstone' in filename:
            return 'tombstone'
        elif 'dropbox' in filename:
            return 'dropbox'
        elif 'anr' in filename:
            return 'anr'
        elif 'crash' in filename:
            return 'crash'
        elif 'logcat' in filename or 'main' in filename:
            return 'logcat'
        elif 'dumpsys' in filename:
            return 'dumpsys'
        elif 'battery' in filename:
            return 'battery'
        elif 'network' in filename:
            return 'network'
        elif 'package' in filename:
            return 'package'
        elif 'build.prop' in filename:
            return 'system_properties'
        else:
            return 'unknown'
    
    def _execute_command_group(self, device_id: str, group_name: str, commands: Dict[str, str], output_dir: Path) -> List[DataSource]:
        """Execute a group of ADB commands."""
        sources = []
        
        for command_name, command in commands.items():
            try:
                # Execute command
                result = subprocess.run(
                    ['adb', '-s', device_id, 'shell'] + command.split(),
                    capture_output=True,
                    text=True,
                    timeout=30,
                    encoding='utf-8',
                    errors='ignore'  # Handle encoding issues gracefully
                )
                
                if result.returncode == 0:
                    # Save output to file
                    output_file = output_dir / f"shell_{command_name}.txt"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(result.stdout)
                    
                    # Create data source
                    source = DataSource(
                        type='adb_shell',
                        path=output_file,
                        size_bytes=output_file.stat().st_size,
                        metadata={
                            'source': 'adb_shell',
                            'command_group': group_name,
                            'command_name': command_name,
                            'command': command
                        }
                    )
                    sources.append(source)
                    
                    self.logger.debug(f"✓ Executed {command_name}: {len(result.stdout)} chars")
                else:
                    self.logger.warning(f"Command {command_name} failed: {result.stderr}")
            
            except Exception as e:
                self.logger.error(f"Failed to execute {command_name}: {e}")
                continue
        
        return sources
    
    def _validate_collection_completeness(self, result: CollectionResult, output_dir: Path):
        """Validate that collection is complete."""
        # Check for critical files
        critical_files = [
            'shell_package.txt',
            'shell_logcat_main.txt',
            'shell_batterystats.txt'
        ]

        missing_critical = []
        for critical_file in critical_files:
            if not any(source.path.name == critical_file for source in result.sources):
                missing_critical.append(critical_file)

        if missing_critical:
            self.logger.warning(f"Missing critical files: {missing_critical}")
            result.errors.append(f"Missing critical files: {missing_critical}")

        # Check for bug report specific files with proper Android file patterns
        # Android tombstone files typically don't have .txt extensions
        bugreport_patterns = [
            'tombstone',     # Match any tombstone file (tombstone_00, tombstone_01, etc.)
            'dropbox',       # Match dropbox files in various locations
            'anr'            # Match ANR files (anr.txt, anr_*, traces.txt)
        ]

        missing_bugreport = []
        for pattern in bugreport_patterns:
            # Check if any source contains this pattern in its path or name
            found = any(
                pattern in source.path.name.lower() or
                pattern in str(source.path).lower() or
                (pattern == 'anr' and 'traces.txt' in source.path.name.lower())
                for source in result.sources
            )
            if not found:
                missing_bugreport.append(f"{pattern} files")

        if missing_bugreport:
            self.logger.info(f"Missing bug report file types (may be normal): {missing_bugreport}")
    
    def _resolve_device_id(self, target: str) -> Optional[str]:
        """Resolve device ID from target."""
        if not target or target == "auto":
            # Get first available device
            try:
                result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=10, encoding='utf-8', errors='ignore')
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')[1:]  # Skip header
                    devices = [line.split('\t')[0] for line in lines if line.strip() and '\tdevice' in line]
                    if devices:
                        return devices[0]
            except Exception:
                pass
            return None
        else:
            return target
