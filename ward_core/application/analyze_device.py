"""
Main use case for analyzing a device.

This replaces the old ward_analysis.py script with a cleaner use case implementation.
Main use case handling for main.py. 
"""

import sys
import time
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional
import logging

from ward_core.logic.models import AnalysisConfig, LogData, AnalysisResult
from ward_core.logic.services import AnalysisService
from ward_core.infrastructure.data_loader_service import DataLoaderService
from ward_core.infrastructure.collectors import CollectionProfiles, CollectionConfig
from ward_core.infrastructure.device import AdbDeviceDetector, AdbDevice
from ward_core.infrastructure.storage import ResultStorage, CollectionArchive
from ward_core.infrastructure.logging import enhanced_logger


class AnalyzeDeviceUseCase:
    """
    Use case for analyzing a device from collected logs or live ADB collection.
    
    This encapsulates the entire analysis workflow supporting two modes:
    1. Analyze existing logs from a directory
    2. Detect ADB device, collect data, and analyze
    """
    
    def __init__(self, config_path: str = None, verbose: bool = False):
        """
        Initialize the analyze device use case.

        Args:
            config_path: Path to configuration file (optional)
            verbose: Enable verbose logging (optional)
        """
        self.logger = logging.getLogger("analyze.device")
        self.progress_logger = logging.getLogger("progress")
        self.verbose = verbose

        # Load configuration
        if config_path and Path(config_path).exists():
            self.config = AnalysisConfig.from_file(config_path)
        else:
            self.config = AnalysisConfig()  # Use defaults

        # Initialize services
        self.analysis_service = AnalysisService(self.config)
        self.data_loader = DataLoaderService()
        self.adb_detector = AdbDeviceDetector()
        self.storage = ResultStorage()
        self.collection_archive = CollectionArchive()
    
    def execute_from_logs(self, log_directory: str) -> AnalysisResult:
        """
        Execute analysis from existing log directory.
        
        Args:
            log_directory: Path to directory containing collected logs
            
        Returns:
            Complete analysis result
        """
        start_time = time.time()
        log_file_path = None
        
        try:
            # Set up enhanced logging (logs to both console and file)
            log_file_path = enhanced_logger.setup_logging(log_directory, "analysis.log", verbose=self.verbose)
            
            # Log system information for troubleshooting
            enhanced_logger.log_system_info()
            
            # Progress message for non-verbose mode
            self.progress_logger.warning(f"Starting analysis of logs from: {log_directory}")

            self.logger.info(f"Starting device analysis from logs: {log_directory}")
            enhanced_logger.create_analysis_log_entry("start", f"Analysis initiated from logs", {
                "log_directory": log_directory,
                "config_file": getattr(self.config, '_source_file', 'default'),
                "log_file": log_file_path,
                "mode": "existing_logs"
            })
            
            # Step 1: Load log data using new data loader service
            self.progress_logger.warning("Loading log data...")
            enhanced_logger.create_analysis_log_entry("loading", "Starting log data loading")
            log_data = self._load_existing_logs(log_directory)
            self.progress_logger.warning(f"Loaded {log_data.get_line_count():,} log lines from {log_data.get_package_count()} packages")
            enhanced_logger.create_analysis_log_entry("loading", "Log data loading completed", {
                "total_lines": log_data.get_line_count(),
                "packages_found": log_data.get_package_count()
            })
            
            # Step 2: Run analysis
            self.progress_logger.warning("Running heuristic analysis...")
            enhanced_logger.create_analysis_log_entry("analysis", "Starting heuristic analysis")
            result = self.analysis_service.analyze(log_data)
            self.progress_logger.warning(f"Analysis complete - Risk Level: {result.risk_level.value.upper()}, Score: {result.overall_score:.1f}")
            enhanced_logger.create_analysis_log_entry("analysis", "Heuristic analysis completed", {
                "heuristics_run": len(result.heuristic_results),
                "overall_score": result.overall_score,
                "risk_level": result.risk_level.value
            })
            
            # Step 3: Store results
            self.progress_logger.warning("Saving results...")
            enhanced_logger.create_analysis_log_entry("storage", "Storing analysis results")
            self._store_results(result, log_directory, log_file_path)
            self.progress_logger.warning(f"Results saved to: {log_directory}")
            enhanced_logger.create_analysis_log_entry("storage", "Results stored successfully")
            
            # Log execution summary
            execution_time = time.time() - start_time
            enhanced_logger.log_analysis_summary(
                log_directory=log_directory,
                total_lines=log_data.get_line_count(),
                package_count=log_data.get_package_count(),
                heuristics_run=len(result.heuristic_results),
                execution_time=execution_time
            )
            
            self.progress_logger.warning("Analysis completed successfully!")
            self.logger.info("Device analysis completed successfully")
            enhanced_logger.finalize_logging(success=True)
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            # Log detailed error information
            enhanced_logger.log_error_details(e, f"Analysis from logs failed after {execution_time:.2f} seconds")
            enhanced_logger.create_analysis_log_entry("error", "Analysis failed", {
                "error_type": type(e).__name__,
                "error_message": str(e),
                "execution_time": execution_time,
                "mode": "existing_logs"
            })
            
            self.logger.error(f"Device analysis from logs failed: {e}", exc_info=True)
            enhanced_logger.finalize_logging(success=False)
            
            raise
    
    def execute_live_collection(self, 
                               device_serial: Optional[str] = None,
                               collection_profile: str = "standard",
                               output_directory: Optional[str] = None) -> AnalysisResult:
        """
        Execute live collection from ADB device and analyze.
        
        Args:
            device_serial: Specific device serial (optional, auto-detect if None)
            collection_profile: Collection profile to use (default: "standard")
            output_directory: Where to save collected data (optional, creates temp dir)
            
        Returns:
            Complete analysis result
        """
        start_time = time.time()
        temp_dir_created = False
        log_file_path = None
        
        try:
            # Detect device first to get proper metadata for archive
            # TODO: include error handling for multipe devices
            enhanced_logger.create_analysis_log_entry("detection", "Detecting ADB device")
            if not self.adb_detector.is_adb_available():
                raise RuntimeError("ADB command not found. Please install Android SDK platform-tools.")
            
            if device_serial:
                device = self.adb_detector.select_device_by_serial(device_serial)
            else:
                device = self.adb_detector.get_single_device()
            
            if not device:
                raise RuntimeError("No suitable ADB device found. Please connect a device and enable USB debugging.")
            
            # Create permanent collection directory if not provided
            if not output_directory:
                output_directory = self.collection_archive.create_collection_directory(
                    device_serial=device.serial,
                    device_model=device.model or "Unknown",
                    device_manufacturer=device.manufacturer or "Unknown", 
                    collection_profile=collection_profile
                )
                temp_dir_created = False  # This is permanent storage now
                self.logger.info(f"Created permanent collection directory: {output_directory}")
            
            # Set up enhanced logging
            log_file_path = enhanced_logger.setup_logging(output_directory, "analysis.log", verbose=self.verbose)
            enhanced_logger.log_system_info()
            
            # Progress message for non-verbose mode
            device_info = f"{device.model or 'Unknown'} ({device.serial})" if device.model else device.serial
            self.progress_logger.warning(f"Starting live collection from device: {device_info}")

            self.logger.info(f"Starting live device collection and analysis")
            enhanced_logger.create_analysis_log_entry("start", f"Live collection initiated", {
                "device_serial": device.serial,
                "device_model": device.model or "Unknown",
                "device_manufacturer": device.manufacturer or "Unknown",
                "collection_profile": collection_profile,
                "output_directory": output_directory,
                "config_file": getattr(self.config, '_source_file', 'default'),
                "log_file": log_file_path,
                "mode": "live_collection",
                "storage_type": "permanent_archive"
            })
            
            # Device was already detected above, log the confirmation
            enhanced_logger.create_analysis_log_entry("detection", "ADB device confirmed", {
                "device_serial": device.serial,
                "device_model": device.model or "Unknown",
                "device_state": device.state
            })
            
            # Collect data using new collection system
            self.progress_logger.warning("Collecting device data...")
            enhanced_logger.create_analysis_log_entry("collection", "Starting data collection")
            log_data = self._collect_live_data(device, collection_profile, output_directory)
            self.progress_logger.warning(f"Collected {log_data.get_line_count():,} log lines from {log_data.get_package_count()} packages")
            enhanced_logger.create_analysis_log_entry("collection", "Data collection completed", {
                "total_lines": log_data.get_line_count(),
                "packages_found": log_data.get_package_count(),
                "collection_profile": collection_profile
            })
            
            # Run analysis
            self.progress_logger.warning("Running heuristic analysis...")
            enhanced_logger.create_analysis_log_entry("analysis", "Starting heuristic analysis")
            result = self.analysis_service.analyze(log_data)
            self.progress_logger.warning(f"Analysis complete - Risk Level: {result.risk_level.value.upper()}, Score: {result.overall_score:.1f}")
            enhanced_logger.create_analysis_log_entry("analysis", "Heuristic analysis completed", {
                "heuristics_run": len(result.heuristic_results),
                "overall_score": result.overall_score,
                "risk_level": result.risk_level.value
            })
            
            # Store results
            self.progress_logger.warning("Saving results...")
            enhanced_logger.create_analysis_log_entry("storage", "Storing analysis results")
            self._store_results(result, output_directory, log_file_path)
            self.progress_logger.warning(f"Results saved to: {output_directory}")
            enhanced_logger.create_analysis_log_entry("storage", "Results stored successfully")
            
            # Log execution summary
            execution_time = time.time() - start_time
            enhanced_logger.log_analysis_summary(
                log_directory=output_directory,
                total_lines=log_data.get_line_count(),
                package_count=log_data.get_package_count(),
                heuristics_run=len(result.heuristic_results),
                execution_time=execution_time
            )
            
            # Finalize collection in archive (for permanent storage)
            # TODO: Encrypt stored collection for chain of custody
            if not temp_dir_created:  # This is permanent archive storage
                enhanced_logger.create_analysis_log_entry("archive", "Finalizing collection archive")
                
                device_info = {
                    "android_version": device.android_version or "Unknown",
                    "device_model": device.model or "Unknown",
                    "device_manufacturer": device.manufacturer or "Unknown"
                }
                
                collection_id = self.collection_archive.finalize_collection(
                    collection_path=output_directory,
                    analysis_result=result.to_dict(),
                    analysis_duration=execution_time,
                    device_info=device_info
                )
                
                enhanced_logger.create_analysis_log_entry("archive", "Collection archived", {
                    "collection_id": collection_id,
                    "archive_path": output_directory
                })
                
                self.progress_logger.warning("Live collection and analysis completed successfully!")
                self.logger.info(f"Live collection and analysis completed successfully")
                self.logger.info(f"Collection archived with ID: {collection_id}")
                self.logger.info(f"Permanent storage location: {output_directory}")
            else:
                self.progress_logger.warning("Live collection and analysis completed successfully!")
                self.logger.info(f"Live collection and analysis completed successfully")
                self.logger.info(f"Results saved to: {output_directory}")

            enhanced_logger.finalize_logging(success=True)
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            # Log detailed error information
            enhanced_logger.log_error_details(e, f"Live collection failed after {execution_time:.2f} seconds")
            enhanced_logger.create_analysis_log_entry("error", "Live collection failed", {
                "error_type": type(e).__name__,
                "error_message": str(e),
                "execution_time": execution_time,
                "mode": "live_collection"
            })
            
            self.logger.error(f"Live device collection and analysis failed: {e}", exc_info=True)
            enhanced_logger.finalize_logging(success=False)
            
            raise
    
    def _load_existing_logs(self, log_directory: str) -> LogData:
        """Load and parse logs from existing directory using new data loader service."""
        self.logger.info("Loading log data using new data loader service...")
        
        # Use the new data loader service with standard profile for existing logs
        log_data = self.data_loader.load_data_with_profile(log_directory, "standard")
        
        self.logger.info(f"Loaded {log_data.get_line_count():,} log lines")
        self.logger.info(f"Found {log_data.get_package_count()} packages")
        
        return log_data
    
    def _collect_live_data(self, device: AdbDevice, collection_profile: str, output_directory: str) -> LogData:
        """Collect live data from ADB device using new collection system."""
        self.logger.info(f"Collecting live data from device: {device.get_display_name()}")

        # Create collection config from the loaded configuration
        collection_config = self.config.create_collection_config()
        collection_config.output_directory = Path(output_directory)

        # Update the data loader with the configured collection config
        self.data_loader.collection_config = collection_config
        self.logger.info(f"Configured collection to store raw data in: {output_directory}/raw_data")

        # Log APK collection settings if enabled
        if collection_config.collect_userland_apks:
            self.logger.info("APK collection enabled: userland APKs only")
        elif collection_config.collect_all_apks:
            self.logger.info("APK collection enabled: all APKs including system")
        
        # Use the data loader service to collect and parse live data
        # Pass the device serial as the source (target for ADB collector)
        log_data = self.data_loader.load_data_with_profile(
            source=device.serial,  # Device serial is the source/target
            profile_name=collection_profile
        )
        
        self.logger.info(f"Collected {log_data.get_line_count():,} log lines from live device")
        self.logger.info(f"Found {log_data.get_package_count()} packages")
        
        return log_data
    
    def _store_results(self, result: AnalysisResult, log_directory: str, log_file_path: str = None) -> None:
        """Store analysis results."""
        self.logger.info("Storing analysis results...")
        
        output_path = Path(log_directory) / "risk_assessment.json"
        self.storage.save_result(result, str(output_path))
        
        self.logger.info(f"Results saved to: {output_path}")
        
        # Log file information for reference
        if log_file_path:
            log_file = Path(log_file_path)
            if log_file.exists():
                try:
                    log_size = log_file.stat().st_size
                    self.logger.info(f"Analysis log saved to: {log_file_path} ({log_size:,} bytes)")
                    
                    # Create a small reference file linking to the log
                    log_reference = {
                        "analysis_log": log_file.name,
                        "analysis_log_full_path": str(log_file_path),
                        "log_file_size_bytes": log_size,
                        "created": log_file.stat().st_ctime
                    }
                    
                    log_ref_path = Path(log_directory) / "analysis_log_info.json"
                    import json
                    with open(log_ref_path, 'w', encoding='utf-8') as f:
                        json.dump(log_reference, f, indent=2)
                    
                    self.logger.info(f"Log reference saved to: {log_ref_path}")
                    
                except Exception as e:
                    self.logger.warning(f"Could not create log reference: {e}")
    
    def execute(self, log_directory: str) -> AnalysisResult:
        """
        Backward compatibility method - analyze existing logs.
        #TODO: Ensure MVT can intergrate with this format via AndroidQF
        # Right now it won't
        Args:
            log_directory: Path to directory containing collected logs
            
        Returns:
            Complete analysis result
        """
        return self.execute_from_logs(log_directory)
    
    def execute_from_command_line(self, args: list = None) -> Dict[str, Any]:
        """
        Execute from command line with error handling for JSON output.
        
        Supports two modes:
        1. No args or --live: Auto-detect ADB device and collect live data
        2. <log_directory>: Analyze existing logs
        3. --device <serial> [--profile <profile>] [--output <dir>]: Live collection with options
        
        Args:
            args: Command line arguments (defaults to sys.argv)
            
        Returns:
            Analysis results as dictionary for JSON serialization
        """
        if args is None:
            args = sys.argv[1:]
        
        try:
            # Parse command line arguments
            if len(args) == 0 or (len(args) == 1 and args[0] == "--live"):
                # Mode 1: Auto-detect device and live collect
                self.logger.info("No arguments provided - attempting live ADB collection")
                result = self.execute_live_collection()
                
            elif len(args) == 1 and not args[0].startswith("--"):
                # Check if this is a directory path or device identifier
                arg_path = Path(args[0])

                if arg_path.exists() and arg_path.is_dir():
                    # Mode 2: Analyze existing logs
                    log_directory = args[0]
                    self.logger.info(f"Analyzing existing logs from: {log_directory}")
                    result = self.execute_from_logs(log_directory)

                elif ':' in args[0] or args[0].replace('.', '').isdigit():
                    # This looks like a device identifier (IP:port or device ID)
                    device_serial = args[0]
                    self.logger.info(f"Live collection from device: {device_serial}")
                    result = self.execute_live_collection(device_serial=device_serial)

                else:
                    # Path doesn't exist
                    return {
                        "error": f"Log directory '{args[0]}' not found",
                        "heuristic_results": {},
                        "overall_score": 0.0,
                        "risk_level": "unknown"
                    }
                
            elif len(args) >= 2 and args[0] == "--device":
                # Live collection with device specification
                device_serial = args[1]
                
                # Parse optional arguments
                collection_profile = "standard"
                output_directory = None
                
                i = 2
                while i < len(args):
                    if args[i] == "--profile" and i + 1 < len(args):
                        collection_profile = args[i + 1]
                        i += 2
                    elif args[i] == "--output" and i + 1 < len(args):
                        output_directory = args[i + 1]
                        i += 2
                    else:
                        i += 1
                
                self.logger.info(f"Live collection from device: {device_serial}")
                result = self.execute_live_collection(
                    device_serial=device_serial,
                    collection_profile=collection_profile,
                    output_directory=output_directory
                )
                
            else:
                # Invalid usage
                return {
                    "error": self._get_usage_message(),
                    "heuristic_results": {},
                    "overall_score": 0.0,
                    "risk_level": "unknown"
                }
            
            # Convert to dictionary for JSON output
            return result.to_dict()
            
        except Exception as e:
            self.logger.error(f"Command line execution failed: {e}", exc_info=True)
            return {
                "error": str(e),
                "error_type": type(e).__name__,
                "heuristic_results": {},
                "overall_score": 0.0,
                "risk_level": "unknown"
            }
    
    def _get_usage_message(self) -> str:
        # TODO: need -h...
        """Get usage message for command line interface."""
        return """Usage:
        python main.py [--verbose|-v]                          # Auto-detect ADB device and collect live data
        python main.py [--verbose|-v] --live                   # Same as above
        python main.py [--verbose|-v] <log_directory>          # Analyze existing logs
        python main.py [--verbose|-v] --device <serial>        # Live collection from specific device
        python main.py [--verbose|-v] --device <serial> --profile <profile> --output <directory>

        Options:
        --verbose, -v    Enable verbose logging (shows all debug information)
                        Without this flag, only progress and status messages are shown"""
