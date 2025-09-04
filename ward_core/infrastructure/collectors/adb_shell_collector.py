"""
ADB Shell Collector for comprehensive Android forensic data collection.

This collector executes ADB shell commands to gather all data needed by the heuristics.
"""

import subprocess
import tempfile
import time
import shutil
import concurrent.futures
import zipfile
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from .base_collector import BaseCollector, CollectionResult, DataSource, CollectionError


class AdbShellCollector(BaseCollector):
    """
    ADB Shell collector for comprehensive Android forensic data collection.
    
    This collector executes the complete set of ADB commands needed by all heuristics
    including system information, package data, permissions, network stats, and logs.
    """
    
    # Core ADB commands organized by category for comprehensive heuristic coverage
    ADB_COMMAND_GROUPS = {
        'system_info': {
            'getprop': 'getprop',
            'build_info': 'cat /system/build.prop',
            'version_info': 'cat /proc/version', 
            'uptime': 'uptime',
            'date': 'date',
        },
        
        'package_management': {
            'packages_full': 'pm list packages -f -i',  # Full package info with installer
            'packages_system': 'pm list packages -s',   # System packages
            'packages_third_party': 'pm list packages -3', # Third-party packages
            'packages_enabled': 'pm list packages -e',   # Enabled packages
            'packages_disabled': 'pm list packages -d',  # Disabled packages
            'permissions_list': 'pm list permissions -g -d',  # All permissions with groups
            'permissions_dangerous': 'pm list permissions -d',  # Dangerous permissions only
        },
        
        'dumpsys_core': {
            'package': 'dumpsys package',
            'appops': 'dumpsys appops',
            'accessibility': 'dumpsys accessibility',
            'activity_services': 'dumpsys activity services',
            'permission': 'dumpsys permission',  # Permission manager data
            'netstats': 'dumpsys netstats',
            'connectivity': 'dumpsys connectivity',
            'network_policy': 'dumpsys network_policy',
            'role': 'dumpsys role',  # Role manager (Android 10+)
            'notification': 'dumpsys notification',
        },

        'dumpsys_optional': {
            # These commands may not be supported on all devices/Android versions
            'appops_per_uid': 'dumpsys appops --uid',  # More accurate per-UID data (Android 11+)
            'permission_dump_all': 'dumpsys permission --dump-all',  # Complete permission state (Android 10+)
            'notification_proto': 'dumpsys notification --proto',  # Structured notification data (Android 9+)
        },
        
        'dumpsys_power_performance': {
            'batterystats': 'dumpsys batterystats',
            'batterystats_checkin': 'dumpsys batterystats --checkin',
            'power': 'dumpsys power',
            'deviceidle': 'dumpsys deviceidle',
            'deviceidle_whitelist': 'dumpsys deviceidle whitelist',  # Doze whitelist abuse
            'alarm': 'dumpsys alarm',
            'jobscheduler': 'dumpsys jobscheduler',
            'usagestats': 'dumpsys usagestats',
            'stats': 'dumpsys stats --dump-all',  # System stats for behavioral analysis
        },
        
        'dumpsys_security': {
            'device_policy': 'dumpsys device_policy',
            'location': 'dumpsys location',
            'privacy': 'dumpsys privacy',  # Privacy dashboard data (Android 12+)
            'shortcut': 'dumpsys shortcut',  # Shortcut abuse detection
            'slice': 'dumpsys slice',  # Slice provider abuse
            'trust': 'dumpsys trust',  # Trust agents
            'biometric': 'dumpsys biometric',  # Biometric authentication
        },
        
        'dumpsys_system': {
            'window': 'dumpsys window',
            'sensorservice': 'dumpsys sensorservice', 
            'binder': 'dumpsys binder',
            'meminfo': 'dumpsys meminfo',
            'cpuinfo': 'dumpsys cpuinfo',
        },
        
        'system_logs': {
            'logcat_main': 'logcat -v threadtime -d',
            'logcat_system': 'logcat -b system -v threadtime -d', 
            'logcat_events': 'logcat -b events -v threadtime -d',
            'logcat_crash': 'logcat -b crash -v threadtime -d',
            'dmesg': 'dmesg',
        },
        
        'filesystem_analysis': {
            'mount_info': 'mount',
            'proc_mounts': 'cat /proc/mounts',
            'disk_usage': 'df -h',
            'running_processes': 'ps -A',
            'network_connections': 'netstat -an',
        },
        
        'process_analysis': {
            'ps_detailed': 'ps -A -o PID,UID,USER,NAME,ARGS',
            'top_processes': 'top -n 1 -b',
            'procrank': 'procrank',  # If available
            'dumpsys_activity_processes': 'dumpsys activity processes',
            'dumpsys_meminfo_detailed': 'dumpsys meminfo -d',
        },
        
        'dex_analysis': {
            'dexopt_logs': 'logcat -d | grep -E "(dexopt|dex2oat)"',
            'code_cache_listing': 'find /data/data/*/code_cache -type f 2>/dev/null',
            'secondary_dex_scan': 'find /data/data/*/files -name "*.dex" 2>/dev/null',
        },
        
        'user_analysis': {
            'dumpsys_package_users': 'dumpsys package | grep -A 10 "User"',
            'pm_list_users': 'pm list-users',
            'id_mapping': 'cat /proc/self/uid_map 2>/dev/null',
        },
        
        'additional_forensics': {
            'settings_global': 'settings list global',
            'settings_system': 'settings list system',
            'settings_secure': 'settings list secure',
            'accounts': 'dumpsys account',
        },

        'oem_specific': {
            # Samsung-specific
            'samsung_persona': 'dumpsys SemPersonaManagerService',  # Knox/Secure Folder
            'samsung_enterprise': 'dumpsys enterprise_policy',  # Samsung MDM
            'samsung_knox': 'dumpsys knoxguard',  # Knox Guard

            # Xiaomi-specific
            'xiaomi_security': 'dumpsys miui.security',  # MIUI security center
            'xiaomi_autostart': 'dumpsys autostart',  # MIUI autostart management
            'xiaomi_power': 'dumpsys miui.power',  # MIUI power management

            # Huawei-specific
            'huawei_system': 'dumpsys hwsystemmanager',  # Huawei system manager
            'huawei_power': 'dumpsys hwpowermanager',  # Huawei power manager
            'huawei_security': 'dumpsys hwsecurity',  # Huawei security

            # OPPO/OnePlus-specific
            'oppo_power': 'dumpsys oppopowermanager',  # OPPO power management
            'oneplus_zen': 'dumpsys zenmode',  # OnePlus Zen mode

            # Vivo-specific
            'vivo_power': 'dumpsys vivopowermanager',  # Vivo power management
            'vivo_security': 'dumpsys vivosecurity',  # Vivo security center
        },
        
        'bug_report': {
            'bugreport': 'bugreport',  # Generate comprehensive bug report
        },

        'apk_collection': {
            # APK collection commands - these will be handled specially
            'list_userland_packages': 'pm list packages -3 -f',  # Third-party packages with paths
            'list_all_packages': 'pm list packages -f',          # All packages with paths
        }
    }
    
    # Commands that require special handling or have known issues
    PROBLEMATIC_COMMANDS = {
        'settings_global': 'May require elevated permissions',
        'settings_system': 'May require elevated permissions',
        'settings_secure': 'May require elevated permissions', 
        'network_connections': 'May not work on all Android versions',
        'running_processes': 'Output format varies by Android version',
    }
    
    # Commands with high data volume that should have size limits
    # This limits fidelity, but necessary to avoid errors, though these shouldn't be hit often
    HIGH_VOLUME_COMMANDS = {
        'logcat_main': 50000,      # Max 50k lines
        'logcat_system': 20000,    # Max 20k lines  
        'logcat_events': 15000,    # Max 15k lines
        'logcat_crash': 10000,     # Max 10k lines
        'batterystats': 100000,    # Max 100k lines (can be huge)
        'package': 50000,          # Max 50k lines
    }
    
    @property
    def collector_type(self) -> str:
        """Get collector type identifier."""
        return "adb_shell"
    
    def can_collect_from(self, target: str) -> bool:
        """Check if we can collect from the target via ADB."""
        try:
            # Try to connect to device
            if not target or target == "auto":
                # Check for any connected device
                result = subprocess.run(['adb', 'devices'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    devices = self._parse_adb_devices(result.stdout)
                    return len(devices) > 0
            else:
                # Check specific device
                result = subprocess.run(['adb', '-s', target, 'get-state'], 
                                      capture_output=True, text=True, timeout=10)
                return result.returncode == 0 and result.stdout.strip() == 'device'
                
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False
    
    def collect(self, target: str) -> CollectionResult:
        """
        Collect comprehensive ADB data from Android device.
        
        Args:
            target: Device ID or "auto" for first available device
            
        Returns:
            Collection result with all gathered data sources
        """
        self.logger.info(f"Starting ADB collection from target: {target}")
        
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
            temp_dir = Path(tempfile.mkdtemp(prefix="barghest_adb_"))
            self.logger.info(f"Using temporary directory: {temp_dir}")
        
        result = CollectionResult(metadata={
            'device_id': device_id,
            'collector_type': self.collector_type,
            'collection_start': datetime.now()
        })
        
        try:
            # Execute command groups
            total_commands = sum(len(commands) for commands in self.ADB_COMMAND_GROUPS.values())
            executed = 0
            
            for group_name, commands in self.ADB_COMMAND_GROUPS.items():
                if not self.config.get_command_group_enabled(group_name):
                    self.logger.info(f"Skipping disabled command group: {group_name}")
                    continue
                
                self.logger.info(f"Executing {group_name} commands...")
                group_sources = self._execute_command_group(
                    device_id, group_name, commands, temp_dir
                )
                result.sources.extend(group_sources)
                
                executed += len(commands)
                self.logger.info(f"Progress: {executed}/{total_commands} commands executed")
            
            # Collect device metadata
            device_metadata = self._collect_device_metadata(device_id)
            result.metadata.update(device_metadata)
            
            # Final validation and cleanup
            result = self._validate_collection_result(result, temp_dir)
            result.metadata['collection_end'] = datetime.now()
            result.metadata['temp_directory'] = str(temp_dir)
            
            self.logger.info(f"ADB collection completed: {len(result.sources)} sources collected")
            return result
            
        except Exception as e:
            # Cleanup on failure (only if using temp directory)
            if not self.config.preserve_temp_files and not self.config.output_directory:
                shutil.rmtree(temp_dir, ignore_errors=True)
            raise CollectionError(f"ADB collection failed: {e}")
    
    def get_supported_sources(self) -> List[str]:
        """Get list of supported data source types."""
        return [
            'system_info', 'package_info', 'dumpsys_output', 
            'system_logs', 'filesystem_info', 'settings_data'
        ]
    
    def _resolve_device_id(self, target: str) -> Optional[str]:
        """Resolve target to actual device ID."""
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
                
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            self.logger.error(f"Error resolving device ID: {e}")
        
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
    
    def _execute_command_group(
        self,
        device_id: str,
        group_name: str,
        commands: Dict[str, str],
        output_dir: Path
    ) -> List[DataSource]:
        """Execute a group of related ADB commands with parallel execution for independent commands."""
        sources = []

        # Special handling for APK collection
        if group_name == 'apk_collection':
            return self._collect_apks(device_id, commands, output_dir)

        # Identify commands that can run in parallel (most dumpsys commands are independent)
        parallel_safe_groups = {
            'dumpsys_core', 'dumpsys_power_performance', 'dumpsys_security',
            'dumpsys_system', 'dumpsys_optional', 'oem_specific', 'additional_forensics'
        }

        if group_name in parallel_safe_groups and len(commands) > 1:
            # Execute commands in parallel using ThreadPoolExecutor
            sources = self._execute_commands_parallel(device_id, group_name, commands, output_dir)
        else:
            # Execute commands sequentially for groups that may have dependencies
            for cmd_name, cmd in commands.items():
                try:
                    source = self._execute_single_command(
                        device_id, group_name, cmd_name, cmd, output_dir
                    )
                    if source:
                        sources.append(source)

                except Exception as e:
                    error_msg = f"Failed to execute {cmd_name}: {e}"
                    self.logger.error(error_msg)

                    # Add to warnings but continue with other commands
                    if hasattr(self, '_current_result'):
                        self._current_result.warnings.append(error_msg)

        return sources

    def _execute_commands_parallel(
        self,
        device_id: str,
        group_name: str,
        commands: Dict[str, str],
        output_dir: Path
    ) -> List[DataSource]:
        """Execute commands in parallel using ThreadPoolExecutor."""
        sources = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            # Submit all commands
            future_to_cmd = {
                executor.submit(
                    self._execute_single_command,
                    device_id, group_name, cmd_name, cmd, output_dir
                ): cmd_name
                for cmd_name, cmd in commands.items()
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_cmd):
                cmd_name = future_to_cmd[future]
                try:
                    source = future.result()
                    if source:
                        sources.append(source)
                except Exception as e:
                    error_msg = f"Failed to execute {cmd_name}: {e}"
                    self.logger.error(error_msg)

                    # Add to warnings but continue with other commands
                    if hasattr(self, '_current_result'):
                        self._current_result.warnings.append(error_msg)

        return sources

    def _is_command_error_output(self, output: str, command: str, group_name: str) -> bool:
        """
        Check if command output indicates an error or unsupported command.

        Args:
            output: Command output to check
            command: The command that was executed
            group_name: The command group name

        Returns:
            True if output indicates an error
        """
        output_lower = output.lower().strip()

        # Common error patterns
        error_patterns = [
            'unknown option',
            'invalid option',
            'command not found',
            'permission denied',
            'no such file or directory',
            'service not found',
            'failed to',
            'error:',
            'exception:',
            'usage:',  # Usually indicates wrong usage
        ]

        # Check for error patterns
        for pattern in error_patterns:
            if pattern in output_lower:
                return True

        # Check for very short output that might be an error
        if len(output.strip()) < 50 and any(word in output_lower for word in ['unknown', 'invalid', 'error', 'failed']):
            return True

        # Check for dumpsys-specific errors
        if command.startswith('dumpsys') and 'service not found' in output_lower:
            return True

        # Special handling for optional commands
        if group_name == 'dumpsys_optional':
            # Optional commands are more likely to have compatibility issues
            if len(output.strip()) < 100 and any(word in output_lower for word in ['unknown', 'invalid', 'not found']):
                return True

        return False
    
    def _execute_single_command(
        self, 
        device_id: str, 
        group_name: str, 
        cmd_name: str, 
        cmd: str, 
        output_dir: Path
    ) -> Optional[DataSource]:
        """Execute a single ADB command and save output."""
        
        # Generate output filename
        output_file = output_dir / f"shell_{cmd_name}.txt"
        
        # Prepare ADB command
        full_cmd = ['adb', '-s', device_id, 'shell', cmd]
        
        # Apply volume limits for high-volume commands
        if cmd_name in self.HIGH_VOLUME_COMMANDS:
            max_lines = self.HIGH_VOLUME_COMMANDS[cmd_name]
            if 'logcat' in cmd:
                # For logcat, add line limit
                cmd_with_limit = cmd + f" | head -{max_lines}"
                full_cmd = ['adb', '-s', device_id, 'shell', cmd_with_limit]
        
        # Execute command
        start_time = time.time()
        try:
            self.logger.debug(f"Executing: {' '.join(full_cmd)}")
            
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=self.config.adb_timeout_seconds,
                encoding='utf-8',
                errors='ignore'  # Handle encoding issues gracefully
            )
            
            execution_time = time.time() - start_time
            
            if result.returncode != 0:
                error_msg = f"Command failed with return code {result.returncode}: {result.stderr}"
                self.logger.warning(f"{cmd_name}: {error_msg}")
                
                # Still save partial output if available
                if result.stdout:
                    self._save_command_output(output_file, result.stdout, cmd_name, error=error_msg)
                return None
            
            if not result.stdout or len(result.stdout.strip()) == 0:
                self.logger.warning(f"{cmd_name}: Command produced no output")
                return None

            # Check for command-specific errors in output
            if self._is_command_error_output(result.stdout, cmd, group_name):
                error_msg = f"Command produced error output: {result.stdout.strip()[:100]}"
                self.logger.warning(f"{cmd_name}: {error_msg}")

                # For optional commands, don't treat as failure
                if group_name == 'dumpsys_optional':
                    self.logger.info(f"{cmd_name}: Optional command not supported on this device/Android version")
                    return None

                # Save error output for debugging
                self._save_command_output(output_file, result.stdout, cmd_name, error=error_msg)
                return None
            
            # Save output to file
            self._save_command_output(output_file, result.stdout, cmd_name)
            
            # Create data source
            source = DataSource(
                type=f"adb_{group_name}",
                path=output_file,
                metadata={
                    'command': cmd,
                    'command_name': cmd_name,
                    'group_name': group_name,
                    'execution_time': execution_time,
                    'device_id': device_id,
                    'line_count': len(result.stdout.splitlines()),
                    'is_temporary': True
                }
            )
            
            self.logger.debug(f"Success: {cmd_name}: {source.size_bytes} bytes, {source.metadata['line_count']} lines")
            return source
            
        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after {self.config.adb_timeout_seconds}s"
            self.logger.error(f"{cmd_name}: {error_msg}")
            raise CollectionError(error_msg)
            
        except Exception as e:
            error_msg = f"Unexpected error executing command: {e}"
            self.logger.error(f"{cmd_name}: {error_msg}")
            raise CollectionError(error_msg)
    
    def _save_command_output(self, output_file: Path, content: str, cmd_name: str, error: Optional[str] = None):
        """Save command output to file with metadata header."""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                # Write metadata header
                f.write(f"# BARGHEST WARD ADB Collection\n")
                f.write(f"# Command: {cmd_name}\n")
                f.write(f"# Collected: {datetime.now().isoformat()}\n")
                f.write(f"# Device: {self._current_device_id if hasattr(self, '_current_device_id') else 'unknown'}\n")
                if error:
                    f.write(f"# Error: {error}\n")
                f.write(f"# Lines: {len(content.splitlines())}\n")
                f.write("# " + "="*60 + "\n\n")
                
                # Write actual content
                f.write(content)
                
        except Exception as e:
            self.logger.error(f"Failed to save output for {cmd_name}: {e}")
            raise
    
    def _collect_device_metadata(self, device_id: str) -> Dict[str, any]:
        """Collect basic device metadata."""
        metadata = {'device_id': device_id}
        
        try:
            # Get device properties
            result = subprocess.run(
                ['adb', '-s', device_id, 'shell', 'getprop'],
                capture_output=True, text=True, timeout=30,
                encoding='utf-8', errors='ignore'
            )
            
            if result.returncode == 0:
                props = self._parse_device_properties(result.stdout)
                metadata.update({
                    'device_model': props.get('ro.product.model', 'Unknown'),
                    'android_version': props.get('ro.build.version.release', 'Unknown'),
                    'api_level': props.get('ro.build.version.sdk', 'Unknown'),
                    'build_fingerprint': props.get('ro.build.fingerprint', 'Unknown'),
                    'manufacturer': props.get('ro.product.manufacturer', 'Unknown'),
                    'brand': props.get('ro.product.brand', 'Unknown'),
                })
                
        except Exception as e:
            self.logger.warning(f"Failed to collect device metadata: {e}")
        
        return metadata
    
    def _parse_device_properties(self, props_output: str) -> Dict[str, str]:
        """Parse getprop output into property dictionary."""
        import re
        props = {}
        
        for line in props_output.splitlines():
            match = re.match(r'\[([^\]]+)\]:\s*\[([^\]]*)\]', line.strip())
            if match:
                key, value = match.groups()
                props[key] = value
        
        return props
    
    def _validate_collection_result(self, result: CollectionResult, temp_dir: Path) -> CollectionResult:
        """Validate collection result and add quality metrics."""

        # Add temp directory info to metadata for debugging
        result.metadata['temp_directory_size'] = sum(
            f.stat().st_size for f in temp_dir.rglob('*') if f.is_file()
        ) if temp_dir.exists() else 0

        # Check for critical missing sources
        critical_sources = {
            'package', 'appops', 'accessibility', 'netstats', 
            'batterystats', 'logcat_main'
        }
        
        found_sources = set()
        for source in result.sources:
            cmd_name = source.metadata.get('command_name', '')
            found_sources.add(cmd_name)
        
        missing_critical = critical_sources - found_sources
        if missing_critical:
            warning = f"Missing critical data sources: {missing_critical}"
            result.warnings.append(warning)
            self.logger.warning(warning)
        
        # Add collection statistics
        result.metadata['collection_stats'] = {
            'total_sources': len(result.sources),
            'total_size_mb': result.get_total_size_mb(),
            'missing_critical_count': len(missing_critical),
            'coverage_score': result.get_coverage_score()
        }
        
        return result

    def _collect_apks(
        self,
        device_id: str,
        commands: Dict[str, str],
        output_dir: Path
    ) -> List[DataSource]:
        """
        Collect APK files from the device based on configuration.

        Args:
            device_id: Target device ID
            commands: APK collection commands
            output_dir: Directory to save APKs

        Returns:
            List of data sources for collected APKs
        """
        sources = []

        # Create APK collection directory
        apk_dir = output_dir / "apks"
        apk_dir.mkdir(parents=True, exist_ok=True)

        # Determine which command to use based on configuration
        if self.config.collect_userland_apks:
            cmd_name = 'list_userland_packages'
            self.logger.info("Collecting userland APKs only")
        elif self.config.collect_all_apks:
            cmd_name = 'list_all_packages'
            self.logger.info("Collecting all APKs including system")
        else:
            self.logger.warning("APK collection enabled but no collection type specified")
            return sources

        if cmd_name not in commands:
            self.logger.error(f"APK collection command '{cmd_name}' not found")
            return sources

        try:
            # Get package list with paths
            cmd = commands[cmd_name]
            full_cmd = ['adb', '-s', device_id, 'shell', cmd]

            self.logger.info(f"Getting package list: {cmd}")
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=self.config.adb_timeout_seconds,
                encoding='utf-8',
                errors='ignore'
            )

            if result.returncode != 0:
                error_msg = f"Failed to get package list: {result.stderr}"
                self.logger.error(error_msg)
                return sources

            # Parse package list and extract APKs
            package_paths = self._parse_package_list(result.stdout)
            self.logger.info(f"Found {len(package_paths)} packages to collect")

            # Pull APKs from device
            collected_apks = []
            for package_name, apk_path in package_paths.items():
                try:
                    apk_file = self._pull_apk(device_id, package_name, apk_path, apk_dir)
                    if apk_file:
                        collected_apks.append(apk_file)
                except Exception as e:
                    self.logger.warning(f"Failed to pull APK for {package_name}: {e}")
                    continue

            self.logger.info(f"Successfully collected {len(collected_apks)} APKs")

            # Create zip archive of APKs to save space
            if collected_apks:
                zip_file = self._create_apk_archive(collected_apks, output_dir)
                if zip_file:
                    # Create data source for the zip archive
                    source = DataSource(
                        type="apk_collection",
                        path=zip_file,
                        metadata={
                            'collection_type': 'userland' if self.config.collect_userland_apks else 'all',
                            'apk_count': len(collected_apks),
                            'device_id': device_id,
                            'is_temporary': True
                        }
                    )
                    sources.append(source)

                    # Clean up individual APK files after zipping
                    for apk_file in collected_apks:
                        try:
                            apk_file.unlink()
                        except Exception as e:
                            self.logger.warning(f"Failed to clean up APK file {apk_file}: {e}")

                    # Remove empty APK directory
                    try:
                        apk_dir.rmdir()
                    except Exception:
                        pass  # Directory might not be empty due to failed cleanup

        except Exception as e:
            error_msg = f"APK collection failed: {e}"
            self.logger.error(error_msg)
            if hasattr(self, '_current_result'):
                self._current_result.errors.append(error_msg)

        return sources

    def _parse_package_list(self, package_output: str) -> Dict[str, str]:
        """
        Parse package list output to extract package names and APK paths.

        Args:
            package_output: Output from 'pm list packages -f' command

        Returns:
            Dictionary mapping package names to APK paths
        """
        packages = {}

        for line in package_output.strip().split('\n'):
            line = line.strip()
            if not line or not line.startswith('package:'):
                continue

            # Format: package:/path/to/package.apk=com.example.package
            try:
                # Remove 'package:' prefix
                line = line[8:]  # len('package:') = 8

                # Split on '=' to separate path and package name
                if '=' in line:
                    apk_path, package_name = line.split('=', 1)
                    packages[package_name] = apk_path

            except Exception as e:
                self.logger.debug(f"Failed to parse package line '{line}': {e}")
                continue

        return packages

    def _pull_apk(
        self,
        device_id: str,
        package_name: str,
        apk_path: str,
        output_dir: Path
    ) -> Optional[Path]:
        """
        Pull an APK file from the device.

        Args:
            device_id: Target device ID
            package_name: Package name
            apk_path: Path to APK on device
            output_dir: Local directory to save APK

        Returns:
            Path to pulled APK file, or None if failed
        """
        try:
            # Create safe filename from package name
            safe_name = package_name.replace('/', '_').replace(':', '_')
            local_apk_path = output_dir / f"{safe_name}.apk"

            # Pull APK using adb pull
            pull_cmd = ['adb', '-s', device_id, 'pull', apk_path, str(local_apk_path)]

            self.logger.debug(f"Pulling APK: {package_name} from {apk_path}")
            result = subprocess.run(
                pull_cmd,
                capture_output=True,
                text=True,
                timeout=60,  # 1 minute timeout per APK
                encoding='utf-8',
                errors='ignore'
            )

            if result.returncode != 0:
                self.logger.warning(f"Failed to pull APK for {package_name}: {result.stderr}")
                return None

            # Verify file was created and has reasonable size
            if local_apk_path.exists() and local_apk_path.stat().st_size > 1024:  # At least 1KB
                self.logger.debug(f"Successfully pulled APK: {package_name} ({local_apk_path.stat().st_size} bytes)")
                return local_apk_path
            else:
                self.logger.warning(f"APK file for {package_name} is missing or too small")
                return None

        except Exception as e:
            self.logger.warning(f"Exception pulling APK for {package_name}: {e}")
            return None

    def _create_apk_archive(
        self,
        apk_files: List[Path],
        output_dir: Path
    ) -> Optional[Path]:
        """
        Create a compressed archive of collected APK files.

        Args:
            apk_files: List of APK file paths
            output_dir: Directory to save archive

        Returns:
            Path to created archive, or None if failed
        """
        if not apk_files:
            return None

        try:
            # Create archive filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            collection_type = 'userland' if self.config.collect_userland_apks else 'all'
            archive_name = f"apks_{collection_type}_{timestamp}.zip"
            archive_path = output_dir / archive_name

            self.logger.info(f"Creating APK archive: {archive_name}")

            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zip_file:
                for apk_file in apk_files:
                    if apk_file.exists():
                        # Use just the filename in the archive (not full path)
                        zip_file.write(apk_file, apk_file.name)
                        self.logger.debug(f"Added to archive: {apk_file.name}")

            # Verify archive was created
            if archive_path.exists() and archive_path.stat().st_size > 0:
                self.logger.info(f"APK archive created: {archive_path} ({archive_path.stat().st_size} bytes)")
                return archive_path
            else:
                self.logger.error("APK archive creation failed - file missing or empty")
                return None

        except Exception as e:
            self.logger.error(f"Failed to create APK archive: {e}")
            return None
