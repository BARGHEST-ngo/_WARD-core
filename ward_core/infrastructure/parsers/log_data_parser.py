"""
Log data parser that adapts the existing data_loader functionality.

This provides a clean interface to the existing parsing logic.
"""

from pathlib import Path
from typing import Dict, Any

from ward_core.logic.models import LogData, PackageInfo, DeviceInfo
from .improved_package_parser import ImprovedPackageParser
from .parser_registry import ParserRegistry


class LogDataParser:
    """
    Parser that converts raw log data into clean domain models.

    This is a clean implementation that doesn't depend on legacy code.
    """

    def __init__(self):
        """Initialize the parser."""
        self.improved_parser = ImprovedPackageParser()
        self.parser_registry = ParserRegistry()
        self._register_parsers()

    def _register_parsers(self):
        """Register all available parsers."""
        # Import and register specialized parsers
        from .specialized.appops_parser import AppOpsParser
        from .specialized.battery_stats_parser import BatteryStatsParser
        from .specialized.network_stats_parser import NetworkStatsParser
        from .specialized.package_parser import PackageParser

        self.parser_registry.register(AppOpsParser)
        self.parser_registry.register(BatteryStatsParser)
        self.parser_registry.register(NetworkStatsParser)
        self.parser_registry.register(PackageParser)

    def parse_directory(self, log_directory: str) -> LogData:
        """
        Parse logs from a directory using clean architecture.

        Args:
            log_directory: Path to directory containing log files

        Returns:
            Parsed LogData object
        """
        # Parse directory using clean parsers
        raw_data = self._parse_directory_clean(log_directory)

        # Convert to clean domain models
        log_data = self._convert_to_domain_model(raw_data, log_directory)

        return log_data

    def _parse_directory_clean(self, log_directory: str) -> Dict[str, Any]:
        """Parse directory using clean parser architecture."""
        log_dir = Path(log_directory)
        raw_data = {
            'raw_lines': [],
            'packages': {},
            'device_info': {},
            'parsed_events': [],
            'missing_sections': []
        }

        # Parse all files in directory with prioritization
        all_files = list(log_dir.glob('*.txt'))

        # Prioritize files to avoid conflicts (e.g., prefer main appops over per-uid version)
        prioritized_files = self._prioritize_files(all_files)

        for file_path in prioritized_files:
            try:
                # Use the parser registry's smart selection
                parser = self.parser_registry.get_parser_for_file(file_path)

                if parser:
                    # Parse file and collect entries
                    for entry in parser.parse_file(file_path):
                        raw_data['parsed_events'].append({
                            'entry_type': entry.entry_type,
                            'package': entry.package,
                            'content': entry.parsed_content,
                            'raw_line': entry.raw_line,
                            'source_file': entry.source_file,
                            'line_number': entry.line_number,
                            'confidence': entry.confidence
                        })
                else:
                    # Fallback: read as raw lines
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        raw_data['raw_lines'].extend(f.readlines())

            except Exception as e:
                raw_data['missing_sections'].append(f"Failed to parse {file_path.name}: {e}")

        return raw_data

    def _prioritize_files(self, files: list) -> list:
        """
        Prioritize files to avoid parsing conflicts.

        For example, prefer shell_dumpsys_appops.txt over shell_appops_per_uid.txt
        since the per-uid version may contain errors on some devices.
        """
        # Create priority groups
        high_priority = []
        medium_priority = []
        low_priority = []

        for file_path in files:
            filename = file_path.name.lower()

            # High priority: Main dumpsys files
            if any(pattern in filename for pattern in [
                'shell_dumpsys_appops.txt',  # Main AppOps file
                'shell_dumpsys_package.txt',  # Main package file
                'shell_dumpsys_batterystats.txt',  # Main battery stats
                'shell_dumpsys_netstats.txt'  # Main network stats
            ]):
                high_priority.append(file_path)

            # Low priority: Optional/per-uid versions that may have errors
            elif any(pattern in filename for pattern in [
                'appops_per_uid',  # May not be supported on all devices
                'permission_dump_all',  # May not be supported on older devices
                'notification_proto'  # May not be supported on older devices
            ]):
                low_priority.append(file_path)

            # Medium priority: Everything else
            else:
                medium_priority.append(file_path)

        # Return prioritized list
        return high_priority + medium_priority + low_priority
    
    def _convert_to_domain_model(self, raw_data: Dict[str, Any], log_directory: str) -> LogData:
        """Convert raw data to domain model."""
        
        # Extract device info
        device_info = DeviceInfo(
            device_id=raw_data.get('device_id', 'Unknown Device'),
            device_model=raw_data.get('device_model', 'Unknown Model'),
            android_version=raw_data.get('android_version', 'Unknown'),
            build_fingerprint=raw_data.get('build_fingerprint', ''),
            device_props=raw_data.get('device_props', {})
        )
        
        # Extract package info
        packages = {}
        package_uids = raw_data.get('package_uids', {})
        installer_info = raw_data.get('installer_info', {})
        package_permissions = raw_data.get('package_permissions', {})
        
        for package_name in set(list(package_uids.keys()) + list(installer_info.keys()) + list(package_permissions.keys())):
            try:
                packages[package_name] = PackageInfo(
                    name=package_name,
                    uid=package_uids.get(package_name),
                    installer=installer_info.get(package_name, 'unknown'),
                    permissions=set(package_permissions.get(package_name, [])),
                    # Additional fields can be populated from raw_data if available
                )
            except ValueError:
                # Skip invalid package names
                continue
        
        # Create LogData object
        log_data = LogData(
            raw_lines=raw_data.get('raw_lines', []),
            log_directory=log_directory,
            data_format=raw_data.get('data_format', 'shell_commands'),
            device_info=device_info,
            packages=packages,
            parsed_events=raw_data.get('parsed', []),
            # Legacy compatibility fields
            package_uids=package_uids,
            installer_info=installer_info,
            package_permissions=package_permissions,
            appops=raw_data.get('appops', {}),
            missing_sections=raw_data.get('missing_sections', [])
        )
        
        return log_data
