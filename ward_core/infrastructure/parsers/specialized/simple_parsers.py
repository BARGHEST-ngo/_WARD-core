"""
Simple parsers for basic ADB command outputs.

These parsers handle simple text files from ADB commands that don't require
complex parsing but still contain valuable forensic information.
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class SimpleTextParser(BaseParser):
    """Parser for simple text files with basic content extraction."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.supported_formats = ["txt"]
    
    @property
    def parser_name(self) -> str:
        """Get the name of this parser."""
        return "simple_text_parser"
    
    @property
    def parser_version(self) -> str:
        """Get the version of this parser."""
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=['shell_date', 'shell_version_info', 'shell_uptime', 'shell_build_info', 'shell_disk_usage'],
            output_entry_types={'system_time', 'kernel_version', 'system_uptime', 'build_property', 'disk_usage'}
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the file."""
        if not file_path.suffix.lower() == '.txt':
            return False
        
        # Handle simple text files by name patterns
        simple_patterns = [
            'shell_date.txt',
            'shell_version_info.txt', 
            'shell_uptime.txt',
            'shell_build_info.txt',
            'shell_disk_usage.txt'
        ]
        
        return any(pattern in file_path.name for pattern in simple_patterns)
    
    def get_confidence_score(self, file_path: Path) -> float:
        """Get confidence score for parsing this file."""
        if self.can_parse(file_path):
            return 0.9  # High confidence for simple text files
        return 0.0
    
    def parse_file(self, file_path: Path) -> List[ParsedLogEntry]:
        """Parse simple text file."""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            file_name = file_path.name
            
            if 'shell_date.txt' in file_name:
                entries.extend(self._parse_date_info(content, file_path))
            elif 'shell_version_info.txt' in file_name:
                entries.extend(self._parse_version_info(content, file_path))
            elif 'shell_uptime.txt' in file_name:
                entries.extend(self._parse_uptime_info(content, file_path))
            elif 'shell_build_info.txt' in file_name:
                entries.extend(self._parse_build_info(content, file_path))
            elif 'shell_disk_usage.txt' in file_name:
                entries.extend(self._parse_disk_usage(content, file_path))
            
        except Exception as e:
            self.logger.error(f"Error parsing {file_path}: {e}")
        
        return entries
    
    def _parse_date_info(self, content: str, file_path: Path) -> List[ParsedLogEntry]:
        """Parse date command output."""
        entries = []
        content = content.strip()
        
        if content:
            entry = ParsedLogEntry(
                line_number=1,
                source_file=str(file_path),
                entry_type="system_time",
                timestamp=None,
                raw_line=content,
                parsed_content={
                    "system_date": content,
                    "collection_time": datetime.now().isoformat()
                },
                confidence=0.9,
                tags={"system_time", "forensic_timestamp"}
            )
            entries.append(entry)
        
        return entries
    
    def _parse_version_info(self, content: str, file_path: Path) -> List[ParsedLogEntry]:
        """Parse kernel version information."""
        entries = []
        content = content.strip()
        
        if content:
            # Extract kernel version details
            parsed_data = {"kernel_version": content}
            
            # Look for version patterns
            version_match = re.search(r'Linux version ([^\s]+)', content)
            if version_match:
                parsed_data["kernel_release"] = version_match.group(1)
            
            # Look for compiler information
            gcc_match = re.search(r'\(gcc version ([^)]+)\)', content)
            if gcc_match:
                parsed_data["compiler_version"] = gcc_match.group(1)
            
            entry = ParsedLogEntry(
                line_number=1,
                source_file=str(file_path),
                entry_type="kernel_version",
                timestamp=None,
                raw_line=content,
                parsed_content=parsed_data,
                confidence=0.9,
                tags={"kernel_version", "system_info", "security_baseline"}
            )
            entries.append(entry)
        
        return entries
    
    def _parse_uptime_info(self, content: str, file_path: Path) -> List[ParsedLogEntry]:
        """Parse system uptime information."""
        entries = []
        content = content.strip()
        
        if content:
            parsed_data = {"uptime_raw": content}
            
            # Parse uptime format: "up 1 day, 2:30, load average: 0.1, 0.2, 0.3"
            uptime_match = re.search(r'up\s+(.+?),\s*load average:', content)
            if uptime_match:
                parsed_data["uptime_description"] = uptime_match.group(1).strip()
            
            load_match = re.search(r'load average:\s*([0-9.]+),\s*([0-9.]+),\s*([0-9.]+)', content)
            if load_match:
                parsed_data["load_average"] = {
                    "1min": float(load_match.group(1)),
                    "5min": float(load_match.group(2)), 
                    "15min": float(load_match.group(3))
                }
            
            entry = ParsedLogEntry(
                line_number=1,
                source_file=str(file_path),
                entry_type="system_uptime",
                timestamp=None,
                raw_line=content,
                parsed_content=parsed_data,
                confidence=0.9,
                tags={"uptime", "system_performance", "load_average"}
            )
            entries.append(entry)
        
        return entries
    
    def _parse_build_info(self, content: str, file_path: Path) -> List[ParsedLogEntry]:
        """Parse build.prop information."""
        entries = []
        
        try:
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Identify security-relevant properties
                    tags = {"build_prop"}
                    
                    if any(sec_key in key.lower() for sec_key in ['secure', 'debug', 'root', 'su', 'selinux']):
                        tags.add("security_property")
                    elif any(dev_key in key.lower() for dev_key in ['dev', 'test', 'eng']):
                        tags.add("development_property")
                    
                    entry = ParsedLogEntry(
                        line_number=line_num,
                        source_file=str(file_path),
                        entry_type="build_property",
                        timestamp=None,
                        raw_line=line,
                        parsed_content={
                            "property_name": key,
                            "property_value": value
                        },
                        confidence=0.9,
                        tags=tags
                    )
                    entries.append(entry)
        
        except Exception as e:
            self.logger.error(f"Error parsing build info: {e}")
        
        return entries
    
    def _parse_disk_usage(self, content: str, file_path: Path) -> List[ParsedLogEntry]:
        """Parse disk usage information (df -h output)."""
        entries = []
        
        try:
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if not line or line.startswith('Filesystem'):
                    continue
                
                # Parse df output: Filesystem Size Used Avail Use% Mounted_on
                parts = line.split()
                if len(parts) >= 6:
                    parsed_data = {
                        "filesystem": parts[0],
                        "size": parts[1],
                        "used": parts[2], 
                        "available": parts[3],
                        "use_percent": parts[4],
                        "mount_point": ' '.join(parts[5:])  # Handle spaces in mount points
                    }
                    
                    # Flag high usage as potential security concern
                    tags = {"disk_usage", "system_resources"}
                    
                    try:
                        usage_pct = int(parts[4].rstrip('%'))
                        if usage_pct > 90:
                            tags.add("high_usage")
                    except (ValueError, IndexError):
                        pass
                    
                    entry = ParsedLogEntry(
                        line_number=line_num,
                        source_file=str(file_path),
                        entry_type="disk_usage",
                        timestamp=None,
                        raw_line=line,
                        parsed_content=parsed_data,
                        confidence=0.9,
                        tags=tags
                    )
                    entries.append(entry)
        
        except Exception as e:
            self.logger.error(f"Error parsing disk usage: {e}")
        
        return entries


class PackageListParser(BaseParser):
    """Parser for package list commands (pm list packages variants)."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.supported_formats = ["txt"]
    
    @property
    def parser_name(self) -> str:
        """Get the name of this parser."""
        return "package_list_parser"
    
    @property
    def parser_version(self) -> str:
        """Get the version of this parser."""
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=['shell_packages_system', 'shell_packages_third_party', 'shell_packages_enabled', 'shell_packages_disabled', 'shell_packages_full'],
            output_entry_types={'package_entry'}
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the file."""
        if not file_path.suffix.lower() == '.txt':
            return False
        
        # Handle package list files
        package_patterns = [
            'shell_packages_system.txt',
            'shell_packages_third_party.txt',
            'shell_packages_enabled.txt',
            'shell_packages_disabled.txt',
            'shell_packages_full.txt'
        ]
        
        return any(pattern in file_path.name for pattern in package_patterns)
    
    def get_confidence_score(self, file_path: Path) -> float:
        """Get confidence score for parsing this file."""
        if self.can_parse(file_path):
            return 0.95  # Very high confidence for package lists
        return 0.0
    
    def parse_file(self, file_path: Path) -> List[ParsedLogEntry]:
        """Parse package list file."""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            file_name = file_path.name
            
            # Determine package list type
            if 'system' in file_name:
                list_type = "system_packages"
            elif 'third_party' in file_name:
                list_type = "third_party_packages"
            elif 'enabled' in file_name:
                list_type = "enabled_packages"
            elif 'disabled' in file_name:
                list_type = "disabled_packages"
            elif 'full' in file_name:
                list_type = "full_package_info"
            else:
                list_type = "package_list"
            
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if not line or not line.startswith('package:'):
                    continue
                
                # Parse package entry
                package_data = self._parse_package_line(line, list_type)
                if package_data:
                    tags = {"package_management", list_type, "application_inventory"}
                    
                    entry = ParsedLogEntry(
                        line_number=line_num,
                        source_file=str(file_path),
                        entry_type="package_entry",
                        timestamp=None,
                        raw_line=line,
                        parsed_content=package_data,
                        confidence=0.95,
                        tags=tags
                    )
                    
                    # Add package to the entry
                    if 'package_name' in package_data:
                        entry.package = package_data['package_name']
                    
                    entries.append(entry)
        
        except Exception as e:
            self.logger.error(f"Error parsing package list: {e}")
        
        return entries
    
    def _parse_package_line(self, line: str, list_type: str) -> Dict[str, Any]:
        """Parse a single package line."""
        # Remove 'package:' prefix
        line = line[8:] if line.startswith('package:') else line
        
        parsed_data = {"list_type": list_type}
        
        if list_type == "full_package_info":
            # Format: package:/path/to/apk=package.name  installer=installer_name
            parts = line.split('=')
            if len(parts) >= 2:
                apk_path = parts[0].strip()
                
                # Handle case where there are spaces before "installer"
                # parts[1] might be "com.package.name  installer"
                middle_part = parts[1].strip()
                
                # Split on whitespace to separate package name from "installer"
                if ' installer' in middle_part:
                    package_name = middle_part.split(' installer')[0].strip()
                else:
                    package_name = middle_part
                
                parsed_data.update({
                    "apk_path": apk_path,
                    "package_name": package_name
                })
                
                # Look for installer information
                if len(parts) >= 3 and 'installer=' in parts[2]:
                    installer = parts[2].split('installer=')[1].strip()
                    parsed_data["installer"] = installer
        else:
            # Simple package name format
            parsed_data["package_name"] = line.strip()
        
        return parsed_data


class ProcessListParser(BaseParser):
    """Parser for process list output (ps command)."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.supported_formats = ["txt"]
    
    @property
    def parser_name(self) -> str:
        """Get the name of this parser."""
        return "process_list_parser"
    
    @property
    def parser_version(self) -> str:
        """Get the version of this parser."""
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=['shell_running_processes'],
            output_entry_types={'running_process'}
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the file."""
        return 'shell_running_processes.txt' in file_path.name
    
    def get_confidence_score(self, file_path: Path) -> float:
        """Get confidence score for parsing this file."""
        if self.can_parse(file_path):
            return 0.9  # High confidence for process lists
        return 0.0
    
    def parse_file(self, file_path: Path) -> List[ParsedLogEntry]:
        """Parse process list file."""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            header_line = None
            
            # Find header line
            for line in lines[:5]:  # Check first 5 lines for header
                if any(col in line.upper() for col in ['PID', 'PPID', 'CMD', 'NAME']):
                    header_line = line
                    break
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line == header_line or line.startswith('#'):
                    continue
                
                # Parse process entry
                process_data = self._parse_process_line(line)
                if process_data:
                    tags = {"process_list", "running_processes"}
                    
                    entry = ParsedLogEntry(
                        line_number=line_num,
                        source_file=str(file_path),
                        entry_type="running_process",
                        timestamp=None,
                        raw_line=line,
                        parsed_content=process_data,
                        confidence=0.9,
                        tags=tags
                    )
                    
                    # Add process name as package if available
                    if 'command' in process_data:
                        cmd = process_data['command']
                        if '.' in cmd and not cmd.startswith('/'):  # Looks like package name
                            entry.package = cmd
                    
                    entries.append(entry)
        
        except Exception as e:
            self.logger.error(f"Error parsing process list: {e}")
        
        return entries
    
    def _parse_process_line(self, line: str) -> Dict[str, Any]:
        """Parse a single process line."""
        parts = line.split()
        if len(parts) < 2:
            return {}
        
        process_data = {}
        
        try:
            # Correct ps output format: USER PID PPID VSZ RSS WCHAN PC STATE NAME
            if len(parts) >= 9:
                process_data.update({
                    "user": parts[0],
                    "pid": parts[1], 
                    "ppid": parts[2],
                    "vsz": parts[3],
                    "rss": parts[4],
                    "wchan": parts[5],
                    "pc": parts[6],
                    "state": parts[7],  # Process state (R, S, Z, etc.)
                    "command": ' '.join(parts[8:])  # Skip the state field
                })
            elif len(parts) >= 8:
                # Fallback for different format: USER PID PPID VSZ RSS WCHAN PC NAME (no state)
                process_data.update({
                    "user": parts[0],
                    "pid": parts[1], 
                    "ppid": parts[2],
                    "vsz": parts[3],
                    "rss": parts[4],
                    "wchan": parts[5],
                    "pc": parts[6],
                    "command": ' '.join(parts[7:])
                })
            else:
                # Minimal fallback - just capture what we can
                process_data.update({
                    "pid": parts[0] if parts[0].isdigit() else "unknown",
                    "command": ' '.join(parts[1:]) if len(parts) > 1 else parts[0]
                })
        except (IndexError, ValueError):
            # Last resort - capture the whole line
            process_data["raw_process_info"] = line
        
        return process_data


class NetworkConnectionParser(BaseParser):
    """Parser for network connections (netstat output)."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.supported_formats = ["txt"]
    
    @property
    def parser_name(self) -> str:
        """Get the name of this parser."""
        return "network_connection_parser"
    
    @property
    def parser_version(self) -> str:
        """Get the version of this parser."""
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=['shell_network_connections'],
            output_entry_types={'network_connection'}
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the file."""
        return 'shell_network_connections.txt' in file_path.name
    
    def get_confidence_score(self, file_path: Path) -> float:
        """Get confidence score for parsing this file."""
        if self.can_parse(file_path):
            return 0.9  # High confidence for network connections
        return 0.0
    
    def parse_file(self, file_path: Path) -> List[ParsedLogEntry]:
        """Parse network connections file."""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if not line or 'Active' in line or 'Proto' in line or line.startswith('#'):
                    continue
                
                # Parse connection entry
                connection_data = self._parse_connection_line(line)
                if connection_data:
                    tags = {"network_connections", "network_forensics"}
                    
                    entry = ParsedLogEntry(
                        line_number=line_num,
                        source_file=str(file_path),
                        entry_type="network_connection",
                        timestamp=None,
                        raw_line=line,
                        parsed_content=connection_data,
                        confidence=0.9,
                        tags=tags
                    )
                    entries.append(entry)
        
        except Exception as e:
            self.logger.error(f"Error parsing network connections: {e}")
        
        return entries
    
    def _parse_connection_line(self, line: str) -> Dict[str, Any]:
        """Parse a single network connection line."""
        parts = line.split()
        if len(parts) < 3:
            return {}
        
        connection_data = {}
        
        try:
            # Common netstat format: Proto Local_Address Foreign_Address State
            connection_data.update({
                "protocol": parts[0],
                "local_address": parts[1],
                "foreign_address": parts[2]
            })
            
            if len(parts) > 3:
                connection_data["state"] = parts[3]
            
            # Extract ports
            if ':' in parts[1]:
                local_parts = parts[1].split(':')
                connection_data["local_port"] = local_parts[-1]
            
            if ':' in parts[2]:
                foreign_parts = parts[2].split(':')
                connection_data["foreign_port"] = foreign_parts[-1]
                connection_data["remote_ip"] = ':'.join(foreign_parts[:-1])
            
        except (IndexError, ValueError):
            connection_data["raw_connection_info"] = line
        
        return connection_data