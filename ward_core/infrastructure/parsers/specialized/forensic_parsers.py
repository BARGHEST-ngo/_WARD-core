"""
Forensic-specific parsers for security-critical ADB outputs.

These parsers handle specialized forensic data sources that are critical
for security analysis and threat detection.
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class DmesgParser(BaseParser):
    """Parser for kernel message buffer (dmesg output)."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.supported_formats = ["txt"]
    
    @property
    def parser_name(self) -> str:
        """Get the name of this parser."""
        return "dmesg_parser"
    
    @property
    def parser_version(self) -> str:
        """Get the version of this parser."""
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=['shell_dmesg'],
            output_entry_types={'kernel_message'}
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the file."""
        return 'shell_dmesg.txt' in file_path.name
    
    def get_confidence_score(self, file_path: Path) -> float:
        """Get confidence score for parsing this file."""
        if self.can_parse(file_path):
            return 0.95  # Very high confidence for dmesg
        return 0.0
    
    def parse_file(self, file_path: Path) -> List[ParsedLogEntry]:
        """Parse dmesg kernel messages."""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse dmesg entry
                dmesg_data = self._parse_dmesg_line(line)
                if dmesg_data:
                    tags = {"kernel_messages", "dmesg"}
                    
                    if "error" in dmesg_data.get('level', '').lower():
                        tags.add("kernel_error")
                    
                    entry = ParsedLogEntry(
                        line_number=line_num,
                        source_file=str(file_path),
                        entry_type="kernel_message",
                        timestamp=dmesg_data.get('timestamp'),
                        raw_line=line,
                        parsed_content=dmesg_data,
                        confidence=0.95,
                        tags=tags
                    )
                    entries.append(entry)
        
        except Exception as e:
            self.logger.error(f"Error parsing dmesg: {e}")
        
        return entries
    
    def _parse_dmesg_line(self, line: str) -> Dict[str, Any]:
        """Parse a single dmesg line."""
        dmesg_data = {"raw_message": line}
        
        # Parse timestamp format: [12345.678901] message
        timestamp_match = re.match(r'^\[([0-9.]+)\]\s*(.*)$', line)
        if timestamp_match:
            boot_time = float(timestamp_match.group(1))
            message = timestamp_match.group(2)
            
            dmesg_data.update({
                "boot_time_seconds": boot_time,
                "message": message
            })
            
            # Try to convert boot time to approximate timestamp
            # This is rough since we don't know exact boot time
            try:
                approx_timestamp = datetime.now().timestamp() - boot_time
                dmesg_data["approximate_timestamp"] = datetime.fromtimestamp(approx_timestamp).isoformat()
            except (ValueError, OverflowError):
                pass
        else:
            dmesg_data["message"] = line
        
        # Extract log level and facility
        message = dmesg_data.get('message', '')
        
        # Look for log level indicators
        level_patterns = {
            'emergency': r'\bemerg\b|\bpanic\b',
            'alert': r'\balert\b',
            'critical': r'\bcrit\b|\bfatal\b',
            'error': r'\berr\b|\berror\b|\bfailed\b',
            'warning': r'\bwarn\b|\bwarning\b',
            'notice': r'\bnotice\b',
            'info': r'\binfo\b',
            'debug': r'\bdebug\b'
        }
        
        for level, pattern in level_patterns.items():
            if re.search(pattern, message, re.IGNORECASE):
                dmesg_data["level"] = level
                break
        
        # Extract subsystem/driver information
        subsystem_match = re.search(r'(\w+):\s*(.+)', message)
        if subsystem_match:
            dmesg_data["subsystem"] = subsystem_match.group(1)
            dmesg_data["subsystem_message"] = subsystem_match.group(2)
        
        return dmesg_data


class BinderParser(BaseParser):
    """Parser for Android Binder IPC information."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.supported_formats = ["txt"]
    
    @property
    def parser_name(self) -> str:
        """Get the name of this parser."""
        return "binder_parser"
    
    @property
    def parser_version(self) -> str:
        """Get the version of this parser."""
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=['shell_binder'],
            output_entry_types={'binder_transaction'}
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the file."""
        return 'shell_binder.txt' in file_path.name
    
    def get_confidence_score(self, file_path: Path) -> float:
        """Get confidence score for parsing this file."""
        if self.can_parse(file_path):
            return 0.8  # Good confidence for binder data
        return 0.0
    
    def parse_file(self, file_path: Path) -> List[ParsedLogEntry]:
        """Parse binder IPC information."""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse binder entry
                binder_data = self._parse_binder_line(line)
                if binder_data:
                    tags = {"binder_ipc", "inter_process_communication"}
                    
                    entry = ParsedLogEntry(
                        line_number=line_num,
                        source_file=str(file_path),
                        entry_type="binder_transaction",
                        timestamp=None,
                        raw_line=line,
                        parsed_content=binder_data,
                        confidence=0.8,
                        tags=tags
                    )
                    entries.append(entry)
        
        except Exception as e:
            self.logger.error(f"Error parsing binder data: {e}")
        
        return entries
    
    def _parse_binder_line(self, line: str) -> Dict[str, Any]:
        """Parse a single binder line."""
        binder_data = {"raw_binder_info": line}
        
        # Look for binder transaction patterns
        if 'proc' in line and 'thread' in line:
            proc_match = re.search(r'proc (\d+)', line)
            thread_match = re.search(r'thread (\d+)', line)
            
            if proc_match:
                binder_data["process_id"] = proc_match.group(1)
            if thread_match:
                binder_data["thread_id"] = thread_match.group(1)
        
        # Look for transaction information
        if 'transaction' in line:
            binder_data["entry_type"] = "transaction"
        elif 'node' in line:
            binder_data["entry_type"] = "node"
        elif 'ref' in line:
            binder_data["entry_type"] = "reference"
        
        return binder_data


class SensorServiceParser(BaseParser):
    """Parser for sensor service information."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.supported_formats = ["txt"]
    
    @property
    def parser_name(self) -> str:
        """Get the name of this parser."""
        return "sensor_service_parser"
    
    @property
    def parser_version(self) -> str:
        """Get the version of this parser."""
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=['shell_sensorservice'],
            output_entry_types={'sensor_info'}
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the file."""
        return 'shell_sensorservice.txt' in file_path.name
    
    def get_confidence_score(self, file_path: Path) -> float:
        """Get confidence score for parsing this file."""
        if self.can_parse(file_path):
            return 0.8  # Good confidence for sensor data
        return 0.0
    
    def parse_file(self, file_path: Path) -> List[ParsedLogEntry]:
        """Parse sensor service information."""
        entries = []
        current_sensor = None
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse sensor entries
                if line.startswith('Sensor List:') or 'sensors:' in line.lower():
                    continue
                
                sensor_data = self._parse_sensor_line(line, current_sensor)
                if sensor_data:
                    tags = {"sensors", "hardware_access"}
                    
                    entry = ParsedLogEntry(
                        line_number=line_num,
                        source_file=str(file_path),
                        entry_type="sensor_info",
                        timestamp=None,
                        raw_line=line,
                        parsed_content=sensor_data,
                        confidence=0.8,
                        tags=tags
                    )
                    entries.append(entry)
                    
                    # Track current sensor for multi-line parsing
                    if 'sensor_name' in sensor_data:
                        current_sensor = sensor_data['sensor_name']
        
        except Exception as e:
            self.logger.error(f"Error parsing sensor service: {e}")
        
        return entries
    
    def _parse_sensor_line(self, line: str, current_sensor: str = None) -> Dict[str, Any]:
        """Parse a single sensor line."""
        sensor_data = {}
        
        # Look for sensor identification
        if re.match(r'^\d+\)', line) or 'Sensor{' in line:
            # New sensor entry
            sensor_data["sensor_info"] = line
            
            # Extract sensor name
            name_match = re.search(r'name="([^"]+)"', line)
            if name_match:
                sensor_data["sensor_name"] = name_match.group(1)
            
            # Extract sensor type
            type_match = re.search(r'type=(\d+)', line)
            if type_match:
                sensor_data["sensor_type"] = type_match.group(1)
                sensor_data["sensor_type_name"] = self._get_sensor_type_name(int(type_match.group(1)))
            
            # Extract vendor
            vendor_match = re.search(r'vendor="([^"]+)"', line)
            if vendor_match:
                sensor_data["vendor"] = vendor_match.group(1)
        
        elif current_sensor and ('rate' in line or 'power' in line or 'resolution' in line):
            # Sensor properties
            sensor_data["sensor_name"] = current_sensor
            sensor_data["property_info"] = line
            
            # Extract specific properties
            if 'maxDelay' in line:
                delay_match = re.search(r'maxDelay=(\d+)', line)
                if delay_match:
                    sensor_data["max_delay_us"] = int(delay_match.group(1))
        
        else:
            # General sensor information
            sensor_data["sensor_detail"] = line
        
        return sensor_data
    
    def _get_sensor_type_name(self, sensor_type: int) -> str:
        """Map sensor type ID to human-readable name."""
        sensor_types = {
            1: "ACCELEROMETER",
            2: "MAGNETIC_FIELD", 
            3: "ORIENTATION",
            4: "GYROSCOPE",
            5: "LIGHT",
            6: "PRESSURE",
            7: "TEMPERATURE",
            8: "PROXIMITY",
            9: "GRAVITY",
            10: "LINEAR_ACCELERATION",
            11: "ROTATION_VECTOR",
            12: "RELATIVE_HUMIDITY",
            13: "AMBIENT_TEMPERATURE",
            14: "MAGNETIC_FIELD_UNCALIBRATED",
            15: "GAME_ROTATION_VECTOR",
            16: "GYROSCOPE_UNCALIBRATED",
            17: "SIGNIFICANT_MOTION",
            18: "STEP_DETECTOR",
            19: "STEP_COUNTER",
            20: "GEOMAGNETIC_ROTATION_VECTOR"
        }
        return sensor_types.get(sensor_type, f"UNKNOWN_TYPE_{sensor_type}")


class NetworkPolicyParser(BaseParser):
    """Parser for network policy information."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.supported_formats = ["txt"]
    
    @property
    def parser_name(self) -> str:
        """Get the name of this parser."""
        return "network_policy_parser"
    
    @property
    def parser_version(self) -> str:
        """Get the version of this parser."""
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=['shell_network_policy'],
            output_entry_types={'network_policy'}
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the file."""
        return 'shell_network_policy.txt' in file_path.name
    
    def get_confidence_score(self, file_path: Path) -> float:
        """Get confidence score for parsing this file."""
        if self.can_parse(file_path):
            return 0.85  # High confidence for network policy
        return 0.0
    
    def parse_file(self, file_path: Path) -> List[ParsedLogEntry]:
        """Parse network policy information."""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse policy entry
                policy_data = self._parse_policy_line(line)
                if policy_data:
                    tags = {"network_policy", "data_usage"}
                    
                    entry = ParsedLogEntry(
                        line_number=line_num,
                        source_file=str(file_path),
                        entry_type="network_policy",
                        timestamp=None,
                        raw_line=line,
                        parsed_content=policy_data,
                        confidence=0.85,
                        tags=tags
                    )
                    
                    # Extract UID or package info
                    if 'uid' in policy_data:
                        entry.package = f"uid_{policy_data['uid']}"
                    
                    entries.append(entry)
        
        except Exception as e:
            self.logger.error(f"Error parsing network policy: {e}")
        
        return entries
    
    def _parse_policy_line(self, line: str) -> Dict[str, Any]:
        """Parse a single network policy line."""
        policy_data = {"raw_policy": line}
        
        # Look for UID-based policies
        uid_match = re.search(r'uid=(\d+)', line)
        if uid_match:
            policy_data["uid"] = uid_match.group(1)
        
        # Look for policy flags
        if 'REJECT' in line:
            policy_data["policy_type"] = "REJECT"
        elif 'ALLOW' in line:
            policy_data["policy_type"] = "ALLOW"
        elif 'METERED' in line:
            policy_data["policy_type"] = "METERED"
        
        # Look for data usage information
        bytes_match = re.search(r'(\d+)\s*bytes', line)
        if bytes_match:
            policy_data["bytes_used"] = int(bytes_match.group(1))
        
        return policy_data