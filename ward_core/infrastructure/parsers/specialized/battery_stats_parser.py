"""
Battery Stats Parser for dumpsys batterystats output.

This parser extracts battery usage data, wakelocks, jobs, alarms, and other
power-related information critical for behavioral analysis.
"""

import re
from typing import Iterator, Optional, List
from pathlib import Path

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class BatteryStatsParser(BaseParser):
    """
    Parser for Android dumpsys batterystats output, especially --checkin format.
    
    Extracts wakelocks, jobs, alarms, network usage, CPU usage, and other
    power-related data used for behavioral analysis of potentially malicious apps.
    """
    
    # Critical data types in batterystats checkin format
    CRITICAL_DATA_TYPES = {
        'wl',   # Wakelocks
        'jb',   # Jobs
        'al',   # Alarms
        'cpu',  # CPU usage
        'nt',   # Network usage
        'wfl',  # WiFi usage
        'cam',  # Camera usage
        'aud',  # Audio usage
        'sr',   # Sensors
        'fg',   # Foreground time
        'fgs',  # Foreground services
        'st',   # State changes
        'ua'    # User activity
    }
    
    # Suspicious wakelock patterns (refined for spyware detection)
    SUSPICIOUS_WAKELOCK_PATTERNS = [
        # Explicit surveillance terms
        re.compile(r'.*(spy|track|monitor|record|capture|stealth|hidden|covert|surveillance).*', re.IGNORECASE),

        # Location tracking patterns
        re.compile(r'.*(location|gps|geo|position|coordinates|latitude|longitude).*', re.IGNORECASE),

        # Data exfiltration patterns
        re.compile(r'.*(sync|upload|report|transmit|send|post|exfil|beacon).*', re.IGNORECASE),

        # Specific spyware wakelock names (from real malware analysis)
        re.compile(r'.*(background_service|data_collector|info_gatherer|system_monitor).*', re.IGNORECASE),

        # Camera/microphone abuse patterns
        re.compile(r'.*(camera|mic|audio|sensor|recording|capture).*service.*', re.IGNORECASE),

        # Suspicious job scheduler patterns (more specific than just "job")
        re.compile(r'.*(background_job|scheduled_task|periodic_job|data_job).*', re.IGNORECASE),

        # Network communication patterns
        re.compile(r'.*(network_task|http_client|socket_service|connection_manager).*', re.IGNORECASE),

        # Modern Android JobScheduler abuse patterns
        re.compile(r'.*JobScheduler.*(?:background|periodic|network|location).*', re.IGNORECASE),

        # OEM-specific suspicious patterns
        re.compile(r'.*(xiaomi_service|samsung_knox|huawei_manager).*(?:background|hidden).*', re.IGNORECASE),
    ]
    
    @property
    def parser_name(self) -> str:
        return "battery_stats_parser"
    
    @property
    def parser_version(self) -> str:
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        return ParserCapabilities(
            supported_extensions={'.txt'},
            supported_mime_types={'text/plain'},
            content_patterns=[
                'dumpsys batterystats',
                'Battery History',
                'CHECKIN BATTERYSTATS', 
                r'\d+,\d+,[il],',  # Checkin format pattern
                'Per-PID Stats:',
                'Statistics since last charge:'
            ],
            header_patterns=[
                'BATTERY HISTORY',
                'Battery History',
                'CHECKIN BATTERYSTATS',
                'Per-PID Stats:'
            ],
            output_entry_types={
                'battery_stats',
                'wakelock',
                'job_info',
                'alarm_info',
                'cpu_usage',
                'network_usage',
                'power_event'
            },
            supports_streaming=True,
            memory_efficient=True,
            estimated_speed="medium"
        )
    
    def can_parse(self, file_path: Path, content_sample: str) -> bool:
        """Check if this file contains battery stats output."""
        content_lower = content_sample.lower()
        
        # Check for battery stats indicators
        battery_indicators = [
            'dumpsys batterystats',
            'battery history',
            'checkin batterystats',
            'statistics since last charge',
            'per-pid stats'
        ]
        
        # Check for checkin format pattern
        checkin_pattern = r'\d+,\d+,[il],'
        if re.search(checkin_pattern, content_sample):
            return True
        
        return any(indicator in content_lower for indicator in battery_indicators)
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse battery stats file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                in_checkin_format = False
                
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Skip very long lines
                    if len(line) > 10000:
                        continue
                    
                    # Detect checkin format
                    if re.match(r'^\d+,\d+,[il],', line):
                        in_checkin_format = True
                        entry = self._parse_checkin_line(line, line_num, file_path.name)
                        if entry:
                            yield entry
                    
                    # Parse non-checkin format
                    elif not in_checkin_format:
                        entry = self._parse_human_readable_line(line, line_num, file_path.name)
                        if entry:
                            yield entry
                            
        except Exception as e:
            self.logger.error(f"Error parsing battery stats file {file_path}: {e}")
            raise
    
    def _parse_checkin_line(
        self,
        line: str,
        line_num: int,
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse a single checkin format line."""
        
        fields = line.split(',')
        if len(fields) < 4:
            return None
        
        try:
            battery_level = self._safe_int(fields[0])
            uid = self._safe_int(fields[1])
            line_type = fields[2].strip()
            
            # Base parsed content
            parsed_content = {
                'battery_level': battery_level,
                'uid': uid,
                'line_type': line_type,
                'checkin_format': True
            }
            
            # Parse info lines (i,...)
            if line_type == "i" and len(fields) >= 6:
                if fields[3] == "uid" and len(fields) >= 6:
                    parsed_content['real_uid'] = self._safe_int(fields[4])
                    parsed_content['package'] = fields[5]
                    
                    return ParsedLogEntry(
                        line_number=line_num,
                        source_file=source_file,
                        entry_type='battery_stats',
                        raw_line=line,
                        package=fields[5],
                        parsed_content=parsed_content,
                        confidence=0.9
                    )
            
            # Parse data lines (l,...)
            elif line_type == "l" and len(fields) >= 4:
                data_type = fields[3]
                
                # Only process critical data types
                if data_type not in self.CRITICAL_DATA_TYPES:
                    return None
                
                # Get package name from UID info or previous context
                package_name = self._get_package_from_uid(uid) if hasattr(self, '_uid_package_map') else None
                
                return self._parse_data_line(
                    fields, data_type, line_num, source_file, line, package_name
                )
            
        except (ValueError, IndexError) as e:
            self.logger.debug(f"Error parsing checkin line {line_num}: {e}")
            return None
        
        return None
    
    def _parse_data_line(
        self,
        fields: List[str],
        data_type: str,
        line_num: int,
        source_file: str,
        raw_line: str,
        package_name: Optional[str]
    ) -> Optional[ParsedLogEntry]:
        """Parse a specific data line type."""
        
        parsed_content = {
            'data_type': data_type,
            'uid': self._safe_int(fields[1]),
            'checkin_format': True
        }
        
        entry_type = 'battery_stats'
        confidence = 0.8
        
        # Wakelock lines (l,wl)
        if data_type == "wl" and len(fields) >= 8:
            wakelock_name = fields[4]
            wakelock_time = self._safe_int(fields[7])
            
            parsed_content.update({
                'wakelock_name': wakelock_name,
                'wakelock_time_ms': wakelock_time,
                'wakelock_count': self._safe_int(fields[5]) if len(fields) > 5 else 0
            })
            
            # Check for suspicious wakelock patterns
            for pattern in self.SUSPICIOUS_WAKELOCK_PATTERNS:
                if pattern.search(wakelock_name):
                    parsed_content['suspicious_wakelock'] = True
                    parsed_content['suspicious_pattern'] = pattern.pattern
                    confidence = 0.95
                    break
            
            entry_type = 'wakelock'
        
        # Job lines (l,jb)
        elif data_type == "jb" and len(fields) >= 6:
            job_name = fields[4]
            job_time = self._safe_int(fields[5])
            
            parsed_content.update({
                'job_name': job_name,
                'job_time_ms': job_time,
                'job_count': self._safe_int(fields[6]) if len(fields) > 6 else 0
            })
            
            entry_type = 'job_info'
        
        # CPU usage lines (l,cpu)
        elif data_type == "cpu" and len(fields) >= 6:
            cpu_user = self._safe_int(fields[4])
            cpu_system = self._safe_int(fields[5])
            
            parsed_content.update({
                'cpu_user_ms': cpu_user,
                'cpu_system_ms': cpu_system,
                'total_cpu_ms': cpu_user + cpu_system
            })
            
            # Flag high CPU usage
            if cpu_user + cpu_system > 3600000:  # > 1 hour
                parsed_content['high_cpu_usage'] = True
                confidence = 0.9
            
            entry_type = 'cpu_usage'
        
        # Network lines (l,nt)
        elif data_type == "nt" and len(fields) >= 6:
            mobile_rx = self._safe_int(fields[4])
            mobile_tx = self._safe_int(fields[5])
            
            parsed_content.update({
                'mobile_rx_bytes': mobile_rx,
                'mobile_tx_bytes': mobile_tx,
                'total_mobile_bytes': mobile_rx + mobile_tx
            })
            
            # Flag high data usage
            if mobile_tx > mobile_rx * 0.5:  # High upload ratio
                parsed_content['high_upload_ratio'] = True
                confidence = 0.9
            
            entry_type = 'network_usage'
        
        # Camera lines (l,cam)
        elif data_type == "cam" and len(fields) >= 6:
            camera_time = self._safe_int(fields[4])
            camera_count = self._safe_int(fields[5])
            
            parsed_content.update({
                'camera_time_ms': camera_time,
                'camera_usage_count': camera_count
            })
            
            # Flag excessive camera usage
            if camera_time > 300000:  # > 5 minutes
                parsed_content['excessive_camera_usage'] = True
                confidence = 0.9
            
            entry_type = 'power_event'
        
        # Audio lines (l,aud)
        elif data_type == "aud" and len(fields) >= 5:
            audio_time = self._safe_int(fields[4])
            
            parsed_content.update({
                'audio_time_ms': audio_time
            })
            
            # Flag excessive audio usage (potential recording)
            if audio_time > 600000:  # > 10 minutes
                parsed_content['excessive_audio_usage'] = True
                confidence = 0.9
            
            entry_type = 'power_event'
        
        # Sensor lines (l,sr)
        elif data_type == "sr" and len(fields) >= 6:
            sensor_number = self._safe_int(fields[4])
            sensor_time = self._safe_int(fields[5])
            
            parsed_content.update({
                'sensor_number': sensor_number,
                'sensor_time_ms': sensor_time
            })
            
            entry_type = 'power_event'
        
        return ParsedLogEntry(
            line_number=line_num,
            source_file=source_file,
            entry_type=entry_type,
            raw_line=raw_line,
            package=package_name,
            parsed_content=parsed_content,
            confidence=confidence
        )
    
    def _parse_human_readable_line(
        self,
        line: str,
        line_num: int,
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse human-readable (non-checkin) battery stats lines."""
        
        line_lower = line.lower()
        
        # Parse wakelock information
        wakelock_match = re.search(r'wake lock.*?(\w+.*?)\s+\((\d+)', line, re.IGNORECASE)
        if wakelock_match:
            wakelock_name = wakelock_match.group(1).strip()
            wakelock_time = int(wakelock_match.group(2))
            
            parsed_content = {
                'wakelock_name': wakelock_name,
                'wakelock_time_ms': wakelock_time
            }
            
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='wakelock',
                raw_line=line,
                parsed_content=parsed_content,
                confidence=0.8
            )
        
        # Parse app usage summaries
        if 'uid' in line_lower and any(keyword in line_lower for keyword in ['cpu', 'network', 'sensor']):
            uid_match = re.search(r'uid\s+(\d+)', line, re.IGNORECASE)
            if uid_match:
                uid = int(uid_match.group(1))
                
                parsed_content = {'uid': uid}
                
                # Extract CPU time
                cpu_match = re.search(r'cpu:\s*(\d+)ms', line, re.IGNORECASE)
                if cpu_match:
                    parsed_content['cpu_time_ms'] = int(cpu_match.group(1))
                
                # Extract network usage
                network_match = re.search(r'network:\s*(\d+)\s*bytes', line, re.IGNORECASE)
                if network_match:
                    parsed_content['network_bytes'] = int(network_match.group(1))
                
                return ParsedLogEntry(
                    line_number=line_num,
                    source_file=source_file,
                    entry_type='battery_stats',
                    raw_line=line,
                    parsed_content=parsed_content,
                    confidence=0.7
                )
        
        return None
    
    def _safe_int(self, value: str) -> int:
        """Safely convert string to int."""
        try:
            return int(value)
        except (ValueError, TypeError):
            return 0
    
    def _get_package_from_uid(self, uid: int) -> Optional[str]:
        """Get package name from UID (if mapping available)."""
        # This would use a UID to package mapping if available
        # For now, return None as mapping needs to be built from package data
        return None


