"""
Network Stats Parser for dumpsys netstats output.

This parser extracts network usage statistics, data transfer patterns,
and network behavior information critical for detecting data exfiltration.
"""

import re
from typing import Iterator, Optional
from pathlib import Path

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class NetworkStatsParser(BaseParser):
    """
    Parser for Android dumpsys netstats output.
    
    Extracts network usage statistics, data transfer patterns, UID mappings,
    and network behavior data used for detecting suspicious network activity.
    """
    
    # Suspicious network patterns
    SUSPICIOUS_UPLOAD_THRESHOLD = 10 * 1024 * 1024  # 10MB upload
    HIGH_UPLOAD_RATIO_THRESHOLD = 0.8  # Upload > 80% of total traffic
    
    @property
    def parser_name(self) -> str:
        return "network_stats_parser"
    
    @property
    def parser_version(self) -> str:
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        return ParserCapabilities(
            supported_extensions={'.txt'},
            supported_mime_types={'text/plain'},
            content_patterns=[
                'NETWORK STATS',
                'dumpsys netstats',
                'uid=',
                'set=',
                'tag=',
                'rb=', 'rp=', 'tb=', 'tp='  # received/transmitted bytes/packets
            ],
            header_patterns=[
                'NETWORK STATS (dumpsys netstats)',
                'Active interfaces:',
                'Dev stats:'
            ],
            output_entry_types={
                'network_stats',
                'uid_network_usage',
                'interface_stats',
                'network_summary'
            },
            supports_streaming=True,
            memory_efficient=True,
            estimated_speed="fast"
        )
    
    def can_parse(self, file_path: Path, content_sample: str) -> bool:
        """Check if this file contains network stats output."""
        content_lower = content_sample.lower()
        
        # Skip BARGHEST WARD header and look for actual content
        if 'barghest ward adb collection' in content_lower:
            # Remove header lines and check the actual content
            lines = content_sample.split('\n')
            actual_content = '\n'.join([line for line in lines if not line.startswith('#')])
            content_lower = actual_content.lower()
        
        network_indicators = [
            'network stats',
            'dumpsys netstats',
            'active interfaces',
            'dev stats',
            'uid stats'
        ]
        
        # Check for network stats data patterns (both old and new formats)
        if any(pattern in actual_content for pattern in ['rb=', 'rp=', 'tb=', 'tp=']):
            return True
        
        # Check for new UID format: {uid=1000,package=android}=4902
        if re.search(r'\{uid=\d+,package=[^}]+\}=\d+', actual_content):
            return True

        # Check for multi-user UID patterns: uid=u0a123, uid=u10a456 (work profile)
        if re.search(r'uid=u\d+a?\d*', actual_content):
            return True
        
        return any(indicator in content_lower for indicator in network_indicators)
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse network stats file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                current_section = None
                
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Skip very long lines
                    if len(line) > 5000:
                        continue
                    
                    # Detect sections
                    section = self._detect_section(line)
                    if section:
                        current_section = section
                        continue
                    
                    # Parse based on current section
                    entry = self._parse_line_by_section(
                        line, line_num, current_section, file_path.name
                    )
                    if entry:
                        yield entry
                        
        except Exception as e:
            self.logger.error(f"Error parsing network stats file {file_path}: {e}")
            raise
    
    def _detect_section(self, line: str) -> Optional[str]:
        """Detect which section of network stats we're in."""
        line_lower = line.lower()
        
        if 'active interfaces' in line_lower:
            return 'interfaces'
        elif 'dev stats' in line_lower:
            return 'dev_stats'
        elif 'uid stats' in line_lower:
            return 'uid_stats'
        elif 'xt stats' in line_lower:
            return 'xt_stats'
        elif 'uid tag stats' in line_lower:
            return 'uid_tag_stats'
        
        return None
    
    def _parse_line_by_section(
        self,
        line: str,
        line_num: int,
        section: Optional[str],
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse line based on the current section."""
        
        if section == 'interfaces':
            return self._parse_interface_line(line, line_num, source_file)
        elif section in ['uid_stats', 'uid_tag_stats']:
            return self._parse_uid_stats_line(line, line_num, source_file)
        elif section == 'dev_stats':
            return self._parse_dev_stats_line(line, line_num, source_file)
        else:
            # Try to parse as general network stats or new UID format
            entry = self._parse_new_uid_format(line, line_num, source_file)
            if entry:
                return entry
            return self._parse_general_stats_line(line, line_num, source_file)
    
    def _parse_interface_line(
        self,
        line: str,
        line_num: int,
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse active interface information."""
        
        # Interface line format: iface=wlan0 ident=[{type=WIFI, ...}]
        iface_match = re.search(r'iface=(\w+)', line)
        if iface_match:
            interface = iface_match.group(1)
            
            parsed_content = {
                'interface': interface
            }
            
            # Extract interface type
            type_match = re.search(r'type=(\w+)', line)
            if type_match:
                parsed_content['interface_type'] = type_match.group(1)
            
            # Extract subscriber ID (for mobile networks)
            subid_match = re.search(r'subId=(\w+)', line)
            if subid_match:
                parsed_content['subscriber_id'] = subid_match.group(1)
            
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='interface_stats',
                raw_line=line,
                parsed_content=parsed_content,
                confidence=0.9
            )
        
        return None
    
    def _parse_uid_stats_line(
        self,
        line: str,
        line_num: int,
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse UID network statistics."""
        
        # UID stats format: uid=10001 set=DEFAULT tag=0x0 rb=1234 rp=56 tb=7890 tp=12
        # Multi-user format: uid=u0a123, uid=u10a456 (work profile), uid=u999a789 (guest)
        uid_match = re.search(r'uid=(u?\d+a?\d*)', line)
        if not uid_match:
            return None

        uid_str = uid_match.group(1)

        # Parse multi-user UID format
        if uid_str.startswith('u'):
            # Multi-user UID: u0a123 (primary user), u10a456 (work profile)
            user_match = re.match(r'u(\d+)a?(\d*)', uid_str)
            if user_match:
                user_id = int(user_match.group(1))
                app_id = int(user_match.group(2)) if user_match.group(2) else 0
                uid = uid_str  # Keep original format for tracking
            else:
                uid = uid_str
        else:
            # Traditional numeric UID
            try:
                uid = int(uid_str)
            except ValueError:
                uid = uid_str
        
        parsed_content = {
            'uid': uid,
            'uid_raw': uid_str
        }

        # Add multi-user information if available
        if uid_str.startswith('u'):
            user_match = re.match(r'u(\d+)a?(\d*)', uid_str)
            if user_match:
                user_id = int(user_match.group(1))
                app_id = int(user_match.group(2)) if user_match.group(2) else 0
                parsed_content['user_id'] = user_id
                parsed_content['app_id'] = app_id
                parsed_content['is_multi_user'] = True

                # Classify user type
                if user_id == 0:
                    parsed_content['user_type'] = 'primary'
                elif user_id >= 10 and user_id < 100:
                    parsed_content['user_type'] = 'work_profile'
                elif user_id >= 999:
                    parsed_content['user_type'] = 'guest'
                else:
                    parsed_content['user_type'] = 'secondary'
        else:
            parsed_content['is_multi_user'] = False
        
        # Extract network statistics
        rb_match = re.search(r'rb=(\d+)', line)  # Received bytes
        if rb_match:
            parsed_content['received_bytes'] = int(rb_match.group(1))
        
        rp_match = re.search(r'rp=(\d+)', line)  # Received packets
        if rp_match:
            parsed_content['received_packets'] = int(rp_match.group(1))
        
        tb_match = re.search(r'tb=(\d+)', line)  # Transmitted bytes
        if tb_match:
            parsed_content['transmitted_bytes'] = int(tb_match.group(1))
        
        tp_match = re.search(r'tp=(\d+)', line)  # Transmitted packets
        if tp_match:
            parsed_content['transmitted_packets'] = int(tp_match.group(1))
        
        # Extract set (foreground/background/default)
        set_match = re.search(r'set=(\w+)', line)
        if set_match:
            parsed_content['set'] = set_match.group(1)
        
        # Extract tag (application-specific tag)
        tag_match = re.search(r'tag=(0x[0-9a-fA-F]+|\d+)', line)
        if tag_match:
            tag_str = tag_match.group(1)
            try:
                if tag_str.startswith('0x'):
                    parsed_content['tag'] = int(tag_str, 16)
                else:
                    parsed_content['tag'] = int(tag_str)
            except ValueError:
                pass
        
        # Calculate derived metrics
        rx_bytes = parsed_content.get('received_bytes', 0)
        tx_bytes = parsed_content.get('transmitted_bytes', 0)
        total_bytes = rx_bytes + tx_bytes
        
        if total_bytes > 0:
            parsed_content['total_bytes'] = total_bytes
            parsed_content['upload_ratio'] = tx_bytes / total_bytes
            
            # Flag suspicious patterns
            if tx_bytes > self.SUSPICIOUS_UPLOAD_THRESHOLD:
                parsed_content['high_upload_volume'] = True
            
            if parsed_content['upload_ratio'] > self.HIGH_UPLOAD_RATIO_THRESHOLD:
                parsed_content['high_upload_ratio'] = True
            
            # Flag background data usage
            if parsed_content.get('set') == 'BACKGROUND' and total_bytes > 1024*1024:  # > 1MB
                parsed_content['significant_background_usage'] = True
        
        # Determine confidence based on data completeness
        confidence = 0.9 if all(key in parsed_content for key in ['received_bytes', 'transmitted_bytes']) else 0.7
        
        return ParsedLogEntry(
            line_number=line_num,
            source_file=source_file,
            entry_type='uid_network_usage',
            raw_line=line,
            parsed_content=parsed_content,
            confidence=confidence
        )
    
    def _parse_dev_stats_line(
        self,
        line: str,
        line_num: int,
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse device-level network statistics."""
        
        # Dev stats format: iface=wlan0 rb=12345 rp=678 tb=90123 tp=456
        iface_match = re.search(r'iface=(\w+)', line)
        if not iface_match:
            return None
        
        interface = iface_match.group(1)
        
        parsed_content = {
            'interface': interface
        }
        
        # Extract bytes and packets
        for stat_type, regex_pattern in [
            ('received_bytes', r'rb=(\d+)'),
            ('received_packets', r'rp=(\d+)'),
            ('transmitted_bytes', r'tb=(\d+)'),
            ('transmitted_packets', r'tp=(\d+)')
        ]:
            match = re.search(regex_pattern, line)
            if match:
                parsed_content[stat_type] = int(match.group(1))
        
        return ParsedLogEntry(
            line_number=line_num,
            source_file=source_file,
            entry_type='interface_stats',
            raw_line=line,
            parsed_content=parsed_content,
            confidence=0.8
        )
    
    def _parse_general_stats_line(
        self,
        line: str,
        line_num: int,
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse general network statistics lines."""
        
        line_lower = line.lower()
        
        # Parse summary statistics
        if 'total bytes' in line_lower or 'total packets' in line_lower:
            # Extract total usage numbers
            bytes_match = re.search(r'(\d+)\s*bytes', line, re.IGNORECASE)
            packets_match = re.search(r'(\d+)\s*packets', line, re.IGNORECASE)
            
            if bytes_match or packets_match:
                parsed_content = {}
                
                if bytes_match:
                    parsed_content['total_bytes'] = int(bytes_match.group(1))
                
                if packets_match:
                    parsed_content['total_packets'] = int(packets_match.group(1))
                
                return ParsedLogEntry(
                    line_number=line_num,
                    source_file=source_file,
                    entry_type='network_summary',
                    raw_line=line,
                    parsed_content=parsed_content,
                    confidence=0.7
                )
        
        # Parse interface state changes
        if any(keyword in line_lower for keyword in ['connected', 'disconnected', 'up', 'down']):
            iface_match = re.search(r'(\w+)\s+(connected|disconnected|up|down)', line, re.IGNORECASE)
            if iface_match:
                interface = iface_match.group(1)
                state = iface_match.group(2).lower()
                
                parsed_content = {
                    'interface': interface,
                    'state': state,
                    'event_type': 'interface_state_change'
                }
                
                return ParsedLogEntry(
                    line_number=line_num,
                    source_file=source_file,
                    entry_type='network_stats',
                    raw_line=line,
                    parsed_content=parsed_content,
                    confidence=0.8
                )
        
        return None
    
    def _parse_new_uid_format(
        self,
        line: str,
        line_num: int,
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse new UID format: {uid=1000,package=android}=4902"""
        
        # Match pattern: {uid=1000,package=android}=4902
        uid_match = re.search(r'\{uid=(\d+),package=([^}]+)\}=(\d+)', line)
        if not uid_match:
            return None
        
        uid = int(uid_match.group(1))
        package = uid_match.group(2)
        value = int(uid_match.group(3))
        
        parsed_content = {
            'uid': uid,
            'package': package,
            'value': value
        }
        
        # Determine what the value represents based on context
        if 'bytes' in line.lower():
            parsed_content['data_type'] = 'bytes'
        elif 'packets' in line.lower():
            parsed_content['data_type'] = 'packets'
        else:
            parsed_content['data_type'] = 'unknown'
        
        return ParsedLogEntry(
            line_number=line_num,
            source_file=source_file,
            entry_type='uid_network_usage',
            raw_line=line,
            parsed_content=parsed_content,
            confidence=0.8
        )


