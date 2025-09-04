"""
AppOps Parser for dumpsys appops output.

This parser extracts AppOps (App Operations) data showing which apps have used
sensitive permissions and when, crucial for privacy and security analysis.
"""

import re
from typing import Iterator, Dict, Optional, List
from pathlib import Path
from datetime import datetime, timedelta

from ..base_parser import BaseParser, ParsedLogEntry, ParseError, FileTooBigError, EncodingError, ParserCapabilities


class AppOpsParser(BaseParser):
    """
    Parser for Android dumpsys appops output.
    
    Extracts app operations data showing permission usage, access times,
    and app behavior patterns related to sensitive operations.
    """
    
    # Critical AppOps operations for security analysis (expanded for modern Android)
    CRITICAL_APPOPS = {
        # Location operations
        'COARSE_LOCATION', 'FINE_LOCATION', 'GPS', 'ACCESS_BACKGROUND_LOCATION',

        # Audio/Video operations
        'CAMERA', 'RECORD_AUDIO', 'MICROPHONE', 'CAPTURE_AUDIO_OUTPUT',

        # Communication operations
        'READ_PHONE_STATE', 'CALL_PHONE', 'READ_SMS', 'SEND_SMS', 'WRITE_SMS',
        'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_CALL_LOG', 'WRITE_CALL_LOG',
        'READ_CALENDAR', 'WRITE_CALENDAR', 'ANSWER_PHONE_CALLS',

        # Account and system operations
        'GET_ACCOUNTS', 'MANAGE_ACCOUNTS', 'SYSTEM_ALERT_WINDOW', 'WRITE_SETTINGS',
        'WRITE_SECURE_SETTINGS', 'DEVICE_POWER', 'BIND_ACCESSIBILITY_SERVICE',

        # Modern Android 11+ operations
        'MANAGE_EXTERNAL_STORAGE', 'QUERY_ALL_PACKAGES', 'AUTO_REVOKE_PERMISSIONS_IF_UNUSED',
        'ACCESS_RESTRICTED_SETTINGS', 'SCHEDULE_EXACT_ALARM', 'USE_BIOMETRIC',

        # Network and connectivity
        'CHANGE_WIFI_STATE', 'ACCESS_WIFI_STATE', 'BLUETOOTH_SCAN', 'BLUETOOTH_CONNECT',

        # Storage operations
        'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'MANAGE_MEDIA',

        # Surveillance-related operations
        'GET_USAGE_STATS', 'PACKAGE_USAGE_STATS', 'ACTIVITY_RECOGNITION',
        'BIND_NOTIFICATION_LISTENER_SERVICE', 'PROJECT_MEDIA', 'TOAST_WINDOW',

        # Background operations
        'RUN_IN_BACKGROUND', 'START_FOREGROUND', 'WAKE_LOCK', 'TURN_SCREEN_ON',

        # OEM-specific operations (common patterns)
        'XIAOMI_AUTO_START', 'SAMSUNG_KNOX_OPERATION', 'HUAWEI_POWER_MANAGER',
        'MIUI_BACKGROUND_START_ACTIVITY', 'OPPO_AUTO_START', 'VIVO_BACKGROUND_APP_CONTROL'
    }
    
    # Privacy-sensitive operations
    PRIVACY_SENSITIVE = {
        'COARSE_LOCATION', 'FINE_LOCATION', 'GPS',
        'CAMERA', 'RECORD_AUDIO', 'MICROPHONE', 
        'READ_PHONE_STATE', 'READ_SMS', 'READ_CONTACTS',
        'READ_CALL_LOG', 'READ_CALENDAR', 'GET_ACCOUNTS'
    }
    
    # OEM-specific duration patterns for real-world compatibility
    OEM_DURATION_PATTERNS = {
        'samsung': re.compile(r'duration=\+(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?'),
        'xiaomi': re.compile(r'time_used=(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?'),
        'huawei': re.compile(r'usage_time=(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?'),
        'oneplus': re.compile(r'duration=\+(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?'),
        'generic': re.compile(r'(?:duration|time|usage)[=:].*?(\d+).*?(?:h|hour|m|min|s|sec)')
    }
    
    # Access pattern for multi-line parsing
    ACCESS_PATTERN = re.compile(r'Access:\s*(\w+)\s*=\s*([^()]+)\s*\(([^)]+)\)')
    # Pattern for indented access states (without "Access:" prefix)
    INDENTED_ACCESS_PATTERN = re.compile(r'^\s*(\w+)\s*=\s*([^()]+)\s*\(([^)]+)\)')
    
    @property
    def parser_name(self) -> str:
        return "appops_parser"
    
    @property
    def parser_version(self) -> str:
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        return ParserCapabilities(
            supported_extensions={'.txt'},
            supported_mime_types={'text/plain'},
            content_patterns=[
                'APP OPS MANAGER',
                'dumpsys appops',
                'Current AppOps Service state:',  # BARGHEST format
                'Package ',                        # BARGHEST format
                'uid=',
                'op=',
                'mode=',
                'time=',
                'Access:',                        # BARGHEST format
                'duration='                       # BARGHEST format
            ],
            header_patterns=[
                'APP OPS MANAGER (dumpsys appops)',
                'Current AppOps Service state:'
            ],
            output_entry_types={
                'appops_entry',
                'appops_summary',
                'permission_usage'
            },
            supports_streaming=True,
            memory_efficient=True,
            estimated_speed="fast"
        )
    
    def can_parse(self, file_path: Path, content_sample: str) -> bool:
        """Check if this file contains AppOps output."""
        content_lower = content_sample.lower()
        
        # Skip BARGHEST WARD header and look for actual content
        if 'barghest ward adb collection' in content_lower:
            # Remove header lines and check the actual content
            lines = content_sample.split('\n')
            actual_content = '\n'.join([line for line in lines if not line.startswith('#')])
            content_lower = actual_content.lower()
        else:
            actual_content = content_sample

        # Check for error output first - if it's an error file, don't parse it
        if self._is_error_file(actual_content):
            self.logger.info(f"Skipping AppOps file {file_path.name} - contains error output")
            return False
        
        appops_indicators = [
            'app ops manager',
            'dumpsys appops',
            'current appops service',
            'uid=',
            'package ',
            'op=',
            'mode='
        ]
        
        # Must have at least one specific appops indicator
        has_appops_indicator = any(indicator in content_lower for indicator in appops_indicators)
        
        # Additional check: must have appops-specific patterns (the actual format used)
        has_appops_patterns = any(pattern in actual_content for pattern in [
            ' (allow):', ' (deny):', ' (default):',  # New format: OPERATION (mode):
            'op=', 'mode='  # Old format
        ])
        
        # Additional check: must NOT have network-specific patterns (to avoid false matches)
        has_network_patterns = any(pattern in actual_content for pattern in ['rb=', 'rp=', 'tb=', 'tp='])
        
        # Additional check: must NOT have logcat-specific patterns (to avoid conflicts)
        has_logcat_patterns = any(pattern in actual_content for pattern in ['I/', 'D/', 'W/', 'E/', 'V/', 'F/'])
        
        return has_appops_indicator and has_appops_patterns and not has_network_patterns and not has_logcat_patterns

    def _is_error_file(self, content: str) -> bool:
        """Check if the file contains error output instead of actual AppOps data."""
        content_lower = content.lower().strip()

        # Check for common error patterns
        error_patterns = [
            'unknown option',
            'invalid option',
            'command not found',
            'permission denied',
            'service not found',
            'failed to',
            'error:',
            'exception:',
            'usage:'
        ]

        # If content is very short and contains error patterns, it's likely an error
        if len(content.strip()) < 200:
            for pattern in error_patterns:
                if pattern in content_lower:
                    return True

        # Specific check for the "--uid" error case
        if 'unknown option: --uid' in content_lower:
            return True

        # Check for other dumpsys appops error patterns
        if 'total number of currently running services:0' in content_lower and len(content.strip()) < 100:
            return True

        return False
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse dumpsys appops file with multi-line support."""
        # Use streaming for large files (>10MB)
        if file_path.stat().st_size > 10 * 1024 * 1024:
            yield from self._parse_file_streaming(file_path)
        else:
            yield from self._parse_file_memory(file_path)

    def _parse_file_memory(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse file by loading into memory (for smaller files)."""
        try:
            # Check file size limits
            file_size_mb = file_path.stat().st_size / (1024 * 1024)
            if file_size_mb > 50:  # 50MB limit for memory parsing
                raise FileTooBigError(file_path, file_size_mb, 50)

            # Attempt to read with proper encoding handling
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
            except UnicodeDecodeError as e:
                # Try alternative encodings
                for encoding in ['latin1', 'cp1252', 'utf-16']:
                    try:
                        with open(file_path, 'r', encoding=encoding) as f:
                            lines = f.readlines()
                        break
                    except UnicodeDecodeError:
                        continue
                else:
                    raise EncodingError(file_path, str(e))

            # Validate line count
            if len(lines) > 100000:  # 100k lines limit
                self.logger.warning(f"Large file {file_path.name} has {len(lines)} lines, may impact performance")

            yield from self._parse_lines(lines, file_path)

        except (FileTooBigError, EncodingError):
            raise  # Re-raise specific errors
        except Exception as e:
            self.logger.error(f"Error parsing appops file {file_path}: {e}")
            raise ParseError(f"Failed to parse AppOps file: {e}", file_path)

    def _parse_file_streaming(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse file using streaming approach (for larger files)."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = []
                for line in f:
                    lines.append(line)
                    # Process in chunks to avoid memory issues
                    if len(lines) >= 1000:
                        yield from self._parse_lines(lines, file_path)
                        lines = []

                # Process remaining lines
                if lines:
                    yield from self._parse_lines(lines, file_path)

        except Exception as e:
            self.logger.error(f"Error streaming appops file {file_path}: {e}")
            raise

    def _parse_lines(self, lines: List[str], file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse a list of lines from AppOps output."""
        current_uid = None
        current_package = None
        current_operation = None
        current_operation_data = {}

        try:
            
            for line_num, line in enumerate(lines, 1):
                original_line = line
                line = line.strip()
                if not line:
                    continue
                
                # Skip very long lines
                if len(line) > 5000:
                    continue
                
                # Parse UID headers: "Uid 1000:" or "Uid u0a65:"
                uid_match = re.search(r'Uid\s+([\w]+):', line)
                if uid_match:
                    uid_str = uid_match.group(1)
                    try:
                        current_uid = int(uid_str)
                    except ValueError:
                        # Handle user IDs like u0a65
                        current_uid = uid_str
                    current_package = None
                    current_operation = None
                    current_operation_data = {}
                    continue
                
                # Parse package headers: "Package com.example.app:"
                package_match = re.search(r'Package\s+([\w.]+):', line)
                if package_match:
                    current_package = package_match.group(1)
                    current_operation = None
                    current_operation_data = {}
                    
                    # Yield package header entry
                    yield ParsedLogEntry(
                        line_number=line_num,
                        source_file=file_path.name,
                        entry_type='appops_package_header',
                        raw_line=line,
                        package=current_package,
                        parsed_content={
                            'package': current_package,
                            'uid': current_uid
                        },
                        confidence=0.9
                    )
                    continue
                
                # Parse main AppOps entry format: "OPERATION_NAME (mode):" or "OPERATION_NAME (mode / switch ...):"
                appops_match = re.search(r'([A-Z_]+)\s*\(([a-z]+)(?:\s*/\s*switch\s+[^)]+)?\):', line)
                if appops_match:
                    # If we have a previous operation with data, yield it
                    if current_operation and current_operation_data:
                        yield self._create_appops_entry(
                            line_num, file_path.name, current_uid, current_package,
                            current_operation, current_operation_data
                        )
                    
                    # Start new operation
                    operation = appops_match.group(1)
                    mode = appops_match.group(2).lower()
                    
                    current_operation = operation
                    current_operation_data = {
                        'operation': operation,
                        'mode': mode,
                        'uid': current_uid,
                        'package': current_package,
                        'access_states': [],
                        'duration_secs': None,
                        'raw_line': line
                    }
                    continue
                
                # Parse access patterns from indented lines (exactly 10 spaces)
                if current_operation and original_line.startswith('          Access:'):
                    access_match = self.ACCESS_PATTERN.search(line)
                    if access_match:
                        access_type = access_match.group(1)  # top, fgsvc, bg, cch, etc.
                        timestamp_str = access_match.group(2).strip()
                        relative_time_str = access_match.group(3).strip()

                        current_operation_data['access_states'].append(access_type)
                        current_operation_data['raw_line'] += '\n' + line

                        # Store timestamp information for behavioral analysis
                        if 'timestamps' not in current_operation_data:
                            current_operation_data['timestamps'] = {}
                        current_operation_data['timestamps'][access_type] = {
                            'timestamp': timestamp_str,
                            'relative_time': relative_time_str
                        }
                    continue

                # Parse reject patterns from indented lines (exactly 10 spaces)
                if current_operation and original_line.startswith('          Reject:'):
                    reject_match = self.ACCESS_PATTERN.search(line.replace('Reject:', 'Access:'))
                    if reject_match:
                        access_type = reject_match.group(1)  # top, fgsvc, bg, cch, etc.
                        timestamp_str = reject_match.group(2).strip()
                        relative_time_str = reject_match.group(3).strip()

                        # Track rejections separately
                        if 'rejections' not in current_operation_data:
                            current_operation_data['rejections'] = []
                        current_operation_data['rejections'].append(access_type)
                        current_operation_data['raw_line'] += '\n' + line

                        # Store rejection timestamp information
                        if 'reject_timestamps' not in current_operation_data:
                            current_operation_data['reject_timestamps'] = {}
                        current_operation_data['reject_timestamps'][access_type] = {
                            'timestamp': timestamp_str,
                            'relative_time': relative_time_str
                        }
                    continue
                
                # Parse indented access states (without "Access:" prefix)
                if current_operation and original_line.startswith('                  '):
                    indented_access_match = self.INDENTED_ACCESS_PATTERN.search(line)
                    if indented_access_match:
                        access_type = indented_access_match.group(1)  # fgsvc, bg, cch, fg, etc.
                        timestamp_str = indented_access_match.group(2).strip()
                        relative_time_str = indented_access_match.group(3).strip()

                        # Only add if it's a valid access type
                        if access_type in ['top', 'fgsvc', 'bg', 'cch', 'fg', 'pers']:
                            current_operation_data['access_states'].append(access_type)
                            current_operation_data['raw_line'] += '\n' + line

                            # Store timestamp information for behavioral analysis
                            if 'timestamps' not in current_operation_data:
                                current_operation_data['timestamps'] = {}
                            current_operation_data['timestamps'][access_type] = {
                                'timestamp': timestamp_str,
                                'relative_time': relative_time_str
                            }
                    continue
                
                # Parse duration patterns from indented lines (exactly 10 spaces)
                if current_operation and original_line.startswith('          ') and ('duration=' in line or 'time_used=' in line or 'usage_time=' in line):
                    duration_secs = self._parse_duration_multi_oem(line)
                    if duration_secs:
                        current_operation_data['duration_secs'] = duration_secs
                        current_operation_data['raw_line'] += '\n' + line
                    continue
            
            # Yield the last operation if it has data
            if current_operation and current_operation_data:
                yield self._create_appops_entry(
                    len(lines), file_path.name, current_uid, current_package,
                    current_operation, current_operation_data
                )
                        
        except Exception as e:
            self.logger.error(f"Error parsing appops file {file_path}: {e}")
            raise
    
    def _create_appops_entry(self, line_num: int, source_file: str, current_uid, current_package: str, 
                           operation: str, operation_data: Dict) -> ParsedLogEntry:
        """Create a ParsedLogEntry for an AppOps operation."""
        
        # Calculate ratios from access states
        access_states = operation_data.get('access_states', [])
        if access_states:
            total_states = len(access_states)
            operation_data['bg_ratio'] = access_states.count('bg') / total_states
            operation_data['fgsvc_ratio'] = access_states.count('fgsvc') / total_states
            operation_data['top_ratio'] = access_states.count('top') / total_states
            operation_data['cch_ratio'] = access_states.count('cch') / total_states
            operation_data['fg_ratio'] = access_states.count('fg') / total_states
        else:
            operation_data['bg_ratio'] = 0
            operation_data['fgsvc_ratio'] = 0
            operation_data['top_ratio'] = 0
            operation_data['cch_ratio'] = 0
            operation_data['fg_ratio'] = 0
        
        # Determine entry type and add security flags
        entry_type = 'appops_entry'
        confidence = 0.9
        
        # Flag critical operations
        if operation in self.CRITICAL_APPOPS:
            operation_data['is_critical'] = True
            confidence = 0.95
        
        # Flag privacy-sensitive operations
        if operation in self.PRIVACY_SENSITIVE:
            operation_data['is_privacy_sensitive'] = True
        
        # Flag suspicious patterns
        if operation_data.get('mode') == 'allow' and operation in self.CRITICAL_APPOPS:
            operation_data['allowed_critical_op'] = True
        
        # Add UID information to operation data
        operation_data['uid'] = current_uid

        return ParsedLogEntry(
            line_number=line_num,
            source_file=source_file,
            entry_type=entry_type,
            raw_line=operation_data.get('raw_line', ''),
            package=current_package,
            parsed_content=operation_data,
            confidence=confidence
        )
    
    def _parse_duration_multi_oem(self, line: str) -> Optional[int]:
        """Parse duration using multiple OEM-specific patterns."""
        
        # Try Samsung/OnePlus pattern first (most common)
        match = self.OEM_DURATION_PATTERNS['samsung'].search(line)
        if match:
            return self._convert_duration_to_seconds(match)
        
        # Try Xiaomi pattern
        match = self.OEM_DURATION_PATTERNS['xiaomi'].search(line)
        if match:
            return self._convert_duration_to_seconds(match)
        
        # Try Huawei pattern
        match = self.OEM_DURATION_PATTERNS['huawei'].search(line)
        if match:
            return self._convert_duration_to_seconds(match)
        
        # Try generic pattern as fallback
        match = self.OEM_DURATION_PATTERNS['generic'].search(line)
        if match:
            return self._convert_duration_to_seconds(match)
        
        return None
    
    def _convert_duration_to_seconds(self, match) -> int:
        """Convert duration match groups to total seconds."""
        hours = int(match.group(1)) if match.group(1) else 0
        minutes = int(match.group(2)) if match.group(2) else 0
        seconds = int(match.group(3)) if match.group(3) else 0
        milliseconds = int(match.group(4)) if len(match.groups()) > 3 and match.group(4) else 0
        
        total_seconds = hours * 3600 + minutes * 60 + seconds + (milliseconds / 1000)
        return int(total_seconds)
    
    def _parse_relative_time(self, relative_time: str) -> Optional[datetime]:
        """Parse relative time string into datetime."""
        try:
            # Handle formats like "-35d22h26m7s953ms" or "-1d0h3m21s891ms"
            if not relative_time.startswith('-'):
                return None
            
            # Remove the minus sign
            time_str = relative_time[1:]
            
            # Extract components
            days = 0
            hours = 0
            minutes = 0
            seconds = 0
            
            # Parse days
            d_match = re.search(r'(\d+)d', time_str)
            if d_match:
                days = int(d_match.group(1))
            
            # Parse hours
            h_match = re.search(r'(\d+)h', time_str)
            if h_match:
                hours = int(h_match.group(1))
            
            # Parse minutes
            m_match = re.search(r'(\d+)m', time_str)
            if m_match:
                minutes = int(m_match.group(1))
            
            # Parse seconds
            s_match = re.search(r'(\d+)s', time_str)
            if s_match:
                seconds = int(s_match.group(1))
            
            # Calculate the time
            total_seconds = days * 86400 + hours * 3600 + minutes * 60 + seconds
            return datetime.now() - timedelta(seconds=total_seconds)
            
        except Exception:
            return None
