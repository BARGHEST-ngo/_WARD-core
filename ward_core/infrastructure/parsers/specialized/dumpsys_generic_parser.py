"""
Generic Dumpsys Parser for various Android system services.

This parser handles dumpsys output from services that don't have specialized parsers,
extracting common patterns and service-specific information.
"""

import re
from typing import Iterator, Dict, Optional, Set
from pathlib import Path

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class DumpsysGenericParser(BaseParser):
    """
    Generic parser for Android dumpsys output from various services.
    
    Handles common dumpsys patterns and extracts relevant information
    from services like alarm, jobscheduler, power, connectivity, etc.
    """
    
    # Service types and their indicators
    SERVICE_INDICATORS = {
        'alarm': ['ALARM MANAGER', 'alarm manager', 'alarm=', 'alarms:'],
        'jobscheduler': ['JOB SCHEDULER', 'job scheduler', 'job=', 'jobs:'],
        'power': ['POWER MANAGER', 'power manager', 'wake locks', 'wakelocks'],
        'connectivity': ['CONNECTIVITY MANAGER', 'connectivity', 'networks:', 'wifi'],
        'location': ['LOCATION MANAGER', 'location manager', 'providers:', 'gps'],
        'window': ['WINDOW MANAGER', 'window manager', 'windows:', 'activities'],
        'device_policy': ['DEVICE POLICY', 'device policy', 'admin='],
        'notification': ['NOTIFICATION MANAGER', 'notifications:', 'channels:'],
        'usage': ['USAGE STATS', 'usage stats', 'package usage'],
        'meminfo': ['MEMINFO', 'memory info', 'total pss:', 'heap size:'],
        'cpuinfo': ['CPUINFO', 'cpu info', 'cpu usage', 'load average']
    }
    
    # Common patterns to extract across services
    COMMON_PATTERNS = {
        'uid_pattern': re.compile(r'uid[=:\s]+(\d+)', re.IGNORECASE),
        'package_pattern': re.compile(r'(?:package|pkg)[=:\s]+([\w.]+)', re.IGNORECASE),
        'time_pattern': re.compile(r'(\d+(?:\.\d+)?)\s*(?:ms|sec|min|hr|hours?|minutes?|seconds?)', re.IGNORECASE),
        'count_pattern': re.compile(r'count[=:\s]+(\d+)', re.IGNORECASE),
        'size_pattern': re.compile(r'(\d+(?:\.\d+)?)\s*(?:kb|mb|gb|bytes?)', re.IGNORECASE)
    }
    
    @property
    def parser_name(self) -> str:
        return "dumpsys_generic_parser"
    
    @property
    def parser_version(self) -> str:
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        return ParserCapabilities(
            supported_extensions={'.txt'},
            supported_mime_types={'text/plain'},
            content_patterns=[
                'ALARM MANAGER',
                'JOB SCHEDULER', 
                'POWER MANAGER',
                'CONNECTIVITY MANAGER',
                'WINDOW MANAGER',
                'dumpsys',
                'uid=',
                'package='
            ],
            header_patterns=[
                r'\w+ MANAGER \(',
                'dumpsys',
                'service:'
            ],
            output_entry_types={
                'dumpsys_data',
                'service_info',
                'system_resource',
                'service_event'
            },
            supports_streaming=True,
            memory_efficient=True,
            estimated_speed="medium"
        )
    
    def can_parse(self, file_path: Path, content_sample: str) -> bool:
        """Check if this file contains dumpsys output."""
        content_lower = content_sample.lower()
        
        # Skip BARGHEST WARD header and look for actual content
        if 'barghest ward adb collection' in content_lower:
            # Remove header lines and check the actual content
            lines = content_sample.split('\n')
            actual_content = '\n'.join([line for line in lines if not line.startswith('#')])
            content_lower = actual_content.lower()
        
        # Check for dumpsys service indicators
        for service, indicators in self.SERVICE_INDICATORS.items():
            if any(indicator in content_lower for indicator in indicators):
                return True
        
        # Check for general dumpsys patterns
        dumpsys_patterns = [
            'dumpsys',
            'uid=',
            'package=',
            r'\w+ MANAGER \('
        ]
        
        # Check for specialized patterns that should be handled by other parsers
        specialized_patterns = [
            'Package [',  # package_parser
            'op=', 'mode=',  # appops_parser
            'rb=', 'rp=', 'tb=', 'tp=',  # network_stats_parser
            'I/', 'D/', 'W/', 'E/', 'V/', 'F/'  # logcat_parser
        ]
        
        # If we find specialized patterns, let other parsers handle it
        if any(pattern in actual_content for pattern in specialized_patterns):
            return False
        
        # Only match if we have general dumpsys patterns but no specialized ones
        for pattern in dumpsys_patterns:
            if re.search(pattern, actual_content, re.IGNORECASE):
                return True
        
        return False
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse generic dumpsys file."""
        try:
            detected_service = self._detect_service_type(file_path)
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Skip very long lines
                    if len(line) > 8000:
                        continue
                    
                    entry = self._parse_dumpsys_line(
                        line, line_num, detected_service, file_path.name
                    )
                    if entry:
                        yield entry
                        
        except Exception as e:
            self.logger.error(f"Error parsing dumpsys file {file_path}: {e}")
            raise
    
    def _detect_service_type(self, file_path: Path) -> Optional[str]:
        """Detect which service this dumpsys output is from."""
        filename_lower = file_path.name.lower()
        
        # Check filename for service indicators
        for service in self.SERVICE_INDICATORS:
            if service in filename_lower:
                return service
        
        # Try to detect from file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                sample = f.read(4096).lower()
                
                for service, indicators in self.SERVICE_INDICATORS.items():
                    if any(indicator in sample for indicator in indicators):
                        return service
        except:
            pass
        
        return 'unknown'
    
    def _parse_dumpsys_line(
        self,
        line: str,
        line_num: int,
        service_type: Optional[str],
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse a generic dumpsys line."""
        
        line_lower = line.lower()
        
        # Extract common patterns
        extracted_data = self._extract_common_patterns(line)
        
        if not extracted_data:
            return None
        
        # Add service-specific parsing
        service_data = self._parse_service_specific(line, service_type)
        extracted_data.update(service_data)
        
        # Add metadata
        extracted_data['service_type'] = service_type
        
        # Determine entry type based on content
        entry_type = self._determine_entry_type(extracted_data, line_lower)
        
        # Calculate confidence
        confidence = self._calculate_confidence(extracted_data, service_type)
        
        return ParsedLogEntry(
            line_number=line_num,
            source_file=source_file,
            entry_type=entry_type,
            raw_line=line,
            package=extracted_data.get('package'),
            parsed_content=extracted_data,
            confidence=confidence
        )
    
    def _extract_common_patterns(self, line: str) -> Dict:
        """Extract common patterns from the line."""
        extracted = {}
        
        # Extract UID
        uid_match = self.COMMON_PATTERNS['uid_pattern'].search(line)
        if uid_match:
            extracted['uid'] = int(uid_match.group(1))
        
        # Extract package name
        pkg_match = self.COMMON_PATTERNS['package_pattern'].search(line)
        if pkg_match:
            extracted['package'] = pkg_match.group(1)
        
        # Extract time values
        time_matches = self.COMMON_PATTERNS['time_pattern'].findall(line)
        if time_matches:
            extracted['time_values'] = [float(t[0]) for t in time_matches]
        
        # Extract counts
        count_match = self.COMMON_PATTERNS['count_pattern'].search(line)
        if count_match:
            extracted['count'] = int(count_match.group(1))
        
        # Extract sizes
        size_matches = self.COMMON_PATTERNS['size_pattern'].findall(line)
        if size_matches:
            extracted['size_values'] = [float(s[0]) for s in size_matches]
        
        return extracted
    
    def _parse_service_specific(self, line: str, service_type: Optional[str]) -> Dict:
        """Parse service-specific patterns."""
        service_data = {}
        line_lower = line.lower()
        
        if service_type == 'alarm':
            # Parse alarm information
            if 'alarm' in line_lower:
                alarm_match = re.search(r'alarm\s*=\s*([^,\s]+)', line, re.IGNORECASE)
                if alarm_match:
                    service_data['alarm_type'] = alarm_match.group(1)
                
                # Extract next fire time
                when_match = re.search(r'when[=:\s]+([^,\s]+)', line, re.IGNORECASE)
                if when_match:
                    service_data['when'] = when_match.group(1)
        
        elif service_type == 'jobscheduler':
            # Parse job information
            if 'job' in line_lower:
                job_match = re.search(r'job\s*=\s*([^,\s]+)', line, re.IGNORECASE)
                if job_match:
                    service_data['job_id'] = job_match.group(1)
                
                # Extract job service
                service_match = re.search(r'service[=:\s]+([\w.]+)', line, re.IGNORECASE)
                if service_match:
                    service_data['job_service'] = service_match.group(1)
        
        elif service_type == 'power':
            # Parse power/wakelock information
            if 'wake' in line_lower or 'lock' in line_lower:
                wakelock_match = re.search(r'(?:wake.*lock|lock)[=:\s]*([^\s,\(]+)', line, re.IGNORECASE)
                if wakelock_match:
                    service_data['wakelock_name'] = wakelock_match.group(1)
        
        elif service_type == 'connectivity':
            # Parse network information
            if any(keyword in line_lower for keyword in ['network', 'wifi', 'mobile']):
                # Extract network type
                if 'wifi' in line_lower:
                    service_data['network_type'] = 'wifi'
                elif 'mobile' in line_lower:
                    service_data['network_type'] = 'mobile'
                
                # Extract connection state
                if 'connected' in line_lower:
                    service_data['connection_state'] = 'connected'
                elif 'disconnected' in line_lower:
                    service_data['connection_state'] = 'disconnected'
        
        elif service_type == 'meminfo':
            # Parse memory information
            pss_match = re.search(r'pss[=:\s]+(\d+)', line, re.IGNORECASE)
            if pss_match:
                service_data['pss_kb'] = int(pss_match.group(1))
            
            heap_match = re.search(r'heap[=:\s]+(\d+)', line, re.IGNORECASE)
            if heap_match:
                service_data['heap_kb'] = int(heap_match.group(1))
        
        return service_data
    
    def _determine_entry_type(self, extracted_data: Dict, line_lower: str) -> str:
        """Determine the entry type based on extracted data."""
        
        # Check for resource usage information
        if any(key in extracted_data for key in ['pss_kb', 'heap_kb', 'size_values']):
            return 'system_resource'
        
        # Check for service events
        if any(key in extracted_data for key in ['alarm_type', 'job_id', 'wakelock_name']):
            return 'service_event'
        
        # Check for configuration/info
        if 'service_type' in extracted_data and extracted_data.get('package'):
            return 'service_info'
        
        # Default to dumpsys data
        return 'dumpsys_data'
    
    def _calculate_confidence(self, extracted_data: Dict, service_type: Optional[str]) -> float:
        """Calculate confidence based on extracted data quality."""
        
        base_confidence = 0.7
        
        # Higher confidence if we have structured data
        data_quality_indicators = ['uid', 'package', 'count', 'time_values']
        quality_score = sum(1 for indicator in data_quality_indicators if indicator in extracted_data)
        
        if quality_score >= 3:
            base_confidence = 0.9
        elif quality_score >= 2:
            base_confidence = 0.8
        
        # Higher confidence for known service types
        if service_type and service_type != 'unknown':
            base_confidence += 0.05
        
        # Higher confidence for service-specific data
        service_specific_keys = [
            'alarm_type', 'job_id', 'wakelock_name', 
            'network_type', 'pss_kb', 'heap_kb'
        ]
        if any(key in extracted_data for key in service_specific_keys):
            base_confidence += 0.05
        
        return min(1.0, base_confidence)


