"""
Activity Services Parser for Android forensic analysis.

This parser handles dumpsys activity services output which contains critical
information about running services, ANR data, service bindings, and crash information.
"""

import re
from pathlib import Path
from typing import Iterator, Dict, Any, Optional, List
from datetime import datetime

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class ActivityServicesParser(BaseParser):
    """
    Parser for dumpsys activity services output.
    
    This parser extracts critical security information from activity services
    including running services, ANR data, service bindings, and crash information.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.supported_formats = ["txt"]
    
    @property
    def parser_name(self) -> str:
        """Get the name of this parser."""
        return "activity_services_parser"
    
    @property
    def parser_version(self) -> str:
        """Get the version of this parser."""
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=[
                'ACTIVITY MANAGER SERVICES',
                'dumpsys activity services',
                'ServiceRecord{',
                'Last ANR service:',
                'User 0 active services:',
                'intent={',
                'packageName=',
                'processName=',
                'permission=',
                'crashCount='
            ],
            output_entry_types={
                'service_record',
                'anr_service',
                'service_binding',
                'service_crash',
                'background_service',
                'foreground_service'
            },
            supports_streaming=True,
            memory_efficient=True,
            estimated_speed="medium"
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the file."""
        if not file_path.suffix.lower() == '.txt':
            return False
        
        # Check for activity services indicators
        content_lower = content_sample.lower()
        activity_indicators = [
            'activity manager services',
            'dumpsys activity services',
            'servicerecord{',
            'last anr service:',
            'user 0 active services:'
        ]
        
        return any(indicator in content_lower for indicator in activity_indicators)
    
    def get_confidence_score(self, file_path: Path) -> float:
        """Get confidence score for parsing this file."""
        if self.can_parse(file_path):
            return 0.95  # Very high confidence for activity services
        return 0.0
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse activity services file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                current_service = None
                current_binding = None
                
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse different sections
                    if 'Last ANR service:' in line:
                        entry = self._parse_anr_service(line, line_num, file_path.name)
                        if entry:
                            yield entry
                    
                    elif line.startswith('* ServiceRecord{'):
                        # Start of a new service record
                        current_service = self._parse_service_record_start(line, line_num, file_path.name)
                        if current_service:
                            yield current_service
                    
                    elif current_service and line.startswith('    intent='):
                        # Service intent information
                        entry = self._parse_service_intent(line, current_service, line_num, file_path.name)
                        if entry:
                            yield entry
                    
                    elif current_service and line.startswith('    packageName='):
                        # Service package information
                        entry = self._parse_service_package(line, current_service, line_num, file_path.name)
                        if entry:
                            yield entry
                    
                    elif current_service and line.startswith('    permission='):
                        # Service permission information
                        entry = self._parse_service_permission(line, current_service, line_num, file_path.name)
                        if entry:
                            yield entry
                    
                    elif current_service and 'crashCount=' in line:
                        # Service crash information
                        entry = self._parse_service_crash(line, current_service, line_num, file_path.name)
                        if entry:
                            yield entry
                    
                    elif line.startswith('    * IntentBindRecord{'):
                        # Service binding information
                        current_binding = self._parse_binding_start(line, line_num, file_path.name)
                        if current_binding:
                            yield current_binding
                    
                    elif current_binding and line.startswith('      intent='):
                        # Binding intent information
                        entry = self._parse_binding_intent(line, current_binding, line_num, file_path.name)
                        if entry:
                            yield entry
                    
                    elif current_binding and line.startswith('      binder='):
                        # Binding binder information
                        entry = self._parse_binding_binder(line, current_binding, line_num, file_path.name)
                        if entry:
                            yield entry
                    
                    elif line.startswith('    All Connections:'):
                        # Connection information
                        entry = self._parse_connections(line, line_num, file_path.name)
                        if entry:
                            yield entry
                    
                    elif line.startswith('      ConnectionRecord{'):
                        # Individual connection record
                        entry = self._parse_connection_record(line, line_num, file_path.name)
                        if entry:
                            yield entry
                        
        except Exception as e:
            self.logger.error(f"Error parsing activity services file {file_path}: {e}")
            raise
    
    def _parse_anr_service(self, line: str, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse ANR service information."""
        try:
            # Extract service record from ANR line
            service_match = re.search(r'ServiceRecord\{([^}]+)\}', line)
            if not service_match:
                return None
            
            service_id = service_match.group(1)
            
            return ParsedLogEntry(
                entry_type='anr_service',
                source_file=source_file,
                line_number=line_num,
                raw_content=line,
                parsed_data={
                    'service_id': service_id,
                    'anr_type': 'last_anr',
                    'timestamp': datetime.now().isoformat()
                },
                tags={'anr', 'service', 'security_relevant'},
                confidence=0.9
            )
        except Exception as e:
            self.logger.debug(f"Error parsing ANR service line: {e}")
            return None
    
    def _parse_service_record_start(self, line: str, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse service record start line."""
        try:
            # Extract service ID and user
            service_match = re.search(r'ServiceRecord\{([^}]+)\}', line)
            if not service_match:
                return None
            
            service_id = service_match.group(1)
            
            # Extract user ID
            user_match = re.search(r'u(\d+)', line)
            user_id = user_match.group(1) if user_match else None
            
            return ParsedLogEntry(
                entry_type='service_record',
                source_file=source_file,
                line_number=line_num,
                raw_content=line,
                parsed_data={
                    'service_id': service_id,
                    'user_id': user_id,
                    'timestamp': datetime.now().isoformat()
                },
                tags={'service', 'foreground_service'},
                confidence=0.9
            )
        except Exception as e:
            self.logger.debug(f"Error parsing service record start: {e}")
            return None
    
    def _parse_service_intent(self, line: str, service_entry: ParsedLogEntry, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse service intent information."""
        try:
            # Extract intent information
            intent_match = re.search(r'intent=\{([^}]+)\}', line)
            if not intent_match:
                return None
            
            intent_data = intent_match.group(1)
            
            # Parse intent components
            components = {}
            if 'cmp=' in intent_data:
                cmp_match = re.search(r'cmp=([^}\s]+)', intent_data)
                if cmp_match:
                    components['component'] = cmp_match.group(1)
            
            if 'act=' in intent_data:
                act_match = re.search(r'act=([^}\s]+)', intent_data)
                if act_match:
                    components['action'] = act_match.group(1)
            
            return ParsedLogEntry(
                entry_type='service_intent',
                source_file=source_file,
                line_number=line_num,
                raw_content=line,
                parsed_data={
                    'service_id': service_entry.parsed_data.get('service_id'),
                    'intent_data': intent_data,
                    'components': components,
                    'timestamp': datetime.now().isoformat()
                },
                tags={'service', 'intent', 'security_relevant'},
                confidence=0.8
            )
        except Exception as e:
            self.logger.debug(f"Error parsing service intent: {e}")
            return None
    
    def _parse_service_package(self, line: str, service_entry: ParsedLogEntry, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse service package information."""
        try:
            # Extract package name
            package_match = re.search(r'packageName=([^\s]+)', line)
            if not package_match:
                return None
            
            package_name = package_match.group(1)
            
            # Extract process name if available
            process_match = re.search(r'processName=([^\s]+)', line)
            process_name = process_match.group(1) if process_match else None
            
            return ParsedLogEntry(
                entry_type='service_package',
                source_file=source_file,
                line_number=line_num,
                raw_content=line,
                parsed_data={
                    'service_id': service_entry.parsed_data.get('service_id'),
                    'package_name': package_name,
                    'process_name': process_name,
                    'timestamp': datetime.now().isoformat()
                },
                tags={'service', 'package', 'security_relevant'},
                confidence=0.9
            )
        except Exception as e:
            self.logger.debug(f"Error parsing service package: {e}")
            return None
    
    def _parse_service_permission(self, line: str, service_entry: ParsedLogEntry, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse service permission information."""
        try:
            # Extract permission
            permission_match = re.search(r'permission=([^\s]+)', line)
            if not permission_match:
                return None
            
            permission = permission_match.group(1)
            
            return ParsedLogEntry(
                entry_type='service_permission',
                source_file=source_file,
                line_number=line_num,
                raw_content=line,
                parsed_data={
                    'service_id': service_entry.parsed_data.get('service_id'),
                    'permission': permission,
                    'timestamp': datetime.now().isoformat()
                },
                tags={'service', 'permission', 'security_relevant'},
                confidence=0.9
            )
        except Exception as e:
            self.logger.debug(f"Error parsing service permission: {e}")
            return None
    
    def _parse_service_crash(self, line: str, service_entry: ParsedLogEntry, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse service crash information."""
        try:
            # Extract crash count
            crash_match = re.search(r'crashCount=(\d+)', line)
            if not crash_match:
                return None
            
            crash_count = int(crash_match.group(1))
            
            # Extract restart count if available
            restart_match = re.search(r'restartCount=(\d+)', line)
            restart_count = int(restart_match.group(1)) if restart_match else 0
            
            return ParsedLogEntry(
                entry_type='service_crash',
                source_file=source_file,
                line_number=line_num,
                raw_content=line,
                parsed_data={
                    'service_id': service_entry.parsed_data.get('service_id'),
                    'crash_count': crash_count,
                    'restart_count': restart_count,
                    'timestamp': datetime.now().isoformat()
                },
                tags={'service', 'crash', 'anomaly', 'security_relevant'},
                confidence=0.9
            )
        except Exception as e:
            self.logger.debug(f"Error parsing service crash: {e}")
            return None
    
    def _parse_binding_start(self, line: str, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse binding start information."""
        try:
            # Extract binding ID
            binding_match = re.search(r'IntentBindRecord\{([^}]+)\}', line)
            if not binding_match:
                return None
            
            binding_id = binding_match.group(1)
            
            return ParsedLogEntry(
                entry_type='service_binding',
                source_file=source_file,
                line_number=line_num,
                raw_content=line,
                parsed_data={
                    'binding_id': binding_id,
                    'timestamp': datetime.now().isoformat()
                },
                tags={'service', 'binding', 'security_relevant'},
                confidence=0.8
            )
        except Exception as e:
            self.logger.debug(f"Error parsing binding start: {e}")
            return None
    
    def _parse_binding_intent(self, line: str, binding_entry: ParsedLogEntry, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse binding intent information."""
        try:
            # Extract intent information
            intent_match = re.search(r'intent=\{([^}]+)\}', line)
            if not intent_match:
                return None
            
            intent_data = intent_match.group(1)
            
            return ParsedLogEntry(
                entry_type='binding_intent',
                source_file=source_file,
                line_number=line_num,
                raw_content=line,
                parsed_data={
                    'binding_id': binding_entry.parsed_data.get('binding_id'),
                    'intent_data': intent_data,
                    'timestamp': datetime.now().isoformat()
                },
                tags={'service', 'binding', 'intent', 'security_relevant'},
                confidence=0.8
            )
        except Exception as e:
            self.logger.debug(f"Error parsing binding intent: {e}")
            return None
    
    def _parse_binding_binder(self, line: str, binding_entry: ParsedLogEntry, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse binding binder information."""
        try:
            # Extract binder information
            binder_match = re.search(r'binder=([^\s]+)', line)
            if not binder_match:
                return None
            
            binder_data = binder_match.group(1)
            
            return ParsedLogEntry(
                entry_type='binding_binder',
                source_file=source_file,
                line_number=line_num,
                raw_content=line,
                parsed_data={
                    'binding_id': binding_entry.parsed_data.get('binding_id'),
                    'binder_data': binder_data,
                    'timestamp': datetime.now().isoformat()
                },
                tags={'service', 'binding', 'binder', 'security_relevant'},
                confidence=0.8
            )
        except Exception as e:
            self.logger.debug(f"Error parsing binding binder: {e}")
            return None
    
    def _parse_connections(self, line: str, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse connections section."""
        try:
            return ParsedLogEntry(
                entry_type='service_connections',
                source_file=source_file,
                line_number=line_num,
                raw_content=line,
                parsed_data={
                    'connection_type': 'all_connections',
                    'timestamp': datetime.now().isoformat()
                },
                tags={'service', 'connection', 'security_relevant'},
                confidence=0.7
            )
        except Exception as e:
            self.logger.debug(f"Error parsing connections: {e}")
            return None
    
    def _parse_connection_record(self, line: str, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse individual connection record."""
        try:
            # Extract connection ID
            connection_match = re.search(r'ConnectionRecord\{([^}]+)\}', line)
            if not connection_match:
                return None
            
            connection_id = connection_match.group(1)
            
            return ParsedLogEntry(
                entry_type='connection_record',
                source_file=source_file,
                line_number=line_num,
                raw_content=line,
                parsed_data={
                    'connection_id': connection_id,
                    'timestamp': datetime.now().isoformat()
                },
                tags={'service', 'connection', 'security_relevant'},
                confidence=0.8
            )
        except Exception as e:
            self.logger.debug(f"Error parsing connection record: {e}")
            return None
