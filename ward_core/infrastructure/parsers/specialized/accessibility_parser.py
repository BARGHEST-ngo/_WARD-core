"""
Accessibility Parser for dumpsys accessibility output.

This parser extracts accessibility service information, which is critical
for detecting spyware and malicious apps that abuse accessibility services.
"""

import re
from typing import Iterator, Dict, Optional
from pathlib import Path

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class AccessibilityParser(BaseParser):
    """
    Parser for Android dumpsys accessibility output.
    
    Extracts accessibility service information including enabled services,
    permissions, and usage patterns that may indicate malicious activity.
    """
    
    # Known legitimate accessibility services
    KNOWN_LEGITIMATE_SERVICES = {
        'com.google.android.marvin.talkback',
        'com.android.talkback',
        'com.google.android.accessibility.selecttospeak',
        'com.android.switchaccess',
        'com.google.android.apps.accessibility.voiceaccess'
    }
    
    @property
    def parser_name(self) -> str:
        return "accessibility_parser"
    
    @property
    def parser_version(self) -> str:
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        return ParserCapabilities(
            supported_extensions={'.txt'},
            supported_mime_types={'text/plain'},
            content_patterns=[
                'ACCESSIBILITY MANAGER',
                'dumpsys accessibility',
                'enabled services:',
                'installed services:',
                'accessibility service'
            ],
            header_patterns=[
                'ACCESSIBILITY MANAGER (dumpsys accessibility)',
                'enabled services:',
                'installed services:'
            ],
            output_entry_types={
                'accessibility_service',
                'accessibility_config',
                'accessibility_event'
            },
            supports_streaming=True,
            memory_efficient=True,
            estimated_speed="fast"
        )
    
    def can_parse(self, file_path: Path, content_sample: str) -> bool:
        """Check if this file contains accessibility output."""
        content_lower = content_sample.lower()
        
        accessibility_indicators = [
            'accessibility manager',
            'dumpsys accessibility',
            'enabled services',
            'installed services',
            'accessibility service'
        ]
        
        # Also check by filename for better coverage
        if 'shell_accessibility.txt' in file_path.name:
            return True
        
        return any(indicator in content_lower for indicator in accessibility_indicators)
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse accessibility service file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                current_section = None
                current_service = None
                
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Detect sections
                    section = self._detect_section(line)
                    if section:
                        current_section = section
                        continue
                    
                    # Parse service information
                    entry = self._parse_accessibility_line(
                        line, line_num, current_section, file_path.name
                    )
                    if entry:
                        yield entry
                        
        except Exception as e:
            self.logger.error(f"Error parsing accessibility file {file_path}: {e}")
            raise
    
    def _detect_section(self, line: str) -> Optional[str]:
        """Detect which section we're in."""
        line_lower = line.lower()
        
        if 'enabled services:' in line_lower:
            return 'enabled_services'
        elif 'installed services:' in line_lower:
            return 'installed_services' 
        elif 'user state[' in line_lower:
            return 'user_state'
        elif 'events:' in line_lower:
            return 'events'
        
        return None
    
    def _parse_accessibility_line(
        self,
        line: str,
        line_num: int,
        section: Optional[str],
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse accessibility service line."""
        
        # Parse service entries
        service_match = re.search(r'([\w.]+)/([\w.]+)', line)
        if service_match:
            package = service_match.group(1)
            service_class = service_match.group(2)
            service_name = f"{package}/{service_class}"
            
            parsed_content = {
                'package': package,
                'service_class': service_class,
                'service_name': service_name,
                'section': section
            }
            
            # Check if this is a known legitimate service
            is_legitimate = any(
                known in service_name.lower() 
                for known in self.KNOWN_LEGITIMATE_SERVICES
            )
            parsed_content['is_known_legitimate'] = is_legitimate
            
            # Flag potentially suspicious services
            if not is_legitimate and section == 'enabled_services':
                parsed_content['potentially_suspicious'] = True
                parsed_content['reason'] = 'Unknown accessibility service enabled'
            
            # Extract additional service information
            if 'flags=' in line:
                flags_match = re.search(r'flags=\[([^\]]+)\]', line)
                if flags_match:
                    flags = [f.strip() for f in flags_match.group(1).split(',')]
                    parsed_content['flags'] = flags
                    
                    # Check for dangerous flags
                    dangerous_flags = ['FLAG_RETRIEVE_INTERACTIVE_WINDOWS', 'FLAG_REQUEST_TOUCH_EXPLORATION_MODE']
                    if any(flag in flags for flag in dangerous_flags):
                        parsed_content['has_dangerous_permissions'] = True
            
            if 'eventTypes=' in line:
                events_match = re.search(r'eventTypes=\[([^\]]+)\]', line)
                if events_match:
                    event_types = [e.strip() for e in events_match.group(1).split(',')]
                    parsed_content['monitored_events'] = event_types
            
            # Calculate confidence
            confidence = 0.9 if service_match else 0.7
            if parsed_content.get('potentially_suspicious'):
                confidence = 0.95
            
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='accessibility_service',
                raw_line=line,
                package=package,
                parsed_content=parsed_content,
                confidence=confidence
            )
        
        # Parse accessibility events
        if 'EventType:' in line:
            event_match = re.search(r'EventType:\s*(\w+)', line)
            if event_match:
                event_type = event_match.group(1)
                
                parsed_content = {
                    'event_type': event_type
                }
                
                # Extract package name from event
                pkg_match = re.search(r'PackageName:\s*([\w.]+)', line)
                if pkg_match:
                    parsed_content['source_package'] = pkg_match.group(1)
                
                # Extract class name
                class_match = re.search(r'ClassName:\s*([\w.]+)', line)
                if class_match:
                    parsed_content['class_name'] = class_match.group(1)
                
                return ParsedLogEntry(
                    line_number=line_num,
                    source_file=source_file,
                    entry_type='accessibility_event',
                    raw_line=line,
                    package=parsed_content.get('source_package'),
                    parsed_content=parsed_content,
                    confidence=0.8
                )
        
        # Parse configuration settings
        if any(keyword in line.lower() for keyword in ['touch exploration', 'speak passwords', 'captions']):
            setting_match = re.search(r'(\w+(?:\s+\w+)*):?\s*(enabled|disabled|true|false|\d+)', line, re.IGNORECASE)
            if setting_match:
                setting_name = setting_match.group(1).strip()
                setting_value = setting_match.group(2).lower()
                
                parsed_content = {
                    'setting_name': setting_name,
                    'setting_value': setting_value
                }
                
                # Flag potentially risky settings
                if 'speak passwords' in setting_name.lower() and setting_value in ['enabled', 'true']:
                    parsed_content['security_concern'] = 'Password speaking enabled'
                
                return ParsedLogEntry(
                    line_number=line_num,
                    source_file=source_file,
                    entry_type='accessibility_config',
                    raw_line=line,
                    parsed_content=parsed_content,
                    confidence=0.8
                )
        
        return None


