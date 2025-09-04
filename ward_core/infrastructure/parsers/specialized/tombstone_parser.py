"""
Tombstone Parser for Android native crash tombstone files.

This parser extracts forensically relevant information from Android tombstone files
including crash details, register dumps, memory maps, and stack traces.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterator
from datetime import datetime

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class TombstoneParser(BaseParser):
    """Parser for Android tombstone files containing native crash information."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        # Android tombstone files typically have no extension
        self.supported_formats = ["txt", ""]
    
    @property
    def parser_name(self) -> str:
        """Get the name of this parser."""
        return "tombstone_parser"
    
    @property
    def parser_version(self) -> str:
        """Get the version of this parser."""
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        return ParserCapabilities(
            supported_extensions={'.txt', ''},  # Android tombstones often have no extension
            content_patterns=[
                '*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***',
                'Build fingerprint:',
                'Revision:',
                'ABI:',
                'Timestamp:',
                'pid:',
                'tid:',
                'signal',
                'fault addr',
                'Cause:',
                'backtrace:',
                'stack:',
                'memory near',
                'code around'
            ],
            header_patterns=[
                '*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***',
                'Build fingerprint:',
                'pid:'
            ],
            output_entry_types={
                'tombstone_header',
                'crash_info',
                'signal_info',
                'register_dump',
                'backtrace',
                'stack_dump',
                'memory_dump',
                'memory_map'
            },
            supports_streaming=True,
            memory_efficient=True,
            estimated_speed="medium"
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the given file."""
        filename = file_path.name.lower()

        # Check filename patterns - Android tombstone files typically named like:
        # tombstone_00, tombstone_01, tombstone, etc. (usually no extension)
        tombstone_patterns = [
            'tombstone',
            'tombstone_',
            'tombstone.',  # Some might have extensions
        ]

        if any(pattern in filename for pattern in tombstone_patterns):
            return True
        
        # Check content patterns for tombstone files
        tombstone_indicators = [
            '*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***',
            'build fingerprint:',
            'signal ',
            'fault addr',
            'backtrace:',
            'memory near'
        ]
        
        content_lower = content_sample.lower()
        return any(indicator in content_lower for indicator in tombstone_indicators)
    
    def get_confidence_score(self, file_path: Path) -> float:
        """Get confidence score for parsing this file."""
        filename = file_path.name.lower()

        # High confidence for typical Android tombstone naming patterns
        if filename.startswith('tombstone'):
            return 0.95
        elif 'tombstone' in filename:
            return 0.90

        return 0.7 if self.can_parse(file_path) else 0.0
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse tombstone file and yield structured entries."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse different sections of the tombstone
            yield from self._parse_tombstone_content(content, str(file_path))
            
        except Exception as e:
            self.logger.error(f"Error parsing tombstone file {file_path}: {e}")
            # Yield error entry
            yield ParsedLogEntry(
                entry_type='parse_error',
                source_file=str(file_path),
                line_number=0,
                raw_line=f"Parse error: {e}",
                parsed_content={'error': str(e)},
                tags={'error'},
                confidence=0.0
            )
    
    def _parse_tombstone_content(self, content: str, source_file: str) -> Iterator[ParsedLogEntry]:
        """Parse tombstone file content into structured entries."""
        lines = content.split('\n')
        current_section = None
        line_num = 0
        
        for line in lines:
            line_num += 1
            line = line.strip()
            
            if not line:
                continue
            
            # Parse header information
            if line.startswith('*** *** ***'):
                current_section = 'header'
                yield self._create_header_entry(line, line_num, source_file)
            
            elif line.startswith('Build fingerprint:'):
                yield self._parse_build_info(line, line_num, source_file)
            
            elif line.startswith('pid:') and 'tid:' in line:
                yield self._parse_process_info(line, line_num, source_file)
            
            elif 'signal' in line.lower() and 'fault addr' in line.lower():
                yield self._parse_signal_info(line, line_num, source_file)
            
            elif line.startswith('Cause:'):
                yield self._parse_crash_cause(line, line_num, source_file)
            
            elif line == 'backtrace:':
                current_section = 'backtrace'
            
            elif line.startswith('stack:'):
                current_section = 'stack'
            
            elif line.startswith('memory near'):
                current_section = 'memory'
            
            elif line.startswith('code around'):
                current_section = 'code'
            
            elif current_section == 'backtrace' and line.startswith('#'):
                yield self._parse_backtrace_entry(line, line_num, source_file)
            
            elif current_section in ['stack', 'memory', 'code'] and re.match(r'^[0-9a-fA-F]+:', line):
                yield self._parse_memory_dump(line, line_num, source_file, current_section)
    
    def _create_header_entry(self, line: str, line_num: int, source_file: str) -> ParsedLogEntry:
        """Create header entry for tombstone."""
        return ParsedLogEntry(
            entry_type='tombstone_header',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'section': 'header',
                'timestamp': datetime.now().isoformat()
            },
            tags={'tombstone', 'header', 'crash'},
            confidence=1.0
        )
    
    def _parse_build_info(self, line: str, line_num: int, source_file: str) -> ParsedLogEntry:
        """Parse build fingerprint information."""
        build_info = line.replace('Build fingerprint:', '').strip().strip("'")
        
        return ParsedLogEntry(
            entry_type='crash_info',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'info_type': 'build_fingerprint',
                'build_fingerprint': build_info,
                'timestamp': datetime.now().isoformat()
            },
            tags={'tombstone', 'build_info', 'system_info'},
            confidence=0.95
        )
    
    def _parse_process_info(self, line: str, line_num: int, source_file: str) -> ParsedLogEntry:
        """Parse process and thread information."""
        # Extract PID and TID
        pid_match = re.search(r'pid:\s*(\d+)', line)
        tid_match = re.search(r'tid:\s*(\d+)', line)
        name_match = re.search(r'name:\s*([^\s,]+)', line)
        
        return ParsedLogEntry(
            entry_type='crash_info',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'info_type': 'process_info',
                'pid': pid_match.group(1) if pid_match else 'unknown',
                'tid': tid_match.group(1) if tid_match else 'unknown',
                'process_name': name_match.group(1) if name_match else 'unknown',
                'timestamp': datetime.now().isoformat()
            },
            tags={'tombstone', 'process_info', 'crash'},
            confidence=0.9
        )
    
    def _parse_signal_info(self, line: str, line_num: int, source_file: str) -> ParsedLogEntry:
        """Parse signal and fault address information."""
        signal_match = re.search(r'signal\s+(\d+)', line)
        fault_match = re.search(r'fault addr\s+(0x[0-9a-fA-F]+)', line)
        
        return ParsedLogEntry(
            entry_type='signal_info',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'signal_number': signal_match.group(1) if signal_match else 'unknown',
                'fault_address': fault_match.group(1) if fault_match else 'unknown',
                'timestamp': datetime.now().isoformat()
            },
            tags={'tombstone', 'signal', 'crash', 'security_relevant'},
            confidence=0.95
        )
    
    def _parse_crash_cause(self, line: str, line_num: int, source_file: str) -> ParsedLogEntry:
        """Parse crash cause information."""
        cause = line.replace('Cause:', '').strip()
        
        return ParsedLogEntry(
            entry_type='crash_info',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'info_type': 'crash_cause',
                'cause': cause,
                'timestamp': datetime.now().isoformat()
            },
            tags={'tombstone', 'crash_cause', 'security_relevant'},
            confidence=0.9
        )
    
    def _parse_backtrace_entry(self, line: str, line_num: int, source_file: str) -> ParsedLogEntry:
        """Parse backtrace stack frame."""
        # Extract frame info: #00 pc 00001234 /system/lib/libc.so (function+offset)
        frame_match = re.match(r'#(\d+)\s+pc\s+([0-9a-fA-F]+)\s+([^\s]+)(?:\s+\(([^)]+)\))?', line)
        
        if frame_match:
            frame_num, pc, library, function = frame_match.groups()
            
            return ParsedLogEntry(
                entry_type='backtrace',
                source_file=source_file,
                line_number=line_num,
                raw_line=line,
                parsed_content={
                    'frame_number': int(frame_num),
                    'program_counter': pc,
                    'library': library,
                    'function': function or 'unknown',
                    'timestamp': datetime.now().isoformat()
                },
                tags={'tombstone', 'backtrace', 'stack_trace'},
                confidence=0.9
            )
        
        # Fallback for malformed backtrace entries
        return ParsedLogEntry(
            entry_type='backtrace',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'raw_backtrace': line,
                'timestamp': datetime.now().isoformat()
            },
            tags={'tombstone', 'backtrace'},
            confidence=0.5
        )
    
    def _parse_memory_dump(self, line: str, line_num: int, source_file: str, section: str) -> ParsedLogEntry:
        """Parse memory dump information."""
        # Extract address and hex data
        parts = line.split(':', 1)
        address = parts[0].strip()
        hex_data = parts[1].strip() if len(parts) > 1 else ''
        
        return ParsedLogEntry(
            entry_type='memory_dump',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'dump_type': section,
                'address': address,
                'hex_data': hex_data,
                'timestamp': datetime.now().isoformat()
            },
            tags={'tombstone', 'memory_dump', section},
            confidence=0.8
        )
