"""
DropBox Parser for Android system crash and error reports.

This parser extracts forensically relevant information from Android DropBox files
including system crashes, ANR reports, and other system error events.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterator
from datetime import datetime

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class DropBoxParser(BaseParser):
    """Parser for Android DropBox system error and crash reports."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.supported_formats = ["txt"]
    
    @property
    def parser_name(self) -> str:
        """Get the name of this parser."""
        return "dropbox_parser"
    
    @property
    def parser_version(self) -> str:
        """Get the version of this parser."""
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=[
                'SYSTEM_TOMBSTONE',
                'SYSTEM_CRASH',
                'SYSTEM_ANR',
                'SYSTEM_BOOT',
                'SYSTEM_RESTART',
                'WATCHDOG',
                'data_app_crash',
                'system_app_crash',
                'system_server_crash',
                'Process:',
                'Package:',
                'Flags:',
                'Build:',
                'Time:'
            ],
            header_patterns=[
                'SYSTEM_TOMBSTONE',
                'SYSTEM_CRASH',
                'SYSTEM_ANR',
                'Process:',
                'Build:'
            ],
            output_entry_types={
                'dropbox_header',
                'system_crash',
                'system_anr',
                'system_tombstone',
                'app_crash',
                'watchdog_event',
                'boot_event',
                'process_info'
            },
            supports_streaming=True,
            memory_efficient=True,
            estimated_speed="fast"
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the given file."""
        filename = file_path.name.lower()
        
        # Check filename patterns
        if 'dropbox' in filename:
            return True
        
        # Check content patterns for DropBox files
        dropbox_indicators = [
            'system_tombstone',
            'system_crash',
            'system_anr',
            'watchdog',
            'data_app_crash',
            'system_app_crash',
            'system_server_crash'
        ]
        
        content_lower = content_sample.lower()
        return any(indicator in content_lower for indicator in dropbox_indicators)
    
    def get_confidence_score(self, file_path: Path) -> float:
        """Get confidence score for parsing this file."""
        if 'dropbox' in file_path.name.lower():
            return 0.95
        return 0.8 if self.can_parse(file_path) else 0.0
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse DropBox file and yield structured entries."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse different sections of the DropBox file
            yield from self._parse_dropbox_content(content, str(file_path))
            
        except Exception as e:
            self.logger.error(f"Error parsing DropBox file {file_path}: {e}")
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
    
    def _parse_dropbox_content(self, content: str, source_file: str) -> Iterator[ParsedLogEntry]:
        """Parse DropBox file content into structured entries."""
        # Split content into individual DropBox entries
        entries = self._split_dropbox_entries(content)
        
        for entry_num, entry_content in enumerate(entries):
            if not entry_content.strip():
                continue
            
            # Parse each DropBox entry
            yield from self._parse_single_dropbox_entry(entry_content, source_file, entry_num)
    
    def _split_dropbox_entries(self, content: str) -> List[str]:
        """Split DropBox content into individual entries."""
        # DropBox entries are typically separated by timestamps or entry headers
        # Look for patterns like "SYSTEM_TOMBSTONE" or timestamp patterns
        
        entries = []
        current_entry = []
        
        lines = content.split('\n')
        for line in lines:
            # Check if this line starts a new DropBox entry
            if self._is_dropbox_entry_start(line):
                if current_entry:
                    entries.append('\n'.join(current_entry))
                    current_entry = []
            
            current_entry.append(line)
        
        # Add the last entry
        if current_entry:
            entries.append('\n'.join(current_entry))
        
        return entries
    
    def _is_dropbox_entry_start(self, line: str) -> bool:
        """Check if a line starts a new DropBox entry."""
        line_upper = line.upper()
        entry_starters = [
            'SYSTEM_TOMBSTONE',
            'SYSTEM_CRASH',
            'SYSTEM_ANR',
            'SYSTEM_BOOT',
            'SYSTEM_RESTART',
            'WATCHDOG',
            'DATA_APP_CRASH',
            'SYSTEM_APP_CRASH',
            'SYSTEM_SERVER_CRASH'
        ]
        
        return any(starter in line_upper for starter in entry_starters)
    
    def _parse_single_dropbox_entry(self, entry_content: str, source_file: str, entry_num: int) -> Iterator[ParsedLogEntry]:
        """Parse a single DropBox entry."""
        lines = entry_content.split('\n')
        entry_type = self._determine_entry_type(entry_content)
        line_offset = entry_num * 100  # Approximate line offset for multiple entries
        
        for line_num, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            
            actual_line_num = line_offset + line_num + 1
            
            # Parse header information
            if self._is_dropbox_entry_start(line):
                yield self._parse_dropbox_header(line, actual_line_num, source_file, entry_type)
            
            # Parse process information
            elif line.startswith('Process:'):
                yield self._parse_process_info(line, actual_line_num, source_file, entry_type)
            
            # Parse package information
            elif line.startswith('Package:'):
                yield self._parse_package_info(line, actual_line_num, source_file, entry_type)
            
            # Parse build information
            elif line.startswith('Build:'):
                yield self._parse_build_info(line, actual_line_num, source_file, entry_type)
            
            # Parse time information
            elif line.startswith('Time:'):
                yield self._parse_time_info(line, actual_line_num, source_file, entry_type)
            
            # Parse flags information
            elif line.startswith('Flags:'):
                yield self._parse_flags_info(line, actual_line_num, source_file, entry_type)
            
            # Parse stack traces or other crash details
            elif line.startswith('at ') or 'Exception' in line or 'Error' in line:
                yield self._parse_crash_detail(line, actual_line_num, source_file, entry_type)
    
    def _determine_entry_type(self, content: str) -> str:
        """Determine the type of DropBox entry."""
        content_upper = content.upper()
        
        if 'SYSTEM_TOMBSTONE' in content_upper:
            return 'system_tombstone'
        elif 'SYSTEM_CRASH' in content_upper:
            return 'system_crash'
        elif 'SYSTEM_ANR' in content_upper:
            return 'system_anr'
        elif 'WATCHDOG' in content_upper:
            return 'watchdog_event'
        elif 'SYSTEM_BOOT' in content_upper:
            return 'boot_event'
        elif 'APP_CRASH' in content_upper:
            return 'app_crash'
        else:
            return 'unknown'
    
    def _parse_dropbox_header(self, line: str, line_num: int, source_file: str, entry_type: str) -> ParsedLogEntry:
        """Parse DropBox entry header."""
        return ParsedLogEntry(
            entry_type='dropbox_header',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'dropbox_type': entry_type,
                'header_line': line,
                'timestamp': datetime.now().isoformat()
            },
            tags={'dropbox', 'header', entry_type, 'security_relevant'},
            confidence=0.95
        )
    
    def _parse_process_info(self, line: str, line_num: int, source_file: str, entry_type: str) -> ParsedLogEntry:
        """Parse process information."""
        process_info = line.replace('Process:', '').strip()
        
        return ParsedLogEntry(
            entry_type='process_info',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'dropbox_type': entry_type,
                'process_info': process_info,
                'timestamp': datetime.now().isoformat()
            },
            tags={'dropbox', 'process_info', entry_type},
            confidence=0.9
        )
    
    def _parse_package_info(self, line: str, line_num: int, source_file: str, entry_type: str) -> ParsedLogEntry:
        """Parse package information."""
        package_info = line.replace('Package:', '').strip()
        
        return ParsedLogEntry(
            entry_type='process_info',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'dropbox_type': entry_type,
                'package_info': package_info,
                'timestamp': datetime.now().isoformat()
            },
            tags={'dropbox', 'package_info', entry_type},
            confidence=0.9
        )
    
    def _parse_build_info(self, line: str, line_num: int, source_file: str, entry_type: str) -> ParsedLogEntry:
        """Parse build information."""
        build_info = line.replace('Build:', '').strip()
        
        return ParsedLogEntry(
            entry_type='process_info',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'dropbox_type': entry_type,
                'build_info': build_info,
                'timestamp': datetime.now().isoformat()
            },
            tags={'dropbox', 'build_info', entry_type},
            confidence=0.8
        )
    
    def _parse_time_info(self, line: str, line_num: int, source_file: str, entry_type: str) -> ParsedLogEntry:
        """Parse time information."""
        time_info = line.replace('Time:', '').strip()
        
        return ParsedLogEntry(
            entry_type='process_info',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'dropbox_type': entry_type,
                'crash_time': time_info,
                'timestamp': datetime.now().isoformat()
            },
            tags={'dropbox', 'time_info', entry_type},
            confidence=0.8
        )
    
    def _parse_flags_info(self, line: str, line_num: int, source_file: str, entry_type: str) -> ParsedLogEntry:
        """Parse flags information."""
        flags_info = line.replace('Flags:', '').strip()
        
        return ParsedLogEntry(
            entry_type='process_info',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'dropbox_type': entry_type,
                'flags': flags_info,
                'timestamp': datetime.now().isoformat()
            },
            tags={'dropbox', 'flags_info', entry_type},
            confidence=0.7
        )
    
    def _parse_crash_detail(self, line: str, line_num: int, source_file: str, entry_type: str) -> ParsedLogEntry:
        """Parse crash details like stack traces and exceptions."""
        return ParsedLogEntry(
            entry_type=entry_type,
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'dropbox_type': entry_type,
                'crash_detail': line,
                'timestamp': datetime.now().isoformat()
            },
            tags={'dropbox', 'crash_detail', entry_type, 'security_relevant'},
            confidence=0.8
        )
