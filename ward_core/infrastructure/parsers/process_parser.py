"""
Process parser for process-related data sources.

Parses process information from ps, top, meminfo, and related commands
to support process anomaly detection.
"""

import re
from typing import Iterator, Optional
from pathlib import Path

from .base_parser import BaseParser, ParserCapabilities, ParsedLogEntry


class ProcessParser(BaseParser):
    """Parser for process-related data sources."""
    
    @property
    def parser_name(self) -> str:
        return "process_parser"
    
    @property
    def parser_version(self) -> str:
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=['ps', 'top', 'meminfo', 'procrank', 'activity_processes'],
            output_entry_types={'process_ps', 'process_meminfo', 'process_top', 'process_activity'},
            estimated_speed="fast"
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the given file."""
        filename = file_path.name.lower()
        return any(keyword in filename for keyword in [
            'ps', 'top', 'meminfo', 'procrank', 'activity_processes'
        ])
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse process-related data files."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    entry = self._parse_process_line(line.strip(), line_num, file_path.name)
                    if entry:
                        yield entry
        except Exception as e:
            self.logger.error(f"Error parsing {file_path}: {e}")
    
    def _parse_process_line(self, line: str, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse a single process-related line."""
        if not line or line.startswith('#'):
            return None
        
        # PS output format: PID UID USER NAME ARGS
        ps_match = re.match(r'^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$', line)
        if ps_match:
            pid, uid, user, name, args = ps_match.groups()
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='process_ps',
                raw_line=line,
                parsed_content={
                    'pid': int(pid),
                    'uid': int(uid),
                    'user': user,
                    'name': name,
                    'args': args.strip()
                },
                confidence=0.9
            )
        
        # Meminfo process format: UID,MEMORYK: PROCESS_NAME (pid PID)
        meminfo_match = re.match(r'^\s*(\d+),(\d+)K:\s+([^\s]+)\s+\(pid\s+(\d+).*\)$', line)
        if meminfo_match:
            uid, memory, process_name, pid = meminfo_match.groups()
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='process_meminfo',
                raw_line=line,
                parsed_content={
                    'uid': int(uid),
                    'memory_kb': int(memory),
                    'process_name': process_name,
                    'pid': int(pid)
                },
                confidence=0.9
            )
        
        # Top output format (simplified)
        top_match = re.match(r'^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([^\s]+)\s+(.+)$', line)
        if top_match:
            pid, uid = top_match.group(1), top_match.group(2)
            process_name = top_match.group(7)
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='process_top',
                raw_line=line,
                parsed_content={
                    'pid': int(pid),
                    'uid': int(uid),
                    'process_name': process_name
                },
                confidence=0.8
            )
        
        # Activity processes format
        activity_match = re.search(r'ProcessRecord\{([^}]+)\s+(\d+):([^}]+)\}', line)
        if activity_match:
            process_id, pid, process_name = activity_match.groups()
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='process_activity',
                raw_line=line,
                parsed_content={
                    'process_id': process_id,
                    'pid': int(pid),
                    'process_name': process_name
                },
                confidence=0.8
            )
        
        return None
