"""
User parser for user-related data sources.

Parses user information from dumpsys package, pm list-users, and related commands
to support hidden user and shared user detection.
"""

import re
from typing import Iterator, Optional
from pathlib import Path

from .base_parser import BaseParser, ParserCapabilities, ParsedLogEntry


class UserParser(BaseParser):
    """Parser for user-related data sources."""
    
    @property
    def parser_name(self) -> str:
        return "user_parser"
    
    @property
    def parser_version(self) -> str:
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=['package_users', 'list_users', 'uid_map'],
            output_entry_types={'hidden_user', 'pm_user', 'shared_user', 'uid_mapping'},
            estimated_speed="fast"
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the given file."""
        filename = file_path.name.lower()
        return any(keyword in filename for keyword in [
            'package_users', 'list_users', 'uid_map'
        ])
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse user-related data files."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    entry = self._parse_user_line(line.strip(), line_num, file_path.name)
                    if entry:
                        yield entry
        except Exception as e:
            self.logger.error(f"Error parsing {file_path}: {e}")
    
    def _parse_user_line(self, line: str, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse a single user-related line."""
        if not line or line.startswith('#'):
            return None
        
        # Hidden user pattern from dumpsys package
        hidden_match = re.search(r'User\s+(\d+):.*?hidden=([^\s]+)', line, re.IGNORECASE)
        if hidden_match:
            user_id = hidden_match.group(1)
            hidden_flag = hidden_match.group(2).lower()
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='hidden_user',
                raw_line=line,
                parsed_content={
                    'user_id': int(user_id),
                    'hidden': hidden_flag == 'true'
                },
                confidence=0.9
            )
        
        # PM list users format: UserInfo{ID:NAME:FLAGS}
        pm_user_match = re.search(r'UserInfo\{(\d+):([^:]+):([^\}]+)\}', line, re.IGNORECASE)
        if pm_user_match:
            user_id, user_name, flags = pm_user_match.groups()
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='pm_user',
                raw_line=line,
                parsed_content={
                    'user_id': int(user_id),
                    'user_name': user_name,
                    'flags': flags
                },
                confidence=0.9
            )
        
        # Shared user pattern
        shared_match = re.search(r'sharedUser=([^\s]+)', line, re.IGNORECASE)
        if shared_match:
            shared_user = shared_match.group(1)
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='shared_user',
                raw_line=line,
                parsed_content={
                    'shared_user': shared_user
                },
                confidence=0.8
            )
        
        # UID mapping format: START END OFFSET
        uid_map_match = re.match(r'^\s*(\d+)\s+(\d+)\s+(\d+)\s*$', line)
        if uid_map_match:
            start, end, offset = uid_map_match.groups()
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='uid_mapping',
                raw_line=line,
                parsed_content={
                    'start_uid': int(start),
                    'end_uid': int(end),
                    'offset': int(offset)
                },
                confidence=0.9
            )
        
        return None
