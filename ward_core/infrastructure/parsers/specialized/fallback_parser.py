"""
Fallback Parser for unhandled Android forensic data.

This parser provides basic parsing for files that don't match specific parsers
but still contain valuable forensic information.
"""

import re
from pathlib import Path
from typing import Iterator, Dict, Any, Optional
from datetime import datetime

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class FallbackParser(BaseParser):
    """
    Fallback parser for unhandled Android forensic data.
    
    This parser provides basic parsing for files that don't match specific parsers
    but still contain valuable forensic information.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.supported_formats = ["txt"]
    
    @property
    def parser_name(self) -> str:
        """Get the name of this parser."""
        return "fallback_parser"
    
    @property
    def parser_version(self) -> str:
        """Get the version of this parser."""
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=['*'],  # Matches any content
            output_entry_types={
                'fallback_entry',
                'unparsed_data',
                'raw_forensic_data'
            },
            supports_streaming=True,
            memory_efficient=True,
            estimated_speed="fast"
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the file."""
        # This is a fallback parser - it should only be used when no other parser matches
        # We'll let the parser registry handle this logic
        # But we can still check if it's a text file we can potentially parse
        if not file_path.suffix.lower() == '.txt':
            return False
        
        # Only match if we have some content to work with
        if not content_sample or len(content_sample.strip()) < 10:
            return False
        
        return True  # Can parse any text file with content
    
    def get_confidence_score(self, file_path: Path) -> float:
        """Get confidence score for parsing this file."""
        # Low confidence since this is a fallback
        return 0.3
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse file with fallback parsing."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Skip very long lines (likely binary data)
                    if len(line) > 5000:
                        continue
                    
                    entry = self._parse_fallback_line(line, line_num, file_path.name)
                    if entry:
                        yield entry
                        
        except Exception as e:
            self.logger.error(f"Error parsing fallback file {file_path}: {e}")
            raise
    
    def _parse_fallback_line(self, line: str, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse a line with fallback parsing."""
        try:
            # Extract basic patterns that might be useful
            parsed_data = {
                'raw_content': line,
                'line_length': len(line),
                'timestamp': datetime.now().isoformat()
            }
            
            # Look for common patterns
            patterns = {
                'package_pattern': r'package[:\s]+([^\s]+)',
                'permission_pattern': r'permission[:\s]+([^\s]+)',
                'uid_pattern': r'uid[:\s]*(\d+)',
                'pid_pattern': r'pid[:\s]*(\d+)',
                'timestamp_pattern': r'(\d{4}-\d{2}-\d{2}|\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
                'ip_pattern': r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                'hash_pattern': r'([a-fA-F0-9]{32,})',
                'error_pattern': r'(error|exception|crash|fail|denied)',
                'warning_pattern': r'(warning|warn|caution)',
                'security_pattern': r'(security|auth|permission|denied|blocked)'
            }
            
            for pattern_name, pattern in patterns.items():
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    parsed_data[pattern_name] = match.group(1)
            
            # Determine entry type based on content
            entry_type = 'fallback_entry'
            tags = {'unparsed', 'fallback'}
            
            if any(key in parsed_data for key in ['error_pattern', 'warning_pattern']):
                entry_type = 'fallback_error'
                tags.add('error')
            
            if 'security_pattern' in parsed_data:
                entry_type = 'fallback_security'
                tags.add('security_relevant')
            
            if 'package_pattern' in parsed_data:
                entry_type = 'fallback_package'
                tags.add('package')
            
            if 'permission_pattern' in parsed_data:
                entry_type = 'fallback_permission'
                tags.add('permission')
            
            return ParsedLogEntry(
                entry_type=entry_type,
                source_file=source_file,
                line_number=line_num,
                raw_content=line,
                parsed_data=parsed_data,
                tags=tags,
                confidence=0.3  # Low confidence for fallback parsing
            )
            
        except Exception as e:
            self.logger.debug(f"Error parsing fallback line: {e}")
            return None
