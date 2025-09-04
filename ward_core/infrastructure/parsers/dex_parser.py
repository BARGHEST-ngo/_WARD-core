"""
DEX parser for DEX-related data sources.

Parses DEX compilation logs, code cache information, and secondary DEX loading
to support in-memory DEX loading detection.
"""

import re
from typing import Iterator, Optional
from pathlib import Path

from .base_parser import BaseParser, ParserCapabilities, ParsedLogEntry


class DexParser(BaseParser):
    """Parser for DEX-related data sources."""
    
    @property
    def parser_name(self) -> str:
        return "dex_parser"
    
    @property
    def parser_version(self) -> str:
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=['dexopt', 'dex2oat', 'code_cache', 'secondary_dex'],
            output_entry_types={'dex2oat_compilation', 'dexopt_secondary', 'dex_compilation_reason', 'code_cache_activity', 'secondary_dex_loading'},
            estimated_speed="fast"
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the given file."""
        filename = file_path.name.lower()
        return any(keyword in filename for keyword in [
            'dexopt', 'dex2oat', 'code_cache', 'secondary_dex'
        ])
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse DEX-related data files."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    entry = self._parse_dex_line(line.strip(), line_num, file_path.name)
                    if entry:
                        yield entry
        except Exception as e:
            self.logger.error(f"Error parsing {file_path}: {e}")
    
    def _parse_dex_line(self, line: str, line_num: int, source_file: str) -> Optional[ParsedLogEntry]:
        """Parse a single DEX-related line."""
        if not line or line.startswith('#'):
            return None
        
        # DEX2OAT compilation line
        dex2oat_match = re.search(r'dex2oat.*--classpath-dir\s+([^\s]+)', line, re.IGNORECASE)
        if dex2oat_match:
            classpath_dir = dex2oat_match.group(1)
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='dex2oat_compilation',
                raw_line=line,
                parsed_content={
                    'classpath_dir': classpath_dir,
                    'compilation_type': 'dex2oat'
                },
                confidence=0.9
            )
        
        # DEXOPT compilation line
        dexopt_match = re.search(r'dexopt.*secondary.*([^\s]+)', line, re.IGNORECASE)
        if dexopt_match:
            dex_path = dexopt_match.group(1)
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='dexopt_secondary',
                raw_line=line,
                parsed_content={
                    'dex_path': dex_path,
                    'compilation_type': 'dexopt'
                },
                confidence=0.9
            )
        
        # Compilation reason
        reason_match = re.search(r'compilation-reason=([^\s]+)', line, re.IGNORECASE)
        if reason_match:
            reason = reason_match.group(1)
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='dex_compilation_reason',
                raw_line=line,
                parsed_content={
                    'compilation_reason': reason
                },
                confidence=0.8
            )
        
        # Code cache activity
        cache_match = re.search(r'code_cache.*([^\s]+)', line, re.IGNORECASE)
        if cache_match:
            cache_path = cache_match.group(1)
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='code_cache_activity',
                raw_line=line,
                parsed_content={
                    'cache_path': cache_path
                },
                confidence=0.8
            )
        
        # Secondary DEX loading
        secondary_match = re.search(r'secondary-dex.*([^\s]+)', line, re.IGNORECASE)
        if secondary_match:
            dex_path = secondary_match.group(1)
            return ParsedLogEntry(
                line_number=line_num,
                source_file=source_file,
                entry_type='secondary_dex_loading',
                raw_line=line,
                parsed_content={
                    'dex_path': dex_path
                },
                confidence=0.8
            )
        
        return None
