"""
ANR Trace Parser for Android Application Not Responding trace files.

This parser extracts forensically relevant information from Android ANR trace files
including thread dumps, lock information, and CPU usage data.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterator
from datetime import datetime

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class ANRTraceParser(BaseParser):
    """Parser for Android ANR trace files containing thread dumps and lock information."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.supported_formats = ["txt"]
    
    @property
    def parser_name(self) -> str:
        """Get the name of this parser."""
        return "anr_trace_parser"
    
    @property
    def parser_version(self) -> str:
        """Get the version of this parser."""
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        return ParserCapabilities(
            supported_extensions={'.txt'},
            content_patterns=[
                '----- pid',
                'at ',
                'DALVIK THREADS',
                'suspend all histogram:',
                'Total number of allocations',
                'Total bytes allocated',
                'Total bytes freed',
                'Free memory',
                'Used memory',
                'External memory',
                'held by thread',
                'waiting to lock',
                'locked by thread'
            ],
            header_patterns=[
                '----- pid',
                'DALVIK THREADS',
                'suspend all histogram:'
            ],
            output_entry_types={
                'anr_header',
                'process_info',
                'thread_dump',
                'stack_frame',
                'lock_info',
                'memory_stats',
                'gc_stats'
            },
            supports_streaming=True,
            memory_efficient=True,
            estimated_speed="medium"
        )
    
    def can_parse(self, file_path: Path, content_sample: str = "") -> bool:
        """Check if this parser can handle the given file."""
        filename = file_path.name.lower()
        
        # Check filename patterns
        if any(keyword in filename for keyword in ['anr', 'traces', 'trace']):
            return True
        
        # Check content patterns for ANR trace files
        anr_indicators = [
            '----- pid',
            'dalvik threads',
            'suspend all histogram:',
            'at android.',
            'at java.',
            'held by thread',
            'waiting to lock'
        ]
        
        content_lower = content_sample.lower()
        return any(indicator in content_lower for indicator in anr_indicators)
    
    def get_confidence_score(self, file_path: Path) -> float:
        """Get confidence score for parsing this file."""
        filename = file_path.name.lower()
        if any(keyword in filename for keyword in ['anr', 'traces']):
            return 0.95
        return 0.7 if self.can_parse(file_path) else 0.0
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse ANR trace file and yield structured entries."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse different sections of the ANR trace
            yield from self._parse_anr_content(content, str(file_path))
            
        except Exception as e:
            self.logger.error(f"Error parsing ANR trace file {file_path}: {e}")
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
    
    def _parse_anr_content(self, content: str, source_file: str) -> Iterator[ParsedLogEntry]:
        """Parse ANR trace file content into structured entries."""
        lines = content.split('\n')
        current_section = None
        current_thread = None
        line_num = 0
        
        for line in lines:
            line_num += 1
            line = line.strip()
            
            if not line:
                continue
            
            # Parse process header
            if line.startswith('----- pid'):
                current_section = 'process_header'
                yield self._parse_process_header(line, line_num, source_file)
            
            # Parse thread information
            elif line.startswith('"') and 'tid=' in line:
                current_section = 'thread_info'
                current_thread = self._extract_thread_name(line)
                yield self._parse_thread_info(line, line_num, source_file)
            
            # Parse stack frames
            elif line.startswith('at '):
                yield self._parse_stack_frame(line, line_num, source_file, current_thread)
            
            # Parse lock information
            elif 'held by thread' in line or 'waiting to lock' in line or 'locked by thread' in line:
                yield self._parse_lock_info(line, line_num, source_file, current_thread)
            
            # Parse memory statistics
            elif any(keyword in line.lower() for keyword in ['total number of allocations', 'total bytes', 'free memory', 'used memory']):
                yield self._parse_memory_stats(line, line_num, source_file)
            
            # Parse GC information
            elif 'suspend all histogram:' in line.lower():
                current_section = 'gc_stats'
                yield self._parse_gc_header(line, line_num, source_file)
            
            # Parse DALVIK THREADS header
            elif 'DALVIK THREADS' in line:
                current_section = 'dalvik_threads'
                yield self._parse_dalvik_header(line, line_num, source_file)
    
    def _parse_process_header(self, line: str, line_num: int, source_file: str) -> ParsedLogEntry:
        """Parse process header information."""
        # Extract PID and process name: ----- pid 1234 at 2023-08-26 12:58:11 -----
        pid_match = re.search(r'pid\s+(\d+)', line)
        time_match = re.search(r'at\s+([\d-]+\s+[\d:]+)', line)
        
        return ParsedLogEntry(
            entry_type='anr_header',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'pid': pid_match.group(1) if pid_match else 'unknown',
                'anr_timestamp': time_match.group(1) if time_match else 'unknown',
                'timestamp': datetime.now().isoformat()
            },
            tags={'anr', 'process_header', 'security_relevant'},
            confidence=0.95
        )
    
    def _parse_thread_info(self, line: str, line_num: int, source_file: str) -> ParsedLogEntry:
        """Parse thread information."""
        # Extract thread info: "main" prio=5 tid=1 RUNNABLE
        thread_match = re.match(r'"([^"]+)"\s+prio=(\d+)\s+tid=(\d+)\s+(\w+)', line)
        
        if thread_match:
            thread_name, priority, tid, state = thread_match.groups()
            
            return ParsedLogEntry(
                entry_type='thread_dump',
                source_file=source_file,
                line_number=line_num,
                raw_line=line,
                parsed_content={
                    'thread_name': thread_name,
                    'priority': int(priority),
                    'thread_id': int(tid),
                    'thread_state': state,
                    'timestamp': datetime.now().isoformat()
                },
                tags={'anr', 'thread_info', 'security_relevant'},
                confidence=0.9
            )
        
        # Fallback for malformed thread info
        return ParsedLogEntry(
            entry_type='thread_dump',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'raw_thread_info': line,
                'timestamp': datetime.now().isoformat()
            },
            tags={'anr', 'thread_info'},
            confidence=0.5
        )
    
    def _parse_stack_frame(self, line: str, line_num: int, source_file: str, current_thread: Optional[str]) -> ParsedLogEntry:
        """Parse stack frame information."""
        # Extract stack frame: at com.example.Class.method(Class.java:123)
        frame_match = re.match(r'at\s+([^(]+)(?:\(([^:]+):(\d+)\))?', line)
        
        if frame_match:
            method, file_name, line_number = frame_match.groups()
            
            return ParsedLogEntry(
                entry_type='stack_frame',
                source_file=source_file,
                line_number=line_num,
                raw_line=line,
                parsed_content={
                    'thread_name': current_thread or 'unknown',
                    'method': method.strip(),
                    'source_file': file_name or 'unknown',
                    'source_line': int(line_number) if line_number else 0,
                    'timestamp': datetime.now().isoformat()
                },
                tags={'anr', 'stack_frame', 'thread_dump'},
                confidence=0.85
            )
        
        # Fallback for malformed stack frames
        return ParsedLogEntry(
            entry_type='stack_frame',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'thread_name': current_thread or 'unknown',
                'raw_frame': line,
                'timestamp': datetime.now().isoformat()
            },
            tags={'anr', 'stack_frame'},
            confidence=0.5
        )
    
    def _parse_lock_info(self, line: str, line_num: int, source_file: str, current_thread: Optional[str]) -> ParsedLogEntry:
        """Parse lock information."""
        lock_type = 'unknown'
        if 'held by thread' in line:
            lock_type = 'held'
        elif 'waiting to lock' in line:
            lock_type = 'waiting'
        elif 'locked by thread' in line:
            lock_type = 'locked'
        
        # Extract thread ID from lock info
        thread_match = re.search(r'thread\s+(\d+)', line)
        
        return ParsedLogEntry(
            entry_type='lock_info',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'current_thread': current_thread or 'unknown',
                'lock_type': lock_type,
                'related_thread': thread_match.group(1) if thread_match else 'unknown',
                'timestamp': datetime.now().isoformat()
            },
            tags={'anr', 'lock_info', 'security_relevant'},
            confidence=0.8
        )
    
    def _parse_memory_stats(self, line: str, line_num: int, source_file: str) -> ParsedLogEntry:
        """Parse memory statistics."""
        # Extract memory values
        value_match = re.search(r'(\d+(?:\.\d+)?)\s*([KMGT]?B)?', line)
        
        stat_type = 'unknown'
        if 'total number of allocations' in line.lower():
            stat_type = 'allocations'
        elif 'total bytes allocated' in line.lower():
            stat_type = 'bytes_allocated'
        elif 'total bytes freed' in line.lower():
            stat_type = 'bytes_freed'
        elif 'free memory' in line.lower():
            stat_type = 'free_memory'
        elif 'used memory' in line.lower():
            stat_type = 'used_memory'
        
        return ParsedLogEntry(
            entry_type='memory_stats',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'stat_type': stat_type,
                'value': value_match.group(1) if value_match else 'unknown',
                'unit': value_match.group(2) if value_match and value_match.group(2) else 'bytes',
                'timestamp': datetime.now().isoformat()
            },
            tags={'anr', 'memory_stats'},
            confidence=0.8
        )
    
    def _parse_gc_header(self, line: str, line_num: int, source_file: str) -> ParsedLogEntry:
        """Parse GC statistics header."""
        return ParsedLogEntry(
            entry_type='gc_stats',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'section': 'gc_histogram',
                'timestamp': datetime.now().isoformat()
            },
            tags={'anr', 'gc_stats'},
            confidence=0.9
        )
    
    def _parse_dalvik_header(self, line: str, line_num: int, source_file: str) -> ParsedLogEntry:
        """Parse DALVIK THREADS header."""
        return ParsedLogEntry(
            entry_type='anr_header',
            source_file=source_file,
            line_number=line_num,
            raw_line=line,
            parsed_content={
                'section': 'dalvik_threads',
                'timestamp': datetime.now().isoformat()
            },
            tags={'anr', 'dalvik_threads'},
            confidence=0.9
        )
    
    def _extract_thread_name(self, line: str) -> Optional[str]:
        """Extract thread name from thread info line."""
        thread_match = re.match(r'"([^"]+)"', line)
        return thread_match.group(1) if thread_match else None
