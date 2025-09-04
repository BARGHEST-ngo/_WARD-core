"""
Logcat Parser for Android system logs.

This parser extracts security events, crashes, system anomalies, and suspicious
behavior patterns from Android logcat output.
"""

import re
from typing import Iterator, Dict, Optional, Set
from pathlib import Path
from datetime import datetime

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class LogcatParser(BaseParser):
    """
    Parser for Android logcat output in various formats.
    
    Supports multiple logcat formats and extracts security-relevant events,
    crashes, system anomalies, and behavioral patterns.
    """
    
    # Security-relevant log tags
    SECURITY_TAGS = {
        'ActivityManager', 'PackageManager', 'WindowManager',
        'SELinux', 'audit', 'Zygote', 'AndroidRuntime',
        'System.err', 'dalvikvm', 'DEBUG'
    }
    
    # Crash indicators in log messages
    CRASH_PATTERNS = [
        re.compile(r'fatal\s+exception', re.IGNORECASE),
        re.compile(r'process.*crashed', re.IGNORECASE),
        re.compile(r'signal\s+\d+\s+\(SIG\w+\)', re.IGNORECASE),
        re.compile(r'segmentation\s+fault|segfault', re.IGNORECASE),
        re.compile(r'abort.*signal', re.IGNORECASE),
        re.compile(r'native\s+crash', re.IGNORECASE),
    ]
    
    # SELinux denial patterns
    SELINUX_PATTERNS = [
        re.compile(r'avc:\s+denied', re.IGNORECASE),
        re.compile(r'selinux.*denied', re.IGNORECASE),
        re.compile(r'type=\d+.*avc', re.IGNORECASE),
    ]
    
    # Exploitation indicators
    EXPLOIT_PATTERNS = [
        re.compile(r'exploit|privesc|privilege.*escalat', re.IGNORECASE),
        re.compile(r'root.*exploit|rooting', re.IGNORECASE),
        re.compile(r'buffer\s+overflow|heap\s+overflow', re.IGNORECASE),
        re.compile(r'use.*after.*free|double.*free', re.IGNORECASE),
        re.compile(r'injection|shellcode', re.IGNORECASE),
    ]
    
    # Suspicious activity patterns
    SUSPICIOUS_PATTERNS = [
        re.compile(r'su\s+|superuser', re.IGNORECASE),
        re.compile(r'busybox|magisk', re.IGNORECASE),
        re.compile(r'xposed|frida', re.IGNORECASE),
        re.compile(r'/system/bin/sh|/system/xbin', re.IGNORECASE),
    ]
    
    @property
    def parser_name(self) -> str:
        return "logcat_parser"
    
    @property
    def parser_version(self) -> str:
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        return ParserCapabilities(
            supported_extensions={'.txt', '.log'},
            supported_mime_types={'text/plain'},
            content_patterns=[
                r'\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}',  # Android timestamp format
                'AndroidRuntime',
                'ActivityManager',
                'PackageManager',
                'beginning of /dev/log'
            ],
            header_patterns=[
                'beginning of /dev/log/',
                'beginning of main',
                'beginning of system'
            ],
            output_entry_types={
                'system_log',
                'crash_log',
                'security_event',
                'selinux_denial',
                'exploit_attempt',
                'suspicious_activity'
            },
            supports_streaming=True,
            memory_efficient=True,
            estimated_speed="fast"
        )
    
    def can_parse(self, file_path: Path, content_sample: str) -> bool:
        """Check if this file contains logcat output."""
        
        # Check for logcat timestamp format
        timestamp_pattern = r'\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}'
        if re.search(timestamp_pattern, content_sample):
            return True
        
        # Check for common Android log indicators
        logcat_indicators = [
            'androidruntime',
            'activitymanager',
            'packagemanager',
            'beginning of /dev/log',
            'beginning of main',
            'beginning of system'
        ]
        
        content_lower = content_sample.lower()
        return any(indicator in content_lower for indicator in logcat_indicators)
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse logcat file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Skip very long lines (likely binary data or corrupted)
                    if len(line) > 8000:
                        continue
                    
                    # Skip logcat headers
                    if line.startswith('--------- beginning of'):
                        continue
                    
                    entry = self._parse_logcat_line(line, line_num, file_path.name)
                    if entry:
                        yield entry
                        
        except Exception as e:
            self.logger.error(f"Error parsing logcat file {file_path}: {e}")
            raise
    
    def _parse_logcat_line(
        self,
        line: str,
        line_num: int,
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse a single logcat line."""
        
        # Try to parse standard logcat format: timestamp PID TID priority tag: message
        logcat_match = re.match(
            r'^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEFS])\s+([^:]+):\s*(.*)$',
            line
        )
        
        if not logcat_match:
            # Try alternative format without TID
            alt_match = re.match(
                r'^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+([VDIWEFS])/([^(]+)\(\s*(\d+)\):\s*(.*)$',
                line
            )
            if alt_match:
                timestamp = alt_match.group(1)
                priority = alt_match.group(2)
                tag = alt_match.group(3).strip()
                pid = int(alt_match.group(4))
                message = alt_match.group(5)
                tid = None
            else:
                # Fallback - treat as unknown format but still analyze content
                return self._parse_unstructured_log(line, line_num, source_file)
        else:
            # Standard format parsing
            timestamp = logcat_match.group(1)
            pid = int(logcat_match.group(2))
            tid = int(logcat_match.group(3))
            priority = logcat_match.group(4)
            tag = logcat_match.group(5).strip()
            message = logcat_match.group(6)
        
        # Build parsed content
        parsed_content = {
            'timestamp': timestamp,
            'pid': pid,
            'priority': priority,
            'tag': tag,
            'message': message
        }
        
        if tid is not None:
            parsed_content['tid'] = tid
        
        # Determine entry type and extract security-relevant information
        entry_type, additional_content = self._analyze_log_content(tag, message, priority)
        parsed_content.update(additional_content)
        
        # Calculate confidence based on content analysis
        confidence = self._calculate_confidence(entry_type, tag, message)
        
        return ParsedLogEntry(
            line_number=line_num,
            source_file=source_file,
            entry_type=entry_type,
            raw_line=line,
            parsed_content=parsed_content,
            confidence=confidence,
            log_level=priority
        )
    
    def _parse_unstructured_log(
        self,
        line: str,
        line_num: int,
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse unstructured log line (fallback)."""
        
        # Still analyze content for security patterns
        entry_type, additional_content = self._analyze_log_content("unknown", line, "I")
        
        parsed_content = {
            'message': line,
            'tag': 'unstructured'
        }
        parsed_content.update(additional_content)
        
        return ParsedLogEntry(
            line_number=line_num,
            source_file=source_file,
            entry_type=entry_type,
            raw_line=line,
            parsed_content=parsed_content,
            confidence=0.6
        )
    
    def _analyze_log_content(self, tag: str, message: str, priority: str) -> tuple[str, Dict]:
        """Analyze log content for security-relevant patterns."""
        
        tag_lower = tag.lower()
        message_lower = message.lower()
        additional_content = {}
        
        # Check for crash patterns
        for pattern in self.CRASH_PATTERNS:
            if pattern.search(message):
                additional_content['crash_type'] = 'native_crash' if 'native' in message_lower else 'java_crash'
                additional_content['is_crash'] = True
                
                # Extract process information from crash
                proc_match = re.search(r'process\s+([\w.]+)', message, re.IGNORECASE)
                if proc_match:
                    additional_content['crashed_process'] = proc_match.group(1)
                
                # Extract signal information
                signal_match = re.search(r'signal\s+(\d+)\s+\((\w+)\)', message, re.IGNORECASE)
                if signal_match:
                    additional_content['signal_number'] = int(signal_match.group(1))
                    additional_content['signal_name'] = signal_match.group(2)
                
                return 'crash_log', additional_content
        
        # Check for SELinux denials
        for pattern in self.SELINUX_PATTERNS:
            if pattern.search(message):
                additional_content['is_selinux_denial'] = True
                
                # Extract SELinux context information
                scontext_match = re.search(r'scontext=([^\s]+)', message)
                if scontext_match:
                    additional_content['source_context'] = scontext_match.group(1)
                
                tcontext_match = re.search(r'tcontext=([^\s]+)', message)
                if tcontext_match:
                    additional_content['target_context'] = tcontext_match.group(1)
                
                # Extract denied permissions
                perms_match = re.search(r'\{([^}]+)\}', message)
                if perms_match:
                    permissions = [p.strip() for p in perms_match.group(1).split()]
                    additional_content['denied_permissions'] = permissions
                
                return 'selinux_denial', additional_content
        
        # Check for exploitation patterns
        for pattern in self.EXPLOIT_PATTERNS:
            if pattern.search(message):
                additional_content['is_exploit_attempt'] = True
                additional_content['exploit_indicator'] = pattern.pattern
                return 'exploit_attempt', additional_content
        
        # Check for suspicious activity
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern.search(message):
                additional_content['is_suspicious'] = True
                additional_content['suspicious_indicator'] = pattern.pattern
                return 'suspicious_activity', additional_content
        
        # Check for security-relevant tags
        if tag_lower in [t.lower() for t in self.SECURITY_TAGS]:
            additional_content['is_security_relevant'] = True
            
            # Special handling for specific tags
            if tag_lower == 'activitymanager':
                # Extract app launch/kill information
                if 'start proc' in message_lower or 'starting:' in message_lower:
                    proc_match = re.search(r'(start proc|starting:)\s+([\w.]+)', message, re.IGNORECASE)
                    if proc_match:
                        additional_content['started_process'] = proc_match.group(2)
                        additional_content['activity_type'] = 'process_start'
                
                elif 'killing' in message_lower or 'died' in message_lower:
                    proc_match = re.search(r'(killing|died).*?([\w.]+)', message, re.IGNORECASE)
                    if proc_match:
                        additional_content['killed_process'] = proc_match.group(2)
                        additional_content['activity_type'] = 'process_kill'
            
            elif tag_lower == 'packagemanager':
                # Extract package install/uninstall events
                if any(keyword in message_lower for keyword in ['installed', 'uninstalled', 'updated']):
                    pkg_match = re.search(r'([\w.]+)', message)
                    if pkg_match:
                        additional_content['affected_package'] = pkg_match.group(1)
                        if 'installed' in message_lower:
                            additional_content['package_event'] = 'install'
                        elif 'uninstalled' in message_lower:
                            additional_content['package_event'] = 'uninstall'
                        elif 'updated' in message_lower:
                            additional_content['package_event'] = 'update'
            
            return 'security_event', additional_content
        
        # Default to system log
        return 'system_log', additional_content
    
    def _calculate_confidence(self, entry_type: str, tag: str, message: str) -> float:
        """Calculate confidence score for the parsed entry."""
        
        base_confidence = 0.8
        
        # Higher confidence for structured entries
        if entry_type in ['crash_log', 'selinux_denial', 'exploit_attempt']:
            base_confidence = 0.95
        
        # Higher confidence for security-relevant tags
        if tag.lower() in [t.lower() for t in self.SECURITY_TAGS]:
            base_confidence += 0.05
        
        # Higher confidence for high-priority logs
        if any(keyword in message.lower() for keyword in ['error', 'fatal', 'crash', 'exception']):
            base_confidence += 0.05
        
        return min(1.0, base_confidence)


