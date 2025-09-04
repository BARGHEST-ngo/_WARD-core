"""
Package Parser for dumpsys package output.

This parser extracts comprehensive package information from Android's package manager
including permissions, installers, UIDs, signatures, and package metadata.
"""

import re
from typing import Iterator, Dict, Optional, Set
from pathlib import Path

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class PackageParser(BaseParser):
    """
    Parser for Android dumpsys package output.
    
    Extracts package information, permissions, installers, UIDs, and signatures
    from the package manager service dump.
    """
    
    @property
    def parser_name(self) -> str:
        return "package_parser"
    
    @property
    def parser_version(self) -> str:
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        return ParserCapabilities(
            supported_extensions={'.txt'},
            supported_mime_types={'text/plain'},
            content_patterns=[
                'PACKAGE MANAGER',
                'dumpsys package',
                'Package [',
                'installerPackageName='
            ],
            header_patterns=[
                'PACKAGE MANAGER (dumpsys package)',
                'Packages:'
            ],
            output_entry_types={
                'package_info',
                'installer_info', 
                'permission',
                'package_signature',
                'uid_mapping'
            },
            supports_streaming=True,
            memory_efficient=True,
            estimated_speed="fast"
        )
    
    def can_parse(self, file_path: Path, content_sample: str) -> bool:
        """Check if this file contains package manager output."""
        content_lower = content_sample.lower()
        
        # Skip BARGHEST WARD header and look for actual content
        if 'barghest ward adb collection' in content_lower:
            # Remove header lines and check the actual content
            lines = content_sample.split('\n')
            actual_content = '\n'.join([line for line in lines if not line.startswith('#')])
            content_lower = actual_content.lower()
        else:
            actual_content = content_sample
            content_lower = content_sample.lower()
        
        # Check for package manager indicators
        package_indicators = [
            'package manager',
            'dumpsys package',
            'package [',
            'installerpkg=',
            'installerpackagename=',
            'installerpackagename=',  # Note: case variations
            'installer:',
            'uninstaller:',
            'total number of currently running services',
            'database versions:',
            'verifiers:',
            'libraries:',
            'features:'
        ]
        
        # Must have at least one specific package indicator
        has_package_indicator = any(indicator in content_lower for indicator in package_indicators)
        
        # Additional check: must have package-specific patterns
        has_package_patterns = any(pattern in actual_content for pattern in ['Package [', 'installer:', 'uninstaller:', 'Database versions:', 'Verifiers:'])
        
        return has_package_indicator and has_package_patterns
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse dumpsys package file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                current_package = None
                in_package_section = False
                
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Skip very long lines (likely binary data)
                    if len(line) > 10000:
                        continue
                    
                    # Check for package section start
                    package_match = re.search(r'Package \[([\w.]+)\]', line)
                    if package_match:
                        current_package = package_match.group(1)
                        in_package_section = True
                        
                        # Create package info entry
                        entry = self._create_package_info_entry(
                            line, line_num, current_package, file_path.name
                        )
                        if entry:
                            yield entry
                        continue
                    
                    # Parse package-specific lines
                    if in_package_section and current_package:
                        entry = self._parse_package_line(
                            line, line_num, current_package, file_path.name
                        )
                        if entry:
                            yield entry
                    
                    # Parse general lines (not package-specific)
                    else:
                        entry = self._parse_general_line(
                            line, line_num, file_path.name
                        )
                        if entry:
                            yield entry
                    
                    # Check if we're leaving a package section
                    if in_package_section and (
                        line.startswith('Package [') or 
                        line.startswith('Shared users:') or
                        line.startswith('Settings version:')
                    ):
                        if not line.startswith('Package ['):
                            in_package_section = False
                            current_package = None
                            
        except Exception as e:
            self.logger.error(f"Error parsing package file {file_path}: {e}")
            raise
    
    def _create_package_info_entry(
        self, 
        line: str, 
        line_num: int, 
        package: str,
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Create a package info entry."""
        
        # Extract additional package metadata from the Package line
        parsed_content = {'package_name': package}
        
        # Look for additional info in the same line
        if 'codePath=' in line:
            code_path_match = re.search(r'codePath=([^\s]+)', line)
            if code_path_match:
                parsed_content['code_path'] = code_path_match.group(1)
        
        if 'versionCode=' in line:
            version_match = re.search(r'versionCode=([^\s]+)', line)
            if version_match:
                parsed_content['version_code'] = version_match.group(1)
        
        return ParsedLogEntry(
            line_number=line_num,
            source_file=source_file,
            entry_type='package_info',
            raw_line=line,
            package=package,
            parsed_content=parsed_content,
            confidence=0.9
        )
    
    def _parse_package_line(
        self, 
        line: str, 
        line_num: int, 
        package: str,
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse a line within a package section."""
        
        line_lower = line.lower()
        
        # Installer information
        if 'installerpackagename=' in line_lower:
            installer_match = re.search(r'installerPackageName=([^\s]+)', line, re.IGNORECASE)
            if installer_match:
                installer = installer_match.group(1)
                
                return ParsedLogEntry(
                    line_number=line_num,
                    source_file=source_file,
                    entry_type='installer_info',
                    raw_line=line,
                    package=package,
                    parsed_content={'installer': installer},
                    confidence=0.95
                )
        
        # UID information
        if 'userid=' in line_lower or 'uid=' in line_lower:
            uid_match = re.search(r'(userId|uid)=(\d+)', line, re.IGNORECASE)
            if uid_match:
                uid = int(uid_match.group(2))
                
                return ParsedLogEntry(
                    line_number=line_num,
                    source_file=source_file,
                    entry_type='uid_mapping',
                    raw_line=line,
                    package=package,
                    parsed_content={'uid': uid},
                    confidence=0.9
                )
        
        # Permission grants
        if 'permission=' in line_lower and ('granted=true' in line_lower or 'granted' in line_lower):
            perm_match = re.search(r'permission=([\w.]+)', line, re.IGNORECASE)
            if perm_match:
                permission = perm_match.group(1)
                granted = 'granted=true' in line_lower or 'granted' in line_lower
                
                return ParsedLogEntry(
                    line_number=line_num,
                    source_file=source_file,
                    entry_type='permission',
                    raw_line=line,
                    package=package,
                    parsed_content={
                        'permission': permission,
                        'granted': granted
                    },
                    confidence=0.9
                )
        
        # Signature information
        if ('signatures' in line_lower or 'signinginfo' in line_lower) and ('sha-256' in line_lower or 'sha256' in line_lower):
            sha_match = re.search(r'(SHA-256:|sha256:|certDigest=)\s*([0-9A-Fa-f:]{32,})', line, re.IGNORECASE)
            if sha_match:
                digest = sha_match.group(2).replace(':', '').lower()
                
                return ParsedLogEntry(
                    line_number=line_num,
                    source_file=source_file,
                    entry_type='package_signature',
                    raw_line=line,
                    package=package,
                    parsed_content={'sha256_digest': digest},
                    confidence=0.85
                )
        
        # Additional package metadata
        if any(keyword in line_lower for keyword in ['versionname=', 'targetsdkversion=', 'flags=']):
            parsed_content = {}
            
            # Version name
            version_name_match = re.search(r'versionName=([^\s]+)', line, re.IGNORECASE)
            if version_name_match:
                parsed_content['version_name'] = version_name_match.group(1)
            
            # Target SDK version
            target_sdk_match = re.search(r'targetSdkVersion=(\d+)', line, re.IGNORECASE)
            if target_sdk_match:
                parsed_content['target_sdk_version'] = int(target_sdk_match.group(1))
            
            # Package flags
            flags_match = re.search(r'flags=\[\s*([^\]]+)\s*\]', line, re.IGNORECASE)
            if flags_match:
                flags_str = flags_match.group(1)
                parsed_content['flags'] = [f.strip() for f in flags_str.split() if f.strip()]
            
            if parsed_content:
                return ParsedLogEntry(
                    line_number=line_num,
                    source_file=source_file,
                    entry_type='package_info',
                    raw_line=line,
                    package=package,
                    parsed_content=parsed_content,
                    confidence=0.8
                )
        
        return None
    
    def _parse_general_line(
        self, 
        line: str, 
        line_num: int, 
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse general (non-package-specific) lines."""
        
        line_lower = line.lower()
        
        # Shared user information
        if 'shared user' in line_lower and 'userid=' in line_lower:
            shared_user_match = re.search(r'SharedUser \[([\w.]+)\].*userId=(\d+)', line, re.IGNORECASE)
            if shared_user_match:
                shared_user = shared_user_match.group(1)
                uid = int(shared_user_match.group(2))
                
                return ParsedLogEntry(
                    line_number=line_num,
                    source_file=source_file,
                    entry_type='shared_user',
                    raw_line=line,
                    parsed_content={
                        'shared_user': shared_user,
                        'uid': uid
                    },
                    confidence=0.9
                )
        
        # Feature declarations
        if 'feature' in line_lower and ('available' in line_lower or 'unavailable' in line_lower):
            feature_match = re.search(r'feature:([\w.]+)', line, re.IGNORECASE)
            if feature_match:
                feature = feature_match.group(1)
                available = 'available' in line_lower
                
                return ParsedLogEntry(
                    line_number=line_num,
                    source_file=source_file,
                    entry_type='system_feature',
                    raw_line=line,
                    parsed_content={
                        'feature': feature,
                        'available': available
                    },
                    confidence=0.8
                )
        
        # Permission definitions
        if 'permission:' in line_lower and ('protection=' in line_lower or 'level=' in line_lower):
            perm_def_match = re.search(r'permission:([\w.]+)', line, re.IGNORECASE)
            protection_match = re.search(r'(protection|protectionLevel)=([\w|]+)', line, re.IGNORECASE)
            
            if perm_def_match:
                permission = perm_def_match.group(1)
                parsed_content = {'permission_name': permission}
                
                if protection_match:
                    protection_level = protection_match.group(2)
                    parsed_content['protection_level'] = protection_level
                
                return ParsedLogEntry(
                    line_number=line_num,
                    source_file=source_file,
                    entry_type='permission_definition',
                    raw_line=line,
                    parsed_content=parsed_content,
                    confidence=0.8
                )
        
        return None
