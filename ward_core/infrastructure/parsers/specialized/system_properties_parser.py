"""
System Properties Parser for getprop and build.prop output.

This parser extracts Android system properties including device information,
security settings, build configuration, and other system-level data.
"""

import re
from typing import Iterator, Dict, Optional, Set
from pathlib import Path

from ..base_parser import BaseParser, ParsedLogEntry, ParserCapabilities


class SystemPropertiesParser(BaseParser):
    """
    Parser for Android system properties (getprop output, build.prop files).
    
    Extracts device information, security configuration, build details,
    and other system properties relevant for forensic analysis.
    """
    
    # Security-relevant property categories
    SECURITY_PROPERTIES = {
        'ro.debuggable',
        'ro.secure',
        'ro.adb.secure',
        'service.adb.root',
        'ro.boot.verifiedbootstate',
        'ro.boot.flash.locked',
        'ro.boot.veritymode',
        'ro.build.selinux',
        'selinux.status',
        'ro.crypto.state',
        'ro.crypto.type'
    }
    
    # Device identification properties
    DEVICE_ID_PROPERTIES = {
        'ro.product.model',
        'ro.product.brand', 
        'ro.product.manufacturer',
        'ro.product.device',
        'ro.product.name',
        'ro.build.fingerprint',
        'ro.build.id',
        'ro.build.display.id',
        'ro.serialno',
        'ro.boot.serialno'
    }
    
    # Build information properties
    BUILD_PROPERTIES = {
        'ro.build.version.release',
        'ro.build.version.sdk',
        'ro.build.version.codename',
        'ro.build.type',
        'ro.build.tags',
        'ro.build.date',
        'ro.build.user',
        'ro.build.host'
    }
    
    # Suspicious property patterns (indicating modification/rooting)
    SUSPICIOUS_PATTERNS = [
        re.compile(r'.*magisk.*', re.IGNORECASE),
        re.compile(r'.*xposed.*', re.IGNORECASE),
        re.compile(r'.*supersu.*', re.IGNORECASE),
        re.compile(r'.*root.*', re.IGNORECASE),
        re.compile(r'.*busybox.*', re.IGNORECASE),
    ]
    
    @property
    def parser_name(self) -> str:
        return "system_properties_parser"
    
    @property
    def parser_version(self) -> str:
        return "1.0.0"
    
    def _define_capabilities(self) -> ParserCapabilities:
        return ParserCapabilities(
            supported_extensions={'.txt', '.prop'},
            supported_mime_types={'text/plain'},
            content_patterns=[
                '[ro.',
                '[sys.',
                '[persist.',
                '[init.',
                r'ro\.\w+',
                'getprop'
            ],
            header_patterns=[
                '# build.prop',
                '# BEGIN',
                '# PROPERTY'
            ],
            output_entry_types={
                'system_property',
                'device_info',
                'security_config',
                'build_info',
                'suspicious_property'
            },
            supports_streaming=True,
            memory_efficient=True,
            estimated_speed="fast"
        )
    
    def can_parse(self, file_path: Path, content_sample: str) -> bool:
        """Check if this file contains system properties."""
        
        # Check for getprop output format
        getprop_pattern = r'\[[\w.]+\]:\s*\[.*\]'
        if re.search(getprop_pattern, content_sample):
            return True
        
        # Check for build.prop format
        if '# build.prop' in content_sample or 'ro.' in content_sample:
            return True
        
        # Check for property assignment format
        prop_assignment = r'\w+\.\w+=.*'
        if re.search(prop_assignment, content_sample):
            return True
        
        return False
    
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """Parse system properties file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    entry = self._parse_property_line(line, line_num, file_path.name)
                    if entry:
                        yield entry
                        
        except Exception as e:
            self.logger.error(f"Error parsing system properties file {file_path}: {e}")
            raise
    
    def _parse_property_line(
        self,
        line: str,
        line_num: int,
        source_file: str
    ) -> Optional[ParsedLogEntry]:
        """Parse a single property line."""
        
        # Try getprop format first: [property.name]: [value]
        getprop_match = re.match(r'\[([^\]]+)\]:\s*\[([^\]]*)\]', line)
        if getprop_match:
            property_name = getprop_match.group(1)
            property_value = getprop_match.group(2)
        else:
            # Try build.prop format: property.name=value
            prop_match = re.match(r'^([^=]+)=(.*)$', line)
            if prop_match:
                property_name = prop_match.group(1).strip()
                property_value = prop_match.group(2).strip()
            else:
                return None
        
        # Build parsed content
        parsed_content = {
            'property_name': property_name,
            'property_value': property_value
        }
        
        # Categorize property
        entry_type, additional_content = self._categorize_property(property_name, property_value)
        parsed_content.update(additional_content)
        
        # Calculate confidence
        confidence = self._calculate_confidence(property_name, property_value, entry_type)
        
        return ParsedLogEntry(
            line_number=line_num,
            source_file=source_file,
            entry_type=entry_type,
            raw_line=line,
            parsed_content=parsed_content,
            confidence=confidence
        )
    
    def _categorize_property(self, prop_name: str, prop_value: str) -> tuple[str, Dict]:
        """Categorize property and extract additional information."""
        
        additional_content = {}
        
        # Check for security properties
        if prop_name in self.SECURITY_PROPERTIES:
            additional_content['is_security_property'] = True
            
            # Analyze security-relevant values
            if prop_name == 'ro.debuggable' and prop_value == '1':
                additional_content['debug_enabled'] = True
                additional_content['security_concern'] = 'Debug mode enabled'
            
            elif prop_name == 'ro.secure' and prop_value == '0':
                additional_content['secure_disabled'] = True
                additional_content['security_concern'] = 'Secure mode disabled'
            
            elif prop_name == 'ro.adb.secure' and prop_value == '0':
                additional_content['adb_secure_disabled'] = True
                additional_content['security_concern'] = 'ADB security disabled'
            
            elif prop_name == 'service.adb.root' and prop_value == '1':
                additional_content['adb_root_enabled'] = True
                additional_content['security_concern'] = 'ADB root access enabled'
            
            elif prop_name == 'ro.boot.verifiedbootstate' and prop_value != 'green':
                additional_content['boot_verification_issue'] = True
                additional_content['security_concern'] = f'Boot verification state: {prop_value}'
            
            return 'security_config', additional_content
        
        # Check for device identification properties
        if prop_name in self.DEVICE_ID_PROPERTIES:
            additional_content['is_device_id'] = True
            
            # Extract specific device info
            if prop_name == 'ro.product.model':
                additional_content['device_model'] = prop_value
            elif prop_name == 'ro.product.manufacturer':
                additional_content['manufacturer'] = prop_value
            elif prop_name == 'ro.build.fingerprint':
                additional_content['build_fingerprint'] = prop_value
            elif prop_name in ['ro.serialno', 'ro.boot.serialno']:
                additional_content['serial_number'] = prop_value
            
            return 'device_info', additional_content
        
        # Check for build properties
        if prop_name in self.BUILD_PROPERTIES:
            additional_content['is_build_property'] = True
            
            # Extract specific build info
            if prop_name == 'ro.build.version.release':
                additional_content['android_version'] = prop_value
            elif prop_name == 'ro.build.version.sdk':
                try:
                    additional_content['api_level'] = int(prop_value)
                except ValueError:
                    pass
            elif prop_name == 'ro.build.type':
                additional_content['build_type'] = prop_value
                if prop_value not in ['user', 'userdebug']:
                    additional_content['non_production_build'] = True
            elif prop_name == 'ro.build.tags':
                additional_content['build_tags'] = prop_value.split(',') if prop_value else []
            
            return 'build_info', additional_content
        
        # Check for suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern.search(prop_name) or pattern.search(prop_value):
                additional_content['is_suspicious'] = True
                additional_content['suspicious_pattern'] = pattern.pattern
                additional_content['security_concern'] = 'Potentially modified system'
                return 'suspicious_property', additional_content
        
        # Check for root-related properties
        if 'root' in prop_name.lower() or 'root' in prop_value.lower():
            additional_content['root_related'] = True
            if prop_value.lower() in ['1', 'true', 'enabled']:
                additional_content['security_concern'] = 'Root access indicated'
            return 'suspicious_property', additional_content
        
        # Check for custom ROM indicators
        if any(keyword in prop_name.lower() for keyword in ['lineage', 'cyanogen', 'paranoid', 'omni']):
            additional_content['custom_rom_indicator'] = True
            additional_content['rom_type'] = prop_name
            return 'build_info', additional_content
        
        # Default to system property
        return 'system_property', additional_content
    
    def _calculate_confidence(self, prop_name: str, prop_value: str, entry_type: str) -> float:
        """Calculate confidence score for the property."""
        
        base_confidence = 0.9
        
        # Higher confidence for well-known properties
        all_known_props = (
            self.SECURITY_PROPERTIES | 
            self.DEVICE_ID_PROPERTIES | 
            self.BUILD_PROPERTIES
        )
        
        if prop_name in all_known_props:
            base_confidence = 0.95
        
        # Higher confidence for security-related entries
        if entry_type in ['security_config', 'suspicious_property']:
            base_confidence += 0.03
        
        # Lower confidence for empty values
        if not prop_value.strip():
            base_confidence -= 0.1
        
        return min(1.0, max(0.5, base_confidence))


