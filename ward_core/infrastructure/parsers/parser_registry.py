"""
Parser registry for managing and discovering log parsers.

Provides centralized registration and discovery of log parsers with auto-discovery.
"""

import importlib
import pkgutil
from typing import Dict, List, Type, Optional, Iterator, Tuple
from pathlib import Path
import logging

from .base_parser import BaseParser, ParsedLogEntry, ParseError, ParserCapabilities
from .format_detector import FormatDetector, DataFormat


class ParserRegistry:
    """
    Registry for managing and discovering log parsers.
    
    This class handles registration, discovery, and selection of parsers
    for different Android log formats.
    """
    
    def __init__(self):
        """Initialize the parser registry."""
        self._parsers: Dict[str, Type[BaseParser]] = {}
        self._instances: Dict[str, BaseParser] = {}
        self.format_detector = FormatDetector()
        self.logger = logging.getLogger("parser.registry")
        
        # Performance cache
        self._capability_cache: Dict[str, ParserCapabilities] = {}
        self._compatibility_cache: Dict[Tuple[str, str], bool] = {}
    
    def register(self, parser_class: Type[BaseParser]) -> None:
        """
        Register a parser class.
        
        Args:
            parser_class: Parser class to register
            
        Raises:
            ValueError: If parser class is invalid
        """
        if not issubclass(parser_class, BaseParser):
            raise ValueError(f"Class {parser_class} must inherit from BaseParser")
        
        # Create temporary instance to get parser info
        try:
            temp_instance = parser_class()
            parser_name = temp_instance.parser_name
            
            if parser_name in self._parsers:
                self.logger.debug(f"Parser {parser_name} is already registered, overwriting")
            
            self._parsers[parser_name] = parser_class
            self._capability_cache[parser_name] = temp_instance.capabilities
            
            self.logger.info(f"Registered parser: {parser_name} v{temp_instance.parser_version}")
            
        except Exception as e:
            self.logger.error(f"Failed to register parser {parser_class}: {e}")
            raise ValueError(f"Invalid parser class {parser_class}: {e}")
    
    def get_parser(self, parser_name: str, config: Optional[Dict] = None) -> BaseParser:
        """
        Get a parser instance by name.
        
        Args:
            parser_name: Name of parser to get
            config: Configuration for the parser
            
        Returns:
            Parser instance
            
        Raises:
            ValueError: If parser is not found
        """
        if parser_name not in self._parsers:
            available_parsers = list(self._parsers.keys())
            raise ValueError(
                f"Unknown parser: {parser_name}. "
                f"Available parsers: {available_parsers}"
            )
        
        # Check if we have a cached instance with matching config
        cache_key = f"{parser_name}_{hash(str(config))}"
        if cache_key in self._instances:
            return self._instances[cache_key]
        
        # Create new instance
        parser_class = self._parsers[parser_name]
        try:
            instance = parser_class(config)
            self._instances[cache_key] = instance
            return instance
        except Exception as e:
            raise ValueError(f"Failed to instantiate parser {parser_name}: {e}")
    
    def get_parser_for_file(self, file_path: Path, config: Optional[Dict] = None) -> Optional[BaseParser]:
        """
        Get the best parser for a specific file.
        
        Args:
            file_path: Path to file to parse
            config: Configuration for the parser
            
        Returns:
            Best parser for the file, or None if no suitable parser found
        """
        # Get content sample for parser testing
        content_sample = self._get_content_sample(file_path)
        if not content_sample:
            self.logger.warning(f"Could not read content from {file_path}")
            return None
        
        # Score all parsers for this file
        parser_scores = []
        fallback_parser = None
        
        for parser_name, parser_class in self._parsers.items():
            try:
                # Check cache first
                cache_key = (parser_name, str(file_path))
                if cache_key in self._compatibility_cache:
                    can_parse = self._compatibility_cache[cache_key]
                else:
                    # Test parser compatibility
                    temp_instance = parser_class(config)
                    can_parse = temp_instance.can_parse(file_path, content_sample)
                    self._compatibility_cache[cache_key] = can_parse
                    
                    # Debug output for specific files
                    if file_path.name in ['shell_appops.txt', 'shell_netstats.txt', 'shell_package.txt']:
                        self.logger.info(f"Parser {parser_name} can_parse {file_path.name}: {can_parse}")
                
                if can_parse:
                    # Calculate score based on parser capabilities and file characteristics
                    score = self._calculate_parser_score(parser_name, file_path, content_sample)
                    parser_scores.append((parser_name, score))
                
                # Keep track of fallback parser
                if parser_name == 'fallback_parser':
                    fallback_parser = parser_class
                    
            except Exception as e:
                self.logger.debug(f"Error testing parser {parser_name} on {file_path}: {e}")
        
        # Return highest scoring parser
        if parser_scores:
            parser_scores.sort(key=lambda x: x[1], reverse=True)
            best_parser_name = parser_scores[0][0]
            best_score = parser_scores[0][1]
            
            # Only use fallback parser if no other parser has a reasonable score
            if best_parser_name == 'fallback_parser' and best_score < 0.2:
                # Check if any non-fallback parser has a score > 0.1
                non_fallback_scores = [(name, score) for name, score in parser_scores if name != 'fallback_parser' and score > 0.1]
                if non_fallback_scores:
                    # Use the best non-fallback parser
                    non_fallback_scores.sort(key=lambda x: x[1], reverse=True)
                    best_parser_name = non_fallback_scores[0][0]
                    best_score = non_fallback_scores[0][1]
                    self.logger.debug(f"Selected non-fallback parser {best_parser_name} for {file_path} (score: {best_score:.2f})")
                else:
                    self.logger.debug(f"Using fallback parser for {file_path} (score: {best_score:.2f})")
            else:
                self.logger.debug(f"Selected parser {best_parser_name} for {file_path} (score: {best_score:.2f})")
            
            return self.get_parser(best_parser_name, config)
        
        # No suitable parser found - use fallback parser if available
        if fallback_parser:
            self.logger.info(f"Using fallback parser for {file_path} (no other parsers matched)")
            return fallback_parser(config)
        
        self.logger.warning(f"No suitable parser found for {file_path}")
        return None
    
    def get_parsers_for_format(self, data_format: DataFormat) -> List[str]:
        """
        Get parsers that can handle a specific data format.
        
        Args:
            data_format: Data format to find parsers for
            
        Returns:
            List of parser names that support the format
        """
        matching_parsers = []
        
        for parser_name, parser_class in self._parsers.items():
            try:
                capabilities = self._capability_cache.get(parser_name)
                if not capabilities:
                    temp_instance = parser_class()
                    capabilities = temp_instance.capabilities
                    self._capability_cache[parser_name] = capabilities
                
                # Check if parser supports this format based on output types
                format_mapping = {
                    DataFormat.LOGCAT: {'logcat_entry', 'system_log'},
                    DataFormat.DUMPSYS: {'dumpsys_entry', 'package_info', 'appops_entry'},
                    DataFormat.DMESG: {'kernel_log', 'dmesg_entry'},
                    DataFormat.BUGREPORT: {'mixed_entry', 'bugreport_section'}
                }
                
                expected_outputs = format_mapping.get(data_format, set())
                if expected_outputs.intersection(capabilities.output_entry_types):
                    matching_parsers.append(parser_name)
                    
            except Exception as e:
                self.logger.debug(f"Error checking format support for parser {parser_name}: {e}")
        
        return matching_parsers
    
    def parse_file_auto(self, file_path: Path, config: Optional[Dict] = None) -> Iterator[ParsedLogEntry]:
        """
        Automatically detect format and parse file.
        
        Args:
            file_path: File to parse
            config: Parser configuration
            
        Yields:
            ParsedLogEntry objects
            
        Raises:
            ParseError: If no suitable parser found or parsing fails
        """
        # Find best parser
        parser = self.get_parser_for_file(file_path, config)
        if not parser:
            raise ParseError(f"No suitable parser found for {file_path}")
        
        # Parse file
        try:
            self.logger.info(f"Parsing {file_path} with {parser.parser_name}")
            yield from parser.parse_file(file_path)
        except Exception as e:
            raise ParseError(f"Parsing failed with {parser.parser_name}: {e}", file_path)
    
    def parse_directory_auto(
        self, 
        directory: Path, 
        config: Optional[Dict] = None
    ) -> Iterator[Tuple[Path, Iterator[ParsedLogEntry]]]:
        """
        Automatically detect and parse all files in directory.
        
        Args:
            directory: Directory to parse
            config: Parser configuration
            
        Yields:
            Tuples of (file_path, entry_iterator)
        """
        if not directory.is_dir():
            raise ParseError(f"Path is not a directory: {directory}")
        
        # Get all parseable files
        files_to_parse = []
        for file_path in directory.iterdir():
            if file_path.is_file() and self.get_parser_for_file(file_path, config):
                files_to_parse.append(file_path)
        
        self.logger.info(f"Found {len(files_to_parse)} parseable files in {directory}")
        
        # Parse each file
        for file_path in files_to_parse:
            try:
                entries = self.parse_file_auto(file_path, config)
                yield file_path, entries
            except Exception as e:
                self.logger.error(f"Failed to parse {file_path}: {e}")
    
    def get_available_parsers(self) -> List[Dict[str, any]]:
        """
        Get information about all registered parsers.
        
        Returns:
            List of parser information dictionaries
        """
        parser_info = []
        
        for parser_name, parser_class in self._parsers.items():
            try:
                temp_instance = parser_class()
                capabilities = temp_instance.capabilities
                
                info = {
                    'name': parser_name,
                    'version': temp_instance.parser_version,
                    'supported_extensions': list(capabilities.supported_extensions),
                    'output_types': list(capabilities.output_entry_types),
                    'supports_streaming': capabilities.supports_streaming,
                    'memory_efficient': capabilities.memory_efficient,
                    'estimated_speed': capabilities.estimated_speed
                }
                parser_info.append(info)
                
            except Exception as e:
                self.logger.error(f"Error getting info for parser {parser_name}: {e}")
        
        return parser_info
    
    def auto_discover(self, package_name: str = "ward_core.infrastructure.parsers") -> int:
        """
        Automatically discover and register parsers from a package.
        
        Args:
            package_name: Package to search for parsers
            
        Returns:
            Number of parsers discovered and registered
        """
        discovered_count = 0
        
        try:
            # Import the parsers package
            parsers_package = importlib.import_module(package_name)
            
            # Walk through all modules in the package
            for importer, modname, ispkg in pkgutil.walk_packages(
                parsers_package.__path__,
                prefix=f"{package_name}."
            ):
                if ispkg:
                    continue
                
                # Skip base modules
                if 'base_parser' in modname or 'format_detector' in modname or 'parser_registry' in modname:
                    continue
                
                try:
                    # Import the module
                    module = importlib.import_module(modname)
                    
                    # Look for classes that inherit from BaseParser
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        
                        if (isinstance(attr, type) and 
                            issubclass(attr, BaseParser) and 
                            attr != BaseParser):
                            
                            self.register(attr)
                            discovered_count += 1
                            
                except Exception as e:
                    self.logger.warning(f"Failed to import parser module {modname}: {e}")
        
        except Exception as e:
            self.logger.debug(f"Failed to auto-discover parsers from package {package_name}: {e}")
        
        self.logger.info(f"Auto-discovered {discovered_count} parsers")
        return discovered_count
    
    def clear(self) -> None:
        """Clear all registered parsers and cached instances."""
        self._parsers.clear()
        self._instances.clear()
        self._capability_cache.clear()
        self._compatibility_cache.clear()
        self.logger.info("Cleared parser registry")
    
    def _get_content_sample(self, file_path: Path, sample_size: int = 16384) -> str:
        """Get content sample for parser testing. Increased size for better pattern detection."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read(sample_size)
        except Exception as e:
            self.logger.debug(f"Could not read content from {file_path}: {e}")
            return ""
    
    def _calculate_parser_score(self, parser_name: str, file_path: Path, content_sample: str) -> float:
        """Calculate compatibility score for a parser and file."""
        # Fallback parser should have very low priority
        if parser_name == 'fallback_parser':
            return 0.1  # Very low base score for fallback parser
        
        score = 0.5  # Base score for being able to parse
        
        capabilities = self._capability_cache.get(parser_name)
        if not capabilities:
            return score
        
        # Bonus for file extension match
        file_ext = file_path.suffix.lower()
        if file_ext in capabilities.supported_extensions:
            score += 0.2
        
        # Bonus for content pattern matches
        content_lower = content_sample.lower()
        pattern_matches = 0
        for pattern in capabilities.content_patterns:
            if pattern.lower() in content_lower:
                pattern_matches += 1
        
        if pattern_matches > 0:
            score += min(0.3, pattern_matches * 0.1)
        
        # Bonus for performance characteristics with large files
        if file_path.stat().st_size > 50 * 1024 * 1024:  # > 50MB
            if capabilities.supports_streaming:
                score += 0.1
            if capabilities.memory_efficient:
                score += 0.1
            if capabilities.estimated_speed == "fast":
                score += 0.1
        
        return min(1.0, score)


# Global registry instance
registry = ParserRegistry()
