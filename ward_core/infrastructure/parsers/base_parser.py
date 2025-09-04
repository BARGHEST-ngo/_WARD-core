"""
Base parser interface for log data parsing.

Defines the contract that all log parsers must implement.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterator, List, Dict, Any, Optional, Set
from datetime import datetime
from pathlib import Path
from enum import Enum

# LogData import removed - not used in base parser


class ParseResult(Enum):
    """Result of parsing attempt."""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"


@dataclass
class ParsedLogEntry:
    """
    Represents a single parsed log entry.
    
    This is the standardized format that all parsers should produce.
    """
    
    # Core identification
    line_number: int
    source_file: str
    entry_type: str  # "package_info", "permission", "appops", etc.
    
    # Timing information
    timestamp: Optional[datetime] = None
    log_level: Optional[str] = None  # "I", "W", "E", "D", "V"
    
    # Content
    raw_line: str = ""
    parsed_content: Dict[str, Any] = field(default_factory=dict)
    
    # Context
    package: Optional[str] = None
    process: Optional[str] = None
    component: Optional[str] = None
    
    # Metadata
    confidence: float = 1.0  # 0.0-1.0, how confident we are in the parsing
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation and cleanup."""
        # Ensure confidence is in valid range
        self.confidence = max(0.0, min(1.0, self.confidence))
        
        # Convert tags to set if it's a list
        if isinstance(self.tags, (list, tuple)):
            self.tags = set(self.tags)
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to this entry."""
        self.tags.add(tag)
    
    def has_tag(self, tag: str) -> bool:
        """Check if entry has a specific tag."""
        return tag in self.tags
    
    def get_field(self, field_name: str, default: Any = None) -> Any:
        """Get a field from parsed content with fallback to default."""
        return self.parsed_content.get(field_name, default)


@dataclass
class ParserCapabilities:
    """Describes what a parser can do."""
    
    # File types this parser can handle
    supported_extensions: Set[str] = field(default_factory=set)
    supported_mime_types: Set[str] = field(default_factory=set)
    
    # Content patterns it recognizes
    content_patterns: List[str] = field(default_factory=list)
    header_patterns: List[str] = field(default_factory=list)
    
    # Output types it produces
    output_entry_types: Set[str] = field(default_factory=set)
    
    # Performance characteristics
    supports_streaming: bool = False
    memory_efficient: bool = True
    estimated_speed: str = "medium"  # "fast", "medium", "slow"
    
    # Requirements
    requires_preprocessing: bool = False
    handles_large_files: bool = True


class BaseParser(ABC):
    """
    Base interface for all log parsers.
    
    This defines the contract that all parsers must implement, providing
    consistent parsing across different Android log formats.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize parser with configuration."""
        self.config = config or {}
        self.logger = self._setup_logger()
        self._capabilities = self._define_capabilities()
    
    def _setup_logger(self):
        """Setup logging for the parser."""
        import logging
        return logging.getLogger(f"parser.{self.__class__.__name__}")
    
    @property
    @abstractmethod
    def parser_name(self) -> str:
        """Get the name of this parser."""
        pass
    
    @property
    @abstractmethod
    def parser_version(self) -> str:
        """Get the version of this parser."""
        pass
    
    @abstractmethod
    def _define_capabilities(self) -> ParserCapabilities:
        """Define what this parser can do."""
        pass
    
    @property
    def capabilities(self) -> ParserCapabilities:
        """Get parser capabilities."""
        return self._capabilities
    
    @abstractmethod
    def can_parse(self, file_path: Path, content_sample: str) -> bool:
        """
        Check if this parser can handle the given file.
        
        Args:
            file_path: Path to the file to parse
            content_sample: Sample of file content (first few KB)
            
        Returns:
            True if this parser can handle the file
        """
        pass
    
    @abstractmethod
    def parse_file(self, file_path: Path) -> Iterator[ParsedLogEntry]:
        """
        Parse a file and yield log entries.

        Args:
            file_path: Path to file to parse

        Yields:
            ParsedLogEntry objects for each parsed line

        Raises:
            ParseError: If parsing fails
        """
        pass

    def parse_file_streaming(self, file_path: Path, chunk_size: int = 8192) -> Iterator[ParsedLogEntry]:
        """
        Parse a file using streaming approach for large files.

        Args:
            file_path: Path to file to parse
            chunk_size: Size of chunks to read at a time

        Yields:
            ParsedLogEntry objects for each parsed line

        Raises:
            ParseError: If parsing fails
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                buffer = ""
                line_number = 0

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        # Process any remaining content in buffer
                        if buffer.strip():
                            line_number += 1
                            entry = self.parse_line(buffer, line_number, file_path.name)
                            if entry:
                                yield entry
                        break

                    buffer += chunk

                    # Process complete lines
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        line_number += 1

                        entry = self.parse_line(line, line_number, file_path.name)
                        if entry:
                            yield entry

        except Exception as e:
            raise ParseError(f"Streaming parse failed: {e}", file_path)
    
    def parse_content(self, content: str, source_name: str = "memory") -> Iterator[ParsedLogEntry]:
        """
        Parse content from memory.
        
        Args:
            content: Content to parse
            source_name: Name to use as source identifier
            
        Yields:
            ParsedLogEntry objects for each parsed line
        """
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            entry = self.parse_line(line, line_num, source_name)
            if entry:
                yield entry
    
    def parse_line(self, line: str, line_number: int, source_file: str) -> Optional[ParsedLogEntry]:
        """
        Parse a single line.
        
        Args:
            line: Line to parse
            line_number: Line number in source
            source_file: Source file name
            
        Returns:
            ParsedLogEntry if line was successfully parsed, None otherwise
        """
        # Default implementation - subclasses should override for efficiency
        try:
            # Create a temporary file-like object and parse it
            temp_entries = list(self.parse_content(line, source_file))
            if temp_entries:
                entry = temp_entries[0]
                entry.line_number = line_number
                return entry
        except Exception as e:
            self.logger.debug(f"Failed to parse line {line_number}: {e}")
        
        return None
    
    def validate_file(self, file_path: Path) -> bool:
        """
        Validate that a file is accessible and readable.
        
        Args:
            file_path: Path to validate
            
        Returns:
            True if file is valid and accessible
        """
        try:
            if not file_path.exists():
                self.logger.error(f"File does not exist: {file_path}")
                return False
            
            if not file_path.is_file():
                self.logger.error(f"Path is not a file: {file_path}")
                return False
            
            # Check if file is readable
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.read(1024)  # Try to read first KB
            
            return True
            
        except Exception as e:
            self.logger.error(f"File validation failed for {file_path}: {e}")
            return False
    
    def get_content_sample(self, file_path: Path, sample_size: int = 4096) -> str:
        """
        Get a sample of file content for format detection.
        
        Args:
            file_path: Path to file
            sample_size: Number of bytes to sample
            
        Returns:
            Sample content as string
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read(sample_size)
        except Exception as e:
            self.logger.warning(f"Failed to read content sample from {file_path}: {e}")
            return ""
    
    def get_estimated_entries(self, file_path: Path) -> int:
        """
        Estimate number of entries this parser would produce.
        
        Args:
            file_path: Path to file
            
        Returns:
            Estimated number of entries (0 if cannot estimate)
        """
        try:
            # Simple line count estimation
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = sum(1 for _ in f)
            
            # Most parsers produce roughly 1 entry per line
            return line_count
            
        except Exception:
            return 0


class ParseError(Exception):
    """Exception raised during parsing operations."""
    
    def __init__(self, message: str, file_path: Optional[Path] = None, line_number: Optional[int] = None):
        """
        Initialize parse error.
        
        Args:
            message: Error message
            file_path: File being parsed when error occurred
            line_number: Line number where error occurred
        """
        super().__init__(message)
        self.file_path = file_path
        self.line_number = line_number
        
        # Enhance message with context
        context_parts = []
        if file_path:
            context_parts.append(f"file: {file_path}")
        if line_number:
            context_parts.append(f"line: {line_number}")
        
        if context_parts:
            self.message = f"{message} ({', '.join(context_parts)})"
        else:
            self.message = message

        # Add error classification
        self.error_type = "general"
        self.recoverable = False


class FileTooBigError(ParseError):
    """Exception raised when file is too large to parse safely."""

    def __init__(self, file_path: Path, size_mb: float, max_size_mb: float = 100):
        message = f"File {file_path.name} is {size_mb:.1f}MB, exceeds maximum {max_size_mb}MB"
        super().__init__(message, file_path)
        self.error_type = "size"
        self.recoverable = False


class EncodingError(ParseError):
    """Exception raised when file encoding cannot be handled."""

    def __init__(self, file_path: Path, encoding_error: str):
        message = f"Encoding error in {file_path.name}: {encoding_error}"
        super().__init__(message, file_path)
        self.error_type = "encoding"
        self.recoverable = True


class FormatError(ParseError):
    """Exception raised when file format is unexpected."""

    def __init__(self, file_path: Path, expected_format: str, line_number: Optional[int] = None):
        message = f"Format error in {file_path.name}: expected {expected_format}"
        super().__init__(message, file_path, line_number)
        self.error_type = "format"
        self.recoverable = True


