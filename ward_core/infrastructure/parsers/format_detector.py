"""
Smart format detection service for Android log data.

This service analyzes files and directories to determine the best parsing strategy.
"""

import re
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import logging


class DataFormat(Enum):
    """Supported data formats."""
    BUGREPORT = "bugreport"
    ADB_LOGS = "adb_logs"  
    INDIVIDUAL_FILES = "individual_files"
    LOGCAT = "logcat"
    DUMPSYS = "dumpsys"
    DMESG = "dmesg"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class SourceType(Enum):
    """Types of data sources."""
    DIRECTORY = "directory"
    SINGLE_FILE = "single_file"
    ARCHIVE = "archive"
    DEVICE = "device"


@dataclass
class FormatDetectionResult:
    """Result of format detection analysis."""
    
    primary_format: DataFormat
    confidence: float  # 0.0-1.0
    source_type: SourceType
    detected_files: Dict[str, str] = None  # filename -> detected type
    missing_expected: List[str] = None      # expected files that are missing
    recommendations: List[str] = None       # parsing recommendations
    metadata: Dict[str, any] = None
    
    def __post_init__(self):
        """Initialize default values."""
        if self.detected_files is None:
            self.detected_files = {}
        if self.missing_expected is None:
            self.missing_expected = []
        if self.recommendations is None:
            self.recommendations = []
        if self.metadata is None:
            self.metadata = {}


class FormatDetector:
    """
    Smart format detector for Android forensic data.
    
    This class analyzes files and directories to determine the optimal parsing strategy.
    """
    
    # Expected files for different formats
    BUGREPORT_INDICATORS = {
        'required': [
            'main.txt',      # Main bugreport content
            'version.txt',   # Bugreport version info
        ],
        'common': [
            'system.txt', 'events.txt', 'radio.txt', 'kernel.txt',
            'bugreport-*.txt', 'dumpstate.txt'
        ],
        'extracted_signs': [
            'extracted/',
            'system/build.prop',
            'data/system/packages.xml'
        ]
    }
    
    ADB_LOGS_INDICATORS = {
        'required': [],
        'common': [
            'shell_dumpsys_package.txt',
            'shell_dumpsys_appops.txt', 
            'shell_dumpsys_accessibility.txt',
            'shell_dumpsys_netstats.txt',
            'shell_getprop.txt',
            'logcat*.txt'
        ]
    }
    
    # Content patterns for file type detection
    CONTENT_PATTERNS = {
        DataFormat.LOGCAT: [
            re.compile(r'\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\s+\d+\s+\d+\s+[VDIWEFS]\s+'),  # Android logcat format
            re.compile(r'--------- beginning of /dev/log/'),
            re.compile(r'AndroidRuntime:\s+(FATAL EXCEPTION|Process:)'),
        ],
        DataFormat.DUMPSYS: [
            re.compile(r'DUMP OF SERVICE\s+\w+:', re.IGNORECASE),
            re.compile(r'dumpsys\s+\w+', re.IGNORECASE),
            re.compile(r'PACKAGE MANAGER \(dumpsys package\)', re.IGNORECASE),
            re.compile(r'ACCESSIBILITY MANAGER \(dumpsys accessibility\)', re.IGNORECASE),
        ],
        DataFormat.DMESG: [
            re.compile(r'^\[\s*\d+\.\d+\]'),  # Kernel timestamp format
            re.compile(r'Linux version \d+\.\d+'),
            re.compile(r'Kernel command line:'),
        ],
        DataFormat.BUGREPORT: [
            re.compile(r'dumpstate: begin'),
            re.compile(r'Bugreport format version:'),
            re.compile(r'== dumpstate'),
        ]
    }
    
    def __init__(self):
        """Initialize the format detector."""
        self.logger = logging.getLogger("format.detector")
    
    def detect_format(self, source_path: str) -> FormatDetectionResult:
        """
        Detect the format of data at the given path.
        
        Args:
            source_path: Path to analyze (file or directory)
            
        Returns:
            Detection result with format and confidence
        """
        source_path = Path(source_path)
        
        if not source_path.exists():
            return FormatDetectionResult(
                primary_format=DataFormat.UNKNOWN,
                confidence=0.0,
                source_type=SourceType.DIRECTORY,
                recommendations=["Source path does not exist"]
            )
        
        if source_path.is_file():
            return self._detect_single_file_format(source_path)
        elif source_path.is_dir():
            return self._detect_directory_format(source_path)
        else:
            return FormatDetectionResult(
                primary_format=DataFormat.UNKNOWN,
                confidence=0.0,
                source_type=SourceType.DIRECTORY,
                recommendations=["Source is neither file nor directory"]
            )
    
    def _detect_single_file_format(self, file_path: Path) -> FormatDetectionResult:
        """Detect format of a single file."""
        try:
            # Get file content sample
            content_sample = self._get_content_sample(file_path)
            
            # Check content patterns
            detected_format = self._match_content_patterns(content_sample)
            confidence = 0.8 if detected_format != DataFormat.UNKNOWN else 0.0
            
            # Adjust confidence based on filename
            filename_format, filename_confidence = self._analyze_filename(file_path.name)
            if filename_format != DataFormat.UNKNOWN:
                if detected_format == filename_format:
                    confidence = max(confidence, 0.9)  # Both content and filename agree
                elif detected_format == DataFormat.UNKNOWN:
                    detected_format = filename_format
                    confidence = filename_confidence
            
            recommendations = self._generate_file_recommendations(file_path, detected_format)
            
            return FormatDetectionResult(
                primary_format=detected_format,
                confidence=confidence,
                source_type=SourceType.SINGLE_FILE,
                detected_files={file_path.name: detected_format.value},
                recommendations=recommendations,
                metadata={'file_size': file_path.stat().st_size}
            )
            
        except Exception as e:
            self.logger.error(f"Error detecting format for file {file_path}: {e}")
            return FormatDetectionResult(
                primary_format=DataFormat.UNKNOWN,
                confidence=0.0,
                source_type=SourceType.SINGLE_FILE,
                recommendations=[f"Error analyzing file: {e}"]
            )
    
    def _detect_directory_format(self, dir_path: Path) -> FormatDetectionResult:
        """Detect format of a directory."""
        try:
            # Get list of files
            files = [f.name for f in dir_path.iterdir() if f.is_file()]
            
            # Check for bugreport format
            bugreport_score = self._score_bugreport_format(files, dir_path)
            
            # Check for ADB logs format  
            adb_logs_score = self._score_adb_logs_format(files)
            
            # Analyze individual files
            file_analysis = self._analyze_individual_files(dir_path, files)
            
            # Determine primary format
            if bugreport_score > 0.7:
                primary_format = DataFormat.BUGREPORT
                confidence = bugreport_score
            elif adb_logs_score > 0.6:
                primary_format = DataFormat.ADB_LOGS
                confidence = adb_logs_score
            elif len(file_analysis['detected_files']) > 0:
                # Mixed format based on individual files
                primary_format = DataFormat.MIXED
                confidence = 0.6
            else:
                primary_format = DataFormat.UNKNOWN
                confidence = 0.0
            
            recommendations = self._generate_directory_recommendations(
                primary_format, file_analysis, bugreport_score, adb_logs_score
            )
            
            return FormatDetectionResult(
                primary_format=primary_format,
                confidence=confidence,
                source_type=SourceType.DIRECTORY,
                detected_files=file_analysis['detected_files'],
                missing_expected=file_analysis['missing_expected'],
                recommendations=recommendations,
                metadata={
                    'total_files': len(files),
                    'bugreport_score': bugreport_score,
                    'adb_logs_score': adb_logs_score
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error detecting format for directory {dir_path}: {e}")
            return FormatDetectionResult(
                primary_format=DataFormat.UNKNOWN,
                confidence=0.0,
                source_type=SourceType.DIRECTORY,
                recommendations=[f"Error analyzing directory: {e}"]
            )
    
    def _score_bugreport_format(self, files: List[str], dir_path: Path) -> float:
        """Score how well files match bugreport format."""
        score = 0.0
        
        # Check for required files
        required_found = 0
        for required_file in self.BUGREPORT_INDICATORS['required']:
            if any(required_file in f for f in files):
                required_found += 1
        
        if required_found > 0:
            score += 0.4 * (required_found / len(self.BUGREPORT_INDICATORS['required']))
        
        # Check for common files
        common_found = 0
        for common_file in self.BUGREPORT_INDICATORS['common']:
            if any(common_file.replace('*', '') in f for f in files):
                common_found += 1
        
        if common_found > 0:
            score += 0.3 * min(1.0, common_found / len(self.BUGREPORT_INDICATORS['common']))
        
        # Check for extracted directory structure
        extracted_dir = dir_path / 'extracted'
        if extracted_dir.exists():
            score += 0.3
            
            # Check for build.prop or system files in extracted
            for extracted_sign in self.BUGREPORT_INDICATORS['extracted_signs']:
                if (dir_path / extracted_sign).exists():
                    score += 0.1
                    break
        
        return min(1.0, score)
    
    def _score_adb_logs_format(self, files: List[str]) -> float:
        """Score how well files match ADB logs format."""
        score = 0.0
        
        # Check for common ADB files
        common_found = 0
        for common_file in self.ADB_LOGS_INDICATORS['common']:
            if any(common_file.replace('*', '') in f for f in files):
                common_found += 1
        
        if common_found > 0:
            score = 0.8 * min(1.0, common_found / len(self.ADB_LOGS_INDICATORS['common']))
        
        # Bonus for shell_ prefix pattern
        shell_files = [f for f in files if f.startswith('shell_')]
        if shell_files:
            score += min(0.2, len(shell_files) * 0.05)
        
        return min(1.0, score)
    
    def _analyze_individual_files(self, dir_path: Path, files: List[str]) -> Dict[str, any]:
        """Analyze individual files in directory."""
        detected_files = {}
        missing_expected = []
        
        # Analyze up to 10 files to avoid performance issues
        files_to_analyze = files[:10]
        
        for filename in files_to_analyze:
            file_path = dir_path / filename
            
            try:
                # Get content sample
                content_sample = self._get_content_sample(file_path, max_size=2048)
                
                # Try to detect format
                detected_format = self._match_content_patterns(content_sample)
                if detected_format != DataFormat.UNKNOWN:
                    detected_files[filename] = detected_format.value
                else:
                    # Try filename analysis
                    filename_format, _ = self._analyze_filename(filename)
                    if filename_format != DataFormat.UNKNOWN:
                        detected_files[filename] = filename_format.value
                
            except Exception as e:
                self.logger.debug(f"Could not analyze file {filename}: {e}")
        
        return {
            'detected_files': detected_files,
            'missing_expected': missing_expected
        }
    
    def _match_content_patterns(self, content: str) -> DataFormat:
        """Match content against known patterns."""
        for format_type, patterns in self.CONTENT_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(content):
                    return format_type
        
        return DataFormat.UNKNOWN
    
    def _analyze_filename(self, filename: str) -> Tuple[DataFormat, float]:
        """Analyze filename to detect format."""
        filename_lower = filename.lower()
        
        # Logcat files
        if 'logcat' in filename_lower:
            return DataFormat.LOGCAT, 0.8
        
        # Dumpsys files  
        if 'dumpsys' in filename_lower or filename_lower.startswith('shell_dumpsys_'):
            return DataFormat.DUMPSYS, 0.8
        
        # Dmesg files
        if 'dmesg' in filename_lower or 'kernel' in filename_lower:
            return DataFormat.DMESG, 0.7
        
        # Bugreport files
        if 'bugreport' in filename_lower or 'dumpstate' in filename_lower:
            return DataFormat.BUGREPORT, 0.8
        
        return DataFormat.UNKNOWN, 0.0
    
    def _get_content_sample(self, file_path: Path, max_size: int = 4096) -> str:
        """Get content sample from file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read(max_size)
        except Exception:
            return ""
    
    def _generate_file_recommendations(self, file_path: Path, detected_format: DataFormat) -> List[str]:
        """Generate recommendations for single file processing."""
        recommendations = []
        
        if detected_format == DataFormat.UNKNOWN:
            recommendations.append("Unable to detect file format - may require manual parser selection")
        
        if file_path.stat().st_size > 100 * 1024 * 1024:  # > 100MB
            recommendations.append("Large file detected - consider using streaming parser")
        
        if detected_format == DataFormat.LOGCAT:
            recommendations.append("Use LogcatParser for optimal parsing")
        elif detected_format == DataFormat.DUMPSYS:
            recommendations.append("Use DumpsysParser for structured parsing")
        elif detected_format == DataFormat.DMESG:
            recommendations.append("Use KernelLogParser for kernel message parsing")
        
        return recommendations
    
    def _generate_directory_recommendations(
        self, 
        primary_format: DataFormat,
        file_analysis: Dict[str, any],
        bugreport_score: float,
        adb_logs_score: float
    ) -> List[str]:
        """Generate recommendations for directory processing."""
        recommendations = []
        
        if primary_format == DataFormat.BUGREPORT:
            recommendations.append("Use BugreportCollector for comprehensive parsing")
            if bugreport_score < 0.9:
                recommendations.append("Some expected bugreport files missing - may have incomplete coverage")
        
        elif primary_format == DataFormat.ADB_LOGS:
            recommendations.append("Use AdbLogsCollector for shell command output parsing")
            if adb_logs_score < 0.8:
                recommendations.append("Some expected ADB files missing - consider supplementing collection")
        
        elif primary_format == DataFormat.MIXED:
            recommendations.append("Mixed format detected - use HybridCollector for best coverage")
            recommendations.append("Consider parsing individual files with specialized parsers")
        
        elif primary_format == DataFormat.UNKNOWN:
            recommendations.append("Unable to detect primary format - try individual file analysis")
            if len(file_analysis['detected_files']) == 0:
                recommendations.append("No recognizable Android log files found")
        
        return recommendations


