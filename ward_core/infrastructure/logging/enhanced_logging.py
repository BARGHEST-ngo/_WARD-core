"""
Enhanced logging system for BARGHEST WARD.

Provides logging to both console and file, with the log file saved
alongside the risk assessment for troubleshooting purposes.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, List
import atexit


class EnhancedLogger:
    """
    Enhanced logging system that logs to both console and file.
    
    The log file is saved alongside the risk assessment output for
    troubleshooting and audit purposes.
    """
    
    def __init__(self):
        """Initialize the enhanced logger."""
        self.file_handlers: List[logging.FileHandler] = []
        self.original_handlers: List[logging.Handler] = []
        self.log_file_path: Optional[Path] = None
        
        # Register cleanup on exit
        atexit.register(self.cleanup)
    
    def setup_logging(self, output_directory: str, log_filename: str = "analysis.log", verbose: bool = False) -> str:
        """
        Set up enhanced logging to both console and file.

        Args:
            output_directory: Directory where log file should be saved
            log_filename: Name of the log file (default: analysis.log)
            verbose: Enable verbose console logging (default: False)

        Returns:
            Path to the created log file
        """
        # Create output directory if it doesn't exist
        output_dir = Path(output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate log file path with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename_with_timestamp = f"{timestamp}_{log_filename}"
        self.log_file_path = output_dir / log_filename_with_timestamp
        
        # Get root logger
        root_logger = logging.getLogger()
        
        # Store original handlers for cleanup
        self.original_handlers = root_logger.handlers[:]
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Set logging level
        root_logger.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler (stderr to keep stdout clean for JSON)
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(formatter)
        # In non-verbose mode, only show WARNING and above to reduce noise
        console_level = logging.INFO if verbose else logging.WARNING
        console_handler.setLevel(console_level)
        root_logger.addHandler(console_handler)
        
        # File handler
        file_handler = logging.FileHandler(
            self.log_file_path, 
            mode='w', 
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)  # More detailed logging to file
        root_logger.addHandler(file_handler)
        
        # Store file handler for cleanup
        self.file_handlers.append(file_handler)
        
        # Log the setup
        logger = logging.getLogger("enhanced.logging")
        logger.info(f"Enhanced logging initialized")
        logger.info(f"Log file: {self.log_file_path}")
        console_level_name = "INFO" if verbose else "WARNING"
        logger.info(f"Console logging level: {console_level_name}")
        logger.info(f"File logging level: DEBUG")
        
        return str(self.log_file_path)
    
    def log_system_info(self):
        """Log system information for troubleshooting."""
        logger = logging.getLogger("system.info")
        
        try:
            import platform
            import os
            
            logger.info("=== System Information ===")
            logger.info(f"Platform: {platform.platform()}")
            logger.info(f"Python version: {platform.python_version()}")
            logger.info(f"Working directory: {os.getcwd()}")
            logger.info(f"Command line: {' '.join(sys.argv)}")
            logger.info(f"Analysis start time: {datetime.now().isoformat()}")
            
            # Log environment variables relevant to Python
            python_env_vars = [
                'PYTHONPATH', 'PYTHON_PATH', 'PATH'
            ]
            
            logger.info("=== Environment Variables ===")
            for var in python_env_vars:
                value = os.environ.get(var)
                if value:
                    # Truncate very long paths
                    if len(value) > 200:
                        value = value[:200] + "..."
                    logger.info(f"{var}: {value}")
            
            logger.info("=== System Info Complete ===")
            
        except Exception as e:
            logger.error(f"Failed to log system information: {e}")
    
    def log_analysis_summary(self, 
                           log_directory: str, 
                           total_lines: int, 
                           package_count: int,
                           heuristics_run: int,
                           execution_time: float):
        """Log analysis execution summary."""
        logger = logging.getLogger("analysis.summary")
        
        logger.info("=== Analysis Execution Summary ===")
        logger.info(f"Log directory: {log_directory}")
        logger.info(f"Total log lines processed: {total_lines:,}")
        logger.info(f"Packages analyzed: {package_count}")
        logger.info(f"Heuristics executed: {heuristics_run}")
        logger.info(f"Total execution time: {execution_time:.2f} seconds")
        logger.info(f"Analysis completed: {datetime.now().isoformat()}")
        logger.info("=== Summary Complete ===")
    
    def log_error_details(self, error: Exception, context: str = ""):
        """Log detailed error information for troubleshooting."""
        logger = logging.getLogger("error.details")
        
        logger.error("=== Error Details ===")
        if context:
            logger.error(f"Context: {context}")
        logger.error(f"Error type: {type(error).__name__}")
        logger.error(f"Error message: {str(error)}")
        
        # Log stack trace to file (more detailed)
        logger.exception("Full stack trace:")
        logger.error("=== Error Details Complete ===")
    
    def create_analysis_log_entry(self, 
                                 stage: str, 
                                 message: str, 
                                 details: dict = None):
        """Create a structured log entry for analysis stages."""
        logger = logging.getLogger(f"analysis.{stage}")
        
        log_message = f"[{stage.upper()}] {message}"
        
        if details:
            log_message += f" | Details: {details}"
        
        logger.info(log_message)
    
    def cleanup(self):
        """Clean up file handlers and restore original logging."""
        # Close file handlers
        for handler in self.file_handlers:
            try:
                handler.close()
            except Exception:
                pass
        
        # Clear file handlers list
        self.file_handlers.clear()
        
        # Restore original handlers if we have them
        if self.original_handlers:
            root_logger = logging.getLogger()
            root_logger.handlers.clear()
            
            for handler in self.original_handlers:
                root_logger.addHandler(handler)
            
            self.original_handlers.clear()
    
    def get_log_file_path(self) -> Optional[str]:
        """Get the path to the current log file."""
        return str(self.log_file_path) if self.log_file_path else None
    
    def finalize_logging(self, success: bool = True):
        """Finalize logging with completion status."""
        logger = logging.getLogger("enhanced.logging")
        
        if success:
            logger.info("Analysis completed successfully")
        else:
            logger.error("Analysis completed with errors")
        
        if self.log_file_path:
            # Log file size for reference
            try:
                file_size = self.log_file_path.stat().st_size
                logger.info(f"Log file size: {file_size:,} bytes")
                logger.info(f"Log saved: {self.log_file_path}")
            except Exception as e:
                logger.warning(f"Could not determine log file size: {e}")
        
        # Flush all handlers
        for handler in logging.getLogger().handlers:
            try:
                handler.flush()
            except Exception:
                pass


# Global instance for use throughout the application
enhanced_logger = EnhancedLogger()


