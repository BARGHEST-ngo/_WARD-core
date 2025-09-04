"""
Shared Error Handling Utilities - Centralized error handling and logging.

Consolidates error handling patterns from multiple modules to provide
consistent error handling, logging, and recovery across the system.

This utility standardizes error handling found in:
- Multiple heuristics with different error handling patterns
- Parsers with inconsistent error recovery
- Services with varying logging approaches
"""

import logging
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Callable, TypeVar, Generic
from enum import Enum
from contextlib import contextmanager
import functools

T = TypeVar('T')
R = TypeVar('R')


class ErrorSeverity(Enum):
    """Severity levels for errors."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ErrorContext:
    """Context information for error handling."""
    operation: str
    component: str
    metadata: Dict[str, Any]
    user_data: Optional[Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ErrorInfo:
    """Information about an error that occurred."""
    severity: ErrorSeverity
    message: str
    exception: Optional[Exception]
    context: ErrorContext
    stack_trace: Optional[str] = None
    recovery_attempted: bool = False
    recovery_successful: bool = False
    
    def __post_init__(self):
        if self.exception and not self.stack_trace:
            self.stack_trace = traceback.format_exc()


class ErrorHandler(ABC):
    """Abstract base class for error handlers."""
    
    @abstractmethod
    def can_handle(self, error_info: ErrorInfo) -> bool:
        """Check if this handler can handle the given error."""
        pass
    
    @abstractmethod
    def handle(self, error_info: ErrorInfo) -> bool:
        """Handle the error. Return True if recovery was successful."""
        pass


class LoggingErrorHandler(ErrorHandler):
    """Error handler that logs errors."""
    
    def __init__(self, logger_name: str = "error.handler"):
        """Initialize the logging error handler."""
        self.logger = logging.getLogger(logger_name)
    
    def can_handle(self, error_info: ErrorInfo) -> bool:
        """This handler can handle all errors for logging."""
        return True
    
    def handle(self, error_info: ErrorInfo) -> bool:
        """Log the error with appropriate severity."""
        log_message = f"[{error_info.context.component}] {error_info.context.operation}: {error_info.message}"
        
        if error_info.context.metadata:
            log_message += f" | Metadata: {error_info.context.metadata}"
        
        # Log based on severity
        if error_info.severity == ErrorSeverity.DEBUG:
            self.logger.debug(log_message)
        elif error_info.severity == ErrorSeverity.INFO:
            self.logger.info(log_message)
        elif error_info.severity == ErrorSeverity.WARNING:
            self.logger.warning(log_message)
        elif error_info.severity == ErrorSeverity.ERROR:
            self.logger.error(log_message, exc_info=error_info.exception)
        elif error_info.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(log_message, exc_info=error_info.exception)
        
        return True  # Logging always "succeeds"


class RetryErrorHandler(ErrorHandler):
    """Error handler that attempts to retry operations."""
    
    def __init__(self, max_retries: int = 3, retry_exceptions: List[type] = None):
        """Initialize the retry error handler."""
        self.max_retries = max_retries
        self.retry_exceptions = retry_exceptions or [ConnectionError, TimeoutError]
    
    def can_handle(self, error_info: ErrorInfo) -> bool:
        """Check if this error is retryable."""
        if not error_info.exception:
            return False
        
        return any(isinstance(error_info.exception, exc_type) 
                  for exc_type in self.retry_exceptions)
    
    def handle(self, error_info: ErrorInfo) -> bool:
        """Attempt to retry the operation (placeholder implementation)."""
        # In a real implementation, this would need access to the original operation
        # For now, just mark as recovery attempted
        error_info.recovery_attempted = True
        return False  # Cannot actually retry without the original operation


class ErrorHandlingService:
    """
    Centralized service for error handling across the system.
    
    This service provides consistent error handling, logging, and recovery
    functionality that was previously scattered across multiple modules.
    """
    
    def __init__(self):
        """Initialize the error handling service."""
        self.handlers: List[ErrorHandler] = []
        self.error_stats: Dict[str, int] = {}
        self.logger = logging.getLogger("error.handling.service")
        
        # Add default handlers
        self.add_handler(LoggingErrorHandler())
        self.add_handler(RetryErrorHandler())
    
    def add_handler(self, handler: ErrorHandler) -> None:
        """Add an error handler to the service."""
        self.handlers.append(handler)
    
    def handle_error(self, error_info: ErrorInfo) -> bool:
        """
        Handle an error using registered handlers.
        
        Args:
            error_info: Information about the error
            
        Returns:
            True if error was successfully handled/recovered
        """
        # Update error statistics
        error_key = f"{error_info.context.component}_{error_info.severity.value}"
        self.error_stats[error_key] = self.error_stats.get(error_key, 0) + 1
        
        recovery_successful = False
        
        # Try each handler that can handle this error
        for handler in self.handlers:
            if handler.can_handle(error_info):
                try:
                    if handler.handle(error_info):
                        recovery_successful = True
                        error_info.recovery_successful = True
                        break
                except Exception as handler_error:
                    # Handler itself failed - log but continue
                    self.logger.error(f"Error handler {type(handler).__name__} failed: {handler_error}")
        
        return recovery_successful
    
    def create_error_context(self, operation: str, component: str, **metadata) -> ErrorContext:
        """Create an error context for consistent error reporting."""
        return ErrorContext(
            operation=operation,
            component=component,
            metadata=metadata
        )
    
    def get_error_stats(self) -> Dict[str, int]:
        """Get error statistics."""
        return self.error_stats.copy()
    
    def reset_error_stats(self) -> None:
        """Reset error statistics."""
        self.error_stats.clear()


# Global error handling service instance
_error_service = ErrorHandlingService()


def get_error_service() -> ErrorHandlingService:
    """Get the global error handling service."""
    return _error_service


@contextmanager
def error_context(operation: str, component: str, **metadata):
    """Context manager for consistent error handling."""
    context = _error_service.create_error_context(operation, component, **metadata)
    
    try:
        yield context
    except Exception as e:
        error_info = ErrorInfo(
            severity=ErrorSeverity.ERROR,
            message=str(e),
            exception=e,
            context=context
        )
        
        recovery_successful = _error_service.handle_error(error_info)
        
        if not recovery_successful:
            raise  # Re-raise if not recovered


def handle_errors(operation: str, component: str, severity: ErrorSeverity = ErrorSeverity.ERROR):
    """Decorator for automatic error handling."""
    def decorator(func: Callable[..., R]) -> Callable[..., Optional[R]]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Optional[R]:
            context = _error_service.create_error_context(
                operation=operation,
                component=component,
                function=func.__name__,
                args_count=len(args),
                kwargs_keys=list(kwargs.keys())
            )
            
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_info = ErrorInfo(
                    severity=severity,
                    message=str(e),
                    exception=e,
                    context=context
                )
                
                recovery_successful = _error_service.handle_error(error_info)
                
                if not recovery_successful and severity in [ErrorSeverity.ERROR, ErrorSeverity.CRITICAL]:
                    raise  # Re-raise critical errors
                
                return None  # Return None for handled non-critical errors
        
        return wrapper
    return decorator


def safe_execute(func: Callable[[], T], 
                default_value: T = None,
                operation: str = "unknown_operation",
                component: str = "unknown_component") -> T:
    """
    Safely execute a function with error handling.
    
    Args:
        func: Function to execute
        default_value: Value to return if function fails
        operation: Name of the operation for error context
        component: Name of the component for error context
        
    Returns:
        Function result or default value if error occurred
    """
    context = _error_service.create_error_context(operation, component)
    
    try:
        return func()
    except Exception as e:
        error_info = ErrorInfo(
            severity=ErrorSeverity.WARNING,
            message=str(e),
            exception=e,
            context=context
        )
        
        _error_service.handle_error(error_info)
        return default_value


def log_and_continue(message: str, 
                    component: str = "unknown_component",
                    severity: ErrorSeverity = ErrorSeverity.WARNING,
                    **metadata) -> None:
    """Log an error and continue execution."""
    context = _error_service.create_error_context("log_and_continue", component, **metadata)
    
    error_info = ErrorInfo(
        severity=severity,
        message=message,
        exception=None,
        context=context
    )
    
    _error_service.handle_error(error_info)
