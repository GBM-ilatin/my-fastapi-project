```python
# logger.py
import logging
import logging.config
import json
import sys
from datetime import datetime
from typing import Any, Dict, Optional, Union
from pathlib import Path
from abc import ABC, abstractmethod

class LogFormatter(logging.Formatter):
    """Custom formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        if hasattr(record, 'extra_data'):
            log_entry.update(record.extra_data)
            
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(log_entry, ensure_ascii=False)

class LoggerServiceInterface(ABC):
    """Interface for logger service."""
    
    @abstractmethod
    def debug(self, message: str, **kwargs: Any) -> None:
        pass
    
    @abstractmethod
    def info(self, message: str, **kwargs: Any) -> None:
        pass
    
    @abstractmethod
    def warning(self, message: str, **kwargs: Any) -> None:
        pass
    
    @abstractmethod
    def error(self, message: str, **kwargs: Any) -> None:
        pass
    
    @abstractmethod
    def critical(self, message: str, **kwargs: Any) -> None:
        pass

class LoggerService(LoggerServiceInterface):
    """Service for structured logging functionality."""
    
    def __init__(self, name: str = "app", config: Optional[Dict[str, Any]] = None):
        """Initialize logger service.
        
        Args:
            name: Logger name
            config: Optional logging configuration
        """
        self.name = name
        self.config = config or {}
        self._logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup and configure structured logger.
        
        Returns:
            Configured logger instance
            
        Raises:
            ValueError: If logger configuration is invalid
        """
        try:
            logger = logging.getLogger(self.name)
            
            if not logger.handlers:
                # Console handler
                console_handler = logging.StreamHandler(sys.stdout)
                console_handler.setFormatter(LogFormatter())
                logger.addHandler(console_handler)
                
                # File handler if specified
                if self.config.get('log_file'):
                    file_handler = logging.FileHandler(
                        self.config['log_file'],
                        encoding='utf-8'
                    )
                    file_handler.setFormatter(LogFormatter())
                    logger.addHandler(file_handler)
            
            # Set log level
            log_level = self.config.get('log_level', 'INFO')
            logger.setLevel(getattr(logging, log_level.upper()))
            
            # Prevent duplicate logs
            logger.propagate = False
            
            return logger
            
        except Exception as e:
            raise ValueError(f"Failed to setup logger: {str(e)}")
    
    def _log_with_extra(self, level: int, message: str, **kwargs: Any) -> None:
        """Log message with extra data.
        
        Args:
            level: Log level
            message: Log message
            **kwargs: Additional data to include in log
        """
        try:
            extra_data = {k: v for k, v in kwargs.items() if v is not None}
            self._logger.log(level, message, extra={'extra_data': extra_data})
        except Exception as e:
            # Fallback logging to prevent application crashes
            print(f"Logging error: {str(e)}", file=sys.stderr)
    
    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message.
        
        Args:
            message: Debug message
            **kwargs: Additional context data
        """
        self._log_with_extra(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message.
        
        Args:
            message: Info message
            **kwargs: Additional context data
        """
        self._log_with_extra(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message.
        
        Args:
            message: Warning message
            **kwargs: Additional context data
        """
        self._log_with_extra(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message.
        
        Args:
            message: Error message
            **kwargs: Additional context data
        """
        self._log_with_extra(logging.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs: Any) -> None:
        """Log critical message.
        
        Args:
            message: Critical message
            **kwargs: Additional context data
        """
        self._log_with_extra(logging.CRITICAL, message, **kwargs)
    
    def log_request(self, method: str, path: str, status_code: int, 
                   duration: float, **kwargs: Any) -> None:
        """Log HTTP request information.
        
        Args:
            method: HTTP method
            path: Request path
            status_code: Response status code
            duration: Request duration in seconds
            **kwargs: Additional request data
        """
        self.info(
            f"{method} {path} - {status_code}",
            method=method,
            path=path,
            status_code=status_code,
            duration=duration,
            **kwargs
        )
    
    def log_exception(self, exception: Exception, **kwargs: Any) -> None:
        """Log exception with traceback.
        
        Args:
            exception: Exception to log
            **kwargs: Additional context data
        """
        self._logger.exception(
            f"Exception occurred: {str(exception)}",
            extra={'extra_data': kwargs}
        )
    
    def get_logger(self) -> logging.Logger:
        """Get underlying logger instance.
        
        Returns:
            Logger instance
        """
        return self._logger

class LoggerFactory:
    """Factory for creating logger services."""
    
    _instances: Dict[str, LoggerService] = {}
    
    @classmethod
    def create_logger(cls, name: str, config: Optional[Dict[str, Any]] = None) -> LoggerService:
        """Create or get existing logger service.
        
        Args:
            name: Logger name
            config: Optional logging configuration
            
        Returns:
            Logger service instance
        """
        if name not in cls._instances:
            cls._instances[name] = LoggerService(name, config)
        return cls._instances[name]
    
    @classmethod
    def get_logger(cls, name: str) -> Optional[LoggerService]:
        """Get existing logger service.
        
        Args:
            name: Logger name
            
        Returns:
            Logger service instance or None if not found
        """
        return cls._instances.get(name)
    
    @classmethod
    def clear_loggers(cls) -> None:
        """Clear all logger instances."""
        cls._instances.clear()

# config.py
from typing import Dict, Any, Optional
from pathlib import Path
import os

class LoggingConfig:
    """Configuration for logging service."""
    
    def __init__(self):
        """Initialize logging configuration."""
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.log_file = os.getenv("LOG_FILE")
        self.log_format = os.getenv("LOG_FORMAT", "json")
        self.log_max_size = int(os.getenv("LOG_MAX_SIZE", "10485760"))  # 10MB
        self.log_backup_count = int(os.getenv("LOG_BACKUP_COUNT", "5"))
    
    def get_config(self) -> Dict[str, Any]:
        """Get logging configuration dictionary.
        
        Returns:
            Configuration dictionary
        """
        config = {
            "log_level": self.log_level,
            "log_format": self.log_format,
            "log_max_size": self.log_max_size,
            "log_backup_count": self.log_backup_count,
        }
        
        if self.log_file:
            # Ensure log directory exists
            log_path = Path(self.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            config["log_file"] = str(log_path)
        
        return config
    
    def validate_config(self) -> bool:
        """Validate logging configuration.
        
        Returns:
            True if configuration is valid
            
        Raises:
            ValueError: If configuration is invalid
        """
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {self.log_level}")
        
        if self.log_max_size <= 0:
            raise ValueError("Log max size must be positive")
        
        if self.log_backup_count < 0:
            raise ValueError("Log backup count must be non-negative")
        
        return True

def get_logging_config() -> Dict[str, Any]:
    """Get validated logging configuration.
    
    Returns:
        Logging configuration dictionary
        
    Raises:
        ValueError: If configuration is invalid
    """
    config = LoggingConfig()
    config.validate_config()
    return config.get_config()
```