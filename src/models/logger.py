```python
# logger.py
import logging
import sys
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
from sqlmodel import SQLModel, Field
from pydantic import BaseModel, validator
import json


class LogLevel(str, Enum):
    """Log level enumeration."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogEntry(SQLModel, table=True):
    """Database model for storing log entries."""
    
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)
    level: LogLevel = Field(index=True)
    logger_name: str = Field(max_length=255, index=True)
    message: str = Field(max_length=2000)
    module: Optional[str] = Field(default=None, max_length=255)
    function: Optional[str] = Field(default=None, max_length=255)
    line_number: Optional[int] = Field(default=None)
    extra_data: Optional[str] = Field(default=None)  # JSON string for additional data
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True


class LogEntryCreate(BaseModel):
    """Model for creating log entries."""
    
    level: LogLevel
    logger_name: str = Field(max_length=255)
    message: str = Field(max_length=2000)
    module: Optional[str] = Field(default=None, max_length=255)
    function: Optional[str] = Field(default=None, max_length=255)
    line_number: Optional[int] = Field(default=None, ge=1)
    extra_data: Optional[Dict[str, Any]] = Field(default=None)
    
    @validator('extra_data')
    def validate_extra_data(cls, v):
        """Validate extra_data can be serialized to JSON."""
        if v is not None:
            try:
                json.dumps(v)
            except (TypeError, ValueError):
                raise ValueError("extra_data must be JSON serializable")
        return v


class LogEntryResponse(BaseModel):
    """Model for log entry responses."""
    
    id: int
    timestamp: datetime
    level: LogLevel
    logger_name: str
    message: str
    module: Optional[str]
    function: Optional[str]
    line_number: Optional[int]
    extra_data: Optional[Dict[str, Any]]
    
    class Config:
        """Pydantic configuration."""
        from_attributes = True


class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add extra fields if present
        if hasattr(record, 'extra_data'):
            log_data["extra"] = record.extra_data
            
        return json.dumps(log_data)


class DatabaseLogHandler(logging.Handler):
    """Custom log handler that writes to database."""
    
    def __init__(self, db_session_factory):
        """Initialize database log handler."""
        super().__init__()
        self.db_session_factory = db_session_factory
    
    def emit(self, record: logging.LogRecord) -> None:
        """Emit log record to database."""
        try:
            extra_data = None
            if hasattr(record, 'extra_data'):
                extra_data = json.dumps(record.extra_data)
            
            log_entry = LogEntry(
                level=LogLevel(record.levelname),
                logger_name=record.name,
                message=record.getMessage(),
                module=record.module,
                function=record.funcName,
                line_number=record.lineno,
                extra_data=extra_data
            )
            
            with self.db_session_factory() as session:
                session.add(log_entry)
                session.commit()
                
        except Exception:
            self.handleError(record)


class StructuredLogger:
    """Structured logger wrapper."""
    
    def __init__(self, name: str, db_session_factory=None):
        """Initialize structured logger."""
        self.logger = logging.getLogger(name)
        self.db_session_factory = db_session_factory
        
    def _log_with_extra(self, level: int, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log message with extra structured data."""
        if extra_data:
            self.logger.log(level, message, extra={'extra_data': extra_data})
        else:
            self.logger.log(level, message)
    
    def debug(self, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log debug message."""
        self._log_with_extra(logging.DEBUG, message, extra_data)
    
    def info(self, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log info message."""
        self._log_with_extra(logging.INFO, message, extra_data)
    
    def warning(self, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log warning message."""
        self._log_with_extra(logging.WARNING, message, extra_data)
    
    def error(self, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log error message."""
        self._log_with_extra(logging.ERROR, message, extra_data)
    
    def critical(self, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log critical message."""
        self._log_with_extra(logging.CRITICAL, message, extra_data)


def configure_logger(
    name: str,
    level: LogLevel = LogLevel.INFO,
    enable_console: bool = True,
    enable_file: bool = False,
    file_path: Optional[str] = None,
    enable_database: bool = False,
    db_session_factory=None,
    structured_format: bool = True
) -> StructuredLogger:
    """
    Configure and return a structured logger.
    
    Args:
        name: Logger name
        level: Logging level
        enable_console: Enable console output
        enable_file: Enable file output
        file_path: Path to log file
        enable_database: Enable database logging
        db_session_factory: Database session factory
        structured_format: Use structured JSON format
    
    Returns:
        Configured StructuredLogger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.value))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    formatter = StructuredFormatter() if structured_format else logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler
    if enable_file and file_path:
        file_handler = logging.FileHandler(file_path)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Database handler
    if enable_database and db_session_factory:
        db_handler = DatabaseLogHandler(db_session_factory)
        logger.addHandler(db_handler)
    
    return StructuredLogger(name, db_session_factory)
```

```python
# config.py
from typing import Optional
from pydantic import BaseModel, Field, validator
from enum import Enum


class LogLevel(str, Enum):
    """Log level configuration options."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LoggingConfig(BaseModel):
    """Configuration model for logging settings."""
    
    level: LogLevel = Field(default=LogLevel.INFO, description="Default logging level")
    enable_console: bool = Field(default=True, description="Enable console logging")
    enable_file: bool = Field(default=False, description="Enable file logging")
    file_path: Optional[str] = Field(default=None, description="Path to log file")
    enable_database: bool = Field(default=False, description="Enable database logging")
    structured_format: bool = Field(default=True, description="Use structured JSON format")
    max_file_size: int = Field(default=10485760, ge=1024, description="Maximum log file size in bytes")
    backup_count: int = Field(default=5, ge=1, description="Number of backup log files to keep")
    logger_name: str = Field(default="app", description="Default logger name")
    
    @validator('file_path')
    def validate_file_path(cls, v, values):
        """Validate file path when file logging is enabled."""
        if values.get('enable_file') and not v:
            raise ValueError("file_path is required when enable_file is True")
        return v
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True


class DatabaseConfig(BaseModel):
    """Database configuration for logging."""
    
    url: str = Field(..., description="Database URL")
    echo: bool = Field(default=False, description="Enable SQL query logging")
    pool_size: int = Field(default=5, ge=1, description="Connection pool size")
    max_overflow: int = Field(default=10, ge=0, description="Maximum overflow connections")
    
    class Config:
        """Pydantic configuration."""
        env_prefix = "DB_"


class AppConfig(BaseModel):
    """Main application configuration."""
    
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    database: Optional[DatabaseConfig] = Field(default=None)
    debug: bool = Field(default=False, description="Enable debug mode")
    
    class Config:
        """Pydantic configuration."""
        env_nested_delimiter = "__"
```