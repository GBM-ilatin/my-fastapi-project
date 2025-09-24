```python
# logger.py
import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
from sqlmodel import SQLModel, Field, Session, select, create_engine
from sqlalchemy.exc import SQLAlchemyError
from abc import ABC, abstractmethod

class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class LogEntry(SQLModel, table=True):
    __tablename__ = "log_entries"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    level: LogLevel
    message: str
    module: Optional[str] = None
    function: Optional[str] = None
    line_number: Optional[int] = None
    extra_data: Optional[str] = Field(default=None)  # JSON string
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None

class LogEntryCreate(SQLModel):
    level: LogLevel
    message: str
    module: Optional[str] = None
    function: Optional[str] = None
    line_number: Optional[int] = None
    extra_data: Optional[Dict[str, Any]] = None

class LogEntryUpdate(SQLModel):
    level: Optional[LogLevel] = None
    message: Optional[str] = None
    module: Optional[str] = None
    function: Optional[str] = None
    line_number: Optional[int] = None
    extra_data: Optional[Dict[str, Any]] = None

class LogRepositoryInterface(ABC):
    @abstractmethod
    def create(self, log_entry: LogEntryCreate) -> LogEntry:
        pass
    
    @abstractmethod
    def get_by_id(self, log_id: int) -> Optional[LogEntry]:
        pass
    
    @abstractmethod
    def get_all(self, skip: int = 0, limit: int = 100) -> List[LogEntry]:
        pass
    
    @abstractmethod
    def get_by_level(self, level: LogLevel, skip: int = 0, limit: int = 100) -> List[LogEntry]:
        pass
    
    @abstractmethod
    def update(self, log_id: int, log_update: LogEntryUpdate) -> Optional[LogEntry]:
        pass
    
    @abstractmethod
    def delete(self, log_id: int) -> bool:
        pass
    
    @abstractmethod
    def delete_old_logs(self, days: int) -> int:
        pass

class LogRepository(LogRepositoryInterface):
    def __init__(self, session: Session):
        self.session = session
    
    def create(self, log_entry: LogEntryCreate) -> LogEntry:
        try:
            extra_data_json = None
            if log_entry.extra_data:
                extra_data_json = json.dumps(log_entry.extra_data)
            
            db_log = LogEntry(
                level=log_entry.level,
                message=log_entry.message,
                module=log_entry.module,
                function=log_entry.function,
                line_number=log_entry.line_number,
                extra_data=extra_data_json
            )
            
            self.session.add(db_log)
            self.session.commit()
            self.session.refresh(db_log)
            return db_log
        except SQLAlchemyError as e:
            self.session.rollback()
            raise RuntimeError(f"Failed to create log entry: {str(e)}")
    
    def get_by_id(self, log_id: int) -> Optional[LogEntry]:
        try:
            statement = select(LogEntry).where(LogEntry.id == log_id)
            return self.session.exec(statement).first()
        except SQLAlchemyError as e:
            raise RuntimeError(f"Failed to get log entry by id {log_id}: {str(e)}")
    
    def get_all(self, skip: int = 0, limit: int = 100) -> List[LogEntry]:
        try:
            statement = select(LogEntry).offset(skip).limit(limit).order_by(LogEntry.timestamp.desc())
            return list(self.session.exec(statement).all())
        except SQLAlchemyError as e:
            raise RuntimeError(f"Failed to get all log entries: {str(e)}")
    
    def get_by_level(self, level: LogLevel, skip: int = 0, limit: int = 100) -> List[LogEntry]:
        try:
            statement = (
                select(LogEntry)
                .where(LogEntry.level == level)
                .offset(skip)
                .limit(limit)
                .order_by(LogEntry.timestamp.desc())
            )
            return list(self.session.exec(statement).all())
        except SQLAlchemyError as e:
            raise RuntimeError(f"Failed to get log entries by level {level}: {str(e)}")
    
    def update(self, log_id: int, log_update: LogEntryUpdate) -> Optional[LogEntry]:
        try:
            db_log = self.get_by_id(log_id)
            if not db_log:
                return None
            
            update_data = log_update.dict(exclude_unset=True)
            
            if "extra_data" in update_data and update_data["extra_data"]:
                update_data["extra_data"] = json.dumps(update_data["extra_data"])
            
            update_data["updated_at"] = datetime.utcnow()
            
            for field, value in update_data.items():
                setattr(db_log, field, value)
            
            self.session.add(db_log)
            self.session.commit()
            self.session.refresh(db_log)
            return db_log
        except SQLAlchemyError as e:
            self.session.rollback()
            raise RuntimeError(f"Failed to update log entry {log_id}: {str(e)}")
    
    def delete(self, log_id: int) -> bool:
        try:
            db_log = self.get_by_id(log_id)
            if not db_log:
                return False
            
            self.session.delete(db_log)
            self.session.commit()
            return True
        except SQLAlchemyError as e:
            self.session.rollback()
            raise RuntimeError(f"Failed to delete log entry {log_id}: {str(e)}")
    
    def delete_old_logs(self, days: int) -> int:
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            statement = select(LogEntry).where(LogEntry.timestamp < cutoff_date)
            old_logs = list(self.session.exec(statement).all())
            
            count = len(old_logs)
            for log in old_logs:
                self.session.delete(log)
            
            self.session.commit()
            return count
        except SQLAlchemyError as e:
            self.session.rollback()
            raise RuntimeError(f"Failed to delete old logs: {str(e)}")

class StructuredLogger:
    def __init__(self, repository: LogRepositoryInterface, name: str = __name__):
        self.repository = repository
        self.logger = logging.getLogger(name)
        self._setup_logger()
    
    def _setup_logger(self) -> None:
        """Configure the structured logger."""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def _log(self, level: LogLevel, message: str, extra_data: Optional[Dict[str, Any]] = None) -> None:
        """Internal method to handle logging."""
        import inspect
        
        frame = inspect.currentframe()
        if frame and frame.f_back and frame.f_back.f_back:
            caller_frame = frame.f_back.f_back
            module = caller_frame.f_globals.get('__name__')
            function = caller_frame.f_code.co_name
            line_number = caller_frame.f_lineno
        else:
            module = function = None
            line_number = None
        
        try:
            log_entry = LogEntryCreate(
                level=level,
                message=message,
                module=module,
                function=function,
                line_number=line_number,
                extra_data=extra_data
            )
            self.repository.create(log_entry)
            
            # Also log to standard logger
            log_level = getattr(logging, level.value)
            self.logger.log(log_level, message, extra=extra_data or {})
            
        except Exception as e:
            # Fallback to standard logging if repository fails
            self.logger.error(f"Failed to log to repository: {str(e)}")
            log_level = getattr(logging, level.value)
            self.logger.log(log_level, message, extra=extra_data or {})
    
    def debug(self, message: str, extra_data: Optional[Dict[str, Any]] = None) -> None:
        """Log debug message."""
        self._log(LogLevel.DEBUG, message, extra_data)
    
    def info(self, message: str, extra_data: Optional[Dict[str, Any]] = None) -> None:
        """Log info message."""
        self._log(LogLevel.INFO, message, extra_data)
    
    def warning(self, message: str, extra_data: Optional[Dict[str, Any]] = None) -> None:
        """Log warning message."""
        self._log(LogLevel.WARNING, message, extra_data)
    
    def error(self, message: str, extra_data: Optional[Dict[str, Any]] = None) -> None:
        """Log error message."""
        self._log(LogLevel.ERROR, message, extra_data)
    
    def critical(self, message: str, extra_data: Optional[Dict[str, Any]] = None) -> None:
        """Log critical message."""
        self._log(LogLevel.CRITICAL, message, extra_data)
    
    def exception(self, message: str, extra_data: Optional[Dict[str, Any]] = None) -> None:
        """Log exception with traceback."""
        import traceback
        
        if extra_data is None:
            extra_data = {}
        
        extra_data['traceback'] = traceback.format_exc()
        self._log(LogLevel.ERROR, message, extra_data)

class LoggerService:
    def __init__(self, repository: LogRepositoryInterface):
        self.repository = repository
        self.logger = StructuredLogger(repository)
    
    def get_logger(self, name: str = __name__) -> StructuredLogger:
        """Get a structured logger instance."""
        return StructuredLogger(self.repository, name)
    
    def get_logs(self, skip: int = 0, limit: int = 100) -> List[LogEntry]:
        """Get all logs with pagination."""
        return self.repository.get_all(skip, limit)
    
    def get_logs_by_level(self, level: LogLevel, skip: int = 0, limit: int = 100) -> List[LogEntry]:
        """Get logs by level with pagination."""
        return self.repository.get_by_level(level, skip, limit)
    
    def cleanup_old_logs(self, days: int = 30) -> int:
        """Clean up logs older than specified days."""
        return self.repository.delete_old_logs(days)
```

```python
# config.py
import os
from typing import Optional
from sqlmodel import create_engine, Session
from sqlalchemy.engine import Engine

class LoggerConfig:
    def __init__(
        self,
        database_url: Optional[str] = None,
        log_level: str = "INFO",
        log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        max_log_age_days: int = 30,
        echo_sql: bool = False
    ):
        self.database_url = database_url or os.getenv(
            "DATABASE_URL", 
            "sqlite:///./logs.db"
        )
        self.log_level = log_level
        self.log_format = log_format
        self.max_log_age_days = max_log_age_days
        self.echo_sql = echo_sql
    
    def create_engine(self) -> Engine:
        """Create database engine."""
        return create_engine(
            self.database_url,
            echo=self.echo_sql
        )
    
    def get_session(self, engine: Engine) -> Session:
        """Get database session."""
        return Session(engine)

class LoggerDependencyContainer:
    def __init__(self, config: LoggerConfig):
        self.config = config
        self.engine = config.create_engine()
        self._repository = None
        self._service = None
    
    def get_repository(self) -> 'LogRepository':
        """Get log repository instance."""
        if self._repository is None:
            from logger import LogRepository
            session = self.config.get_session(self.engine)
            self._repository = LogRepository(session)
        return self._repository
    
    def get_service(self) -> 'LoggerService':
        """Get logger service instance."""
        if self._service is None:
            from logger import LoggerService
            self._service = LoggerService(self.get_repository())
        return self._service
    
    def create_tables(self) -> None:
        """Create database tables."""
        from logger import LogEntry
        from sqlmodel import SQLModel
        SQLModel.metadata.create_all(self.engine)

# Factory function for easy setup
def setup_logger(
    database_url: Optional[str] = None,
    log_level: str = "INFO",
    create_tables: bool = True
) -> 'LoggerService':
    """Setup and configure the logger service."""
    config = LoggerConfig(
        database_url=database_url,
        log_level=log_level
    )
    
    container = LoggerDependencyContainer(config)
    
    if create_tables:
        container.create_tables()
    
    return container.get_service()
```