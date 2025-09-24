```python
# logger.py
import logging
import json
import sys
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path

class StructuredFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
            
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(log_entry)

class StructuredLogger:
    def __init__(self, name: str, level: str = "INFO", log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        formatter = StructuredFormatter()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def log(self, level: str, message: str, **kwargs):
        extra_fields = kwargs if kwargs else {}
        self.logger.log(
            getattr(logging, level.upper()),
            message,
            extra={'extra_fields': extra_fields}
        )
    
    def info(self, message: str, **kwargs):
        self.log("INFO", message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self.log("ERROR", message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self.log("WARNING", message, **kwargs)
    
    def debug(self, message: str, **kwargs):
        self.log("DEBUG", message, **kwargs)

# config.py
from pydantic import BaseSettings
from typing import Optional

class LoggerConfig(BaseSettings):
    log_level: str = "INFO"
    log_file: Optional[str] = "logs/app.log"
    logger_name: str = "app"
    
    class Config:
        env_prefix = "LOGGER_"

# main.py
from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
import logging
import json

app = FastAPI(title="Logger Service", version="1.0.0")

class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class LogEntryRequest(BaseModel):
    level: LogLevel = Field(..., description="Log level")
    message: str = Field(..., min_length=1, max_length=1000, description="Log message")
    logger_name: Optional[str] = Field("app", description="Logger name")
    extra_fields: Optional[Dict[str, Any]] = Field(None, description="Additional fields")
    
    @validator('extra_fields')
    def validate_extra_fields(cls, v):
        if v is not None:
            # Ensure all values are JSON serializable
            try:
                json.dumps(v)
            except (TypeError, ValueError):
                raise ValueError("Extra fields must be JSON serializable")
        return v

class LogEntryResponse(BaseModel):
    id: str = Field(..., description="Log entry ID")
    timestamp: datetime = Field(..., description="Log timestamp")
    level: LogLevel = Field(..., description="Log level")
    message: str = Field(..., description="Log message")
    logger_name: str = Field(..., description="Logger name")
    extra_fields: Optional[Dict[str, Any]] = Field(None, description="Additional fields")

class LoggerConfigRequest(BaseModel):
    log_level: LogLevel = Field(LogLevel.INFO, description="Default log level")
    log_file: Optional[str] = Field(None, description="Log file path")
    logger_name: str = Field("app", description="Logger name")

class LoggerConfigResponse(BaseModel):
    log_level: LogLevel
    log_file: Optional[str]
    logger_name: str
    handlers_count: int
    created_at: datetime

class LogQueryParams(BaseModel):
    level: Optional[LogLevel] = None
    logger_name: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)

class LoggerService:
    def __init__(self):
        self.loggers: Dict[str, StructuredLogger] = {}
        self.log_entries: List[Dict[str, Any]] = []
        self.config = LoggerConfig()
    
    def get_or_create_logger(self, name: str, level: str = "INFO", log_file: Optional[str] = None) -> StructuredLogger:
        if name not in self.loggers:
            self.loggers[name] = StructuredLogger(name, level, log_file)
        return self.loggers[name]
    
    def create_log_entry(self, request: LogEntryRequest) -> LogEntryResponse:
        logger = self.get_or_create_logger(
            request.logger_name, 
            request.level.value, 
            self.config.log_file
        )
        
        entry_id = f"{datetime.utcnow().isoformat()}_{len(self.log_entries)}"
        timestamp = datetime.utcnow()
        
        # Log the message
        logger.log(request.level.value, request.message, **(request.extra_fields or {}))
        
        # Store entry for retrieval
        log_entry = {
            "id": entry_id,
            "timestamp": timestamp,
            "level": request.level,
            "message": request.message,
            "logger_name": request.logger_name,
            "extra_fields": request.extra_fields
        }
        self.log_entries.append(log_entry)
        
        return LogEntryResponse(**log_entry)
    
    def get_log_entries(self, params: LogQueryParams) -> List[LogEntryResponse]:
        filtered_entries = self.log_entries
        
        if params.level:
            filtered_entries = [e for e in filtered_entries if e["level"] == params.level]
        
        if params.logger_name:
            filtered_entries = [e for e in filtered_entries if e["logger_name"] == params.logger_name]
        
        if params.start_time:
            filtered_entries = [e for e in filtered_entries if e["timestamp"] >= params.start_time]
        
        if params.end_time:
            filtered_entries = [e for e in filtered_entries if e["timestamp"] <= params.end_time]
        
        # Apply pagination
        start_idx = params.offset
        end_idx = start_idx + params.limit
        paginated_entries = filtered_entries[start_idx:end_idx]
        
        return [LogEntryResponse(**entry) for entry in paginated_entries]
    
    def get_log_entry(self, entry_id: str) -> Optional[LogEntryResponse]:
        for entry in self.log_entries:
            if entry["id"] == entry_id:
                return LogEntryResponse(**entry)
        return None
    
    def configure_logger(self, config_request: LoggerConfigRequest) -> LoggerConfigResponse:
        self.config.log_level = config_request.log_level.value
        self.config.log_file = config_request.log_file
        self.config.logger_name = config_request.logger_name
        
        # Recreate logger with new config
        if config_request.logger_name in self.loggers:
            del self.loggers[config_request.logger_name]
        
        logger = self.get_or_create_logger(
            config_request.logger_name,
            config_request.log_level.value,
            config_request.log_file
        )
        
        return LoggerConfigResponse(
            log_level=config_request.log_level,
            log_file=config_request.log_file,
            logger_name=config_request.logger_name,
            handlers_count=len(logger.logger.handlers),
            created_at=datetime.utcnow()
        )
    
    def get_logger_config(self, logger_name: str) -> Optional[LoggerConfigResponse]:
        if logger_name in self.loggers:
            logger = self.loggers[logger_name]
            return LoggerConfigResponse(
                log_level=LogLevel(logging.getLevelName(logger.logger.level)),
                log_file=self.config.log_file,
                logger_name=logger_name,
                handlers_count=len(logger.logger.handlers),
                created_at=datetime.utcnow()
            )
        return None

logger_service = LoggerService()

def get_logger_service() -> LoggerService:
    return logger_service

router = APIRouter(prefix="/api/v1/logger", tags=["Logger"])

@router.post(
    "/logs",
    response_model=LogEntryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create log entry",
    description="Create a new log entry with specified level and message"
)
async def create_log_entry(
    request: LogEntryRequest,
    service: LoggerService = Depends(get_logger_service)
):
    try:
        return service.create_log_entry(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create log entry: {str(e)}"
        )

@router.get(
    "/logs",
    response_model=List[LogEntryResponse],
    summary="Get log entries",
    description="Retrieve log entries with optional filtering"
)
async def get_log_entries(
    level: Optional[LogLevel] = None,
    logger_name: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 100,
    offset: int = 0,
    service: LoggerService = Depends(get_logger_service)
):
    try:
        params = LogQueryParams(
            level=level,
            logger_name=logger_name,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset
        )
        return service.get_log_entries(params)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve log entries: {str(e)}"
        )

@router.get(
    "/logs/{entry_id}",
    response_model=LogEntryResponse,
    summary="Get log entry by ID",
    description="Retrieve a specific log entry by its ID"
)
async def get_log_entry(
    entry_id: str,
    service: LoggerService = Depends(get_logger_service)
):
    entry = service.get_log_entry(entry_id)
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Log entry with ID {entry_id} not found"
        )
    return entry

@router.post(
    "/config",
    response_model=LoggerConfigResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Configure logger",
    description="Configure logger settings"
)
async def configure_logger(
    config_request: LoggerConfigRequest,
    service: LoggerService = Depends(get_logger_service)
):
    try:
        return service.configure_logger(config_request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to configure logger: {str(e)}"
        )

@router.get(
    "/config/{logger_name}",
    response_model=LoggerConfigResponse,
    summary="Get logger configuration",
    description="Retrieve configuration for a specific logger"
)
async def get_logger_config(
    logger_name: str,
    service: LoggerService = Depends(get_logger_service)
):
    config = service.get_logger_config(logger_name)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Logger {logger_name} not found"
        )
    return config

@router.delete(
    "/logs",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Clear log entries",
    description="Clear all stored log entries"
)
async def clear_log_entries(
    service: LoggerService = Depends(get_logger_service)
):
    try:
        service.log_entries.clear()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear log entries: {str(e)}"
        )

app.include_router(router)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}
```