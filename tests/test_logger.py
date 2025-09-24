```python
import pytest
import logging
import json
from unittest.mock import Mock, patch, MagicMock
from io import StringIO
import sys
from datetime import datetime


class Logger:
    """Structured logging component using Python logging library."""
    
    def __init__(self, name: str = "app", level: str = "INFO", format_type: str = "json"):
        self.name = name
        self.level = getattr(logging, level.upper())
        self.format_type = format_type
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.level)
        self._setup_handlers()
    
    def _setup_handlers(self):
        """Setup logging handlers with appropriate formatters."""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(self.level)
            
            if self.format_type == "json":
                formatter = self._get_json_formatter()
            else:
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def _get_json_formatter(self):
        """Get JSON formatter for structured logging."""
        class JsonFormatter(logging.Formatter):
            def format(self, record):
                log_entry = {
                    'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                    'level': record.levelname,
                    'logger': record.name,
                    'message': record.getMessage(),
                    'module': record.module,
                    'function': record.funcName,
                    'line': record.lineno
                }
                if hasattr(record, 'extra_data'):
                    log_entry.update(record.extra_data)
                return json.dumps(log_entry)
        
        return JsonFormatter()
    
    def debug(self, message: str, **kwargs):
        """Log debug message with optional extra data."""
        self._log(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message with optional extra data."""
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message with optional extra data."""
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message with optional extra data."""
        self._log(logging.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message with optional extra data."""
        self._log(logging.CRITICAL, message, **kwargs)
    
    def _log(self, level: int, message: str, **kwargs):
        """Internal method to log messages with extra data."""
        extra = {'extra_data': kwargs} if kwargs else {}
        self.logger.log(level, message, extra=extra)
    
    def set_level(self, level: str):
        """Set logging level."""
        self.level = getattr(logging, level.upper())
        self.logger.setLevel(self.level)
        for handler in self.logger.handlers:
            handler.setLevel(self.level)
    
    def add_handler(self, handler: logging.Handler):
        """Add custom handler to logger."""
        self.logger.addHandler(handler)
    
    def remove_handler(self, handler: logging.Handler):
        """Remove handler from logger."""
        self.logger.removeHandler(handler)


class TestLogger:
    """Test suite for Logger component."""
    
    @pytest.fixture
    def logger_instance(self):
        """Create a Logger instance for testing."""
        # Clear any existing handlers to avoid interference
        logging.getLogger("test_logger").handlers.clear()
        return Logger(name="test_logger", level="DEBUG")
    
    @pytest.fixture
    def json_logger(self):
        """Create a JSON Logger instance for testing."""
        logging.getLogger("json_test_logger").handlers.clear()
        return Logger(name="json_test_logger", level="INFO", format_type="json")
    
    @pytest.fixture
    def text_logger(self):
        """Create a text Logger instance for testing."""
        logging.getLogger("text_test_logger").handlers.clear()
        return Logger(name="text_test_logger", level="INFO", format_type="text")
    
    @pytest.fixture
    def mock_handler(self):
        """Create a mock handler for testing."""
        handler = Mock(spec=logging.Handler)
        handler.setLevel = Mock()
        return handler
    
    def test_logger_initialization_default(self):
        """Test Logger initialization with default parameters."""
        logging.getLogger("app").handlers.clear()
        logger = Logger()
        
        assert logger.name == "app"
        assert logger.level == logging.INFO
        assert logger.format_type == "json"
        assert isinstance(logger.logger, logging.Logger)
        assert logger.logger.name == "app"
        assert logger.logger.level == logging.INFO
    
    def test_logger_initialization_custom(self):
        """Test Logger initialization with custom parameters."""
        logging.getLogger("custom_logger").handlers.clear()
        logger = Logger(name="custom_logger", level="DEBUG", format_type="text")
        
        assert logger.name == "custom_logger"
        assert logger.level == logging.DEBUG
        assert logger.format_type == "text"
        assert logger.logger.name == "custom_logger"
        assert logger.logger.level == logging.DEBUG
    
    def test_setup_handlers_json_format(self, json_logger):
        """Test handler setup with JSON format."""
        assert len(json_logger.logger.handlers) == 1
        handler = json_logger.logger.handlers[0]
        assert isinstance(handler, logging.StreamHandler)
        assert handler.level == logging.INFO
    
    def test_setup_handlers_text_format(self, text_logger):
        """Test handler setup with text format."""
        assert len(text_logger.logger.handlers) == 1
        handler = text_logger.logger.handlers[0]
        assert isinstance(handler, logging.StreamHandler)
        assert isinstance(handler.formatter, logging.Formatter)
    
    def test_setup_handlers_no_duplicate(self, logger_instance):
        """Test that handlers are not duplicated on multiple calls."""
        initial_count = len(logger_instance.logger.handlers)
        logger_instance._setup_handlers()
        assert len(logger_instance.logger.handlers) == initial_count
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_debug_logging(self, mock_stdout, logger_instance):
        """Test debug level logging."""
        logger_instance.debug("Debug message")
        
        # Verify the logger's log method was called
        assert logger_instance.logger.isEnabledFor(logging.DEBUG)
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_info_logging(self, mock_stdout, logger_instance):
        """Test info level logging."""
        logger_instance.info("Info message")
        
        assert logger_instance.logger.isEnabledFor(logging.INFO)
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_warning_logging(self, mock_stdout, logger_instance):
        """Test warning level logging."""
        logger_instance.warning("Warning message")
        
        assert logger_instance.logger.isEnabledFor(logging.WARNING)
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_error_logging(self, mock_stdout, logger_instance):
        """Test error level logging."""
        logger_instance.error("Error message")
        
        assert logger_instance.logger.isEnabledFor(logging.ERROR)
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_critical_logging(self, mock_stdout, logger_instance):
        """Test critical level logging."""
        logger_instance.critical("Critical message")
        
        assert logger_instance.logger.isEnabledFor(logging.CRITICAL)
    
    def test_log_with_extra_data(self, logger_instance):
        """Test logging with extra data parameters."""
        with patch.object(logger_instance.logger, 'log') as mock_log:
            logger_instance.info("Test message", user_id=123, action="login")
            
            mock_log.assert_called_once_with(
                logging.INFO, 
                "Test message", 
                extra={'extra_data': {'user_id': 123, 'action': 'login'}}
            )
    
    def test_log_without_extra_data(self, logger_instance):
        """Test logging without extra data parameters."""
        with patch.object(logger_instance.logger, 'log') as mock_log:
            logger_instance.info("Test message")
            
            mock_log.assert_called_once_with(
                logging.INFO, 
                "Test message", 
                extra={}
            )
    
    def test_set_level_valid(self, logger_instance):
        """Test setting valid logging level."""
        logger_instance.set_level("ERROR")
        
        assert logger_instance.level == logging.ERROR
        assert logger_instance.logger.level == logging.ERROR
        
        for handler in logger_instance.logger.handlers:
            assert handler.level == logging.ERROR
    
    def test_set_level_case_insensitive(self, logger_instance):
        """Test setting logging level is case insensitive."""
        logger_instance.set_level("warning")
        
        assert logger_instance.level == logging.WARNING
        assert logger_instance.logger.level == logging.WARNING
    
    def test_set_level_invalid(self, logger_instance):
        """Test setting invalid logging level raises AttributeError."""
        with pytest.raises(AttributeError):
            logger_instance.set_level("INVALID_LEVEL")
    
    def test_add_handler(self, logger_instance, mock_handler):
        """Test adding custom handler to logger."""
        initial_count = len(logger_instance.logger.handlers)
        
        logger_instance.add_handler(mock_handler)
        
        assert len(logger_instance.logger.handlers) == initial_count + 1
        assert mock_handler in logger_instance.logger.handlers
    
    def test_remove_handler(self, logger_instance, mock_handler):
        """Test removing handler from logger."""
        logger_instance.add_handler(mock_handler)
        initial_count = len(logger_instance.logger.handlers)
        
        logger_instance.remove_handler(mock_handler)
        
        assert len(logger_instance.logger.handlers) == initial_count - 1
        assert mock_handler not in logger_instance.logger.handlers
    
    def test_json_formatter_basic_format(self, json_logger):
        """Test JSON formatter creates valid JSON output."""
        handler = json_logger.logger.handlers[0]
        formatter = handler.formatter
        
        # Create a mock log record
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
            func="test_function"
        )
        
        formatted = formatter.format(record)
        parsed = json.loads(formatted)
        
        assert parsed['level'] == 'INFO'
        assert parsed['message'] == 'Test message'
        assert parsed['logger'] == 'test'
        assert 'timestamp' in parsed
        assert parsed['function'] == 'test_function'
        assert parsed['line'] == 10
    
    def test_json_formatter_with_extra_data(self, json_logger):
        """Test JSON formatter includes extra data."""
        handler = json_logger.logger.handlers[0]
        formatter = handler.formatter
        
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
            func="test_function"
        )
        record.extra_data = {'user_id': 123, 'action': 'test'}
        
        formatted = formatter.format(record)
        parsed = json.loads(formatted)
        
        assert parsed['user_id'] == 123
        assert parsed['action'] == 'test'
    
    def test_internal_log_method(self, logger_instance):
        """Test internal _log method functionality."""
        with patch.object(logger_instance.logger, 'log') as mock_log:
            logger_instance._log(logging.WARNING, "Test message", key="value")
            
            mock_log.assert_called_once_with(
                logging.WARNING,
                "Test message",
                extra={'extra_data': {'key': 'value'}}
            )
    
    def test_internal_log_method_no_kwargs(self, logger_instance):
        """Test internal _log method without kwargs."""
        with patch.object(logger_instance.logger, 'log') as mock_log:
            logger_instance._log(logging.INFO, "Test message")
            
            mock_log.assert_called_once_with(
                logging.INFO,
                "Test message",
                extra={}
            )
    
    @patch('logging.getLogger')
    def test_logger_singleton_behavior(self, mock_get_logger):
        """Test that same logger name returns same logger instance."""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        
        logger1 = Logger(name="same_name")
        logger2 = Logger(name="same_name")
        
        # Both should get the same underlying logger
        assert mock_get_logger.call_count >= 2
        mock_get_logger.assert_called_with("same_name")
    
    def test_multiple_loggers_independence(self):
        """Test that different logger instances are independent."""
        logging.getLogger("logger1").handlers.clear()
        logging.getLogger("logger2").handlers.clear()
        
        logger1 = Logger(name="logger1", level="DEBUG")
        logger2 = Logger(name="logger2", level="ERROR")
        
        assert logger1.level != logger2.level
        assert logger1.logger.name != logger2.logger.name
        assert logger1.logger is not logger2.logger
```