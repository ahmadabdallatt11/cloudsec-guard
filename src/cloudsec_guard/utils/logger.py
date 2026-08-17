import logging
import sys
from pathlib import Path

def setup_logger(name: str = "cloudsec_guard", log_file: str = "cloudsec_guard.log") -> logging.Logger:
    """
    Configures and returns a production-grade logger that handles audit trails 
    by logging to both a secure local file and standard error stream.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Prevent adding duplicate handlers if logger is called multiple times
    if logger.handlers:
        return logger

    # Professional log format with timestamp, log level, module/function, and message
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s.%(funcName)s:%(lineno)d]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler (Captures WARNING and above to avoid cluttering Rich CLI output)
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.WARNING)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File Handler (Captures DEBUG and above for complete debugging and audit logs)
    try:
        log_path = Path(log_file)
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    except Exception as e:
        print(f"[SECURITY ALERT] Could not initialize file logger: {e}")

    return logger

# Global application logger instance
logger = setup_logger()