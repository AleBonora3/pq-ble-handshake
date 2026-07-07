"""
Shared logging configuration for PQ-BLE-HANDSHAKE.
"""

import logging
import sys

LOG_FORMAT = "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
LOG_DATE_FORMAT = "%H:%M:%S"


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure root logger with consistent formatting."""
    logger = logging.getLogger("pq-ble")
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
        logger.addHandler(handler)

    return logger


# Convenience: get a module-level logger
def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"pq-ble.{name}")
