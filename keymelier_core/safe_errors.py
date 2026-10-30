"""Diagnostic locations without exception text, source lines, locals or user paths."""
import os
import traceback


def log_failure(logger, operation, error):
    where = " < ".join(f"{os.path.basename(frame.filename)}:{frame.lineno} {frame.name}"
                       for frame in reversed(traceback.extract_tb(error.__traceback__)))
    logger.error("%s failed (%s) at %s", operation, type(error).__name__, where or "unknown")
