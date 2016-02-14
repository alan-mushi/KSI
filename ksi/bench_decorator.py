from datetime import datetime
from logging.handlers import MemoryHandler
import logging

from ksi import PERFORM_BENCHMARKS, BENCHMARK_MOTIF


LOGGER_NAME = 'benchmark'
LOGGER_DIR = 'benchmarks_output/'
LOGGER_LEVEL = 100


def add_logger():
    """
    Convenience function, add the custom logger level.
    """
    logging.addLevelName(LOGGER_LEVEL, LOGGER_NAME)


def benchmark_decorator(func):
    def wrapped_func(*args, **kwargs):
        if PERFORM_BENCHMARKS and func.__module__.startswith(BENCHMARK_MOTIF):
            start_t = datetime.now()
            func(*args, **kwargs)
            end_t = datetime.now()

            # Use our custom logger
            logger = logging.getLogger(LOGGER_NAME)
            # Don't propagate to the parent(s)
            logger.propagate = False

            # Add the handler if not already present
            if not logger.hasHandlers():
                # Log to a buffer in memory, if the buffer is full flush it to the target
                logger_outfile = LOGGER_DIR + LOGGER_NAME + '.log'
                logger.addHandler(MemoryHandler(4096, target=logging.FileHandler(logger_outfile, mode='w+')))

            # Log with the custom logger at a custom level
            logger.log(LOGGER_LEVEL, '%s|%s', func.__module__ + "." + func.__name__, str(end_t - start_t))

        else:
            func(*args, **kwargs)

    return wrapped_func
