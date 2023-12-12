# logger_config.py

import logging
import sys


def setup_logger(name=__name__):
    """
    Sets up a logger with given name and returns it.
    """

    # Create a logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)  # Set default level to INFO

    # Create a console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)

    # Create a formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Set formatter to handler
    ch.setFormatter(formatter)

    # Add the handler to logger
    logger.addHandler(ch)

    return logger
