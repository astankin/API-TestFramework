import logging
import os

def setup_logger(name="test_logger", log_file_path="../logs/test_framework.log", level=logging.INFO):
    """
    Set up a logger for the test framework.

    :param name: Name of the logger.
    :param log_file_path: Relative path to the log file.
    :param level: Logging level (e.g., INFO, DEBUG, ERROR).
    :return: Configured logger.
    """
    log_file = os.path.join(os.path.abspath(os.curdir), log_file_path)
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    file_handler = logging.FileHandler(log_file)
    console_handler = logging.StreamHandler()

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
