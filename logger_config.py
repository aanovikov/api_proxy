import logging
from logging.handlers import TimedRotatingFileHandler
import os
from dotenv import load_dotenv

load_dotenv()

LOG_PATH = os.getenv('LOG_PATH')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()

LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL,
}

def setup_logger():
    handler = TimedRotatingFileHandler(
        LOG_PATH,
        when='midnight',
        interval=1,
        backupCount=7
    )
    formatter = logging.Formatter(
        '[%(asctime)s] [PID:%(process)d] [%(levelname)s] - %(message)s',
        # '[%(asctime)s] [%(levelname)s] - %(message)s',
        '%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(LEVELS.get(LOG_LEVEL, logging.INFO))
    logger.addHandler(handler)