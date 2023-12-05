import logging
from logging.handlers import TimedRotatingFileHandler

LOG_PATH = '/var/log/supervisor/API.log'

def setup_logger():
    handler = TimedRotatingFileHandler(
        LOG_PATH,
        when='midnight',
        interval=1,
        backupCount=7
    )
    formatter = logging.Formatter(
        '[%(asctime)s] [PID:%(process)d] [%(levelname)s] - %(message)s',
        '%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)