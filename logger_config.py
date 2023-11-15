import logging
from logging.handlers import TimedRotatingFileHandler

def setup_logger():
    handler = TimedRotatingFileHandler(
        '/var/log/supervisor/API.log',
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
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)