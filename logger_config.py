import logging
import os
from dotenv import load_dotenv

load_dotenv()

LOG_PATH = os.getenv('LOG_PATH')
RQ_WORKER_LOG = os.path.join(LOG_PATH, 'rq_worker.log')
RQ_SCHEDULER_LOG = os.path.join(LOG_PATH, 'rq_scheduler.log')
API_LOG = os.path.join(LOG_PATH, 'API.log')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()

LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL,
}

def setup_logger(log_file):
    handler = logging.FileHandler(log_file)
    formatter = logging.Formatter(
        '[%(asctime)s] [PID:%(process)d] [%(levelname)s] - %(message)s',
        '%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)

    logger = logging.getLogger(log_file)
    logger.setLevel(LEVELS.get(LOG_LEVEL, logging.INFO))
    logger.addHandler(handler)