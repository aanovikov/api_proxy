import mysql.connector
import redis
import traceback
from dotenv import load_dotenv
from redis.exceptions import ResponseError, ConnectionError, TimeoutError, RedisError
import os
from redis.lock import Lock
import logging
import logger_config
from logger_config import API_LOG

load_dotenv()

logger = logging.getLogger(API_LOG)

MYSQL_SETTINGS = {
    "host": os.getenv('MYSQL_HOST'),
    "user": os.getenv('MYSQL_USER'),
    "password": os.getenv('MYSQL_PASSWORD'),
    "database": os.getenv('MYSQL_DATABASE')
}

REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = int(os.getenv('REDIS_PORT'))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')

BUSY_RDB=2
EXPIRY_TIME = 60
ACT_PUT = 1
ACT_DEL = 0

def connect_to_mysql():
    try:
        connection = mysql.connector.connect(**MYSQL_SETTINGS)
        if connection.is_connected():
            logger.info("Successfully connected to MySQL.")
            return connection
    except Exception as e:
        logger.error(f"Failed to connect to MySQL: {str(e)}")
        return None

def connect_to_redis(db=0):
    try:
        # r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=db)
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=db)
        r.ping()
        return r
    except redis.ConnectionError:
        logger.error("Failed to connect to Redis. Aborting operation.")
        return None

def store_to_redis(data, token):
    try:
        r = connect_to_redis()
        if r is None:
            logger.error("Failed to connect to Redis. Aborting operation.")
            return False

        if not r.hset(token, mapping=data):
            logger.error(f"Failed to store data for token: {token}")
            return False

        logger.debug(f"Stored data for token: {token}")
        return True
        
    except redis.ConnectionError:
        logger.error("Could not connect to Redis")
        return False
    except redis.TimeoutError:
        logger.error("Redis operation timed out")
        return False
    except Exception as e:
        logger.error(f"An unknown error occurred while communicating with Redis: {e}")
        return False

def get_data_from_redis(token):
    try:
        r = connect_to_redis()
        all_values = r.hgetall(token)
        if not all_values:
            logger.warning(f"No data found for token {token}")
            return None
        return {k.decode('utf-8'): v.decode('utf-8') for k, v in all_values.items()}
    except RedisError as e:
        logger.error(f"Redis error: {e}")
        raise

def update_data_in_redis(token, fields):
    pipe = get_redis_pipeline()
    if not pipe:
        logger.error("Could not get Redis pipeline. Aborting operation.")
        return False

    for field, value in fields.items():
        pipe.hset(token, field, value)

    if not execute_pipeline(pipe):
        logger.error(f"Failed to update data for token: {token}")
        return False

    logger.debug(f"Updated data: token: {token}, NEW {field} = {value}")
    return True

def delete_from_redis(token):
    try:
        logger.info(f"Deleting Redis token: {token}")

        r = connect_to_redis()

        # Deleting a record by key
        result = r.delete(token)

        if result == 1:
            logger.info(f"Redis token deleted: {token}")
            return True
        else:
            logger.warning(f"Redis token doesn't exist: {token}")
            return False

    except Exception as e:
        logger.error(f"An error occurred during Redis token deletion: {str(e)}")
        return False

def get_redis_pipeline():
    try:
        r = connect_to_redis()
        if r:
            pipeline = r.pipeline()
            logger.debug("Successfully created a Redis pipeline.")
            return pipeline
        else:
            logger.error("Failed to create a Redis pipeline. Redis connection is None.")
            return None
    except Exception as e:
        logger.error(f"An error occurred while creating a Redis pipeline: {str(e)}")
        return None

def execute_pipeline(pipe):
    try:
        pipe.execute()
    except redis.exceptions.RedisError as e:
        logger.error(f"Failed to execute pipeline: {str(e)}")
        raise
    return True

def serial_exists(target_serial):
    try:
        r = connect_to_redis()
        if r is None:
            logger.error("Failed to connect to Redis. Aborting operation.")
            return False
        
        for key in r.scan_iter("*"):  # Replace "*" with a more specific pattern if applicable
            user_data = r.hgetall(key)
            if not user_data:
                continue
            
            user_data_decoded = {k.decode('utf-8'): v.decode('utf-8') for k, v in user_data.items()}
            serial = user_data_decoded.get('serial')

            if serial == target_serial:
                return True
                
        return False

    except redis.ConnectionError:
        logger.error("Could not connect to Redis")
        return False
    except redis.TimeoutError:
        logger.error("Redis operation timed out")
        return False
    except Exception as e:
        logger.error(f"An unknown error occurred while communicating with Redis: {e}")
        return False

def get_redis_lock(job_id, timeout=60, db=1):
    redis_conn = connect_to_redis(db)
    lock = None
    acquired = False
    if redis_conn:
        lock = Lock(redis_conn, f"lock:{job_id}", timeout=timeout)
        acquired = lock.acquire(blocking=False)
        if acquired:
            logger.debug(f"Lock acquired for {job_id}")
        else:
            logger.debug(f"Failed to acquire lock for {job_id}")
    else:
        logger.error("Failed to connect to Redis. Lock not acquired.")
    return acquired, lock

def manage_busy_info_in_redis(serial, action, db=BUSY_RDB, expire=EXPIRY_TIME):
    try:
        r = connect_to_redis(db)
        if r is None:
            logger.error("Failed to connect to Redis. Aborting operation.")
            return False

        if action == ACT_PUT:
            r.setex(serial, expire, '')
            logger.debug(f"Stored busy info: {serial}")
            return True
        if action == ACT_DEL:
            r.delete(serial)
            logger.debug(f"Removed busy info: {serial}")
            return True
        
    except redis.ConnectionError:
        logger.error("Could not connect to Redis reboot DB")
        return False
    except redis.TimeoutError:
        logger.error("Redis operation timed out")
        return False
    except Exception as e:
        logger.error(f"An unknown error occurred while communicating with Redis: {e}")
        return False

def is_device_busy(serial, db):
    r = connect_to_redis(db)
    if r is None:
        logger.error("Failed to connect to Redis. Skipping reboot check.")
        return None

    try:
        return r.exists(serial)  # Возвращает True, если ключ существует, иначе False
    except Exception as e:
        logger.error(f"Error checking busy status in Redis: {e}")
        return None