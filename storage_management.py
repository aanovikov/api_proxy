import logging
import mysql.connector
import redis
import traceback
from dotenv import load_dotenv
from redis.exceptions import ResponseError, ConnectionError, TimeoutError, RedisError
import os
from redis.lock import Lock

load_dotenv()

MYSQL_SETTINGS = {
    "host": os.getenv('MYSQL_HOST'),
    "user": os.getenv('MYSQL_USER'),
    "password": os.getenv('MYSQL_PASSWORD'),
    "database": os.getenv('MYSQL_DATABASE')
}

REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = int(os.getenv('REDIS_PORT'))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')

def connect_to_mysql():
    try:
        connection = mysql.connector.connect(**MYSQL_SETTINGS)
        if connection.is_connected():
            logging.info("Successfully connected to MySQL.")
            return connection
    except Exception as e:
        logging.error(f"Failed to connect to MySQL: {str(e)}")
        return None

def connect_to_redis(db=0):
    try:
        # r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=db)
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=db)
        r.ping()
        return r
    except redis.ConnectionError:
        logging.error("Failed to connect to Redis. Aborting operation.")
        return None

def store_to_redis(data, token):
    try:
        r = connect_to_redis()
        if r is None:
            logging.error("Failed to connect to Redis. Aborting operation.")
            return False

        if not r.hset(token, mapping=data):
            logging.error(f"Failed to store data for token: {token}")
            return False

        logging.info(f"Stored data for token: {token}")
        return True
        
    except redis.ConnectionError:
        logging.error("Could not connect to Redis")
        return False
    except redis.TimeoutError:
        logging.error("Redis operation timed out")
        return False
    except Exception as e:
        logging.error(f"An unknown error occurred while communicating with Redis: {e}")
        return False

def get_data_from_redis(token):
    r = connect_to_redis()
    all_values = r.hgetall(token)
    if not all_values:
        logging.error(f"No data found for token {token}")
        #traceback.print_stack()
        raise Exception(f"No data found for token {token}")
    return {k.decode('utf-8'): v.decode('utf-8') for k, v in all_values.items()}

def update_data_in_redis(token, fields):
    pipe = get_redis_pipeline()
    if not pipe:
        logging.error("Could not get Redis pipeline. Aborting operation.")
        return False

    for field, value in fields.items():
        pipe.hset(token, field, value)

    if not execute_pipeline(pipe):
        logging.error(f"Failed to update data for token: {token}")
        return False

    logging.info(f"Updated data: token: {token}, NEW {field} = {value}")
    return True

def delete_from_redis(token):
    try:
        logging.info(f"Deleting Redis token: {token}")

        r = connect_to_redis()

        # Deleting a record by key
        result = r.delete(token)

        if result == 1:
            logging.info(f"Redis token deleted: {token}")
            return True
        else:
            logging.warning(f"Redis token doesn't exist: {token}")
            return False

    except Exception as e:
        logging.error(f"An error occurred during Redis token deletion: {str(e)}")
        return False

def get_redis_pipeline():
    try:
        r = connect_to_redis()
        if r:
            pipeline = r.pipeline()
            logging.debug("Successfully created a Redis pipeline.")
            return pipeline
        else:
            logging.error("Failed to create a Redis pipeline. Redis connection is None.")
            return None
    except Exception as e:
        logging.error(f"An error occurred while creating a Redis pipeline: {str(e)}")
        return None

def execute_pipeline(pipe):
    try:
        pipe.execute()
    except redis.exceptions.RedisError as e:
        logging.error(f"Failed to execute pipeline: {str(e)}")
        raise
    return True

def serial_exists(target_serial):
    try:
        r = connect_to_redis()
        if r is None:
            logging.error("Failed to connect to Redis. Aborting operation.")
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
        logging.error("Could not connect to Redis")
        return False
    except redis.TimeoutError:
        logging.error("Redis operation timed out")
        return False
    except Exception as e:
        logging.error(f"An unknown error occurred while communicating with Redis: {e}")
        return False

def get_redis_lock(job_id, timeout=60, db=1):
    redis_conn = connect_to_redis(db)
    lock = None
    acquired = False
    if redis_conn:
        lock = Lock(redis_conn, f"lock:{job_id}", timeout=timeout)
        acquired = lock.acquire(blocking=False)
        if acquired:
            logging.debug(f"Lock acquired for {job_id}")
        else:
            logging.debug(f"Failed to acquire lock for {job_id}")
    else:
        logging.error("Failed to connect to Redis. Lock not acquired.")
    return acquired, lock