import logging
import mysql.connector
import redis
import traceback
from dotenv import load_dotenv
from redis.exceptions import ResponseError
import os

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

def connect_to_redis():
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD)
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
            logging.error(f"Failed to store data for token {token}")
            return False

        logging.info(f"Successfully stored data for token {token}")
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
        traceback.print_stack()
        raise Exception(f"No data found for token {token}")
    return {k.decode('utf-8'): v.decode('utf-8') for k, v in all_values.items()}

def update_data_in_redis(token, field, value):
    r = connect_to_redis()
    r.hset(token, field, value)
    logging.info(f"Updated data for token {token}: {field} = {value}")

def delete_from_redis(token):
    try:
        logging.info(f"Deleting token: {token} from Redis")

        r = connect_to_redis()

        # Deleting a record by key
        result = r.delete(token)

        if result == 1:
            logging.info(f"The key {token} has been deleted successfully.")
            return True
        else:
            logging.warning(f"The key {token} does not exist.")
            return False

    except Exception as e:
        logging.error(f"An error occurred during Redis token deletion: {str(e)}")
        return False

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