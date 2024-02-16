import redis
import atexit
#import device_management as dm
import storage_management as sm
import logging
from functools import wraps
import secrets
import string
from flask import request
import re
import ipaddress
import platform

logger = logging.getLogger()

def generate_short_token():
    alphabet = string.ascii_letters + string.digits  # a-z, A-Z, 0-9
    token = ''.join(secrets.choice(alphabet) for _ in range(20))

    hostname = platform.node()

    token_with_hostname = f"{hostname}{token}"

    return token_with_hostname

def requires_role(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = kwargs.pop('token', None)

            r = sm.connect_to_redis()
            if token is None:
                logger.error("Token is missing in the request.")
                return {"message": "Unauthorized"}, 401
            
            # Checking the type of the Redis key
            key_type = r.type(token).decode('utf-8')
            if key_type != 'hash':
                logger.error(f"Token is of invalid type: {key_type}. Expected 'hash'.")
                return {"message": "Invalid acces token"}, 400

            role_data = r.hget(token, "role")
            if role_data is None:
                logger.error(f"No role found for token: {token}")
                return {"message": "Unauthorized"}, 401
            
            role = role_data.decode('utf-8')  # Декодирование может быть необходимым
            if role != required_role:
                logger.warning(f"Permission denied, role doesn't have access: {role} ")
                return {"message": "Permission denied"}, 403
            
            logger.info(f"Authorized: role: {role}, token: {token}")

            kwargs['admin_token'] = token  # Re-insert the token
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def is_valid_port(port):
    try:
        port_num = int(port)
        return 10000 <= port_num <= 65000
    except ValueError:
        return False

def validate_and_extract_data(required_fields):
    data = request.json
    if data is None:
        return None, {"message": "Invalid request: JSON body required"}, 400
    if not all(data.get(field) for field in required_fields):
        return None, {"message": f"Missing required fields: {required_fields}"}, 400
    return data, None, None

def is_valid_logopass(value):
    if len(value) == 6:
        return False
    return bool(re.match("^[a-zA-Z0-9]+$", value))

def is_valid_serial(value):
    if len(value) < 10:
        return False
    return bool(re.match("^[a-zA-Z0-9]+$", value))

def is_valid_device(value):
    if len(value) > 10:
        return False
    return bool(re.match("^[a-zA-Z0-9]+$", value))

def is_valid_id(value):
    if value is None:
        return False
    return value.isdigit()

def validate_field(field_name, field_value, validation_func):
    if not validation_func(field_value):
        logger.warning(f"Invalid {field_name}: {field_value}")
        return {"message": f"Invalid {field_name}"}, 422
    return None, None

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False