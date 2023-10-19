from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
import atexit
import device_management as dm
import storage_management as sm
import logging
from functools import wraps
import secrets
import base64
from flask import request

atexit.register(lambda: scheduler.shutdown())

jobstores = {
    'default': SQLAlchemyJobStore(url='sqlite:///jobs.sqlite')
}

scheduler = BackgroundScheduler(jobstores=jobstores)
scheduler.start()
#__all__ = ['scheduler']

def schedule_job(serial, device, device_id):
    job_id = f"modem_{serial}"    
    try:
        scheduler.add_job(
            dm.os_boot_status,
            'interval', seconds=10,
            args=[serial, device, device_id, True],
            id=job_id,
            replace_existing=True
        )
        logging.info(f"Added task: {job_id}, id{device_id}")
    except Exception as e:
        logging.error(f"Failed add task: {job_id}, id{device_id}, Error: {e}")

def generate_short_token():
    random_bytes = secrets.token_bytes(15)  # 15 bytes should generate a 20-character token when base64 encoded
    token = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
    return token

def requires_role(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = kwargs.pop('token', None)

            r = sm.connect_to_redis()
            if token is None:
                logging.error("Token is missing in the request.")
                return {"message": "Unauthorized"}, 401
            
            # Checking the type of the Redis key
            key_type = r.type(token).decode('utf-8')
            if key_type != 'hash':
                logging.error(f"Token is of invalid type: {key_type}. Expected 'hash'.")
                return {"message": "Invalid acces token"}, 400

            role_data = r.hget(token, "role")
            if role_data is None:
                logging.error(f"No role found for token: {token}")
                return {"message": "Unauthorized"}, 401
            
            role = role_data.decode('utf-8')  # Декодирование может быть необходимым
            if role != required_role:
                logging.warning(f"Permission denied, role doesn't have access: {role} ")
                return {"message": "Permission denied"}, 403
            
            logging.info(f"Authorized: role: {role}, token: {token}")

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