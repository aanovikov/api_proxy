from flask import Flask, request # jsonifyboot_status
from flask_restful import Resource, Api, reqparse
from werkzeug.exceptions import BadRequest
import time
import os
import logger_config
from logger_config import API_LOG
import logging
from logging.handlers import TimedRotatingFileHandler
from ipaddress import ip_address, AddressValueError
from dotenv import load_dotenv
import network_management as nm
from settings import TETHERING_COORDINATES, ALLOWED_PROTOCOLS, ROOT, WG_COORDINATES
import tools as ts
import storage_management as sm
import conf_management as cm
from rq_scheduler.scheduler import Scheduler, Queue
import json
from datetime import datetime, timedelta
from redis.exceptions import ResponseError, ConnectionError, TimeoutError, RedisError
import subprocess

load_dotenv()

logger_config.setup_logger(API_LOG)
logger = logging.getLogger(API_LOG)

parser = reqparse.RequestParser()
parser.add_argument('interval_seconds')

app = Flask(__name__)
api = Api(app)

ACL_PATH = os.getenv('ACL_PATH')
CONFIG_PATH = os.getenv('CONFIG_PATH')
MODEM_UP_TIME = 1
CHANGE_IP_TIMEOUT = 30
ALLOWED_INTERVAL = 60
BUSY_RDB = 2
ACT_PUT = 1
ACT_DEL = 0
EXPIRY_TIME = 60
SCHEDULER_RDB = os.getenv('SCHEDULER_RDB')

# templates for log
USER_LOG_CREDENTIALS = '{tgname}, id{id}'

redis_conn = sm.connect_to_redis(db=SCHEDULER_RDB)
scheduler = Scheduler(connection=redis_conn, interval=30)
logger.debug(redis_conn)

def check_job_exists(scheduler, job_id):
    for job in scheduler.get_jobs():
        if job.id == job_id:
            return True  # Job found
    return False  # Job not found

class Reboot(Resource):
    #@ts.requires_role("user")
    def get(self, token):
        try:
            logger.debug("REBOOT")

            user_data = sm.get_data_from_redis(token)
            if user_data is None:
                return {'error': 'Proxy has expired or the token was not found'}, 404

            serial = user_data.get('serial')
            device = user_data.get('device')
            mode = user_data.get('mode')
            device_id = user_data.get('id')  # Getting from Redis
            tgname = user_data.get('tgname')
            tid = None
            device_found = False

            logger.debug("STARTING get_adb_device_status")
            device_status = nm.get_adb_device_status(serial, device_id, tid=tid) # Получаем adb статус устройства
            logger.debug(f"DEV_STATUS: {device_status}")

            if device_status == "device": # Работа в этой ветке идёт по серийнику, если устройство по нему сразу найдено
                reboot_status = nm.os_boot_status(serial, device, device_id, enable_modem=False, tid=tid)

                if reboot_status != 'OK':
                    logger.warning(f"Device id: {device_id}, serial: {serial} is rebooting.")
                    return {'reboot': 'in progress', 'message': 'Device is still rebooting.'}, 409

                if mode == "android":
                    logger.info(f'REBOOT: {tgname}, id{device_id}')
                    nm.adb_reboot_device(serial, device_id, tid=tid)
                    sm.manage_busy_info_in_redis(serial, ACT_PUT)
                    return {'reboot': 'OK', 'message': 'Reboot is started, wait 1 minute.'}, 200

                if mode == "modem":
                    logger.info(f'REBOOT: {tgname}, id{device_id}')
                    nm.adb_reboot_device(serial, device_id, tid=tid)
                    sm.manage_busy_info_in_redis(serial, ACT_PUT)
                    return {'reboot': 'OK', 'message': 'Reboot is started, wait 1 minute.'}, 200

            elif device_status == "device_not_found": # Если не найдено по серийному номеру, пробуем по transport_id
                logger.debug(f'Device id{device_id} serial {serial} not found, trying by TID')
                tid_usb_dict = nm.get_tid_usb_port()
                logger.debug(f"tid_usb_dict READY")
                logger.debug(f"DICT: {tid_usb_dict}")

                for tid, usb_port in tid_usb_dict.items():
                    cmd_serial_by_tid = [arg.format(tid=tid) for arg in nm.ADB_GET_SERIAL]
                    logger.debug(f"CMD: {cmd_serial_by_tid}")

                    try:
                        serial_by_tid = subprocess.check_output(cmd_serial_by_tid, stderr=subprocess.STDOUT).decode('utf-8').strip()
                        logger.debug(f"SERIAL_by_TID: {serial_by_tid}")
                        
                        if serial_by_tid == serial: # При совпадении выполняем команду для устройства
                            logger.info(f'Device id{device_id} FOUND by TID_{tid}')
                            # Если серийный номер совпадает, проверяем статус устройства
                            device_found = True
                            nm.adb_reboot_device(serial, device_id, tid=tid)
                            return {'reboot': 'OK', 'message': 'Reboot is started, wait 1 minute.'}, 200

                    except subprocess.CalledProcessError as e:
                        logger.error(f"Error fetching serial by tid {tid}: {e}")
                        
                if not device_found:
                    return f"Device {token} not found"

            else:
                logger.warning(f"Device is not in a good state: {device_status}")
                return {'status': 'seems disconnected', 'message': f'Device is {device_status}'}, 400

            logger.error(f"Unknown mode provided for device id: {device_id}, serial: {serial}.")
            return {'error': 'Unknown mode provided'}, 400

        except Exception as e:
            logger.error(f"Reboot_res: An error occurred: {str(e)}")
            return {'error': 'Internal server error'}, 500

class DeviceStatus(Resource):
    #@ts.requires_role("user")
    def get(self, token, serial=None):
        try:
            logger.debug("STATUS")

            serial = request.args.get('serial')  # Get serial from query params
            tid = None
            device_found = False

            if serial:
                # For admin: serial directly provided
                logger.info(f"STATUS (admin only): serial {serial}")
                device_id = None
                device = None
            else:
                user_data = sm.get_data_from_redis(token)
                if user_data is None:
                    return {'error': 'Proxy has expired or the token was not found'}, 404

                serial = user_data.get('serial')
                device = user_data.get('device')
                device_id = user_data.get('id')
                tgname = user_data.get('tgname')

                logger.debug(f"REDIS_DATA: {serial}, {device}, {device_id}")
                
                user_log_credentials = USER_LOG_CREDENTIALS.format(tgname=tgname, id=device_id)
                
                logger.info(f"STATUS: {user_log_credentials}")

            logger.debug("STARTING get_adb_device_status")
            device_status = nm.get_adb_device_status(serial, device_id, tid=tid) # Получаем adb статус устройства
            logger.debug(f"DEV_STATUS: {device_status}")

            if device_status == "device":
                logger.debug(f"GO to check_device_ready")
                status = nm.check_device_ready(serial, device, device_id, tid=tid)
                logger.info(f"STATUS: {status}")
                return status

            elif device_status == "device_not_found": # не найдено по серийному номеру, пробуем по transport_id
                logger.debug(f'Device id{device_id} serial {serial} not found, trying by TID')
                tid_usb_dict = nm.get_tid_usb_port()
                logger.debug(f"DICT: {tid_usb_dict}")

                for tid, usb_port in tid_usb_dict.items():
                    cmd_serial_by_tid = [arg.format(tid=tid) for arg in nm.ADB_GET_SERIAL]
                    logger.debug(f"CMD: {cmd_serial_by_tid}")

                    try:
                        serial_by_tid = subprocess.check_output(cmd_serial_by_tid, stderr=subprocess.STDOUT).decode('utf-8').strip()
                        logger.debug(f"SERIAL_by_TID: {serial_by_tid}")
                        
                        if serial_by_tid == serial:
                            logger.info(f'Device id{device_id} FOUND by TID {tid}')
                            # Если серийный номер совпадает, проверяем статус устройства
                            device_found = False
                            status = nm.check_device_ready(serial, device, device_id, tid)
                            logger.info(f"STATUS: {status}")
                            return status

                    except subprocess.CalledProcessError as e:
                        logger.error(f"Error fetching serial by tid {tid}: {e}")
                        
                if not device_found:
                    return f"Device {token} not found"

            else:
                logger.warning(f"Device is not in a good state: {device_status}")
                return {'status': 'seems disconnected', 'message': f'Device is {device_status}'}, 400
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            return {"error": str(e)}, 500

class ChangeIP(Resource):
    def get(self, token):
        try:
            user_data = sm.get_data_from_redis(token)
            if user_data is None:
                return {'error': 'Proxy has expired or the token was not found'}, 404

            serial = user_data.get('serial')
            device = user_data.get('device')
            username = user_data.get('username')
            tgname = user_data.get('tgname')
            id = user_data.get('id')
            http_port = user_data.get('http_port')
            socks_port = user_data.get('socks_port')
            last_ip_change_time = user_data.get('last_ip_change_time')
            current_time = datetime.now()
            tid = None
            device_found = False

            user_log_credentials = USER_LOG_CREDENTIALS.format(tgname=tgname, id=id)

            if not serial:
                logger.error(f"Serial NOT found in redis: id{id}, user {username}, serial: {serial}")
                return {'error': 'Serial not found'}, 400
            
            busy_status = sm.is_device_busy(serial, BUSY_RDB) # Для телефонов, чтобы не давало выполнять другие действия, пока выполняются действия на экране
            if busy_status is None:
                logger.error(f"Error cheking BUSY status: {serial}, {user_log_credentials}")

            if busy_status:
                logger.info(f"Device is BUSY: {user_log_credentials}")
                return {'message': 'Device is busy, please try again later'}, 202  # HTTP 202 Accepted

            # Если last_ip_change_time не установлен, разрешаем смену IP
            if last_ip_change_time is None:
                logger.info("No IP change recorded previously, proceeding with IP change.")
                last_ip_change_time = current_time.timestamp()

            else:
                last_ip_change_time = datetime.fromtimestamp(float(last_ip_change_time))
                time_passed = current_time - last_ip_change_time
                # Проверяем, прошло ли 30 секунд с последней смены IP
                if time_passed < timedelta(seconds=CHANGE_IP_TIMEOUT):
                    time_left = CHANGE_IP_TIMEOUT - int(time_passed.total_seconds())
                    logger.warning(f"IP CHANGE LIMIT REACHED: {user_log_credentials}, time left: {time_left} sec.")
                    return {'error': f'You can only change IP once every {CHANGE_IP_TIMEOUT} seconds. Try again in {time_left} seconds.'}, 429
                user_data['last_ip_change_time'] = current_time.timestamp()

            # Check if device has ROOT
            if device not in ROOT: # Выполяняется если у телефона нет рута
                logger.debug(f"Airplane on\off via TOUCH: {tgname}, {device}, id{id}, {username}, {serial}")

                if 'toggle_airplane' in nm.MODEM_HANDLERS[device]:
                    airplane_toggle_result = nm.MODEM_HANDLERS[device]['toggle_airplane'](serial)
                else:
                    logger.error(f"No 'toggle_airplane' for device {device}.")
                    return {'error': 'Operation not supported for this device'}, 400

            else: # Условие выполняется если устройство модем
                device_status = nm.get_adb_device_status(serial, id, tid=tid) # Получаем adb статус устройства
                logger.debug(f"DEV_STATUS: {device_status}")

                if device_status == "device":
                    logger.debug(f"Airplane on\off via CMD: {tgname}, {device}, id{id}, {username}, {serial}")
                    airplane_toggle_result = nm.MODEM_HANDLERS[device]['toggle_airplane'](serial)
                
                elif device_status == "device_not_found": # не найдено по серийному номеру, пробуем по transport_id
                    logger.debug(f'Device id{id} serial {serial} not found, trying by TID')
                    tid_usb_dict = nm.get_tid_usb_port()

                    logger.debug(f"DICT: {tid_usb_dict}")

                    for tid, usb_port in tid_usb_dict.items():
                        cmd_serial_by_tid = [arg.format(tid=tid) for arg in nm.ADB_GET_SERIAL]
                        logger.debug(f"CMD: {cmd_serial_by_tid}")

                        try:
                            serial_by_tid = subprocess.check_output(cmd_serial_by_tid, stderr=subprocess.STDOUT).decode('utf-8').strip()
                            logger.debug(f"SERIAL by TID: {serial_by_tid}")
                            
                            if serial_by_tid == serial:
                                logger.info(f'Device id{id} FOUND by TID {tid}')
                                device_found = True
                                # Если серийный номер совпадает, проверяем статус устройства
                                airplane_toggle_result = nm.MODEM_HANDLERS[device]['toggle_airplane_tid'](tid)
                                break

                        except subprocess.CalledProcessError as e:
                            logger.error(f"Error fetching serial by tid {tid}: {e}")
                            
                    if not device_found:
                        return f"Device {token} not found"

                else:
                    logger.warning(f"Device is not in a good state: {device_status}")
                    return {'status': 'seems disconnected', 'message': f'Device is {device_status}'}, 400

            if airplane_toggle_result:
                fields_to_update = {'last_ip_change_time': current_time.timestamp()}
                sm.update_data_in_redis(token, fields_to_update)
                logger.debug(f"Updated data for token: {token} with the following fields: {fields_to_update}")

                logger.info(f"IP CHANGE SUCCESS: {user_log_credentials}")
                return {'status': 'success', 'message': 'IP was changed'}, 200
            else:
                logger.error(f"Failed to change IP: {tgname}, {device}, id{id}, {username}, {serial}")
                return {'status': 'failure', 'message': 'Failed to change IP'}, 400

        except Exception as e:
            logger.error(f"An error occurred: {e}")
            return {'status': 'failure', 'message': 'An error occurred while changing IP'}, 500

class AutoChangeIP(Resource):
    def post(self, token):
        try:
            logger.debug("SET IP AUTO CHANGE")

            user_data = sm.get_data_from_redis(token)
            if user_data is None:
                return {'error': 'Proxy has expired or the token was not found'}, 404

            logger.debug(f"GOT data from redis, token {token}")
            serial = user_data.get('serial')
            device_id = user_data.get('id')
            device_model = user_data.get('device')
            tgname = user_data.get('tgname')
            action = 'toggle_airplane'
            job_id = f"changeip_{serial}"

            user_log_credentials = USER_LOG_CREDENTIALS.format(tgname=tgname, id=id)

            if not serial:
                logger.error("Serial number not found in user_data.")
                return {'error': 'Serial number not found'}, 400

            args = parser.parse_args()
            interval_seconds = int(args['interval_seconds'])

            # Obtain a lock to prevent concurrent modifications by other schedulers or workers
            with scheduler.connection.lock(job_id):
                if check_job_exists(scheduler, job_id):  # Checking if job exists
                    if interval_seconds == 0:
                        scheduler.cancel(job_id)  # cancel job if interval_seconds == 0
                        # Verify job cancellation
                        if not check_job_exists(scheduler, job_id):
                            logger.info(f'IP ROTATION CANCELED: {user_log_credentials}, {job_id}')
                            return {'status': 'success', 'message': f'IP rotation canceled'}, 200
                        else:
                            logger.error(f'IP ROTATION CANCELLATION FAILED: {user_log_credentials}, {job_id}')
                    elif interval_seconds >= ALLOWED_INTERVAL:
                        # cancel existing job and create a new one with updated interval
                        scheduler.cancel(job_id)
                        scheduler.schedule(
                            scheduled_time=datetime.utcnow(),
                            func=nm.dispatcher,
                            args=[device_model, serial, action],
                            interval=interval_seconds,
                            repeat=None,  # Repeat forever
                            id=job_id
                        )
                        # Verify job update
                        if check_job_exists(scheduler, job_id):
                            logger.info(f'IP ROTATION UPDATED: {user_log_credentials}, {job_id}, interval: {interval_seconds} sec.')
                            return {'status': 'success', 'message': f'IP rotation updated: interval {interval_seconds} sec'}, 200
                        else:
                            logger.error(f'IP ROTATION UPDATE FAILED: {user_log_credentials}, {job_id}')
                else:
                    if interval_seconds >= ALLOWED_INTERVAL:
                        # create a new job as it doesn't exist
                        scheduler.schedule(
                            scheduled_time=datetime.utcnow(),
                            func=nm.dispatcher,
                            args=[device_model, serial, action],
                            interval=interval_seconds,
                            repeat=None,  # Repeat forever
                            id=job_id
                        )
                        # Verify job creation
                        if check_job_exists(scheduler, job_id):
                            logger.info(f'IP ROTATION SCHEDULED: {user_log_credentials}, {job_id}, interval: {interval_seconds} sec.')
                            return {'status': 'success', 'message': f'IP rotation scheduled: interval {interval_seconds} sec'}, 200
                        else:
                            logger.error(f'IP ROTATION SCHEDULING FAILED: {user_log_credentials}, {job_id}')
                    elif interval_seconds == 0:
                        logger.warning(f'IP ROTATION NOT FOUND TO CANCEL: {user_log_credentials}, {job_id}')
                    else:
                        logger.warning(f'INVALID INTERVAL: Interval cannot be less than 30 seconds. {user_log_credentials}, {job_id}')

        except Exception as e:
            logger.error(f"Error occurred in AutoChangeIP: {str(e)}")
            return {'status': 'failure', 'message': str(e)}, 500

class DeleteUser(Resource):
    @ts.requires_role("admin")
    def delete(self, admin_token):
        try:
            logger.info("DELETE USER.")

            data = request.json
            logger.info(f"Got data: {data}")
            if data is None:
                logger.error("Invalid request: JSON body required.")
                return {"message": "Invalid request: JSON body required"}, 400

            # Get proxy_id and token from JSON body
            token = data.get('token') # to remove key using token in redis

            user_data = sm.get_data_from_redis(token)
            if user_data is None:
                return {'error': 'Proxy has expired or the token was not found'}, 404

            logger.debug(f"GOT data from redis, token {token}")

            serial = user_data.get('serial')
            proxy_id = user_data.get('id')
            device = user_data.get('device')
            username = user_data.get('username')
            tgname = user_data.get('tgname')
            job_id = f"changeip_{serial}"  # Определение job_id
            
            logger.debug(f"DATA: {token}, {serial}, {proxy_id}, {device}, {username}, {tgname}")
            
            if not proxy_id or not token or not username:
                logger.error("Missing required fields: proxy_id and/or token/or username.")
                return {"message": "Missing required fields: proxy_id and/or token/or username"}, 400

            # Check if the user exists
            if not cm.username_exists_in_ACL(username):
                logger.error("User does not exist.")
                return {"message": "User does not exist"}, 404

            # Check token and username in Redis
            user_data = sm.get_data_from_redis(token)
            if not user_data or user_data.get('id') != proxy_id:
                logger.error("Invalid proxy_id or token.")
                return {"message": "Invalid proxy_id or token"}, 400

            #logger.info(f"Reading config")
            lines = cm.read_file(CONFIG_PATH)
            
            #logger.info(f"Counting username")
            count_users = cm.user_count_in_ACL(username, proxy_id, tgname, lines)
            #logger.info(f"Count username: {count_users}")

            if count_users == 1:
                logger.info(f"User has only 1 proxy, removing ACL: {username}, id{proxy_id}")
            elif count_users > 1:
                logger.warning(f"User has {count_users} proxy, SKIP removing ACL: {username}, id{proxy_id}")

            # Remove from configuration
            if not cm.remove_user_config(username, proxy_id):
                logger.error(f"Failed to remove user's config: {username}, id{proxy_id}")
                return ({f"message": f"Failed to remove user's config: {username}, id{proxy_id}"}, 500)

            # Remove from ACL
            if count_users == 1:
                if not cm.remove_user_from_acl(username):
                    logger.error(f"Failed to remove user from ACL: {username}")
                    return ({f"message": f"Failed to remove user from ACL: {username}"}, 500)

                #logger.info(f"User removed from ACL: {username}")
            elif count_users > 1:
                logger.info(f"User has {count_users} proxy, SKIP removing ACL: {username}")
            
            # Remove from Redis
            result = sm.delete_from_redis(token)
            if not result:
                logger.error(f"Token not found in Redis or failed to remove: {token}")
                return ({f"message": f"Token not found in Redis or failed to remove: {token}"}, 404)

            with scheduler.connection.lock(job_id, timeout=10):  # Получение блокировки
                if check_job_exists(scheduler, job_id):
                    scheduler.cancel(job_id)  # Отмена задания, если оно существует
                    logger.info(f"Job {job_id} canceled.")
                else:
                    logger.warning(f"Job {job_id} not found, cannot cancel.")

            logger.info(f"User deleted: {username}")
            return ({f"message": f"User deleted: {username}"}, 200)

        except BadRequest:
            logger.error("Bad request, possibly malformed JSON.")
            return {"message": "Invalid JSON format received"}, 400

        except Exception as e:
            logger.exception(f"An error occurred: {str(e)}")
            return {"message": f"An error occurred: {str(e)}"}, 500

class UpdateAuth(Resource):
    @ts.requires_role("admin")
    def patch(self, admin_token):
        try:
            logger.info("UPDATE AUTH.")

            data = request.json
            if data is None:
                logger.error("Invalid request: JSON body required.")
                return {"message": "Invalid request: JSON body required"}, 400
            
            # tgname = data.get('tgname')
            # if not tgname:
            #     logger.error("Missing required field: tgname.")
            #     return {"message": "Missing required field: tgname"}, 400

            # proxy_id = data.get('id')
            # if not proxy_id:
            #     logger.error("Missing required field: id.")
            #     return {"message": "Missing required field: id"}, 400

            token = data.get('token')
            if not token:
                logger.error("Missing required field: token.")
                return {"message": "Missing required field: token"}, 400

            protocol = data.get('protocol')  # Should be either 'http', 'socks', or 'both'
            if not protocol:
                logger.error("Missing required field: protocol.")
                return {"message": "Missing required field: protocol"}, 400

            auth_type = data.get('auth_type')
            if not auth_type:
                logger.error("Missing required field: auth_type.")
                return {"message": "Missing required field: auth_type"}, 400

            allow_ip = data.get('allow_ip')
            if not allow_ip:
                logger.error("Missing required field: allow_ip.")
                return {"message": "Missing required field: allow_ip"}, 400

            user_data = sm.get_data_from_redis(token)
            if user_data is None:
                return {'error': 'Proxy has expired or the token was not found'}, 404

            username = user_data.get('username')
            tgname = user_data.get('tgname')
            proxy_id = user_data.get('id')

            logger.info(f"Received DATA: id{proxy_id}, Username: {username}, Protocol: {protocol}, New Auth Type: {auth_type}, Allow ip: {allow_ip}")

            if protocol not in ALLOWED_PROTOCOLS:
                logger.error("Invalid protocol provided.")
                return {"message": "Invalid protocol provided"}, 400

            if auth_type == "strong":
                allow_ip = username
            elif auth_type == "iponly":
                if 'allow_ip' not in data:
                    logger.error("allow_ip required for iponly auth_type.")
                    return {"message": "allow_ip required for iponly auth_type"}, 400
                allow_ip = data['allow_ip']
            else:
                logger.error("Invalid auth_type provided.")
                return {"message": "Invalid auth_type provided"}, 400
            
            messages = []

            if protocol == 'both':
                result1, message1 = cm.update_auth_in_config(proxy_id, username, 'http', auth_type, allow_ip)
                result2, message2 = cm.update_auth_in_config(proxy_id, username, 'socks', auth_type, allow_ip)
                if not result1:
                    messages.append(f"Failed to update HTTP for {username}: {message1}")
                else:
                    messages.append(f"Successfully updated HTTP for {username}")

                if not result2:
                    messages.append(f"Failed to update SOCKS for {username}: {message2}")
                else:
                    messages.append(f"Successfully updated SOCKS for {username}")
            else:
                result, message = cm.update_auth_in_config(proxy_id, username, protocol, auth_type, allow_ip)
                if not result:
                    messages.append(f"Failed to update for {protocol}: {message}")
                else:
                    messages.append(f"Successfully updated for {protocol}")

            if messages:
                logger.info(" | ".join(messages))
                if 'both' == protocol:
                    return {"message": " | ".join(messages)}, 200 if all([result1, result2]) else 400
                else:
                    return {"message": " | ".join(messages)}, 200 if result else 400

        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class UpdateMode(Resource):
    @ts.requires_role("admin")
    def post(self, admin_token):
        try:
            logger.info("UPDATE MODE.")

            data = request.json
            if data is None:
                logger.warning("Invalid request: Missing JSON body")
                return {"message": "Invalid request: JSON body required"}, 400

            required_fields = ['token', 'new_mode', 'parent_ip', 'http_port', 'socks_port']
            if not all(data.get(field) for field in required_fields):
                logger.warning("Missing required fields in data")
                return {"message": "Missing required fields"}, 400

            token = data.get('token')
            new_mode = data.get('new_mode')
            parent_ip = data.get('parent_ip')
            http_port = int(data.get('http_port'))
            socks_port = int(data.get('socks_port'))

            if new_mode not in ['android', 'modem']:
                logger.warning("Invalid mode. Use either 'android' or 'modem'")
                return {"message": "Invalid mode. Use either 'android' or 'modem'"}, 400

            # Проверка корректности parent_ip
            if new_mode == 'android':
                try:
                    ip_address(parent_ip)
                except AddressValueError:
                    logger.warning("Invalid parent IP address")
                    return {"message": "Invalid parent IP address. Should be a valid IPv4 or IPv6 address."}, 400

            logger.debug(f"Got: token: {token}, new_mode: {new_mode}, parent_ip: {parent_ip}, http_port: {http_port}, socks_port: {socks_port}")

            if not (10000 <= http_port <= 65000 and 10000 <= socks_port <= 65000):
                logger.warning("Port numbers out of allowed range")
                return {"message": "Port numbers should be between 10000 and 65000"}, 400

            response = cm.update_mode_in_config(new_mode, parent_ip, token, http_port, socks_port)
            
            logger.info("Successfully updated mode.")
            return {"message": response["message"]}, response["status_code"]
            
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return {"message": f"Internal server error: {str(e)}"}, 500

class AddUserModem(Resource):
    @ts.requires_role("admin")
    def post(self, admin_token):
        try:
            logger.info("ADD USER MODEM.")
            
            data = request.json
            if data is None:
                logger.warning("Invalid request: Missing JSON body")
                return {"message": "Invalid request: JSON body required"}, 400

            logger.info(f"Received data: {data}")

            required_fields = ['username', 'password', 'http_port', 'socks_port', 'serial', 'device', 'id', 'tgname']

            data, error_message, error_code = ts.validate_and_extract_data(required_fields)

            if error_message:
                logger.warning(f"Validation failed: {error_message}")
                return error_message, error_code

            user_data = {field: data[field] for field in required_fields}
            user_data['mode'] = 'modem'
            parent_ip = 'none'
            tgname = user_data['tgname']
            id = user_data['id']
            serial = user_data['serial']

            user_log_credentials = USER_LOG_CREDENTIALS.format(tgname=tgname, id=id)

            #check existing in redis
            if sm.serial_exists(user_data['serial']):
                logger.warning(f"Serial already exists: {user_data['serial']}")
                return {"message": f"Serial already exists: {user_data['serial']}"}, 400

            logger.debug(f"Redis check OK: {user_data['username']}")
            
            status_handler = nm.MODEM_HANDLERS.get(user_data['device'], {}).get('modem_status')
            logger.debug(f'LAMBDA_STATUS_HANDLER: {status_handler}')

            status = status_handler(user_data['serial']) if status_handler else None
            logger.debug(f'LAMBDA_STATUS: {status}')

            if status == "device_not_found":
                logger.error("Device not found, possibly it has lost connection")
                return {"message": "Device not found, possibly it has lost connection"}, 500
            elif status == "timeout":
                logger.error("Device timed out, possibly it has lost connection")
                return {"message": "Device timed out, possibly it has lost connection"}, 500

            if status == "rndis":
                interface_name = f"id{user_data['id']}"
                ip_address = nm.wait_for_ip(interface_name)
                if ip_address != '127.0.0.1':
                    logger.debug(f"Modem is already on, IP: {ip_address}")

            else:
                handler = nm.MODEM_HANDLERS.get(user_data['device'], {}).get('modem_on')
                logger.debug(f'HANDLER 1: {handler}, maybe wrong device model')
                handler(user_data['serial'])
                interface_name = f"id{user_data['id']}"
                ip_address = nm.wait_for_ip(interface_name)
                if ip_address != '127.0.0.1':
                    logger.info(f"Modem up success: {user_log_credentials}")
                else:
                    logger.error("Interface not ready, unable to get IP address")
                    return {"message": "Interface not ready, unable to get IP address"}, 500

            token = ts.generate_short_token()
            logger.info(f"Generated token: {token}")

            acl_result = cm.add_user_to_acl(user_data['username'], user_data['password'])
            config_result = cm.add_user_config(user_data['username'], user_data['mode'], user_data['http_port'], user_data['socks_port'], user_data['id'], user_data['tgname'])

            if not acl_result:
                logger.error(f"Failed to add user to ACL. Aborting operation.: {user_data['username']}")
                return {"message": "Failed to add user to ACL"}, 500
            else:
                logger.info(f"Added user to ACL: {user_data['username']}")

            if not config_result:
                logger.error(f"Failed to add config. Rolling back ACL.: {user_data['username']}.")
                cm.remove_user_from_acl(user_data['username'])
                return {"message": "Failed to add user config. Rolled back ACL"}, 500
            else:
                logger.info(f"Added user config: {user_data['username']}.")

            data_to_redis = ['tgname', 'username', 'id', 'serial', 'device', 'http_port', 'socks_port', 'mode']
            data_to_redis_storage = {field: user_data[field] for field in data_to_redis}
            redis_result = sm.store_to_redis(data_to_redis_storage, token)

            if not redis_result:
                logger.error(f"Failed to store user data to Redis for user {user_data['username']} id{user_data['id']}. Rolling back ACL and config.")
                cm.remove_user_from_acl(user_data['username'])
                cm.remove_user_config(user_data['username'], user_data['id'])
                return {"message": "Failed to store user data to Redis. Rolled back ACL and config"}, 500
            else:
                logger.info(f"Added data to redis: {user_data['username']}, id{user_data['id']}.")

                logger.info(f"User added: {user_data['username']}")
                return {
                    "message": f"User added successfully: {user_data['username']}",
                    "token": token
                }, 201
        
        except BadRequest:
            logger.error("Bad request, possibly malformed JSON.")
            return {"message": "Invalid JSON format received"}, 400

        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return {"message": f"Internal server error: {str(e)}"}, 500

class AddUserAndroid(Resource):
    @ts.requires_role("admin")
    def post(self, admin_token):
        try:
            logger.info("ADD USER ANDROID.")
            
            data = request.json
            if data is None:
                logger.warning("Invalid request: Missing JSON body")
                return {"message": "Invalid request: JSON body required"}, 400

            logger.info(f"Received data: {data}")

            required_fields = ['username', 'password', 'http_port', 'socks_port', 'serial', 'device', 'id', 'parent_ip', 'tgname']

            data, error_message, error_code = ts.validate_and_extract_data(required_fields)

            if error_message:
                logger.warning(f"Validation failed: {error_message}")
                return error_message, error_code

            user_data = {field: data[field] for field in required_fields}
            user_data['mode'] = 'android'
            
            #validating data
            # fields_to_validate = {
            #     'username': ts.is_valid_logopass,
            #     'password': ts.is_valid_logopass,
            #     'serial': ts.is_valid_serial,
            #     'device': ts.is_valid_device,
            #     'http_port': ts.is_valid_port,
            #     'socks_port': ts.is_valid_port,
            #     'id': ts.is_valid_id,
            #     'parent_ip': ts.is_valid_ip
            # }

            # for field, validation_func in fields_to_validate.items():
            #     error_message, error_code = ts.validate_field(field, user_data[field], validation_func)
            #     if error_message:
            #         return error_message, error_code

            if sm.serial_exists(user_data['serial']):
                logger.warning(f"Serial already exists: {user_data['serial']}")
                return {"message": f"Serial already exists: {user_data['serial']}"}, 400

            logger.debug(f"Redis check OK: {user_data['username']}")

            #checking modem
            status_handler = nm.MODEM_HANDLERS.get(user_data['device'], {}).get('modem_status')
            status = status_handler(user_data['serial']) if status_handler else None
            
            if status == "device_not_found":
                logger.error("Device not found, possibly it has lost connection")
                return {"message": "Device not found, possibly it has lost connection"}, 500
            elif status == "timeout":
                logger.error("Device timed out, possibly it has lost connection")
                return {"message": "Device timed out, possibly it has lost connection"}, 500

            if status == "rndis":
                handler = nm.MODEM_HANDLERS.get(user_data['device'], {}).get('modem_off')
                handler(user_data['serial'])
                logger.info("Modem turned off successfully")
            else:
                logger.warning("Modem is NOT turned off")

            token = ts.generate_short_token()
            logger.info(f"Generated token: {token}")

            acl_result = cm.add_user_to_acl(user_data['username'], user_data['password'])
            config_result = cm.add_user_config(user_data['username'], user_data['mode'], user_data['http_port'], user_data['socks_port'], user_data['id'], user_data['tgname'], user_data['parent_ip'])

            if not acl_result:
                logger.error(f"Failed to add user to ACL. Aborting operation.: {user_data['username']}")
                return {"message": "Failed to add user to ACL"}, 500
            else:
                logger.info(f"Added user to ACL: {user_data['username']}")

            if not config_result:
                logger.error(f"Failed to add config. Rolling back ACL.: {user_data['username']}.")
                cm.remove_user_from_acl(user_data['username'])
                return {"message": "Failed to add user config. Rolled back ACL"}, 500
            else:
                logger.info(f"Added user config: {user_data['username']}.")

            data_to_redis = ['serial', 'device', 'mode', 'id', 'username', 'parent_ip', 'tgname']
            data_to_redis_storage = {field: user_data[field] for field in data_to_redis}
            redis_result = sm.store_to_redis(data_to_redis_storage, token)

            if not redis_result:
                logger.error(f"Failed to store user data to Redis for user {user_data['username']} id{user_data['id']}. Rolling back ACL and config.")
                cm.remove_user_from_acl(user_data['username'])
                cm.remove_user_config(user_data['username'], user_data['id'])
                return {"message": "Failed to store user data to Redis. Rolled back ACL and config"}, 500
            else:
                logger.info(f"Added data to redis: {user_data['username']}, id{user_data['id']}.")

                logger.info(f"User added: {user_data['username']}")
                return {
                    "message": f"User added successfully: {user_data['username']}",
                    "token": token
                }, 201
        
        except BadRequest:
            logger.error("Bad request, possibly malformed JSON.")
            return {"message": "Invalid JSON format received"}, 400

        except Exception as e:
            logger.error(f"An error occurred: TOKEN: {token} ERROR: {str(e)}")
            return {f"Internal server error: {token}, {str(e)}"}, 500

class UpdateUser(Resource):
    @ts.requires_role("admin")
    def patch(self, admin_token):
        try:
            logger.debug("UPDATE LOGOPASS.")
            
            data = request.json
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400
            
            token = data.get('token')
            if not token:
                logger.warning(f"Invalid or missing device token: {token}.")
                return {"message": f"Invalid or missing device token: {token}"}, 400

            new_username = data.get('new_username')
            old_username = data.get('old_username')
            new_password = data.get('new_password')
            old_password = data.get('old_password')

            update_username = old_username is not None and new_username is not None
            update_password = old_password is not None and new_password is not None

            redis_data = sm.get_data_from_redis(token)
            if redis_data is None:
                return {'error': 'Proxy has expired or the token was not found'}, 404

            tgname = redis_data.get('tgname', '')
            proxy_id = redis_data.get('id', '')
            serial = redis_data.get('serial', '')
            username = redis_data.get('username', '')

            user_log_credentials = USER_LOG_CREDENTIALS.format(tgname=tgname, id=id)
            
            logger.info(f"UPDATE LOGOPASS: {user_log_credentials}")

            username = {new_username}

            if not (update_username or update_password):
                return {"message": "Invalid input. Either update username or password, not both or neither."}, 400

            if update_username:
                if not cm.username_exists_in_ACL(old_username):
                    logger.error(f"User {old_username} does not exist")
                    return {"message": f"User {old_username} does not exist"}, 404

                if not cm.update_user_in_acl(old_username, new_username, old_password, new_password, proxy_id) or \
                        not cm.update_user_in_config(old_username, new_username, proxy_id):
                    raise Exception("Failed to update username")

                if not sm.update_data_in_redis(token, {'username': new_username}):
                    raise Exception("Failed to update data in Redis")

                logger.debug(f"Username updated in ACL, CONFIG, REDIS: {old_username} --> {new_username}, {old_password} --> {new_password} ")
                return {"message": "Username updated successfully"}, 200

            if update_password:
                logger.debug(f"TO CHECK PASS: {old_password}")
                if not cm.password_exists_in_ACL(old_password):
                    logger.error(f"USER with password {old_password} does not exist")
                    return {"UpdateUser": "User with password does not exist"}, 404

                if not cm.update_user_in_acl(old_username, new_username, old_password, new_password, proxy_id) or \
                        not cm.update_user_in_config(old_username, new_username, proxy_id):
                    raise Exception("Failed to update password")
                
                user_log_credentials = USER_LOG_CREDENTIALS.format(tgname=tgname, id=id)
                logger.info(f"UPDATE LOGOPASS SUCCESS: {user_log_credentials}")
                return {"message": "Password updated successfully"}, 200


            # Backup current state
            current_users = cm.read_file(ACL_PATH)
            current_config = cm.read_file(CONFIG_PATH)

            if current_users is None or current_config is None:
                raise Exception("Failed to read ACL_PATH or CONFIG_PATH files")                

        except Exception as e:
            # ... (your rollback logic)
            logger.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class ReplaceAndroid(Resource):
    @ts.requires_role("admin")
    def patch(self, admin_token):
        pipe = sm.get_redis_pipeline()
        if not pipe:
            logger.error("Could not get Redis pipeline. Aborting operation.")
            return {"message": "Internal server error"}, 500

        try:
            logger.debug("REPLACE ANDROID")

            required_fields = ['token', 'new_id', 'new_serial', 'new_device', 'new_parent_ip']
            
            data, error_message, error_code = ts.validate_and_extract_data(required_fields)
        
            if error_message:
                logger.warning(f"Validation failed: {error_message}")
                return error_message, error_code

            token = data.get('token')
            new_id = data.get('new_id')
            new_serial = data.get('new_serial')
            new_device = data.get('new_device')
            new_parent_ip = data.get('new_parent_ip')

            logger.debug(f'DATA JSON: token {token}, new_id {new_id}, new_serial {new_serial}, new_device {new_device}, new_parent_ip {new_parent_ip}')

            redis_data = sm.get_data_from_redis(token)
            if not redis_data:
                logger.error(f"No data for token: {token}. Exiting.")
                return {"message": f"No data for token: {token}", "status_code": 404}

            username = redis_data.get('username', '')
            old_id = redis_data.get('id', '')
            old_serial = redis_data.get('serial', '')
            old_device = redis_data.get('device', '')
            old_parent_ip = redis_data.get('parent_ip', '')
            tgname = redis_data.get('tgname')
            
            logger.debug(f'DATA REDIS: username: {username}, id: {old_id}, serial: {old_serial}, device: {old_device}, parent_ip: {old_parent_ip}, tgname: {tgname}')

            # if not cm.android_ip_exists_in_config(old_parent_ip):
            #     logger.error(f"IP is NOT found: {old_parent_ip}")
            #     return {"message": f"IP is NOT found: {old_parent_ip}"}, 404

            if not cm.replace_android_in_config(old_parent_ip, new_parent_ip, old_id, new_id, username):
                logger.error(f"IP is NOT replaced: TOKEN {token}, TGNAME {tgname}, OLD IP {old_parent_ip}")
                return {"message": f"IP is NOT replaced: TOKEN {token}, TGNAME {tgname}, OLD IP {old_parent_ip}"}, 404

            logger.debug(f"IP in CONFIG is replaced: {old_parent_ip} --> {new_parent_ip}")

            pipe.hset(token, 'parent_ip', new_parent_ip)
            pipe.hset(token, 'device', new_device)
            pipe.hset(token, 'serial', new_serial)
            pipe.hset(token, 'id', new_id)

            if not sm.execute_pipeline(pipe):
                logger.error("Failed to execute Redis pipeline. Aborting operation.")
                return {"message": "Internal server error"}, 500

            logger.info(f"Android replaced: {tgname}, {old_parent_ip} --> {new_parent_ip}, id{old_id} --> id{new_id}, {old_serial} --> {new_serial}, {old_device} --> {new_device}")
            return {"message": f"Android replaced: tgname: {tgname}, id{old_id} --> id{new_id}"}, 200

        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return {"message": f"No data for token: {token}", "status_code": 404}

class ReplaceModem(Resource):
    @ts.requires_role("admin")
    def patch(self, admin_token):
        pipe = sm.get_redis_pipeline()
        if not pipe:
            logger.error("Could not get Redis pipeline. Aborting operation.")
            return {"message": "Internal server error"}, 500

        try:
            logger.debug("REPLACE MODEM")

            required_fields = ['token', 'new_id', 'new_serial', 'new_device']
            
            data, error_message, error_code = ts.validate_and_extract_data(required_fields)

            if error_message:
                logger.warning(f"Validation failed: {error_message}")
                return error_message, error_code

            token = data.get('token')
            new_id = data.get('new_id')
            new_serial = data.get('new_serial')
            new_device = data.get('new_device')

            redis_data = sm.get_data_from_redis(token)
            if not redis_data:
                logger.error(f"No data for token: {token}. Exiting.")
                return {"message": f"No data for token: {token}", "status_code": 404}

            username = redis_data.get('username', '')
            old_id = redis_data.get('id', '')
            old_serial = redis_data.get('serial', '')
            old_device = redis_data.get('device', '')
            tgname = redis_data.get('tgname', '')

            if not cm.modem_id_exists_in_config(old_id, username):
                logger.error(f"ID is NOT found: id{old_id}")
                return {"message": f"ID is NOT found: id{old_id}"}, 404

            if not cm.replace_modem_in_config(old_id, new_id, username):
                logger.error(f"ID is NOT replaced: {old_id}")
                return {"message": f"IP is NOT replaced: {old_id}"}, 404
            logger.debug(f"ID is replaced: id{old_id} --> id{new_id}")

            pipe.hset(token, 'id', new_id)
            pipe.hset(token, 'serial', new_serial)
            pipe.hset(token, 'device', new_device)

            if not sm.execute_pipeline(pipe):
                logger.error("Failed to execute Redis pipeline. Aborting operation.")
                return {"message": "Internal server error"}, 500

            logger.info(f"Modem replaced: id{old_id} --> id{new_id}, {old_serial} --> {new_serial}, {old_device} --> {new_device}")
            return {"message": f"Modem replaced: id{old_id} --> id{new_id}"}, 200

        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class ProxyCount(Resource):
    @ts.requires_role("admin")
    def get(self, admin_token):
        connection = None
        cursor = None

        try:
            logger.info("GET PROXY COUNT.")

            logger.info("Attempting to connect to MySQL...")
            connection = sm.connect_to_mysql()
            if connection is None:
                logger.error("Failed to connect to MySQL.")
                raise Exception("Failed to connect to MySQL")

            cursor = connection.cursor(dictionary=True)
            sql = """
            SELECT 
                provider,
                COUNT(*) AS count
            FROM 
                testbase.proxy
            WHERE 
                use_status = 0
            GROUP BY 
                provider;
            """
            cursor.execute(sql)
            results = cursor.fetchall()
            logger.info("Proxy count query executed successfully")
            return results, 200

        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

class ModemStatus(Resource):
    @ts.requires_role("admin")
    def post(self, admin_token):
        try:
            logger.debug("CHECK MODEM STATUS.")

            data = request.json
            logger.debug(f"Received data: {data}")  # Логирование данных запроса
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400
            
            token = data.get('token')

            user_data = sm.get_data_from_redis(token)
            if user_data is None:
                return {'error': 'Proxy has expired or the token was not found'}, 404

            logger.debug(f"User data from Redis: {user_data}")  # Логирование данных пользователя
            serial = user_data.get('serial')
            device_model = user_data.get('device')
            mode = user_data.get('mode')
            username = user_data.get('username')
            tgname = user_data.get('tgname')
            id = user_data.get('id')

            user_log_credentials = USER_LOG_CREDENTIALS.format(tgname=tgname, id=id)

            if not serial:
                logger.error("Serial number not found in user data.")
                return {'error': 'Serial number not found'}, 400

            handler = nm.MODEM_HANDLERS.get(device_model, {}).get('modem_status')
            if not handler:
                logger.error("Invalid device model provided. Use a correct 'device' field.")
                return {"message": "Invalid device model provided. Use a correct 'device' field."}, 400

            logger.debug(f"Handler for device model {device_model}: {handler}, Serial: {serial}")  # Подтверждение наличия serial
            status = handler(serial) if handler else None

            if status == "device_not_found":
                logger.error("Device not found, possibly it has lost connection")
                return {"message": "Device not found, possibly it has lost connection"}, 500
            elif status == "timeout":
                logger.error("Device timed out, possibly it has lost connection")
                return {"message": "Device timed out, possibly it has lost connection"}, 500

            logger.info(f"MODEM STATUS is {status}: {user_log_credentials}")
            return {"message": status}, 200

        except Exception as e:
            logger.exception("An error occurred")  # Детализированное логирование исключения
            return {"message": f"An error occurred: {str(e)}"}, 500

class ModemUp(Resource):
    @ts.requires_role("admin")
    def post(self, admin_token):
        try:
            logger.debug("SWITCH MODEM.")

            data = request.json
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400
            
            token = data.get('token')

            user_data = sm.get_data_from_redis(token)
            if user_data is None:
                return {'error': 'Proxy has expired or the token was not found'}, 404

            serial = user_data.get('serial')
            device_model = user_data.get('device')
            mode = user_data.get('mode')
            id = user_data.get('id')
            interface_name = f'id{id}'
            tgname = user_data.get('tgname')

            user_log_credentials = USER_LOG_CREDENTIALS.format(tgname=tgname, id=id)

            logger.debug(f"MODEM UP: {user_log_credentials}: {mode}")

            if not all([serial, device_model, mode]):
                return {"message": "Missing required fields"}, 400
            
            busy_status = sm.is_device_busy(serial, BUSY_RDB)
            if busy_status is None:
                logger.error(f"Error cheking BUSY status: {serial}, {user_log_credentials}")

            if busy_status:
                logger.info(f"Device is BUSY: {user_log_credentials}")
                return {'message': 'Device is busy, please try again later'}, 202  # HTTP 202 Accepted

            status_handler = nm.MODEM_HANDLERS.get(device_model, {}).get('modem_status')
            status = status_handler(serial) if status_handler else None

            if status == "device_not_found":
                logger.error("Device not found, possibly it has lost connection")
                return {"message": "Device not found, possibly it has lost connection"}, 500
            elif status == "timeout":
                logger.error("Device timed out, possibly it has lost connection")
                return {"message": "Device timed out, possibly it has lost connection"}, 500

            if mode == "modem":
                if status == "rndis":
                    ip_address = nm.wait_for_ip(interface_name)
                    if ip_address != '127.0.0.1':
                        logger.info(f"MODEM IS ALREADY ON: {user_log_credentials}")
                        return {"message": "Modem is already on", "ip_address": ip_address}, 200
                    logger.error("Interface not ready, unable to get IP address")
                    return {"message": "Interface not ready, unable to get IP address"}, 500
                else:
                    handler = nm.MODEM_HANDLERS.get(device_model, {}).get('modem_on')
                    handler(serial)
                    ip_address = nm.wait_for_ip(interface_name)
                    if ip_address != '127.0.0.1':
                        logger.info(F"MODEM ON SUCCEES: {user_log_credentials}")
                        return {"message": "Modem turned on successfully", "ip_address": ip_address}, 200
                    logger.error("Interface not ready, unable to get IP address")
                    return {"message": "Interface not ready, unable to get IP address"}, 500

            elif mode == "android":
                if status == "rndis":
                    handler = nm.MODEM_HANDLERS.get(device_model, {}).get('modem_off')
                    handler(serial)
                    logger.info(F"MODEM OFF SUCCEES: {user_log_credentials}")
                    return {"message": "Modem turned off successfully"}, 200
                else:
                    logger.info(f"MODEM IS ALREADY ON: {user_log_credentials}")
                    return {"message": "Modem is already turned off"}, 200
            else:
                logger.error("Invalid mode provided. Use either 'modem' or 'parent' as mode field.")
                return {"message": "Invalid mode provided. Use either 'modem' or 'parent' as mode field."}, 400

        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class AirplaneStatus(Resource):
    @ts.requires_role("admin")
    def post(self, admin_token):
        try:
            logger.debug("CHECK AIRPLANE STATUS.")

            data = request.json
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400
            
            token = data.get('token')

            user_data = sm.get_data_from_redis(token)
            if user_data is None:
                return {'error': 'Proxy has expired or the token was not found'}, 404

            serial_number = user_data.get('serial')
            device_model = user_data.get('device')
            mode = user_data.get('mode')
            id = user_data.get('id')
            tgname = user_data.get('tgname')

            user_log_credentials = USER_LOG_CREDENTIALS.format(tgname=tgname, id=id)

            if not serial_number:
                logger.error(f"Serial number not found, id{id}")
                return {'error': 'Serial number not found'}, 400

            status = nm.check_airplane(serial_number)

            if status == 1:
                logger.info(f"AIRPLANE is ON: {user_log_credentials}")
                return {"message": "Airplane is ON"}, 200
            elif status == 0:
                logger.info(f"AIRPLANE is OFF: {user_log_credentials}")
                return {"message": "Airplane is OFF"}, 200
            else:
                logger.error(f'id{id}: Error or unknown status')
                return {'error': 'Error or unknown status'}, 500

        except Exception as e:
            logger.error(f"id{id}: An error occurred: {str(e)}")
            return {"error": f"An error occurred: {str(e)}"}, 500

class AirplaneOn(Resource):
    @ts.requires_role("admin")
    def post(self, admin_token):
        try:
            data = request.json
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400
            
            token = data.get('token')

            user_data = sm.get_data_from_redis(token)
            if user_data is None:
                return {'error': 'Proxy has expired or the token was not found'}, 404

            serial = user_data.get('serial')
            device = user_data.get('device')
            id = user_data.get('id')
            tgname = user_data.get('tgname')

            user_log_credentials = USER_LOG_CREDENTIALS.format(tgname=tgname, id=id)

            logger.debug(f"AIRPLANE ON: {user_log_credentials}")

            if not serial:
                logger.error(f"Serial NOT found in redis: id{id}({serial}), {device}")
                return {'error': 'Serial not found'}, 400
            
            busy_status = sm.is_device_busy(serial, BUSY_RDB)
            if busy_status is None:
                logger.error(f"Error cheking BUSY status: {serial}, {user_log_credentials}")

            if busy_status:
                logger.info(f"Device is BUSY: {user_log_credentials}")
                return {'message': 'Device is busy, please try again later'}, 202  # HTTP 202 Accepted

            # Check if device has ROOT
            if device not in ROOT:
                logger.debug(f"Airplane ON via TOUCH: id{id}({serial}), {device}")
                if 'enable_airplane_mode' in nm.MODEM_HANDLERS[device]:
                    airplane_on_result = nm.MODEM_HANDLERS[device]['enable_airplane_mode'](serial)
                else:
                    logger.error(f"No 'enable_airplane_mode': id{id}({serial}), {device}")
                    return {'error': 'Operation not supported for this device'}, 400
            else:
                logger.debug(f"Airplane ON via CMD: id{id}({serial}), {device}")
                airplane_on_result = nm.MODEM_HANDLERS[device]['enable_airplane_mode'](serial)
                # airplane_toggle_cmd_su(serial, device)
            
            if airplane_on_result:
                logger.info(f"AIRPLANE ON DONE: {user_log_credentials}")
                return {'status': 'success', 'message': 'Airplane switched ON'}, 200
            else:
                logger.error(f"Failed to turn ON airplane: id{id}({serial}), {device}")
                return {'status': 'failure', 'message': 'Failed to turn ON airplane'}, 400

        except Exception as e:
            logger.error(f"An error occurred: {e}")
            return {'status': 'failure', 'message': 'An error occurred while turn ON airplane'}, 500

class AirplaneOff(Resource):
    @ts.requires_role("admin")
    def post(self, admin_token):
        try:
            data = request.json
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400
            
            token = data.get('token')

            user_data = sm.get_data_from_redis(token)
            if user_data is None:
                return {'error': 'Proxy has expired or the token was not found'}, 404
                
            serial = user_data.get('serial')
            device = user_data.get('device')
            id = user_data.get('id')
            tgname = user_data.get('tgname')

            user_log_credentials = USER_LOG_CREDENTIALS.format(tgname=tgname, id=id)

            logger.debug(f"AIRPLANE OFF: id{id}({serial}), {device}")

            if not serial:
                logger.error(f"Serial NOT found in redis: id{id}({serial}), {device}")
                return {'error': 'Serial not found'}, 400

            busy_status = sm.is_device_busy(serial, BUSY_RDB)
            if busy_status is None:
                logger.error(f"Error cheking BUSY status: {serial}, {user_log_credentials}")

            if busy_status:
                logger.info(f"Device is BUSY: {user_log_credentials}")
                return {'message': 'Device is busy, please try again later'}, 202  # HTTP 202 Accepted

            # Check if device has ROOT
            if device not in ROOT:
                logger.debug(f"Airplane OFF via TOUCH: id{id}({serial}), {device}")
                if 'disable_airplane_mode' in nm.MODEM_HANDLERS[device]:
                    airplane_off_result = nm.MODEM_HANDLERS[device]['disable_airplane_mode'](serial)
                else:
                    logger.error(f"No 'disable_airplane_mode': id{id}({serial}), {device}")
                    return {'error': 'Operation not supported for this device'}, 400
            else:
                logger.debug(f"Airplane OFF via CMD: id{id}({serial}), {device}")
                airplane_off_result = nm.MODEM_HANDLERS[device]['disable_airplane_mode'](serial)
                # airplane_toggle_cmd_su(serial, device)
            
            if airplane_off_result:
                logger.info(f"AIRPLANE OFF: {user_log_credentials}")
                return {'status': 'success', 'message': 'Airplane switched OFF'}, 200
            else:
                logger.error(f"Failed to turn OFF airplane: id{id}({serial}), {device}")
                return {'status': 'failure', 'message': 'Failed to turn OFF airplane'}, 400

        except Exception as e:
            logger.error(f"An error occurred: {e}")
            return {'status': 'failure', 'message': 'An error occurred while turn OFF airplane'}, 500

class WGstatus(Resource):
    @ts.requires_role("admin")
    def post(self, admin_token):
        try:
            logger.debug("CHECK WG STATUS.")

            data = request.json
            logger.debug(f"Received data: {data}")
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400

            token = data.get('token')

            user_data = sm.get_data_from_redis(token)
            if user_data is None:
                return {'error': 'Proxy has expired or the token was not found'}, 404

            logger.debug(f"User data from Redis: {user_data}")
            serial = user_data.get('serial')
            device_model = user_data.get('device')
            mode = user_data.get('mode')
            username = user_data.get('username')
            tgname = user_data.get('tgname')
            id = user_data.get('id')

            user_log_credentials = USER_LOG_CREDENTIALS.format(tgname=tgname, id=id)

            if not serial:
                logger.error("Serial number not found in user data.")
                return {'error': 'Serial number not found'}, 400

            try:
                # checking switcher status in the app
                nm.get_wg_ip_result = nm.get_wg_ip(serial, id)
                logger.debug(f"nm.get_wg_ip result: {nm.get_wg_ip_result}")

                if isinstance(nm.get_wg_ip_result, bool):
                    if nm.get_wg_ip_result:
                        nm.wg_switcher_status = 'ON'
                    else:
                        nm.wg_switcher_status = 'OFF'
                        wg_connection_status = 'disconnected'
                        logger.info(f"WG STATUS: {nm.wg_switcher_status}, {wg_connection_status}: {user_log_credentials}")
                        return {"switcher": nm.wg_switcher_status, "status": wg_connection_status}, 200

                else:
                    nm.wg_switcher_status = 'unknown'
                    wg_connection_status = nm.get_wg_ip_result
                    return {"switcher": nm.wg_switcher_status, "status": nm.get_wg_ip_result}, 500
            
            except Exception as e:
                logger.error(f"IP checking error: {e}")
                return {"message": str(e)}, 500
            

            # Checking WireGuard via ping
            try:
                ping_result = ping(serial, id)
                logger.debug(f"Ping result: {ping_result}")
                
                if ping_result:
                    wg_connection_status = 'connected'
                elif not ping_result:
                    wg_connection_status = 'disconnected'
                else:
                    wg_connection_status = ping_result

            except Exception as e:
                logger.error(f"Ping checking error: {e}")
                return {"message": str(e)}, 500

            logger.info(f"WG STATUS: {nm.wg_switcher_status}, {wg_connection_status}: {user_log_credentials}")
            return {"switcher": nm.wg_switcher_status, "status": wg_connection_status}, 200

        except Exception as e:
            logger.exception("An error occurred")
            return {"message": f"An error occurred: {str(e)}"}, 500

class WGswitcher(Resource):
    @ts.requires_role("admin")
    def post(self, admin_token):
        try:
            data = request.json
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400
            
            token = data.get('token')

            user_data = sm.get_data_from_redis(token)
            if user_data is None:
                return {'error': 'Proxy has expired or the token was not found'}, 404

            serial = user_data.get('serial')
            device = user_data.get('device')
            id = user_data.get('id')
            tgname = user_data.get('tgname')

            user_log_credentials = USER_LOG_CREDENTIALS.format(tgname=tgname, id=id)

            if not serial:
                logger.error(f"Serial NOT found in redis: id{id}({serial}), {device}")
                return {'error': 'Serial not found'}, 400

            busy_status = sm.is_device_busy(serial, BUSY_RDB)
            if busy_status is None:
                logger.error(f"Error cheking BUSY status: {serial}, {user_log_credentials}")

            if busy_status:
                logger.info(f"Device is BUSY: {user_log_credentials}")
                return {'message': 'Device is busy, please try again later'}, 202  # HTTP 202 Accepted
                    
            logger.debug(f"WG SWITCHING: {user_log_credentials}, {device}")
                
            if device not in nm.MODEM_HANDLERS or 'nm.wg_switcher' not in nm.MODEM_HANDLERS[device]:
                logger.error(f"No WG switcher handler for device: {device}")
                return {'error': 'WG switcher handler not found for device'}, 400

            nm.wg_switcher_result = nm.MODEM_HANDLERS[device]['nm.wg_switcher'](serial)

            if isinstance(nm.wg_switcher_result, bool) and nm.wg_switcher_result:
                logger.info(f"WG SWITCHING SUCCESS: {user_log_credentials}")
                return {'status': 'success'}, 200
            else:
                return {'status': 'error', 'message': nm.wg_switcher_result}, 500

        except Exception as e:
            logger.error(f"An error occurred: {e}")
            return {'status': 'failure', 'message': str(e)}, 500

class UpdateIP(Resource):
    @ts.requires_role("admin")
    def patch(self, admin_token):

        try:
            logger.info("GRASS UPDATE IP")

            data = request.get_json()
            new_ip = data.get('new_ip')
            old_ip = data.get('old_ip')

            if not new_ip or not old_ip:
                logger.error("New IP or Old IP is missing.")
                return {"message": "New IP or Old IP is missing."}, 400
            
            update_result = cm.update_ip(old_ip, new_ip)
            
            if not update_result:
                logger.error("Failed to update IP address.")
                return {"message": "Failed to update IP address."}, 500

            logger.info(f"IP updated: {old_ip} --> {new_ip}")
            return {"message": f"IP updated: {old_ip} --> {new_ip}"}, 200

        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

#resources
api.add_resource(Reboot, '/api/reboot/<string:token>') #user role
api.add_resource(DeviceStatus, '/api/device_status/<string:token>') #user role
api.add_resource(ChangeIP, '/api/changeip/<string:token>') #user role
api.add_resource(AutoChangeIP, '/api/changeip_auto/<string:token>') #user role
api.add_resource(AddUserModem, '/api/add_user_modem/<string:token>') #admin role
api.add_resource(AddUserAndroid, '/api/add_user_android/<string:token>') #admin role
api.add_resource(DeleteUser, '/api/delete_user/<string:token>') #admin role
api.add_resource(UpdateAuth, '/api/update_auth/<string:token>') #admin role
api.add_resource(UpdateMode, '/api/update_mode/<string:token>') #admin role

api.add_resource(UpdateUser, '/api/update_user/<string:token>') #admin role
api.add_resource(ReplaceAndroid, '/api/replace_android/<string:token>') #admin role
api.add_resource(ReplaceModem, '/api/replace_modem/<string:token>')
api.add_resource(ModemUp, '/api/modemup/<string:token>') #admin role
api.add_resource(ModemStatus, '/api/modemstatus/<string:token>') #admin role
api.add_resource(ProxyCount, '/api/proxycount/<string:token>') #admin role
api.add_resource(AirplaneStatus, '/api/airplanestatus/<string:token>') #admin role
api.add_resource(AirplaneOn, '/api/airplane_on/<string:token>') #admin role
api.add_resource(AirplaneOff, '/api/airplane_off/<string:token>') #admin role
api.add_resource(WGstatus, '/api/wg_status/<string:token>') #admin role
api.add_resource(WGswitcher, '/api/nm.wg_switcher/<string:token>') #admin role
api.add_resource(UpdateIP, '/api/updateip/<string:token>') #admin role

if __name__ == '__main__':
    app.run(debug=False)