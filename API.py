from flask import Flask, request, jsonify
from flask_restful import Resource, Api, reqparse
from werkzeug.exceptions import BadRequest
import time
import os
#import pexpect
#import subprocess
#from subprocess import Popen, PIPE, TimeoutExpired, run
#import datetime
#from threading import Lock
#import textwrap
import logging
from ipaddress import ip_address, AddressValueError
from dotenv import load_dotenv

from device_management import adb_reboot_device, get_adb_device_status, os_boot_status
from network_management import airplane_toggle_cmd, MODEM_HANDLERS, wait_for_ip, enable_modem
from settings import TETHERING_COORDINATES, ALLOWED_PROTOCOLS
from tools import schedule_job, generate_short_token, requires_role, is_valid_port, scheduler, validate_and_extract_data
import storage_management as sm
import conf_management as cm

load_dotenv()

#config_lock = Lock()

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

parser = reqparse.RequestParser()
parser.add_argument('interval_minutes')

app = Flask(__name__)
api = Api(app)

ACL_PATH = os.getenv('ACL_PATH')
CONFIG_PATH = os.getenv('CONFIG_PATH')

class Reboot(Resource):
    #@requires_role("user")
    def get(self, token):
        try:
            user_data = sm.get_data_from_redis(token)
            serial = user_data.get('serial')
            device = user_data.get('device')
            mode = user_data.get('mode')
            device_id = user_data.get('id')  # Getting from Redis

            if not serial:
                logging.error(f"Serial: {serial} NOT found in redis.")
                return {'error': 'Serial number not found'}, 400

            reboot_status = os_boot_status(serial, device, device_id, enable_modem=False)

            if reboot_status != 'OK':
                logging.warning(f"Device id: {device_id}, serial: {serial} is rebooting.")
                return {'reboot': 'in progress', 'message': 'Device is still rebooting.'}, 409

            if mode == "android":
                adb_reboot_device(serial, device_id)
                return {'reboot': 'OK', 'message': 'Reboot is started.'}, 202

            if mode == "modem":
                adb_reboot_device(serial, device_id)
                schedule_job(serial, device, device_id)
                return {'reboot': 'OK', 'message': 'Reboot is started.'}, 202

            logging.error(f"Unknown mode provided for device id: {device_id}, serial: {serial}.")
            return {'error': 'Unknown mode provided'}, 400

        except Exception as e:
            logging.error(f"Reboot_res: An error occurred: {str(e)}")
            return {'error': 'Internal server error'}, 500

class DeviceStatus(Resource):
    #@requires_role("user")
    def get(self, token, serial=None):
        try:
            serial = request.args.get('serial')  # Get serial from query params

            if serial:
                # For admin: serial directly provided
                logging.info(f"Admin checking status: serial: {serial}")
                device_id = None
                device = None
            else:
                user_data = sm.get_data_from_redis(token)
                serial = user_data.get('serial')
                device = user_data.get('device')
                device_id = user_data.get('id')
                logging.info(f"User checking status: id{device_id}, serial: {serial}")

            if not serial:
                logging.error(f"Serial not found in user data: {serial}.")
                return {'error': 'Serial not found'}, 400

            device_status = get_adb_device_status(serial, device_id)

            if device_status == "device":
                for i in range(3):
                    status = os_boot_status(serial, device, device_id, enable_modem=False)
                    if status == 'OK':
                        #logging.info(f"Device {serial} is READY!")
                        return {'status': 'OK', 'message': 'Device is ready.'}, 200
                    else:
                        logging.warning(f"Device is not ready yet: {status}. Retry {i+1}/3")
                        time.sleep(2)
                return {'status': 'in progress', 'message': 'Device not ready.'}, 200

            else:
                logging.warning(f"Device is not in a good state: {device_status}")
                return {'status': 'seems disconnected', 'message': f'Device is {device_status}'}, 400
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            return {"error": str(e)}, 500

class ChangeIP(Resource):
    def get(self, token):
        try:
            user_data = sm.get_data_from_redis(token)
            serial = user_data.get('serial')
            logging.info(f"Received request: change IP, serial: {serial}")

            if not serial:
                logging.error("Serial not found in user data.")
                return {'error': 'Serial not found'}, 400
            
            airplane_toggle_cmd(serial)
            return {'status': 'success', 'message': 'IP was changed'}, 200

        except Exception as e:
            logging.error("An error occurred")
            return {'status': 'failure', 'message': 'An error occurred while changing IP'}, 500

class AutoChangeIP(Resource):
    def post(self, token):
        try:
            user_data = sm.get_data_from_redis(token)
            serial = user_data.get('serial')
            device_id = user_data.get('id')
            
            if not serial:
                logging.error("Serial number not found in user data.")
                return {'error': 'Serial number not found'}, 400

            args = parser.parse_args()
            interval_minutes = args['interval_minutes']

            job_id = f"changeip_{serial}"

            # Cancel the scheduled job
            if interval_minutes == '0':
                try:
                    scheduler.remove_job(job_id)
                    logging.info(f"Cancelled scheduled IP changes: id{device_id}, serial {serial}, token: {token}")
                    return {'status': 'success', 'message': f'Cancelled scheduled IP changes for device: {token}'}, 200
                except Exception as e:
                    logging.error(f"Error occurred while cancelling scheduled job: {str(e)}")
                    return {'status': 'failure', 'message': "Message to support"}, 500

            # Schedule a new job
            else:
                interval_minutes = int(interval_minutes)  # Convert to int
                try:
                    scheduler.add_job(
                        func=airplane_toggle_cmd, 
                        trigger='interval', 
                        minutes=interval_minutes, 
                        args=[serial], 
                        id=job_id,
                        name=job_id,
                        replace_existing=True
                    )
                    logging.info(f'Auto changing IP every {interval_minutes} minutes.')
                    return {'status': 'success', 'message': f'Auto changing IP every {interval_minutes} minutes'}, 200
                except Exception as e:
                    logging.error(f"Error occurred while scheduling new job: {str(e)}")
                    return {'status': 'failure', 'message': str(e)}, 500

        except Exception as e:
            logging.error(f"Error occurred in AutoChangeIP: {str(e)}")
            return {'status': 'failure', 'message': str(e)}, 500

class DeleteUser(Resource):
    @requires_role("admin")
    def delete(self, admin_token):
        try:
            logging.info("Received request: DELETE USER.")

            data = request.json
            logging.info(f"Got data: {data}")
            if data is None:
                logging.error("Invalid request: JSON body required.")
                return {"message": "Invalid request: JSON body required"}, 400

            # Get proxy_id and device_token from JSON body
            proxy_id = data.get('id') # to remove using proxy_id in config
            device_token = data.get('device_token') # to remove key using token in redis
            username = data.get ('username')

            if not proxy_id or not device_token or not username:
                logging.error("Missing required fields: proxy_id and/or token/or username.")
                return {"message": "Missing required fields: proxy_id and/or token/or username"}, 400

            # Check if the user exists
            if not cm.username_exists_in_ACL(username):
                logging.error("User does not exist.")
                return {"message": "User does not exist"}, 404

            # Check token and username in Redis
            user_data = sm.get_data_from_redis(device_token)
            if not user_data or user_data.get('id') != proxy_id:
                logging.error("Invalid proxy_id or token.")
                return {"message": "Invalid proxy_id or token"}, 400

            #logging.info(f"Reading config")
            lines = cm.read_file(CONFIG_PATH)
            
            #logging.info(f"Counting username")
            count_users = cm.user_count_in_ACL(username, proxy_id, lines)
            #logging.info(f"Count username: {count_users}")

            if count_users == 1:
                logging.info(f"User has only 1 proxy, removing ACL: {username}, id{proxy_id}")
            elif count_users > 1:
                logging.warning(f"User has {count_users} proxy, SKIP removing ACL: {username}, id{proxy_id}")

            # Remove from configuration
            if not cm.remove_user_config(username, proxy_id):
                logging.error(f"Failed to remove user's config: {username}, id{proxy_id}")
                return ({f"message": f"Failed to remove user's config: {username}, id{proxy_id}"}, 500)

            # Remove from ACL
            if count_users == 1:
                if not cm.remove_user_from_acl(username):
                    logging.error(f"Failed to remove user from ACL: {username}")
                    return ({f"message": f"Failed to remove user from ACL: {username}"}, 500)

                #logging.info(f"User removed from ACL: {username}")
            elif count_users > 1:
                logging.info(f"User has {count_users} proxy, SKIP removing ACL: {username}")
            
            # Remove from Redis
            result = sm.delete_from_redis(device_token)
            if not result:
                logging.error(f"Token not found in Redis or failed to remove: {device_token}")
                return ({f"message": f"Token not found in Redis or failed to remove: {device_token}"}, 404)

            logging.info(f"User deleted: {username}")
            return ({f"message": f"User deleted: {username}"}, 200)

        except BadRequest:
            logging.error("Bad request, possibly malformed JSON.")
            return {"message": "Invalid JSON format received"}, 400

        except Exception as e:
            logging.exception(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class UpdateAuth(Resource):
    @requires_role("admin")
    def patch(self, admin_token):
        try:
            logging.info("Received request: UPDATE AUTH.")

            data = request.json
            if data is None:
                logging.error("Invalid request: JSON body required.")
                return {"message": "Invalid request: JSON body required"}, 400
            
            proxy_id = data.get('id')
            if not proxy_id:
                logging.error("Missing required field: id.")
                return {"message": "Missing required field: id"}, 400

            username = data.get('username')
            if not username:
                logging.error("Missing required field: username.")
                return {"message": "Missing required field: username"}, 400

            protocol = data.get('protocol')  # Should be either 'http', 'socks', or 'both'
            if not protocol:
                logging.error("Missing required field: protocol.")
                return {"message": "Missing required field: protocol"}, 400

            auth_type = data.get('auth_type')
            if not auth_type:
                logging.error("Missing required field: auth_type.")
                return {"message": "Missing required field: auth_type"}, 400

            allow_ip = data.get('allow_ip')
            if not allow_ip:
                logging.error("Missing required field: allow_ip.")
                return {"message": "Missing required field: allow_ip"}, 400

            logging.info(f"Received DATA: id{proxy_id}, Username: {username}, Protocol: {protocol}, New Auth Type: {auth_type}, Allow ip: {allow_ip}")

            if protocol not in ALLOWED_PROTOCOLS:
                logging.error("Invalid protocol provided.")
                return {"message": "Invalid protocol provided"}, 400

            if auth_type == "strong":
                allow_ip = username
            elif auth_type == "iponly":
                if 'allow_ip' not in data:
                    logging.error("allow_ip required for iponly auth_type.")
                    return {"message": "allow_ip required for iponly auth_type"}, 400
                allow_ip = data['allow_ip']
            else:
                logging.error("Invalid auth_type provided.")
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
                logging.info(" | ".join(messages))
                if 'both' == protocol:
                    return {"message": " | ".join(messages)}, 200 if all([result1, result2]) else 400
                else:
                    return {"message": " | ".join(messages)}, 200 if result else 400

        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class UpdateMode(Resource):
    @requires_role("admin")
    def post(self, admin_token):
        try:
            logging.info("Received request: UPDATE MODE.")

            data = request.json
            if data is None:
                logging.warning("Invalid request: Missing JSON body")
                return {"message": "Invalid request: JSON body required"}, 400

            required_fields = ['device_token', 'new_mode', 'parent_ip', 'http_port', 'socks_port']
            if not all(data.get(field) for field in required_fields):
                logging.warning("Missing required fields in data")
                return {"message": "Missing required fields"}, 400

            device_token = data.get('device_token')
            new_mode = data.get('new_mode')
            parent_ip = data.get('parent_ip')
            http_port = int(data.get('http_port'))
            socks_port = int(data.get('socks_port'))

            if new_mode not in ['android', 'modem']:
                logging.warning("Invalid mode. Use either 'android' or 'modem'")
                return {"message": "Invalid mode. Use either 'android' or 'modem'"}, 400

            # Проверка корректности parent_ip
            if new_mode == 'android':
                try:
                    ip_address(parent_ip)
                except AddressValueError:
                    logging.warning("Invalid parent IP address")
                    return {"message": "Invalid parent IP address. Should be a valid IPv4 or IPv6 address."}, 400

            logging.debug(f"Got: device_token: {device_token}, new_mode: {new_mode}, parent_ip: {parent_ip}, http_port: {http_port}, socks_port: {socks_port}")

            if not (10000 <= http_port <= 65000 and 10000 <= socks_port <= 65000):
                logging.warning("Port numbers out of allowed range")
                return {"message": "Port numbers should be between 10000 and 65000"}, 400

            response = cm.update_mode_in_config(new_mode, parent_ip, device_token, http_port, socks_port)
            
            logging.info("Successfully updated mode.")
            return {"message": response["message"]}, response["status_code"]
            
        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            return {"message": f"Internal server error: {str(e)}"}, 500

class AddUser(Resource):
    @requires_role("admin")
    def post(self, admin_token):
        try:
            logging.info("Received request: ADD USER.")
            
            data = request.json
            if data is None:
                logging.warning("Invalid request: Missing JSON body")
                return {"message": "Invalid request: JSON body required"}, 400

            logging.info(f"Received data: {data}")

            all_fields = ['username', 'password', 'mode', 'http_port', 'socks_port', 'serial', 'device', 'id', 'parent_ip']

            if not all(data.get(field) for field in all_fields):
                logging.warning("Missing required fields in data")
                return {"message": "Missing required fields"}, 400

            user_data = {field: data[field] for field in all_fields}
            
            if not is_valid_port(user_data['http_port']) or not is_valid_port(user_data['socks_port']):
                logging.warning("Invalid port numbers")
                return {"message": "Port numbers should be between 10000 and 65000"}, 400

            if sm.serial_exists(user_data['serial']):
                logging.warning(f"Serial already exists: {user_data['serial']}")
                return {"message": f"Serial already exists: {user_data['serial']}"}, 400

            logging.info(f"Redis check OK: {user_data['username']}")

            if user_data.get('id') and not user_data['id'].isdigit():
                return {"message": "Invalid ID format"}, 400
            
            status_handler = MODEM_HANDLERS.get(user_data['device'], {}).get('status')
            status = status_handler(user_data['serial']) if status_handler else None

            if status == "device_not_found":
                logging.error("Device not found, possibly it has lost connection")
                return {"message": "Device not found, possibly it has lost connection"}, 500
            elif status == "timeout":
                logging.error("Device timed out, possibly it has lost connection")
                return {"message": "Device timed out, possibly it has lost connection"}, 500

            if user_data['mode'] == 'modem':
                #toggle_wifi(user_data['serial'], "off")

                if id is None:
                    logging.warning("ID is required for modem mode")
                    return {"message": "ID is required for modem mode"}, 400

                if status == "rndis":
                    interface_name = f"id{user_data['id']}"
                    ip_address = wait_for_ip(interface_name)
                    if ip_address != '127.0.0.1':
                        logging.info(f"Modem is already on, IP: {ip_address}")

                else:
                    handler = MODEM_HANDLERS.get(user_data['device'], {}).get('on')
                    handler(user_data['serial'])
                    interface_name = f"id{user_data['id']}"
                    ip_address = wait_for_ip(interface_name)
                    if ip_address != '127.0.0.1':
                        logging.info("Modem turned on successfully")
                    else:
                        logging.error("Interface not ready, unable to get IP address")
                        return {"message": "Interface not ready, unable to get IP address"}, 500

            if user_data['mode'] == "android":
                #toggle_wifi(user_data['serial'], "off")
                
                if user_data['parent_ip'] == "none":
                    logging.warning("In android mode, parent_ip cannot be none")
                    return {"message": "In android mode, parent_ip is required"}, 400
                if status == "rndis":
                    handler = MODEM_HANDLERS.get(user_data['device'], {}).get('on')
                    handler(user_data['serial'])
                    logging.info("Modem turned off successfully")
                else:
                    logging.info("Modem is already turned off")

            token = generate_short_token()
            logging.info(f"Generated token: {token}")

            acl_result = cm.add_user_to_acl(user_data['username'], user_data['password'])
            config_result = cm.add_user_config(user_data['username'], user_data['mode'], user_data['parent_ip'], user_data['http_port'], user_data['socks_port'], user_data['id'])

            if not acl_result:
                logging.error(f"Failed to add user to ACL. Aborting operation.: {user_data['username']}")
                return {"message": "Failed to add user to ACL"}, 500
            else:
                logging.info(f"Added user to ACL: {user_data['username']}")

            if not config_result:
                logging.error(f"Failed to add config. Rolling back ACL.: {user_data['username']}.")
                cm.remove_user_from_acl(user_data['username'])
                return {"message": "Failed to add user config. Rolled back ACL"}, 500
            else:
                logging.info(f"Added user config: {user_data['username']}.")

            data_to_redis = ['serial', 'device', 'mode', 'id', 'username', 'parent_ip']
            data_to_redis_storage = {field: user_data[field] for field in data_to_redis}
            redis_result = sm.store_to_redis(data_to_redis_storage, token)

            if not redis_result:
                logging.error(f"Failed to store user data to Redis for user {user_data['username']} id{user_data['id']}. Rolling back ACL and config.")
                cm.remove_user_from_acl(user_data['username'])
                cm.remove_user_config(user_data['username'], user_data['id'])
                return {"message": "Failed to store user data to Redis. Rolled back ACL and config"}, 500
            else:
                logging.info(f"Added data to redis: {user_data['username']}, id{user_data['id']}.")

                logging.info(f"User added: {user_data['username']}")
                return {"message": f"User added: {user_data['username']}, token: {token}"}, 201
        
        except BadRequest:
            logging.error("Bad request, possibly malformed JSON.")
            return {"message": "Invalid JSON format received"}, 400

        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            return {"message": f"Internal server error: {str(e)}"}, 500

class UpdateUser(Resource):
    @requires_role("admin")
    def patch(self, admin_token):
        try:
            logging.info("Received request: UPDATE LOGOPASS.")
            
            data = request.json
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400
            
            device_token = data.get('device_token')
            if not device_token or not sm.get_data_from_redis(device_token):
                logging.warning(f"Invalid or missing device token: {device_token}.")
                return {"message": f"Invalid or missing device token: {device_token}"}, 400

            proxy_id = data.get('id')
            new_username = data.get('new_username')
            old_username = data.get('old_username')
            new_password = data.get('new_password')
            old_password = data.get('old_password')

            update_username = old_username is not None and new_username is not None
            update_password = old_password is not None and new_password is not None

            redis_data = sm.get_data_from_redis(device_token)
            username = redis_data.get('username', '')

            if not (update_username or update_password):
                return {"message": "Invalid input. Either update username or password, not both or neither."}, 400

            if update_username:
                if not cm.username_exists_in_ACL(old_username):
                    logging.error(f"User {old_username} does not exist")
                    return {"message": f"User {old_username} does not exist"}, 404

                if not cm.update_user_in_acl(old_username, new_username, old_password, new_password, proxy_id) or \
                        not cm.update_user_in_config(old_username, new_username, proxy_id):
                    raise Exception("Failed to update username")

                if not sm.update_data_in_redis(device_token, {'username': new_username}):
                    raise Exception("Failed to update data in Redis")

                logging.debug(f"Username updated in ACL, CONFIG, REDIS: {old_username} --> {new_username}, {old_password} --> {new_password} ")
                return {"message": "Username updated successfully"}, 200

            if update_password:
                logging.info(f"TO CHECK PASS: {old_password}")
                if not cm.password_exists_in_ACL(old_password):
                    logging.error(f"USER with password {old_password} does not exist")
                    return {"UpdateUser": "User with password does not exist"}, 404

                if not cm.update_user_in_acl(old_username, new_username, old_password, new_password, proxy_id) or \
                        not cm.update_user_in_config(old_username, new_username, proxy_id):
                    raise Exception("Failed to update password")
                
                logging.info(f"Password updated successfully")
                return {"message": "Password updated successfully"}, 200


            # Backup current state
            current_users = cm.read_file(ACL_PATH)
            current_config = cm.read_file(CONFIG_PATH)

            if current_users is None or current_config is None:
                raise Exception("Failed to read ACL_PATH or CONFIG_PATH files")                

        except Exception as e:
            # ... (your rollback logic)
            logging.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class ReplaceAndroid(Resource):
    @requires_role("admin")
    def patch(self, admin_token):
        pipe = sm.get_redis_pipeline()
        if not pipe:
            logging.error("Could not get Redis pipeline. Aborting operation.")
            return {"message": "Internal server error"}, 500

        try:
            logging.info("Received request: REPLACE ANDROID")

            required_fields = ['device_token', 'new_id', 'new_serial', 'new_device', 'new_parent_ip']
            
            data, error_message, error_code = validate_and_extract_data(required_fields)

            if error_message:
                logging.warning(f"Validation failed: {error_message}")
                return error_message, error_code

            device_token = data.get('device_token')
            new_id = data.get('new_id')
            new_serial = data.get('new_serial')
            new_device = data.get('new_device')
            new_parent_ip = data.get('new_parent_ip')

            redis_data = sm.get_data_from_redis(device_token)
            if not redis_data:
                logging.error(f"No data for token: {device_token}. Exiting.")
                return {"message": f"No data for token: {device_token}", "status_code": 404}

            username = redis_data.get('username', '')
            old_id = redis_data.get('id', '')
            old_serial = redis_data.get('serial', '')
            old_device = redis_data.get('device', '')
            old_parent_ip = redis_data.get('parent_ip', '')
            
            if not cm.android_ip_exists_in_config(old_parent_ip):
                logging.error(f"IP is NOT found: {old_parent_ip}")
                return {"message": f"IP is NOT found: {old_parent_ip}"}, 404

            if not cm.replace_android_in_config(old_parent_ip, new_parent_ip, old_id, new_id, username):
                logging.error(f"IP is NOT replaced: {old_parent_ip}")
                return {"message": f"IP is NOT replaced: {old_parent_ip}"}, 404
            logging.info(f"IP in CONFIG is replaced: {old_parent_ip} --> {new_parent_ip}")

            pipe.hset(device_token, 'parent_ip', new_parent_ip)
            pipe.hset(device_token, 'device', new_device)
            pipe.hset(device_token, 'serial', new_serial)
            pipe.hset(device_token, 'id', new_id)

            if not sm.execute_pipeline(pipe):
                logging.error("Failed to execute Redis pipeline. Aborting operation.")
                return {"message": "Internal server error"}, 500

            logging.info(f"Android replaced: {old_parent_ip} --> {new_parent_ip}, id{old_id} --> id{new_id}, {old_serial} --> {new_serial}, {old_device} --> {new_device}")
            return {"message": f"Android replaced: id{old_id} --> id{new_id}"}, 200

        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class ReplaceModem(Resource):
    @requires_role("admin")
    def patch(self, admin_token):
        try:
            logging.info("Received request: REPLACE MODEM")

            required_fields = ['device_token', 'new_id', 'new_serial', 'new_device']
            
            data, error_message, error_code = validate_and_extract_data(required_fields)

            if error_message:
                logging.warning(f"Validation failed: {error_message}")
                return error_message, error_code

            device_token = data.get('device_token')
            new_id = data.get('new_id')
            new_serial = data.get('new_serial')
            new_device = data.get('new_device')

            redis_data = sm.get_data_from_redis(device_token)
            if not redis_data:
                logging.error(f"No data for token: {device_token}. Exiting.")
                return {"message": f"No data for token: {device_token}", "status_code": 404}

            username = redis_data.get('username', '')
            old_id = redis_data.get('id', '')
            old_serial = redis_data.get('serial', '')
            old_device = redis_data.get('device', '')

            if not cm.modem_id_exists_in_config(old_id, username):
                logging.error(f"ID is NOT found: id{old_id}")
                return {"message": f"ID is NOT found: id{old_id}"}, 404

            if not cm.replace_modem_in_config(old_id, new_id, username):
                logging.error(f"ID is NOT replaced: {old_id}")
                return {"message": f"IP is NOT replaced: {old_id}"}, 404
            logging.info(f"ID is replaced: id{old_id} --> id{new_id}")

            pipe.hset(device_token, 'id', new_id)
            pipe.hset(device_token, 'serial', new_serial)
            pipe.hset(device_token, 'device', new_device)

            if not sm.execute_pipeline(pipe):
                logging.error("Failed to execute Redis pipeline. Aborting operation.")
                return {"message": "Internal server error"}, 500

            logging.info(f"Modem replaced: id{old_id} --> id{new_id}, {old_serial} --> {new_serial}, {old_device} --> {new_device}")
            return {"message": f"Modem replaced: id{old_id} --> id{new_id}"}, 200

        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class ProxyCount(Resource):
    @requires_role("admin")
    def get(self, admin_token):
        connection = None
        cursor = None

        try:
            logging.info("Received request: GET PROXY COUNT.")

            logging.info("Attempting to connect to MySQL...")
            connection = sm.connect_to_mysql()
            if connection is None:
                logging.error("Failed to connect to MySQL.")
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
            logging.info("Proxy count query executed successfully")
            return results, 200

        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

class ModemStatus(Resource):
    @requires_role("admin")
    def get(self, admin_token, serial, device_model):
        try:
            logging.info("Received request: CHECK MODEM STATUS.")

            handler = MODEM_HANDLERS.get(device_model, {}).get('status')
            if not handler:
                logging.error("Invalid device model provided. Use a correct 'device' field.")
                return {"message": "Invalid device model provided. Use a correct 'device' field."}, 400

            status = handler(serial)
            logging.info(f"Modem status: serial {serial}: {status}")
            return {"message": status}, 200

        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            return {"message": f"An error occurred: {str(e)}"}, 500

#resources
api.add_resource(Reboot, '/api/reboot/<string:token>') #user role
api.add_resource(DeviceStatus, '/api/device_status/<string:token>') #user role
api.add_resource(ChangeIP, '/api/changeip/<string:token>') #user role
api.add_resource(AutoChangeIP, '/api/changeip/auto/<string:token>') #user role
api.add_resource(AddUser, '/api/add_user/<string:token>') #admin role
api.add_resource(DeleteUser, '/api/delete_user/<string:token>') #admin role
api.add_resource(UpdateAuth, '/api/update_auth/<string:token>') #admin role
api.add_resource(UpdateMode, '/api/update_mode/<string:token>') #admin role

api.add_resource(UpdateUser, '/api/update_user/<string:token>') #admin role
api.add_resource(ReplaceAndroid, '/api/replace_android/<string:token>') #admin role
api.add_resource(ReplaceModem, '/api/replace_modem/<string:token>')
#api.add_resource(ModemToggle, '/api/modem/<string:token>') #admin role
api.add_resource(ModemStatus, '/api/modemstatus/<string:token>/<string:device_model>') #admin role
api.add_resource(ProxyCount, '/api/proxycount/<string:token>') #admin role

if __name__ == '__main__':
    app.run(debug=True)