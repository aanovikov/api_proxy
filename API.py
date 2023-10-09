from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from flask_restful import reqparse
import pexpect
import time
import subprocess
import os
#from subprocess import Popen, PIPE, TimeoutExpired, run
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
import atexit
import datetime
from threading import Lock
import textwrap
from textwrap import dedent
from functools import wraps
import mysql.connector
import secrets
import base64
import re
import redis
from redis.exceptions import ResponseError
import traceback
import logging
from ipaddress import ip_address, AddressValueError
import traceback
from dotenv import load_dotenv

from device_management import adb_reboot_device, get_adb_device_status, os_boot_status
from network_management import airplane_toggle_cmd, MODEM_HANDLERS, wait_for_ip

from settings import TETHERING_COORDINATES, ALLOWED_PROTOCOLS

config_lock = Lock()

atexit.register(lambda: scheduler.shutdown())

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

parser = reqparse.RequestParser()
parser.add_argument('interval_minutes')

jobstores = {
    'default': SQLAlchemyJobStore(url='sqlite:///jobs.sqlite')
}

scheduler = BackgroundScheduler(jobstores=jobstores)
scheduler.start()

app = Flask(__name__)
api = Api(app)

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

ACL_PATH = os.getenv('ACL_PATH')
CONFIG_PATH = os.getenv('CONFIG_PATH')

def reestablish_rndis_after_reboot(serial_number, device_model, device_id):
    job_id = f"modem_{serial_number}"

    try:
        logging.info(f"Starting reestablishment of rndis after reboot for serial: {serial_number}, type: {device_model}, id: {device_id}")
        
        for attempt in range(40):  # Maximum number of reboot status checks
            status = os_boot_status(serial_number)
            logging.info(f"Reboot status: {status}")
            
            if status == "OK":
                #scheduler.remove_job(job_id)
                logging.info(f"FROM REESTABLISH: Successfully removed job with ID {job_id}")
                break
            time.sleep(10)  # Waiting time between attempts
        else:
            logging.warning(f"Device {serial_number} did not reboot successfully after 40 attempts")
            #scheduler.remove_job(job_id)
            logging.info(f"FUNC REESTABLISH: Removed job with ID {job_id} due to unsuccessful reboot.")
            return

        if device_model not in MODEM_HANDLERS:
            logging.error(f"Unknown device model: {device_model}. Can't reestablish rndis mode.")
            return

        # After reboot, enable rndis mode for the device
        logging.info(f"Turning on rndis for {serial_number} of model: {device_model}")
        MODEM_HANDLERS[device_model]['on'](serial_number)
        logging.info(f"Modem turned on for: id{device_id}")

    except Exception as e:
        logging.error(f"An error occurred while reestablishing rndis: {e}")

    # Fetch new IP address
    # logging.info(f"Fetching new IP for {device_id}")
    # new_ip = wait_for_ip(device_id)
    
    # Save the new IP address
    # logging.info(f"New IP for {device_id} is {new_ip}")
    # write_modem_ip(new_ip, device_id)

def read_file(filepath):
    try:
        with open(filepath, 'r') as file:
            return file.readlines()
    except Exception as e:
        logging.error(f"Can't read the file {filepath}: {str(e)}")
        raise e

def write_file(filepath, data):
    try:
        logging.info(f"Writing to file at {ACL_PATH}")
        with open(filepath, 'w') as file:
            file.writelines(data)
            logging.info(f"Successfully wrote to file at: {ACL_PATH}")
        return True
    except Exception as e:
        logging.error(f"Can't write to the file: {filepath}: {str(e)}")
        return False

def add_user_to_acl(username, password):
    try:
        logging.info(f"Attempting to add user {username} to ACL.")
        with open(ACL_PATH, 'a') as file:
            file.write(f"{username}:CL:{password}\n")
        logging.info(f"User {username} successfully added to ACL.")
        return True
    except Exception as e:
        logging.error(f"Failed to add user {username} to ACL: {str(e)}")
        return False

def remove_user_from_acl(username):
    try:
        logging.info(f"Attempting to remove user {username} from ACL.")
        lines = read_file(ACL_PATH)

        if lines is None:
            return False

        updated_lines = [line for line in lines if username not in line]

        if len(lines) == len(updated_lines):
            logging.warning(f"??User {username} not found in ACL")
            return False

        if write_file(ACL_PATH, updated_lines):
            logging.info(f"User {username} successfully removed from ACL")
            return True
        else:
            return False

    except Exception as e:
        logging.error(f"An error occurred while removing user {username} from ACL: {str(e)}")
        return False

def update_user_in_acl(old_username, new_username, old_password, new_password):
    try:
        logging.info(f"Attempting to update user in ACL: old_username={old_username}, new_username={new_username}, old_password={old_password}, new_password={new_password}")

        users = read_file(ACL_PATH)
        if users is None:
            logging.error("Failed to read ACL file")
            return False

        logging.info(f"Current ACL: {users}")

        updated_users = []
        user_found = False
        
        if old_username and new_username and old_password and new_password: # change logopass
            for user in users:
                logging.info(f"Checking logopass line: {user.strip()}")
                if re.match(f"^{old_username}:CL:{old_password}", user):
                    new_user_line = f"{new_username}:CL:{new_password}\n"
                    updated_users.append(new_user_line)
                    logging.info(f"Updated users so far: {updated_users}")
                    user_found = True
                    logging.info(f"Username and Password match found. Updated line: {new_user_line.strip()}")
                else:
                    updated_users.append(user)

        elif old_username and new_username: # change only username
            for user in users:
                logging.info(f"Checking user line: {user.strip()}")
                if re.match(f"^{old_username}:CL:", user):
                    new_user_line = f"{new_username}{user[len(old_username):]}"
                    updated_users.append(new_user_line)
                    logging.info(f"Updated users so far: {updated_users}")
                    user_found = True
                    logging.info(f"Username match found. Updated line: {new_user_line.strip()}")
                else:
                    updated_users.append(user)

        elif old_password and new_password: # change only password
            for user in users:
                logging.info(f"Checking password line: {user.strip()}")
                if f":CL:{old_password}" in user:
                    new_user_line = user.replace(f":CL:{old_password}", f":CL:{new_password}")
                    updated_users.append(new_user_line)
                    logging.info(f"Updated users so far: {updated_users}")
                    user_found = True
                    logging.info(f"Password match found. Updated line: {new_user_line.strip()}")
                else:
                    updated_users.append(user)
        
        else:
            logging.info(f"Something wrong with parameters")
            updated_users = users

        if not user_found:
            logging.warning(f"User {old_username if old_username else old_password} not found in ACL")
            updated_users = []
            return False

        logging.info(f"Attempting to write to file with updated_users: {updated_users}")
        if not write_file(ACL_PATH, updated_users):
            logging.error("Failed to write to ACL file")
            return False

        logging.info(f"User {old_username if old_username else old_password} successfully updated to {new_username if new_username else new_password} in ACL")
        return True
    except Exception as e:
        logging.error(f"An error occurred while updating user in ACL: {str(e)}")
        return False

def write_config_to_file(config):
    try:
        logging.info("Attempting to write config to file.")
        
        content = read_file(CONFIG_PATH)
        if content is None:
            logging.error("Failed to read config file")
            return False
        
        content_str = "".join(content)
        if content_str and not content_str.endswith('\n'):
            content.append('\n')
        
        content.append(config)
        
        if not write_file(CONFIG_PATH, content):
            logging.error("Failed to write to config file")
            return False

        logging.info("Config successfully written to file.")
        return True
    except Exception as e:
        logging.error(f"Failed to write config to file: {str(e)}")
        return False

def add_user_config(username, mode, parent_ip, http_port, socks_port, id):
    try:
        logging.info(f"Attempting to add config for device id{id}.")
        ifname = id  # Interface name

        # Common parts for HTTP and SOCKS
        auth_part = "auth strong"
        allow_part = f"allow {username}"

        # Mode and IP-specific parts
        if mode == "android":
            parent_http = f"parent 1000 http {parent_ip} 8080 android android"
            parent_socks = f"parent 1000 socks5 {parent_ip} 1080 android android"
            proxy = f"proxy -n -a -p{http_port}"
            socks = f"socks -n -a -p{socks_port}"
        elif mode == "modem" and parent_ip == "none":
            parent_http = None
            parent_socks = None
            proxy = f"proxy -n -a -p{http_port} -Doid{ifname}"
            socks = f"socks -n -a -p{socks_port} -Doid{ifname}"
        else:
            raise ValueError("Invalid combination of mode and parent_ip")

        # Construct the HTTP and SOCKS blocks
        if mode == "android":
            http_parts = [
                f"# Start http for {username} id{id}",
                "flush",
                auth_part,
                allow_part,
                parent_http,  # 'parent' comes before 'proxy'
                proxy,
                f"# End http for {username} id{id}"
            ]
            socks_parts = [
                f"# Start socks for {username} id{id}",
                "flush",
                auth_part,
                allow_part,
                parent_socks,  # 'parent' comes before 'socks'
                socks,
                f"# End socks for {username} id{id}"
            ]
        elif mode == "modem":
            http_parts = [
                f"# Start http for {username} id{id}",
                "flush",
                auth_part,
                allow_part,
                proxy,  # No 'parent', so 'proxy' comes last before comment
                f"# End http for {username} id{id}"
            ]
            socks_parts = [
                f"# Start socks for {username} id{id}",
                "flush",
                auth_part,
                allow_part,
                socks,  # No 'parent', so 'socks' comes last before comment
                f"# End socks for {username} id{id}"
            ]

        # Join the parts together, adding a newline only at the end
        config = "\n".join(http_parts + socks_parts) + "\n"
        write_result = write_config_to_file(config)
        if not write_result:
            raise IOError("Failed to write user config to file.")
        
        logging.info(f"Successfully added config for id{id}")
        return True

    except ValueError as ve:
        logging.error(f"ValueError occurred: {str(ve)}")
        return False
    except IOError as io:
        logging.error(f"IOError occurred: {str(io)}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
        return False

def remove_user_config(username, proxy_id):
    try:
        logging.info(f"Attempting to remove config for proxy id{proxy_id}.")
        lines = read_file(CONFIG_PATH)
        if lines is None:
            logging.error("Failed to read config file")
            return False

        user_removed = False
        new_config = []
        start_http_tag = f"# Start http for {username} id{proxy_id}"
        end_http_tag = f"# End http for {username} id{proxy_id}"
        start_socks_tag = f"# Start socks for {username} id{proxy_id}"
        end_socks_tag = f"# End socks for {username} id{proxy_id}"

        skip = False
        for line in lines:
            stripped_line = line.strip()
            if stripped_line == start_http_tag or stripped_line == start_socks_tag:
                skip = True
                user_removed = True
            elif stripped_line == end_http_tag or stripped_line == end_socks_tag:
                skip = False
                continue

            if not skip and stripped_line:
                new_config.append(line)

        if not write_file(CONFIG_PATH, new_config):
            logging.error("Failed to write new config")
            return False

        if user_removed:
            logging.info(f"User {username} successfully removed from config")
            return True
        else:
            logging.warning(f"User {username} not found in config")
            return False

    except Exception as e:
        logging.error(f"An error occurred while removing user {username} from config: {str(e)}")
        return False

def update_user_in_config(old_username, new_username, proxy_id):
    try:
        config = read_file(CONFIG_PATH)
        if config is None:
            logging.error("Failed to read config file")
            return False

        config = "".join(config)
        config_updates = {
            f"# Start http for {old_username} id{proxy_id}": f"# Start http for {new_username} id{proxy_id}",
            f"# End http for {old_username} id{proxy_id}": f"# End http for {new_username} id{proxy_id}",
            f"# Start socks for {old_username} id{proxy_id}": f"# Start socks for {new_username} id{proxy_id}",
            f"# End socks for {old_username} id{proxy_id}": f"# End socks for {new_username} id{proxy_id}",
            f"allow {old_username}": f"allow {new_username}"
        }

        for old, new in config_updates.items():
            config = re.sub(re.escape(old), new, config)

        if not write_file(CONFIG_PATH, config):
            logging.error("Failed to write new config")
            return False

        logging.info(f"User {old_username} successfully updated to {new_username} in config")
        return True

    except Exception as e:
        logging.error(f"An error occurred while updating user in config: {str(e)}")
        return False

def username_exists_in_ACL(username):
    try:
        lines = read_file(ACL_PATH)
        if lines is None:
            logging.error("Failed to read ACL file")
            return False

        for line in lines:
            parts = line.split(":")
            if len(parts) > 1 and username == parts[0]:
                logging.info(f"Username {username} exists in ACL.")
                return True

        logging.warning(f"Username {username} does not exist in ACL.")
        return False

    except Exception as e:
        logging.error(f"An error occurred while checking if user exists: {str(e)}")
        return False

def password_exists_in_ACL(password):
    try:
        lines = read_file(ACL_PATH)
        if lines is None:
            logging.error("Failed to read ACL file")
            return False

        for line in lines:
            parts = line.split(":")
            if len(parts) > 1 and password == parts[2].strip():
                logging.info(f"Password {password} exists in ACL.")
                return True

        logging.warning(f"Password {password} does not exist in ACL.")
        return False
    except Exception as e:
        logging.error(f"An error occurred while checking if user exists: {str(e)}")
        return False

def user_count_in_ACL(username, proxy_id, config_lines):
    count = 0
    search_pattern = f"# Start http for {username} id{proxy_id}"
    for line in config_lines:
        if search_pattern in line:
            count += 1
    return count

def update_auth_in_config(proxy_id, username, protocol, auth_type, allow_ip):
    try:
        lines = read_file(CONFIG_PATH)
        if lines is None:
            logging.error("Failed to read config file")
            return False, "Failed to read config file"

        start_tag = f"# Start {protocol} for {username} id{proxy_id}"
        end_tag = f"# End {protocol} for {username} id{proxy_id}"

        search_pattern = f"# Start {protocol} for {username} id{proxy_id}"
        logging.info(search_pattern)
        id_exists_in_config_result = id_exists_in_config(search_pattern, proxy_id, username)

        if not id_exists_in_config_result:
            logging.error(f"No {username} or id{proxy_id} found in the config.")
            return False, f"No {username} or id{proxy_id} found in the config."

        within_block = False
        new_config = []
        current_auth_type = None

        for line in lines:
            stripped_line = line.strip()
            if start_tag in stripped_line:
                within_block = True
            elif end_tag in stripped_line:
                within_block = False

            if within_block:
                if "auth" in line:
                    current_auth_type = line.strip().split(" ")[1]  # auth strong -> strong
                    if current_auth_type == auth_type:
                        return False, "Auth type is already set to " + auth_type
                    line = f"auth {auth_type}\n"
                elif "allow" in line:
                    if auth_type == "strong":
                        line = f"allow {username}\n"
                    elif auth_type == "iponly":
                        line = f"allow * {allow_ip}\n"
        
            new_config.append(line)

        if not write_file(CONFIG_PATH, new_config):
            logging.error("Failed to write new config")
            return False, "Failed to write new config"

        logging.info(f"User configuration updated successfully for {username}.")
        return True, "Auth type updated"
    except Exception as e:
        logging.error(f"An error occurred while updating auth in config: {str(e)}")
        return False, "An error occurred"

def update_mode_in_config(new_mode, parent_ip, device_token, http_port, socks_port):
    logging.info(f"Starting to update mode in config with new_mode: {new_mode}, parent_ip: {parent_ip}, device_token: {device_token}")

    device_data = get_data_from_redis(device_token)
    current_mode = device_data.get('mode')
    device_id = device_data.get('id')
    username = device_data.get('username')

    logging.debug(f"Current device_id: {device_id}, current_mode: {current_mode}")

    if str(new_mode) == str(current_mode):
        logging.info(f"Mode for device {device_id} is already set to {new_mode}. Exiting.")
        return {"message": f"Mode for device {device_id} is already set to {new_mode}", "status_code": 200}

    new_lines = []
    inside_user_block = False

    logging.info(f"Ports info - http_port: {http_port}, socks_port: {socks_port}")

    with open(CONFIG_PATH, "r") as f:
        lines = f.readlines()

    for line in lines:
        new_line = line.strip()

        if f"# Start http for {username}" in line:
            inside_user_block = True
            logging.debug(f"Entering user block for {username}")

        if f"# End socks for {username}" in line:
            inside_user_block = False
            logging.debug(f"Exiting user block for {username}")

        if inside_user_block:
            if new_mode == 'modem':
                if 'parent' in line:
                    continue  # Просто пропустим эту строку, и она не попадет в новый конфиг
                elif 'proxy -n -a -p' in line:
                    new_line = re.sub(r'-p\d+', f'-p{http_port}', line)
                    new_line = new_line.rstrip() + f' -e$"/etc/3proxy/modem_ip/{device_id}"\n'
                elif 'socks -n -a -p' in line:
                    new_line = re.sub(r'-p\d+', f'-p{socks_port}', line)
                    new_line = new_line.rstrip() + f' -e$"/etc/3proxy/modem_ip/{device_id}"\n'
            elif new_mode == 'parent':
                if 'proxy -n -a -p' in line:
                    new_lines.append(f'parent 1000 http {parent_ip} 8080 android android\n')
                    new_line = re.sub(r'-p\d+', f'-p{http_port}', line).strip()
                    new_line = re.sub(r' -e\$\"/etc/3proxy/modem_ip/\w+\"', '', new_line)
                elif 'socks -n -a -p' in line:
                    new_lines.append(f'parent 1000 socks5 {parent_ip} 8080 android android\n')
                    new_line = re.sub(r'-p\d+', f'-p{socks_port}', line).strip()
                    new_line = re.sub(r' -e\$\"/etc/3proxy/modem_ip/\w+\"', '', new_line)

        if new_line:
            new_lines.append(new_line.strip() + '\n')  # Добавляем новую строку, если она не пуста

    with open(CONFIG_PATH, "w") as f:
        f.writelines(new_lines)

    # Обновляем значение в Redis
    update_data_in_redis(device_token, 'mode', new_mode)

    logging.info(f"Mode for device {device_id} has been changed to {new_mode}")
    response = f"Mode for device {device_id} has been changed to {new_mode}"
    return {"message": f"Mode for device {device_id} has been changed to {new_mode}", "status_code": 200}

def ip_exists_in_config(ip_address):
    try:
        content = read_file(CONFIG_PATH)
        if content is None:
            logging.error("An error occurred while reading the config file.")
            return False

        if ip_address in ''.join(content):
            logging.info(f"IP address {ip_address} exists in 3proxy config.")
            return True

        logging.info(f"IP address {ip_address} does not exist in 3proxy config.")
        return False

    except Exception as e:
        logging.error(f"An error occurred while checking IP in config: {str(e)}")
        return False

def change_device_in_config(old_ip, new_ip):
    try:
        content = read_file(CONFIG_PATH)
        if content is None:
            logging.error("An error occurred while reading the config file.")
            return False

        updated_content = ''.join(content).replace(old_ip, new_ip)
        
        if write_file(CONFIG_PATH, updated_content):
            logging.info(f"Changed device IP from {old_ip} to {new_ip} in the configuration.")
            return True
        else:
            logging.error("An error occurred while writing to the config file.")
            return False
    except Exception as e:
        logging.error(f"An error occurred while changing device IP in config: {str(e)}")
        return False

def id_exists_in_config(search_pattern, proxy_id, username):
    try:
        content = read_file(CONFIG_PATH)
        if content is None:
            logging.error("An error occurred while reading the config file.")
            return False

        #search_pattern = f'-Doid{id}'
        if search_pattern in ''.join(content):
            logging.info(f"Config for user <{username}> ID {proxy_id} exists in the configuration.")
            return True

        #logging.info(f"ID {id} does not exist in the configuration.")
        return False

    except Exception as e:
        logging.error(f"An error occurred while checking ID in config: {str(e)}")
        return False

def change_id_in_config(old_id, new_id):
    try:
        content = read_file(CONFIG_PATH)
        if content is None:
            logging.error("An error occurred while reading the config file.")
            return False

        search_string = f'-e$"/etc/3proxy/modem_ip/{old_id}"'
        updated_content = ''.join(content).replace(search_string, f'-e$"/etc/3proxy/modem_ip/{new_id}"')

        if write_file(CONFIG_PATH, updated_content):
            logging.info(f"Changed ID from {old_id} to {new_id} in the configuration.")
            return True
        else:
            logging.error("An error occurred while writing to the config file.")
            return False

    except Exception as e:
        logging.error(f"An error occurred while changing ID in config: {str(e)}")
        return False

def write_modem_ip(ext_ip, id):
    # Define the directory and cross-platform file path
    directory = os.path.join("/etc", "3proxy", "modem_ip")
    file_path = os.path.join(directory, id)

    # Check if the directory exists
    if not os.path.exists(directory):
        logging.error(f"Directory {directory} does not exist.")
        return False

    # Command to write the ext_ip to the file
    shell_command = dedent(f"""
        echo {ext_ip} > {file_path}
    """).strip()

    try:
        if os.name == 'nt':  # For Windows
            subprocess.run(shell_command, shell=True, check=True)
        else:  # For Linux and macOS
            subprocess.run(['bash', '-c', shell_command], check=True)
        logging.info(f"Successfully written {ext_ip} to {file_path}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"An error occurred while writing to {file_path}: {e}")
        return False

def generate_short_token():
    random_bytes = secrets.token_bytes(15)  # 15 bytes should generate a 20-character token when base64 encoded
    token = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
    return token

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

def requires_role(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = kwargs.pop('token', None)

            r = connect_to_redis()
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
                logging.error(f"No role found for token {token}")
                return {"message": "Unauthorized"}, 401
            
            role = role_data.decode('utf-8')  # Декодирование может быть необходимым
            if role != required_role:
                logging.warning(f"Permission denied: role {role} does not have access")
                return {"message": "Permission denied"}, 403
            
            logging.info(f"Successfully authorized with role {role} and token {token}")

            kwargs['admin_token'] = token  # Re-insert the token
            return f(*args, **kwargs)
        return decorated_function
    return decorator

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
            serial_number = user_data_decoded.get('serial')

            if serial_number == target_serial:
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

def is_valid_port(port):
    try:
        port_num = int(port)
        return 10000 <= port_num <= 65000
    except ValueError:
        return False

def schedule_job(serial_number, device, device_id):
    job_id = f"modem_{serial_number}"
    
    logging.info(f"Scheduling job with ID: {job_id} for device with serial number: {serial_number}")
    
    try:
        scheduler.add_job(
            reestablish_rndis_after_reboot, 
            args=[serial_number, device, device_id], 
            id=job_id,
            replace_existing=True  # опционально, если нужно
        )
        logging.info(f"Successfully added job {job_id} to scheduler.")
    except Exception as e:
        logging.error(f"Failed to schedule job {job_id}. Error: {e}")

#3Proxy config apiment end;

class Reboot(Resource):
    #@requires_role("user")
    def get(self, token):
        try:
            user_data = get_data_from_redis(token)
            serial_number = user_data.get('serial')
            device = user_data.get('device')
            mode = user_data.get('mode')
            device_id = user_data.get('id')  # Getting from Redis

            if not serial_number:
                logging.error("Serial number not found in user data.")
                return {'error': 'Serial number not found'}, 400

            reboot_status = os_boot_status(serial_number)

            if reboot_status != 'OK':
                logging.warning(f"Device {serial_number} is still rebooting.")
                return {'reboot': 'in progress', 'message': 'Device is still rebooting.'}, 409

            logging.info(f"Received device ID: {device_id}")

            if mode == "android":
                adb_reboot_device(serial_number)
                return {'reboot': 'OK', 'message': 'Reboot started.'}, 202

            if mode == "modem":
                adb_reboot_device(serial_number)
                #job_id = f"modem_{serial_number}"
                #scheduler.add_job(
                schedule_job(serial_number, device, device_id)
                return {'reboot': 'OK', 'message': 'Reboot in progress.'}, 202

            logging.error("Unknown mode provided in user data.")
            return {'error': 'Unknown mode provided'}, 400

        except Exception as e:
            logging.error(f"An error occurred during reboot: {str(e)}")
            return {'error': 'Internal server error'}, 500

class DeviceStatus(Resource):
    #@requires_role("user")
    def get(self, token, serial=None):
        try:
            serial = request.args.get('serial')  # Get serial_number from query params

            if serial:
                # For admin: serial_number directly provided
                logging.info(f"Admin checking status for serial: {serial}")
            else:
                # For regular users: fetch serial_number from Redis
                user_data = get_data_from_redis(token)
                serial = user_data.get('serial')

            if not serial:
                logging.error("Serial number not found in user data.")
                return {'error': 'Serial number not found'}, 400

            device_status = get_adb_device_status(serial)

            if device_status == "device":
                for i in range(3):
                    status = os_boot_status(serial)
                    if status == 'OK':
                        logging.info(f"Device {serial} is READY!")
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
            return {'error': 'Something went wrong.'}, 500

class ChangeIP(Resource):
    def get(self, token):
        try:
            user_data = get_data_from_redis(token)
            serial_number = user_data.get('serial')
            logging.info(f"Received request to change IP for serial: {serial_number}")

            if not serial_number:
                logging.error("Serial number not found in user data.")
                return {'error': 'Serial number not found'}, 400

            logging.info(f"Received serial number: {serial_number}")
            
            airplane_toggle_cmd(serial_number)
            return {'status': 'success', 'message': 'IP was changed'}, 200

        except Exception as e:
            logging.error("An error occurred")
            return {'status': 'failure', 'message': 'An error occurred while changing IP'}, 500

class AutoChangeIP(Resource):
    def post(self, token):
        try:
            user_data = get_data_from_redis(token)
            serial_number = user_data.get('serial')
            
            if not serial_number:
                logging.error("Serial number not found in user data.")
                return {'error': 'Serial number not found'}, 400

            args = parser.parse_args()
            interval_minutes = args['interval_minutes']

            job_id = f"changeip_{serial_number}"

            # Cancel the scheduled job
            if interval_minutes == '0':
                try:
                    scheduler.remove_job(job_id)
                    logging.info(f"Scheduled IP changes for device {token} have been cancelled.")
                    return {'status': 'success', 'message': f'Scheduled IP changes for device {token} have been cancelled.'}, 200
                except Exception as e:
                    logging.error(f"Error occurred while cancelling scheduled job: {str(e)}")
                    return {'status': 'failure', 'message': str(e)}, 500

            # Schedule a new job
            else:
                interval_minutes = int(interval_minutes)  # Convert to int
                try:
                    scheduler.add_job(
                        func=airplane_toggle_cmd, 
                        trigger='interval', 
                        minutes=interval_minutes, 
                        args=[serial_number], 
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
            logging.info("Received request to DELETE USER.")

            data = request.json
            logging.info(f"Got data: {data}")
            if data is None:
                logging.error("Invalid request: JSON body required.")
                return {"message": "Invalid request: JSON body required"}, 400

            # Get proxy_id and user_token from JSON body
            proxy_id = data.get('id') # to remove using proxy_id in config
            user_token = data.get('token') # to remove key using token in redis
            username = data.get ('username')

            if not proxy_id or not user_token or not username:
                logging.error("Missing required fields: proxy_id and/or token/or username.")
                return {"message": "Missing required fields: proxy_id and/or token/or username"}, 400

            # Check if the user exists
            if not username_exists_in_ACL(username):
                logging.error("User does not exist.")
                return {"message": "User does not exist"}, 404

            # Check token and username in Redis
            user_data = get_data_from_redis(user_token)
            if not user_data or user_data.get('id') != proxy_id:
                logging.error("Invalid proxy_id or token.")
                return {"message": "Invalid proxy_id or token"}, 400

            logging.info(f"Reading config")
            lines = read_file(CONFIG_PATH)
            logging.info(f"Lines: {lines}")
            
            logging.info(f"Counting username")
            count_users = user_count_in_ACL(username, proxy_id, lines)
            logging.info(f"Count username: {count_users}")

            if count_users == 1:
                logging.info(f"Username {username} has only 1 proxy id{proxy_id}, will be removed from ACL")
            elif count_users > 1:
                logging.warning(f"Username {username} has {count_users} proxy will NOT be removed from ACL")


            # Remove from configuration
            if not remove_user_config(username, proxy_id):
                logging.error(f"Failed to remove proxy user: {username} id{proxy_id} from configuration.")
                return ({f"message": f"Failed to remove proxy user: {username} id{proxy_id} from configuration"}, 500)

            # Remove from ACL
            if count_users == 1:
                if not remove_user_from_acl(username):
                    logging.error("Failed to remove user from ACL.")
                    return {"message": "Failed to remove user from ACL"}, 500

                logging.info(f"Username {username} was removed from ACL")
            elif count_users > 1:
                logging.info(f"Username {username} has {count_users}, SKIP removing from ACL")
            
            # Remove from Redis
            result = delete_from_redis(user_token)
            if not result:
                logging.error("Token not found in Redis or failed to remove.")
                return {"message": "Token not found in Redis or failed to remove"}, 404

            logging.info("User deleted successfully.")
            return {"message": "User deleted successfully"}, 200
        except Exception as e:
            logging.exception(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class UpdateAuth(Resource):
    @requires_role("admin")
    def patch(self, admin_token):
        try:
            logging.info("Received request to UPDATE AUTH.")

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

            logging.info(f"Received DATA ID: {proxy_id}, Username: {username}, Protocol: {protocol}, New Auth Type: {auth_type}, Allow ip: {allow_ip}")

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
                result1, message1 = update_auth_in_config(proxy_id, username, 'http', auth_type, allow_ip)
                result2, message2 = update_auth_in_config(proxy_id, username, 'socks', auth_type, allow_ip)
                if not result1:
                    messages.append(f"Failed to update HTTP for {username}: {message1}")
                else:
                    messages.append(f"Successfully updated HTTP for {username}")

                if not result2:
                    messages.append(f"Failed to update SOCKS for {username}: {message2}")
                else:
                    messages.append(f"Successfully updated SOCKS for {username}")
            else:
                result, message = update_auth_in_config(proxy_id, username, protocol, auth_type, allow_ip)
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
            logging.info("Received request to UPDATE MODE.")

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

            if new_mode not in ['parent', 'modem']:
                logging.warning("Invalid mode. Use either 'parent' or 'modem'")
                return {"message": "Invalid mode. Use either 'parent' or 'modem'"}, 400

            # Проверка корректности parent_ip
            if new_mode == 'parent':
                try:
                    ip_address(parent_ip)
                except AddressValueError:
                    logging.warning("Invalid parent IP address")
                    return {"message": "Invalid parent IP address. Should be a valid IPv4 or IPv6 address."}, 400

            logging.debug(f"Got device_token: {device_token}, new_mode: {new_mode}, parent_ip: {parent_ip}, http_port: {http_port}, socks_port: {socks_port}")

            if not (10000 <= http_port <= 65000 and 10000 <= socks_port <= 65000):
                logging.warning("Port numbers out of allowed range")
                return {"message": "Port numbers should be between 10000 and 65000"}, 400

            response = update_mode_in_config(new_mode, parent_ip, device_token, http_port, socks_port)
            
            logging.info("Successfully updated mode.")
            return {"message": response["message"]}, response["status_code"]
            
        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class AddUser(Resource):
    @requires_role("admin")
    def post(self, admin_token):
        try:
            logging.info("Received request to ADD USER.")
            
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

            if serial_exists(user_data['serial']):
                logging.warning(f"Serial {user_data['serial']} already exists")
                return {"message": f"Serial {user_data['serial']} already exists"}, 400

            logging.info(f"Serial existence in Redis check passed for {user_data['username']}")

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
                        logging.info(f"Modem is already on, its IP: {ip_address}")

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

            acl_result = add_user_to_acl(user_data['username'], user_data['password'])
            config_result = add_user_config(user_data['username'], user_data['mode'], user_data['parent_ip'], user_data['http_port'], user_data['socks_port'], user_data['id'])

            if not acl_result:
                logging.error(f"Failed to add user {user_data['username']} to ACL. Aborting operation.")
                return {"message": "Failed to add user to ACL"}, 500
            else:
                logging.info(f"Successfully added user {user_data['username']} to ACL.")

            if not config_result:
                logging.error(f"Failed to add user config for {user_data['username']}. Rolling back ACL.")
                remove_user_from_acl(user_data['username'])
                return {"message": "Failed to add user config. Rolled back ACL"}, 500
            else:
                logging.info(f"Successfully added user config for {user_data['username']}.")

            data_to_redis = ['serial', 'device', 'mode', 'id']
            data_to_redis_storage = {field: user_data[field] for field in data_to_redis}
            redis_result = store_to_redis(data_to_redis_storage, token)

            if not redis_result:
                logging.error(f"Failed to store user data to Redis for user {user_data['username']} id{user_data['id']}. Rolling back ACL and config.")
                remove_user_from_acl(user_data['username'])
                remove_user_config(user_data['username'], user_data['id'])
                return {"message": "Failed to store user data to Redis. Rolled back ACL and config"}, 500
            else:
                logging.info(f"Successfully added data to redis for {user_data['username']} id{user_data['id']}.")

                logging.info("User added successfully")
                return {"message": "User added successfully", "token": token}, 201  

        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            return {"message": f"Internal server error: {str(e)}"}, 500

class UpdateUser(Resource):
    @requires_role("admin")
    def patch(self, admin_token):
        try:
            logging.info("Received request to UPDATE LOGOPASS.")
            
            data = request.json
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400
            
            device_token = data.get('device_token')
            if not device_token or not get_data_from_redis(device_token):
                logging.warning("Invalid or missing device token.")
                return {"message": "Invalid or missing device token"}, 400

            proxy_id = data.get('id')
            new_username = data.get('new_username')
            old_username = data.get('old_username')
            new_password = data.get('new_password')
            old_password = data.get('old_password')

            update_username = old_username is not None and new_username is not None
            update_password = old_password is not None and new_password is not None

            if not (update_username or update_password):
                return {"message": "Invalid input. Either update username or password, not both or neither."}, 400

            if update_username:
                if not username_exists_in_ACL(old_username):
                    logging.error(f"User {old_username} does not exist")
                    return {"message": f"User {old_username} does not exist"}, 404

                if not update_user_in_acl(old_username, new_username, old_password, new_password) or \
                        not update_user_in_config(old_username, new_username, proxy_id):
                    raise Exception("Failed to update username")

                logging.info(f"Username updated successfully")
                return {"message": "Username updated successfully"}, 200

            if update_password:
                logging.info(f"TO CHECK PASS: {old_password}")
                if not password_exists_in_ACL(old_password):
                    logging.error(f"USER with password {old_password} does not exist")
                    return {"UpdateUser": "User with password does not exist"}, 404

                if not update_user_in_acl(old_username, new_username, old_password, new_password) or \
                        not update_user_in_config(old_username, new_username, proxy_id):
                    raise Exception("Failed to update password")
                
                logging.info(f"Password updated successfully")
                return {"message": "Password updated successfully"}, 200


            # Backup current state
            current_users = read_file(ACL_PATH)
            current_config = read_file(CONFIG_PATH)

            if current_users is None or current_config is None:
                raise Exception("Failed to read ACL_PATH or CONFIG_PATH files")                

        except Exception as e:
            # ... (your rollback logic)
            logging.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class ChangeDevice(Resource):
    @requires_role("admin")
    def patch(self, admin_token):
        try:
            logging.info("Received request to CHANGE DEVICE.")
            
            data = request.json
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400

            old_ip = data.get('old_ip')
            new_ip = data.get('new_ip')
            old_id = data.get('old_id')
            new_id = data.get('new_id')
            ext_ip = data.get('ext_ip')  # For function write_modem_ip

            if old_ip and new_ip:
                if not ip_exists_in_config(old_ip):
                    logging.error(f"IP address {old_ip} not found in parent directive")
                    return {"message": f"IP address {old_ip} not found in parent directive"}, 404
                change_device_in_config(old_ip, new_ip)
                logging.info(f"Updated IP address from {old_ip} to {new_ip}")

            if old_id and new_id:
                if not id_exists_in_config(old_id):
                    logging.error(f"ID {old_id} not found in config")
                    return {"message": f"ID {old_id} not found in config"}, 404

                if ext_ip:
                    write_modem_ip(ext_ip, new_id)
                    logging.info(f"Written ext_ip {ext_ip} for ID {new_id}")
                change_id_in_config(old_id, new_id)
                logging.info(f"Updated ID from {old_id} to {new_id}")

            logging.info("IP address and/or ID updated successfully")
            return {"message": "IP address and/or ID updated successfully"}, 200

        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class ProxyCount(Resource):
    @requires_role("admin")
    def get(self, admin_token):
        connection = None
        cursor = None

        try:
            logging.info("Received request to GET PROXY COUNT.")

            logging.info("Attempting to connect to MySQL...")
            connection = connect_to_mysql()
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
    def get(self, admin_token, serial_number, device_model):
        try:
            logging.info("Received request to CHECK MODEM STATUS.")

            handler = MODEM_HANDLERS.get(device_model, {}).get('status')
            if not handler:
                logging.error("Invalid device model provided. Use a correct 'device' field.")
                return {"message": "Invalid device model provided. Use a correct 'device' field."}, 400

            status = handler(serial_number)
            logging.info(f"Modem status for serial {serial_number}: {status}")
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
api.add_resource(ChangeDevice, '/api/change_device/<string:token>') #admin role
#api.add_resource(ModemToggle, '/api/modem/<string:token>') #admin role
api.add_resource(ModemStatus, '/api/modemstatus/<string:token>/<string:device_model>') #admin role
api.add_resource(ProxyCount, '/api/proxycount/<string:token>') #admin role

if __name__ == '__main__':
    app.run(debug=True)