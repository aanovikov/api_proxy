from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from flask_restful import reqparse
import pexpect
import time
import subprocess
import os
from subprocess import Popen, PIPE, TimeoutExpired, run
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
import netifaces as ni
import re
import redis
from redis.exceptions import ResponseError
import traceback
import logging
from ipaddress import ip_address, AddressValueError

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

ACL_PATH = '/etc/3proxy/users.txt'
CONFIG_PATH = '/etc/3proxy/3proxy.cfg'

REDIS_HOST = os.environ['REDIS_HOST']
REDIS_PORT = int(os.environ['REDIS_PORT'])
REDIS_PASSWORD = os.environ['REDIS_PASSWORD']

ALLOWED_PROTOCOLS = ['http', 'socks', 'both']

MYSQL_SETTINGS = {
    "host": os.environ['MYSQL_HOST'],
    "user": os.environ['MYSQL_USER'],
    "password": os.environ['MYSQL_PASSWORD'],
    "database": os.environ['MYSQL_DATABASE']
}

# Device api manage:

def adb_reboot_device(serial_number):
    adb_reboot = f"adb -s {serial_number} reboot"
    logging.info(f"Executing adb reboot command for device: {serial_number}")
    result = subprocess.run(adb_reboot.split(), stdout=subprocess.PIPE)
    logging.debug(f"ADB reboot command output: {result.stdout.decode()}")

def get_adb_device_status(device_id):
    try:
        output = subprocess.check_output(["adb", "-s", device_id, "get-state"], stderr=subprocess.STDOUT).decode('utf-8').strip()
        logging.info(f"Device {device_id} status: {output}")
    except subprocess.CalledProcessError as e:
        error_output = e.output.decode('utf-8').strip()
        if "not found" in error_output:
            logging.error(f"Device {device_id} not found")
            return "not found"
        else:
            logging.error(f"Unexpected error for device {device_id}: {error_output}")
            return "unknown"

    if output == "device":
        return "device"
    elif output == "offline":
        return "offline"
    elif output == "unauthorized":
        return "unauthorized"
    elif output == "bootloader":
        return "bootloader"
    else:
        logging.warning(f"Unknown status for device {device_id}")
        return "unknown"

def os_boot_status(serial_number):
    adb_get_boot_completed = f"adb -s {serial_number} shell getprop sys.boot_completed"
    logging.info(f"Checking reboot status for device: {serial_number}")
    consecutive_ok = 0  # счетчик подтверждений

    for _ in range(3):  # три попытки подтверждения
        process = Popen(adb_get_boot_completed.split(), stdout=PIPE, stderr=PIPE)

        try:
            stdout, stderr = process.communicate(timeout=10)
            output = stdout.decode('utf-8').strip()

            if output == '1':
                consecutive_ok += 1  # увеличиваем счетчик
            else:
                consecutive_ok = 0  # сбрасываем счетчик

            if consecutive_ok == 3:
                logging.info(f"Device {serial_number} is online")
                return 'OK'  # если три подтверждения, возвращаем OK

            time.sleep(1)  # пауза 1 секунда между попытками

        except TimeoutExpired:
            logging.error(f"Timeout during reboot check for device {serial_number}")
            return 'Timeout during reboot check'
        except subprocess.CalledProcessError:
            logging.error(f"CalledProcessError during reboot check for device {serial_number}")
            return 'Reboot in progress'

    logging.warning(f"Reboot in progress for device {serial_number}")
    return 'Reboot in progress'

def toggle_airplane_mode(serial_number, delay=1):
    try:
        logging.info(f"Toggling airplane mode for device {serial_number}")
        adb_command = f"adb -s {serial_number} shell"
        child = pexpect.spawn(adb_command)
        child.expect('\$', timeout=10)

        # Turn airplane mode ON
        airplane_on_command = "su -c 'settings put global airplane_mode_on 1; am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true'"
        logging.info(f"Executing airplane ON command: {airplane_on_command}")
        child.sendline(airplane_on_command)
        child.expect_exact('Broadcast completed: result=0', timeout=10)
        
        logging.info(f"Pause for {delay} seconds")
        time.sleep(delay)

        # Turn airplane mode OFF
        airplane_off_command = "su -c 'settings put global airplane_mode_on 0; am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false'"
        logging.info(f"Executing airplane OFF command: {airplane_off_command}")
        child.sendline(airplane_off_command)
        child.expect_exact('Broadcast completed: result=0', timeout=10)

        logging.info("Airplane mode toggled and exiting shell.")
        child.sendline('exit')
        child.close()

    except pexpect.exceptions.TIMEOUT as e:
        logging.error("Timeout occurred")
        raise

def get_ip_address(interface_name):
    try:
        ip_address = ni.ifaddresses(interface_name)[ni.AF_INET][0]['addr']
        logging.info(f"Interface {interface_name}: IP address obtained - {ip_address}")
        return ip_address
    except Exception as e:
        logging.error(f"Couldn't fetch IP for interface {interface_name}: {str(e)}")
        return '127.0.0.1'

def wait_for_ip(interface_name, retries=5, delay=3):
    logging.info(f"Waiting for IP on interface {interface_name} with {retries} retries and {delay}s delay")
    for i in range(retries):
        ip = get_ip_address(interface_name)
        if ip != '127.0.0.1':
            logging.info(f"Got a valid IP {ip} on attempt {i+1}")
            return ip
        logging.warning(f"Failed to get a valid IP on attempt {i+1}")
        time.sleep(delay)

    logging.error(f"Exceeded max retries for getting IP on interface {interface_name}")
    return '127.0.0.1'

#for alcatel
def modem_on_any(serial_number):
    modem_on_any = f"adb -s {serial_number} shell svc usb setFunctions rndis"
    logging.info(f"Executing adb command to turn ON modem: {modem_on_any}")

    result = subprocess.run(modem_on_any.split(), stdout=subprocess.PIPE)
    logging.info(f"Output of adb command: {result.stdout.decode()}")

def modem_off_any(serial_number):
    modem_off_any = f"adb -s {serial_number} shell svc usb setFunctions none"
    logging.info(f"Executing adb command to turn OFF modem: {modem_off_any}")

    result = subprocess.run(modem_off_any.split(), stdout=subprocess.PIPE)
    logging.info(f"Output of adb command: {result.stdout.decode()}")

def modem_status_any(serial_number):
    modem_status_any_cmd = f"adb -s {serial_number} shell svc usb getFunctions"
    logging.info(f"Checking modem status with adb command: {modem_status_any_cmd}")
    
    process = Popen(modem_status_any_cmd.split(), stdout=PIPE, stderr=PIPE)

    try:
        stdout, stderr = process.communicate(timeout=10)
        error = stderr.decode()

        if f"device '{serial_number}' not found" in error:
            logging.warning(f"Device {serial_number} not found")
            return "device_not_found"
        elif "rndis" in error:
            logging.info(f"Device {serial_number} is in rndis mode")
            return "rndis"
        else:
            logging.info(f"Device {serial_number} is not in rndis mode")
            return "rndis_off"
    except TimeoutExpired:
        logging.error(f"Timeout occurred while checking status for device {serial_number}")
        process.kill()
        return "timeout"

#for samsung
def modem_on_off_a2(serial_number):
    modem_on_off_a2 = f"adb -s {serial_number} shell 'input keyevent KEYCODE_WAKEUP && am start -n com.android.settings/.TetherSettings && sleep 1 && input tap 465 545'"
    logging.info(f"Executing adb command to toggle modem: {modem_on_off_a2}")

    result = subprocess.run(modem_on_off_a2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    logging.info(f"Output of adb command: {result.stdout.decode()}")
    logging.error(f"Error of adb command: {result.stderr.decode()}")

def modem_status_a2(serial_number):
    modem_status_a2 = f"adb -s {serial_number} shell svc usb getFunction"
    logging.info(f"Checking modem status for device {serial_number} with command: {modem_status_a2}")
    
    process = Popen(modem_status_a2.split(), stdout=PIPE, stderr=PIPE)
    try:
        stdout, stderr = process.communicate(timeout=10)  # 10 seconds timeout
        error = stderr.decode()
        logging.info(f"Received stdout: {stdout.decode()}")
        logging.error(f"Received stderr: {error}")

        if f"device '{serial_number}' not found" in error:
            logging.error(f"Device {serial_number} not found")
            return "device_not_found"
        elif "rndis" in error:
            logging.info(f"Device {serial_number} is in rndis mode")
            return "rndis"
        else:
            logging.info(f"Device {serial_number} is not in rndis mode")
            return "rndis_off"
    except TimeoutExpired:
        process.kill()
        logging.error(f"Timeout during modem status check for device {serial_number}")
        return "timeout"

MODEM_HANDLERS = {
    'any': {
        'on': modem_on_any,
        'off': modem_off_any,
        'status': modem_status_any
    },
    'a2': {
        'on': modem_on_off_a2,  # Assuming a similar 'modem_off_a2' function
        'off': modem_on_off_a2, # Same function can be used for on/off in this case
        'status': modem_status_a2
    }
}

def reestablish_rndis_after_reboot(serial_number, device_type, device_id):
    logging.info(f"Starting reestablishment of rndis after reboot for serial: {serial_number}, type: {device_type}, id: {device_id}")
    
    for _ in range(40):  # Maximum number of reboot status checks
        status = os_boot_status(serial_number)
        logging.info(f"Reboot status: {status}")
        
        if status == "OK":
            break
        time.sleep(10)  # Waiting time between attempts
    
    if device_type not in MODEM_HANDLERS:
        logging.error(f"Unknown device type: {device_type}. Can't reestablish rndis mode.")
        return

    # After reboot, enable rndis mode for the device
    logging.info(f"Turning on rndis for {serial_number} of type {device_type}")
    MODEM_HANDLERS[device_type]['on'](serial_number)
    
    # Fetch new IP address
    logging.info(f"Fetching new IP for {device_id}")
    new_ip = wait_for_ip(device_id)
    
    # Save the new IP address
    logging.info(f"New IP for {device_id} is {new_ip}")
    write_modem_ip(new_ip, device_id)

#Device api manage functions end;

#3Proxy config apiment:

def read_file(filepath):
    try:
        with open(filepath, 'r') as file:
            return file.readlines()
    except Exception as e:
        logging.error(f"Can't read the file {filepath}: {str(e)}")
        return None

def write_file(filepath, data):
    try:
        with open(filepath, 'w') as file:
            file.writelines(data)
        return True
    except Exception as e:
        logging.error(f"Can't write to the file {filepath}: {str(e)}")
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
            logging.warning(f"User {username} not found in ACL")
            return False

        if write_file(ACL_PATH, updated_lines):
            logging.info(f"User {username} successfully removed from ACL")
            return True
        else:
            return False

    except Exception as e:
        logging.error(f"An error occurred while removing user {username} from ACL: {str(e)}")
        return False

def update_user_in_acl(old_username, new_username, new_password):
    try:
        users = read_file(ACL_PATH)
        if users is None:
            logging.error("Failed to read ACL file")
            return False

        updated_users = []
        user_found = False
        for user in users:
            if re.match(f"^{old_username}:CL:", user):
                updated_users.append(f"{new_username}:CL:{new_password}\n")
                user_found = True
            else:
                updated_users.append(user)

        if not user_found:
            logging.warning(f"User {old_username} not found in ACL")
            return False

        if not write_file(ACL_PATH, updated_users):
            logging.error("Failed to write to ACL file")
            return False

        logging.info(f"User {old_username} successfully updated to {new_username} in ACL")
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

def add_user_config(username, mode, parent_ip, ext_ip, http_port, socks_port, id=None):
    try:
        logging.info(f"Attempting to add config for user {username}.")
        config_parts = []

        # Common parts for http and socks
        auth_part = "auth strong"
        allow_part = f"allow {username}"

        # Mode and IP-specific parts
        if mode == "parent" and parent_ip != "none":
            parent_http = f"parent 1000 http {parent_ip} 8080 android android"
            parent_socks = f"parent 1000 socks5 {parent_ip} 1080 android android"
        elif mode == "modem" and parent_ip == "none":
            parent_http = None
            parent_socks = None
        else:
            raise ValueError("Invalid combination of mode and parent_ip")

        # Generate proxy and socks strings based on mode and ext_ip
        if mode == "modem" and id:
            ext_ip_path = f'"/etc/3proxy/modem_ip/{id}"'  # Notice the quotes around the path
            proxy = f"proxy -n -a -p{http_port} -e${ext_ip_path}"
            socks = f"socks -n -a -p{socks_port} -e${ext_ip_path}"
        else:
            proxy = f"proxy -n -a -p{http_port}" if ext_ip == "none" else f"proxy -n -a -p{http_port} -e{ext_ip}"
            socks = f"socks -n -a -p{socks_port}" if ext_ip == "none" else f"socks -n -a -p{socks_port} -e{ext_ip}"

        # Construct the HTTP and SOCKS parts
        http_parts = [
            f"# Start http for {username}",
            "flush",
            auth_part,
            allow_part,
            parent_http,
            proxy,
            f"# End http for {username}"
        ]
        socks_parts = [
            f"# Start socks for {username}",
            "flush",
            auth_part,
            allow_part,
            parent_socks,
            socks,
            f"# End socks for {username}"
        ]

        # Remove any None values
        http_parts = [part for part in http_parts if part is not None]
        socks_parts = [part for part in socks_parts if part is not None]

        # Join the parts together, adding a newline only at the end
        config = "\n".join(http_parts + socks_parts) + "\n"
        write_result = write_config_to_file(config)
        if not write_result:
            raise Exception("Failed to write user config to file.")
        
        logging.info(f"Successfully added config for user {username}.")
        return True
    except Exception as e:
        logging.error(f"Failed to add user config: {str(e)}")
        return False

def remove_user_config(username):
    try:
        logging.info(f"Attempting to remove config for user {username}.")
        lines = read_file(CONFIG_PATH)
        if lines is None:
            logging.error("Failed to read config file")
            return False

        user_removed = False
        new_config = []
        start_http_tag = f"# Start http for {username}"
        end_http_tag = f"# End http for {username}"
        start_socks_tag = f"# Start socks for {username}"
        end_socks_tag = f"# End socks for {username}"

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

def update_user_in_config(old_username, new_username):
    try:
        config = read_file(CONFIG_PATH)
        if config is None:
            logging.error("Failed to read config file")
            return False
        
        config = "".join(config)
        config_updates = {
            f"# Start http for {old_username}": f"# Start http for {new_username}",
            f"# End http for {old_username}": f"# End http for {new_username}",
            f"# Start socks for {old_username}": f"# Start socks for {new_username}",
            f"# End socks for {old_username}": f"# End socks for {new_username}",
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

def user_exists(username):
    try:
        lines = read_file(ACL_PATH)
        if lines is None:
            logging.error("Failed to read ACL file")
            return False

        for line in lines:
            parts = line.split(":")
            if len(parts) > 0 and parts[0] == username:
                logging.info(f"OLD user {username} exists in ACL.")
                return True

        logging.info(f"NEW user {username} does not exist in ACL.")
        return False

    except Exception as e:
        logging.error(f"An error occurred while checking if user exists: {str(e)}")
        return False

def update_auth_in_config(username, protocol, auth_type, allow_ip):
    try:
        lines = read_file(CONFIG_PATH)
        if lines is None:
            logging.error("Failed to read config file")
            return False, "Failed to read config file"

        start_tag = f"# Start {protocol} for {username}"
        end_tag = f"# End {protocol} for {username}"

        pattern = re.compile(f"^# Start {protocol} for {username}$")
        user_exists = any(pattern.match(line.strip()) for line in lines)

        if not user_exists:
            logging.error(f"User {username} does not exist.")
            return False, "User does not exist"

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

def id_exists_in_config(id):
    try:
        content = read_file(CONFIG_PATH)
        if content is None:
            logging.error("An error occurred while reading the config file.")
            return False

        search_string = f'-e$"/etc/3proxy/modem_ip/{id}"'
        if search_string in ''.join(content):
            logging.info(f"ID {id} exists in the configuration.")
            return True

        logging.info(f"ID {id} does not exist in the configuration.")
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

            if mode == "parent":
                adb_reboot_device(serial_number)
                return {'reboot': 'OK', 'message': 'Reboot started.'}, 202

            if mode == "modem":
                adb_reboot_device(serial_number)
                scheduler.add_job(reestablish_rndis_after_reboot, args=[serial_number, device, device_id], id=serial_number)
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

            if not serial_number:
                logging.error("Serial number not found in user data.")
                return {'error': 'Serial number not found'}, 400

            logging.info(f"Received serial number: {serial_number}")
            
            toggle_airplane_mode(serial_number)
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

            # Cancel the scheduled job
            if interval_minutes == '0':
                try:
                    scheduler.remove_job(serial_number)
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
                        func=toggle_airplane_mode, 
                        trigger='interval', 
                        minutes=interval_minutes, 
                        args=[serial_number], 
                        id=serial_number,
                        name=serial_number,
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
            if data is None:
                logging.error("Invalid request: JSON body required.")
                return {"message": "Invalid request: JSON body required"}, 400

            # Get username and user_token from JSON body
            username = data.get('username')
            user_token = data.get('token')
            if not username or not user_token:
                logging.error("Missing required fields: username and/or token.")
                return {"message": "Missing required fields: username and/or token"}, 400

            # Check if the user exists
            if not user_exists(username):
                logging.error("User does not exist.")
                return {"message": "User does not exist"}, 404

            # Check token and username in Redis
            user_data = get_data_from_redis(user_token)
            if not user_data or user_data.get('username') != username:
                logging.error("Invalid username or token.")
                return {"message": "Invalid username or token"}, 400

            # Remove from ACL
            if not remove_user_from_acl(username):
                logging.error("Failed to remove user from ACL.")
                return {"message": "Failed to remove user from ACL"}, 500

            # Remove from configuration
            if not remove_user_config(username):
                logging.error("Failed to remove user from configuration.")
                return {"message": "Failed to remove user from configuration"}, 500

            # Remove from Redis
            result = delete_from_redis(user_token)
            if not result:
                logging.error("Token not found in Redis or failed to remove.")
                return {"message": "Token not found in Redis or failed to remove"}, 404

            logging.info("User deleted successfully.")
            return {"message": "User deleted successfully"}, 200
        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
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

            logging.info(f"Received DATA Username: {username}, Protocol: {protocol}, New Auth Type: {auth_type}")

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
                result1, message1 = update_auth_in_config(username, 'http', auth_type, allow_ip)
                result2, message2 = update_auth_in_config(username, 'socks', auth_type, allow_ip)
                if not result1:
                    messages.append(f"Failed to update HTTP for {username}: {message1}")
                else:
                    messages.append(f"Successfully updated HTTP for {username}")

                if not result2:
                    messages.append(f"Failed to update SOCKS for {username}: {message2}")
                else:
                    messages.append(f"Successfully updated SOCKS for {username}")
            else:
                result, message = update_auth_in_config(username, protocol, auth_type, allow_ip)
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

            required_fields = ['username', 'password', 'mode', 'http_port', 'socks_port', 'serial', 'device']
            if not all(data.get(field) for field in required_fields):
                logging.warning("Missing required fields in data")
                return {"message": "Missing required fields"}, 400

            http_port = data.get('http_port')
            socks_port = data.get('socks_port')

            # Check if the ports are numbers and in the given range
            if not (10000 <= int(http_port) <= 65000 and 10000 <= int(socks_port) <= 65000):
                logging.warning("Port numbers out of allowed range")
                return {"message": "Port numbers should be between 10000 and 65000"}, 400

            username = data.get('username')
            id = data.get('id', None)
            serial = data.get('serial')
            device = data.get('device')
            
            if user_exists(username):
                logging.warning(f"User {username} already exists")
                return {"message": f"User with username {username} already exists"}, 400
            
            logging.info(f"User existence check passed for {username}")

            if serial_exists(serial):
                logging.warning(f"Serial {serial} already exists")
                return {"message": f"Serial {serial} already exists"}, 400

            logging.info(f"Serial existence in Redis check passed for {username}")

            if id and not re.match("^[a-zA-Z]{2}[0-9]{1,3}$", id):
                return {"message": "Invalid ID format"}, 400

            mode = data.get('mode')
            ext_ip = data.get('ext_ip', "none")
            parent_ip = data.get('parent_ip', "none")
            http_port = data.get('http_port', 8080)
            socks_port = data.get('socks_port', 1080)

            logging.info(f"Processing {mode} mode with external IP {ext_ip}")

            if mode == "modem":
                if ext_ip == "none":
                    logging.warning("In modem mode, ext_ip cannot be none")
                    return {"message": "In modem mode, ext_ip is required"}, 400
                if parent_ip == "none" and ext_ip == "none":
                    logging.warning("Both parent_ip and ext_ip cannot be 'none', you have to set ext_ip for modem mode.")
                    return {"message": "Both parent_ip and ext_ip cannot be 'none', you have to set ext_ip for modem mode."}, 400
                elif parent_ip != "none" and ext_ip != "none":
                    logging.warning("Both parent_ip and ext_ip cannot be specified, set only ext_ip for modem mode.")
                    return {"message": "Both parent_ip and ext_ip cannot be specified, set only ext_ip for modem mode."}, 400
                elif ext_ip != "none":
                    if id is None:
                        return {"message": "ID is required for modem mode"}, 400
                    write_modem_ip(ext_ip, id)

            if mode == "parent":
                if parent_ip == "none":
                    logging.warning("In parent mode, parent_ip cannot be none")
                    return {"message": "In parent mode, parent_ip is required"}, 400
                elif parent_ip == "none" and ext_ip == "none":
                    logging.warning("Both parent_ip and ext_ip cannot be 'none', you have to set parent_ip for parent mode.")
                    return {"message": "Both parent_ip and ext_ip cannot be 'none', you have to set parent_ip for parent mode."}, 400
                elif parent_ip != "none" and ext_ip != "none":
                    logging.warning("Both parent_ip and ext_ip cannot be specified, set only parent_ip for parent mode.")
                    return {"message": "Both parent_ip and ext_ip cannot be specified, set only parent_ip for parent mode."}, 400

            token = generate_short_token()
            logging.info(f"Generated token: {token}")

            acl_result = add_user_to_acl(username, data.get('password'))
            config_result = add_user_config(username, mode, parent_ip, ext_ip, http_port, socks_port, id=id)

            if not acl_result:
                logging.error(f"Failed to add user {username} to ACL. Aborting operation.")
                return {"message": "Failed to add user to ACL"}, 500
            else:
                logging.info(f"Successfully added user {username} to ACL.")

            if not config_result:
                logging.error(f"Failed to add user config for {username}. Rolling back ACL.")
                remove_user_from_acl(username)
                return {"message": "Failed to add user config. Rolled back ACL"}, 500
            else:
                logging.info(f"Successfully added user config for {username}.")

            redis_result = store_to_redis({
                "username": username,
                "id": id,
                "serial": serial,
                "mode": mode,
                "device": device,
                "role": "user"
            }, token)
            
            if not redis_result:
                logging.error(f"Failed to store user data to Redis for {username}. Rolling back ACL and config.")
                remove_user_from_acl(username)
                remove_user_config(username)
                return {"message": "Failed to store user data to Redis. Rolled back ACL and config"}, 500
            else:
                logging.info(f"Successfully added data to redis for {username}.")

            logging.info("User added successfully")
            return {"message": "User added successfully", "token": token}, 201  

        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500

class UpdateUser(Resource):
    @requires_role("admin")
    def patch(self, admin_token):
        current_users = None
        current_config = None
        current_user_data = None

        try:
            logging.info("Received request to UPDATE LOGOPASS.")

            data = request.json
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400

            device_token = data.get('device_token')
            if not device_token or not get_data_from_redis(device_token):
                logging.warning("Invalid or missing device token.")
                return {"message": "Invalid or missing device token"}, 400

            old_username = data.get('old_username')  
            new_username = data.get('new_username')
            new_password = data.get('new_password')

            if not old_username or not new_username or not new_password:
                return {"message": "Required data missing"}, 400

            if not user_exists(old_username):
                logging.error(f"User {old_username} does not exist")
                return {"message": f"User {old_username} does not exist"}, 404
            
            if user_exists(new_username):
                logging.error(f"User {new_username} already exists")
                return {"message": f"User {new_username} already exists"}, 409

            # Backup current state
            current_users = read_file(ACL_PATH)
            current_config = read_file(CONFIG_PATH)

            if current_users is None or current_config is None:
                raise Exception("Failed to read files")

            if not update_user_in_acl(old_username, new_username, new_password) or \
               not update_user_in_config(old_username, new_username):
                raise Exception("Failed to update user")

            update_data_in_redis(device_token, 'username', new_username)

            logging.info(f"User {old_username} updated successfully")
            return {"message": f"User {old_username} updated successfully"}, 200

        except Exception as e:
            # Rollback changes
            if current_users:
                write_file(ACL_PATH, current_users)

            if current_config:
                write_file(CONFIG_PATH, current_config)
            
            if current_user_data:
                update_data_in_redis(current_user_token, 'username', current_user_data['username'])

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

class ModemToggle(Resource):
    @requires_role("admin")
    def post(self, admin_token):
        try:
            logging.info("Received request to SWITCH MODEM.")

            data = request.json
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400
            
            serial_number = data.get('serial_number')
            device_model = data.get('device')
            mode = data.get('mode')
            interface_name = data.get('ifname')

            logging.info(f"SWITCHING to {mode} for {interface_name} with serial {serial_number}")

            if not all([serial_number, device_model, mode]):
                return {"message": "Missing required fields"}, 400

            status_handler = MODEM_HANDLERS.get(device_model, {}).get('status')
            status = status_handler(serial_number) if status_handler else None

            if status == "device_not_found":
                logging.error("Device not found, possibly it has lost connection")
                return {"message": "Device not found, possibly it has lost connection"}, 500
            elif status == "timeout":
                logging.error("Device timed out, possibly it has lost connection")
                return {"message": "Device timed out, possibly it has lost connection"}, 500

            if mode == "modem":
                if status == "rndis":
                    ip_address = wait_for_ip(interface_name)
                    if ip_address != '127.0.0.1':
                        logging.info("Modem is already on")
                        return {"message": "Modem is already on", "ip_address": ip_address}, 200
                    logging.error("Interface not ready, unable to get IP address")
                    return {"message": "Interface not ready, unable to get IP address"}, 500
                else:
                    handler = MODEM_HANDLERS.get(device_model, {}).get('on')
                    handler(serial_number)
                    ip_address = wait_for_ip(interface_name)
                    if ip_address != '127.0.0.1':
                        logging.info("Modem turned on successfully")
                        return {"message": "Modem turned on successfully", "ip_address": ip_address}, 200
                    logging.error("Interface not ready, unable to get IP address")
                    return {"message": "Interface not ready, unable to get IP address"}, 500

            elif mode == "parent":
                if status == "rndis":
                    handler = MODEM_HANDLERS.get(device_model, {}).get('off')
                    handler(serial_number)
                    logging.info("Modem turned off successfully")
                    return {"message": "Modem turned off successfully"}, 200
                else:
                    logging.info("Modem is already turned off")
                    return {"message": "Modem is already turned off"}, 200
            else:
                logging.error("Invalid mode provided. Use either 'modem' or 'parent' as mode field.")
                return {"message": "Invalid mode provided. Use either 'modem' or 'parent' as mode field."}, 400

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

# don't use
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
api.add_resource(ModemToggle, '/api/modem/<string:token>') #admin role
# don't useapi.add_resource(ModemStatus, '/api/modemstatus/<string:token>/<string:device_model>') #admin role
api.add_resource(ProxyCount, '/api/proxycount/<string:token>') #admin role

if __name__ == '__main__':
    app.run(debug=True)