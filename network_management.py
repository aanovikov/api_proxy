import logging
import pexpect
import subprocess
from subprocess import Popen, PIPE, TimeoutExpired, run
import netifaces as ni
from dotenv import load_dotenv
import os
import time

load_dotenv()

from settings import TETHERING_COORDINATES

AIRPLANE_ON_CMD = "su -c 'settings put global airplane_mode_on 1; am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true'"
AIRPLANE_OFF_CMD = "su -c 'settings put global airplane_mode_on 0; am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false'"
WIFI_STATUS_CMD = "adb -s {} shell dumpsys wifi | grep 'mNetworkInfo'"

def generate_command(serial_number, coordinates):
    x, y = coordinates
    return f"adb -s {serial_number} shell 'input keyevent KEYCODE_WAKEUP && am start -n com.android.settings/.TetherSettings && sleep 1 && input tap {x} {y}'"

def modem_toggle_coordinates(serial_number, device_model): # a2 and ais need to tap on the toggler
    try:
        if TETHERING_COORDINATES is None:
            logging.error("TETHERING_COORDINATES is not defined")
            return

        if device_model not in TETHERING_COORDINATES:
            logging.error("Invalid device type")
            return

        command = generate_command(serial_number, TETHERING_COORDINATES[device_model])
        logging.info(f"Executing adb command to toggle modem: {command}")

        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode != 0:
            logging.error(f"Error of adb command: {result.stderr.decode()}")
            return

        logging.info(f"Output of adb command: {result.stdout.decode()}")
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e}")
    except Exception as e:
        logging.error(f"COORD: An unexpected error occurred: {e}")

def modem_toggle_cmd(serial_number, mode):
    try:
        if mode not in ['rndis', 'none']:
            logging.error("Invalid mode. Valid modes are 'rndis' or 'none'")
            return
        
        command = f"adb -s {serial_number} shell svc usb setFunctions {mode}"
        logging.info(f"Executing adb command to set modem mode to {mode.upper()}: {command}")

        result = subprocess.run(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode != 0:
            logging.error(f"Failed to execute adb command: {result.stderr.decode()}")
            return

        logging.info(f"Output of adb command: {result.stdout.decode()}")
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e}")
    except Exception as e:
        logging.error(f"CMD: An unexpected error occurred: {e}")

def modem_get_status(serial_number, device_type='any'):
    logging.info(f"Checking modem status for serial: {serial_number}, device model: {device_type}")

    # Базовая команда для запроса статуса модема
    base_command = f"adb -s {serial_number} shell svc usb getFunction"

    # Изменяем команду в зависимости от типа устройства
    if device_type == 'any':
        base_command += "s"

    process = Popen(base_command.split(), stdout=PIPE, stderr=PIPE)
    try:
        stdout, stderr = process.communicate(timeout=10)  # 10 секунд таймаут
        error = stderr.decode()
        #logging.info(f"Received stdout: {stdout.decode()}")
        logging.error(f"Received stderr: {error}")

        if f"device '{serial_number}' not found" in error:
            logging.error(f"Device {serial_number} not found")
            return "device_not_found"
        elif "rndis" in error:
            logging.info(f"Device {serial_number} is in rndis mode")
            return "rndis"
        else:
            logging.info(f"Device {serial_number} is NOT in rndis mode")
            return "rndis_off"
    except TimeoutExpired:
        process.kill()
        logging.error(f"Timeout during modem status check for device {serial_number}")
        return "timeout"

MODEM_HANDLERS = {
    'any': {
        'on': lambda sn: modem_toggle_cmd(sn, 'rndis'),
        'off': lambda sn: modem_toggle_cmd(sn, 'none'),
        'status': lambda sn: modem_get_status(sn, 'any')
    },
    'a2': {
        'on': lambda sn: modem_toggle_coordinates(sn, 'a2'),
        'off': lambda sn: modem_toggle_coordinates(sn, 'a2'),
        'status': lambda sn: modem_get_status(sn, 'a2')
    },
    'ais': {
        'on': lambda sn: modem_toggle_coordinates(sn, 'ais'),
        'off': lambda sn: modem_toggle_coordinates(sn, 'ais'),
        'status': lambda sn: modem_get_status(sn, 'ais')
    }
}

def airplane_toggle_cmd(serial_number, delay=1):
    try:
        logging.info(f"Toggling airplane mode for device {serial_number}")
        adb_command = f"adb -s {serial_number} shell"
        child = pexpect.spawn(adb_command)
        child.expect('\$', timeout=10)

        # Turn airplane mode ON
        airplane_on_command = AIRPLANE_ON_CMD
        logging.info(f"Executing airplane ON command: {airplane_on_command}")
        child.sendline(airplane_on_command)
        child.expect_exact('Broadcast completed: result=0', timeout=10)
        
        logging.info(f"Pause for {delay} seconds")
        time.sleep(delay)

        # Turn airplane mode OFF
        airplane_off_command = AIRPLANE_OFF_CMD
        logging.info(f"Executing airplane OFF command: {airplane_off_command}")
        child.sendline(airplane_off_command)
        child.expect_exact('Broadcast completed: result=0', timeout=10)

        logging.info("Airplane mode toggled and exiting shell.")
        child.sendline('exit')
        child.close()

    except pexpect.exceptions.TIMEOUT as e:
        logging.error("Timeout occurred")
        raise

def toggle_wifi(serial_number, action, delay=1, max_retries=10):
    try:
        logging.info(f"Toggling WiFi for device {serial_number}")

        # Initial status check
        adb_command = f"adb -s {serial_number} shell dumpsys wifi | grep 'mNetworkInfo'"
        output = subprocess.getoutput(adb_command)
        status = output.split('state: ')[1].split('/')[0]
        logging.info(f"Current WiFi status: {status}")

        if action == "on" and status == "CONNECTED":
            logging.info("WiFi is already connected. No action needed.")
            return
        elif action == "off" and status == "DISCONNECTED":
            logging.info("WiFi is already disconnected. No action needed.")
            return

        # Toggle WiFi
        toggle_command = "enable" if action == "on" else "disable"
        subprocess.run(f"adb -s {serial_number} shell svc wifi {toggle_command}", shell=True)
        logging.info(f"Switched WiFi {action.upper()}. Waiting to update status...")

        # Re-check status with delay and retries
        retries = 0
        while retries < max_retries:
            time.sleep(delay)
            output = subprocess.getoutput(adb_command)
            new_status = output.split('state: ')[1].split('/')[0]

            if (action == "on" and new_status == "CONNECTED") or (action == "off" and new_status == "DISCONNECTED"):
                logging.info(f"New WiFi status: {new_status}. Done!")
                return
            
            logging.info(f"Status not updated yet. Retrying... ({retries + 1}/{max_retries})")
            retries += 1

        logging.warning("Max retries reached. Exiting function.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
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