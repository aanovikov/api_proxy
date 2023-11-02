import logging
import pexpect
import subprocess
from subprocess import Popen, PIPE, TimeoutExpired, run
import netifaces as ni
from dotenv import load_dotenv
import os
import time
import re
from celery_instance import celery_app
from settings import TETHERING_COORDINATES, AIRPLANE_MODE_SETTINGS

AIRPLANE_ON_CMD = "su -c 'settings put global airplane_mode_on 1; am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true'"
AIRPLANE_OFF_CMD = "su -c 'settings put global airplane_mode_on 0; am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false'"
WIFI_STATUS_CMD = "adb -s {} shell dumpsys wifi | grep 'mNetworkInfo'"
WAKEUP_DISPLAY = "adb -s {} shell input keyevent 26"
DISPLAY_STATUS = "adb -s {} shell dumpsys power | grep 'Display Power'"
AIRPLANE_MODE_WINDOW = "adb -s {} shell am start -a android.settings.AIRPLANE_MODE_SETTINGS"
TETHER_SETTINGS = "adb -s {} shell am start -n com.android.settings/.TetherSettings"
ACTIVE_WINDOW = "adb -s {} shell dumpsys window windows | grep -E 'mCurrentFocus'"
AIRPLANE_STATUS = "adb -s {} shell settings get global airplane_mode_on"
SCREEN_INPUT = "adb -s {} shell input tap {} {}"
RNDIS_STATUS="adb -s {} shell ip a | grep -E 'usb|rndis'"

def dispatcher(device, serial):
    func = MODEM_HANDLERS.get(device, {}).get('on')
    if func is not None:
        return func(serial)
    else:
        raise ValueError(f"No handler found for device {device} and action {action}")

def modem_toggle_coordinates(serial, device_model): # a2 and ais need to tap on the toggler
    try:
        if TETHERING_COORDINATES is None:
            logging.error(f"TETHERING_COORDINATES is not defined, serial: {serial}, type: {device_model}")
            return

        if device_model not in TETHERING_COORDINATES:
            logging.error(f"Invalid device: serial: {serial}, type: {device_model}")
            return

        coordinates = TETHERING_COORDINATES.get(device_model)
        if coordinates is None:
            logging.error(f"No coordinates found for serial: {serial}")
            return
        x, y = coordinates

        wakeup_command = WAKEUP_DISPLAY.format(serial)
        status_display = DISPLAY_STATUS.format(serial)
        open_settings_command = TETHER_SETTINGS.format(serial)
        active_window_command = ACTIVE_WINDOW.format(serial)
        screen_input_command = SCREEN_INPUT.format(serial, x, y)
        rndis_status = RNDIS_STATUS.format(serial)
        
        logging.info(f'MODEM switching is started: {serial}, type: {device_model}')

        for _ in range(3): # Wake up display and check its status
            logging.debug(f'Waking display UP: serial: {serial}, type: {device_model}')
            subprocess.run(wakeup_command, shell=True)  # Wake up the device
            time.sleep(1)
            start_time = time.time()
            # Check display status within a 5-second time limit
            logging.debug(f'Checking display STATE: serial: {serial}, type: {device_model}')
            while time.time() - start_time <= 5:
                result = subprocess.run(status_display, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if 'state=ON' in result.stdout.decode():
                    logging.debug(f'STATE is ON')
                    break
            else:
                continue  # Restart the loop to try again
            break  # Exit the loop if we successfully activated the display
        else:
            logging.error(f"Display did not turn on after 3 attempts, serial: {serial}")
            return False

        for _ in range(3):  # open tethering settings and check what that window focused
            logging.debug(f'Opening TetherSettings: serial: {serial}, type: {device_model}')
            subprocess.run(open_settings_command, shell=True)
            time.sleep(1)
            start_time = time.time()
            logging.debug(f'Checking if TetherSettings is focused: serial: {serial}, type: {device_model}')
            while time.time() - start_time <= 5:
                result = subprocess.run(active_window_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if 'TetherSettings' in result.stdout.decode():
                    logging.debug(f'TetherSettings is OPENED')
                    break
            else:
                continue
            break
        else:
            logging.error(f"TetherSettings did not open after 3 attempts, serial: {serial}")
            return False

        for _ in range(3):  # tap on coordinates to switch tether mode ON and check status
            logging.debug(f'Tapping on coordinates: serial: {serial}, type: {device_model}')
            subprocess.run(screen_input_command, shell=True)
            time.sleep(4)  # Wait a bit longer to give the system time to adjust
            start_time = time.time()
            logging.debug(f'Checking RNDIS status: serial: {serial}, type: {device_model}')
            while time.time() - start_time <= 5:
                result = subprocess.run(rndis_status, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output = result.stdout.decode()
                match = re.search(r'(rndis0|usb0):.*state (UP|DOWN)', output)
                if match:
                    interface, state = match.groups()
                    if state == "UP":
                        logging.info(f"{interface} is UP")
                        return "UP"
                    else:
                        logging.info(f"{interface} is DOWN")
                        return "DOWN"
            else:
                continue
            break
        else:
            logging.error(f"RNDIS mode did not activate after 3 attempts, serial: {serial}")
            return False

    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e}, serial: {serial}, type: {device_model}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}, serial: {serial}, type: {device_model}")

def modem_toggle_cmd(serial, mode):
    try:
        if mode not in ['rndis', 'none']:
            logging.error(f"Invalid mode: {mode} for serial: {serial}. Valid: 'rndis' or 'none'")
            return
        
        command = f"adb -s {serial} shell svc usb setFunctions {mode}"
        logging.info(f"Setting mode to {mode.upper()}: {command}")

        result = subprocess.run(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode != 0:
            logging.error(f"Failed to execute: {result.stderr.decode()}, serial: {serial}")
            return
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e}, serial: {serial}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}, serial: {serial}")

def modem_get_status(serial, device_type='any'):
    logging.info(f"Checking modem status: serial: {serial}, device model: {device_type}")

    # Базовая команда для запроса статуса модема
    base_command = f"adb -s {serial} shell svc usb getFunction"

    # Изменяем команду в зависимости от типа устройства
    if device_type == 'any':
        base_command += "s"

    process = Popen(base_command.split(), stdout=PIPE, stderr=PIPE)

    try:
        stdout, stderr = process.communicate(timeout=10)  # 10 секунд таймаут
        error = stderr.decode()
        logging.debug(f'COMMAND OUTPUT: {error}')

        if f"device '{serial}' not found" in error:
            logging.error(f"Device not found: serial {serial} ")
            return "device_not_found"
        elif "rndis" in error:
            logging.info(f"Device is MODEM: serial {serial}")
            return "rndis"
        else:
            logging.info(f"Device is NOT MODEM: serial {serial}")
            return "rndis_off"

    except TimeoutExpired:
        process.kill()
        logging.error(f"Timeout modem status checking: serial {serial}")
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
        'status': lambda sn: modem_get_status(sn, 'ais'),
        'toggle_airplane': lambda sn: airplane_toggle_coordinates(sn, 'ais')
    }
}

def airplane_toggle_cmd(serial, device_model, device_id):
    try:
        delay = 1
        logging.info(f"Toggling airplane mode: id{device_id}, type: {device_model}, {serial}")
        adb_command = f"adb -s {serial} shell"
        child = pexpect.spawn(adb_command)
        child.expect('\$', timeout=10)

        # Turn airplane mode ON
        airplane_on_command = AIRPLANE_ON_CMD
        logging.info(f"Executing airplane ON: serial: {serial}") #: {airplane_on_command}")
        child.sendline(airplane_on_command)
        child.expect_exact('Broadcast completed: result=0', timeout=10)
        
        logging.info(f"Pause for {delay} seconds")
        time.sleep(delay)

        # Turn airplane mode OFF
        airplane_off_command = AIRPLANE_OFF_CMD
        logging.info(f"Executing airplane OFF: serial: {serial}") # command": {airplane_off_command}")
        child.sendline(airplane_off_command)
        child.expect_exact('Broadcast completed: result=0', timeout=10)

        logging.info(f"Airplane mode toggled: serial {serial}")
        child.sendline('exit')
        child.close()

    except pexpect.exceptions.TIMEOUT as e:
        logging.error("Timeout occurred")
        raise

def airplane_toggle_coordinates(serial, device_model):
    try:
        logging.debug(f"AIRPLANE_MODE_SETTINGS: {AIRPLANE_MODE_SETTINGS}")
        if AIRPLANE_MODE_SETTINGS is None:
            logging.error(f"AIRPLANE_MODE_SETTINGS is not defined, serial: {serial}, type: {device_model}")
            return
        if device_model not in AIRPLANE_MODE_SETTINGS:
            logging.error(f"Invalid device: type: {device_model}, {serial}")
            return

        coordinates = AIRPLANE_MODE_SETTINGS.get(device_model)
        if coordinates is None:
            logging.error(f"No coordinates found for serial: {serial}")
            return
        x, y = coordinates

        wakeup_command = WAKEUP_DISPLAY.format(serial)
        status_display = DISPLAY_STATUS.format(serial)
        open_settings_command = AIRPLANE_MODE_WINDOW.format(serial)
        active_window_command = ACTIVE_WINDOW.format(serial)
        screen_input_command = SCREEN_INPUT.format(serial, x, y)
        status_airplane = AIRPLANE_STATUS.format(serial)

        result = subprocess.run(status_display, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        is_display_on = 'state=ON' in result.stdout.decode()

        logging.info(f'AIRPLANE switching is started: {serial}, type: {device_model}')

        if not is_display_on:
            for _ in range(3): # Wake up display and check its status
                logging.debug(f'Waking display UP: serial: {serial}, type: {device_model}')
                subprocess.run(wakeup_command, shell=True)  # Wake up the device
                time.sleep(1)
                start_time = time.time()
                # Check display status within a 5-second time limit
                logging.debug(f'Checking display STATE: serial: {serial}, type: {device_model}')
                while time.time() - start_time <= 5:
                    result = subprocess.run(status_display, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if 'state=ON' in result.stdout.decode():
                        break
                else:
                    continue  # Restart the loop to try again
                break  # Exit the loop if we successfully activated the display
            else:
                logging.error(f"Display did not turn on after 3 attempts, serial: {serial}")
                return False
        else:
            logging.info("Display is already ON, skipping the wake-up cycle.")

        for _ in range(3): # open network settings and check what that window focused
            logging.debug(f'Opening TetherSettings: serial: {serial}, type: {device_model}')
            subprocess.run(open_settings_command, shell=True)
            time.sleep(1)
            start_time = time.time()
            logging.debug(f'Checking if TetherSettings is focused: serial: {serial}, type: {device_model}')
            while time.time() - start_time <= 5:
                result = subprocess.run(active_window_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if 'NetworkDashboardActivity' in result.stdout.decode():
                    break
            else:
                continue
            break
        else:
            logging.error(f"NetworkDashboardActivity did not open after 3 attempts, serial: {serial}")
            return False

        for _ in range(3): # tap on coordinates to switch airplane mode ON and check status
            logging.debug(f'Tapping on coordinates 1: serial: {serial}, type: {device_model}')
            subprocess.run(screen_input_command, shell=True)
            time.sleep(1)
            start_time = time.time()
            logging.debug(f'Checking AIRPLANE status: serial: {serial}, type: {device_model}')
            while time.time() - start_time <= 5:
                result = subprocess.run(status_airplane, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if '1' in result.stdout.decode():
                    logging.info(f"AIRPLANE ON")
                    break
            else:
                continue
            break
        else:
            logging.error(f"Airplane mode did not activate after 3 attempts, serial: {serial}")
            return False
        
        time.sleep(1) # wait 1 second before turn ARIPLANE OFF

        for _ in range(3): # tap on coordinates to switch airplane mode OFF and check status
            logging.debug(f'Tapping on coordinates 2: serial: {serial}, type: {device_model}')
            subprocess.run(screen_input_command, shell=True)
            time.sleep(1)
            start_time = time.time()
            while time.time() - start_time <= 5:
                result = subprocess.run(status_airplane, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if '0' in result.stdout.decode():
                    logging.info(f"AIRPLANE OFF")
                    break
            else:
                continue
            break
        else:
            logging.error(f"Airplane mode did not DE-activate after 3 attempts, serial: {serial}")
            return False

        return True
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e}, serial: {serial}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}, serial: {serial}")
        return False

def toggle_wifi(serial, action, delay=1, max_retries=10):
    try:
        logging.info(f"Toggling WiFi for device {serial}")

        # Initial status check
        adb_command = f"adb -s {serial} shell dumpsys wifi | grep 'mNetworkInfo'"
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
        subprocess.run(f"adb -s {serial} shell svc wifi {toggle_command}", shell=True)
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
        logging.info(f"IP address obtained: {interface_name} - {ip_address}")
        return ip_address
    except Exception as e:
        logging.error(f"Couldn't fetch IP for interface {interface_name}: {str(e)}")
        return '127.0.0.1'

def wait_for_ip(interface_name, retries=5, delay=3):
    logging.info(f"Waiting for IP with {retries} retries and {delay}s delay: {interface_name}")
    for i in range(retries):
        ip = get_ip_address(interface_name)
        if ip != '127.0.0.1':
            logging.info(f"Got a valid IP {ip} on attempt {i+1}")
            return ip
        logging.warning(f"Failed to get a valid IP on attempt {i+1}")
        time.sleep(delay)

    logging.error(f"Exceeded max retries for getting IP on interface {interface_name}")
    return '127.0.0.1'

def check_rndis_iface(device_id, serial):
    try:
        rndis_status = RNDIS_STATUS.format(serial)
        start_time = time.time()
        
        while time.time() - start_time <= 5:
            result = subprocess.run(rndis_status, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            output = result.stdout.decode()
            match = re.search(r'(rndis0|usb0):.*state (UP|DOWN)', output)
            
            if match:
                interface, state = match.groups()
                logging.info(f"RNDIS iface is ACTIVE: id{device_id}, serial: {serial}")
                return True
        
        logging.warning(f"RNDIS iface is NOT ACTIVE: id{device_id}, serial: {serial}")
        return False

    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: id{device_id}, serial: {serial}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: id{device_id}, serial: {serial}: {e}")
        return False