import logging
import pexpect
import subprocess
from subprocess import Popen, PIPE, TimeoutExpired, run
import netifaces as ni
from dotenv import load_dotenv
import os
import time
import re
from settings import TETHERING_COORDINATES, AIRPLANE_MODE_SETTINGS, WG_COORDINATES
from storage_management import manage_busy_info_in_redis

logger = logging.getLogger()

AIRPLANE_ON_CMD_SU = "su -c 'settings put global airplane_mode_on 1; am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true'"
AIRPLANE_OFF_CMD_SU = "su -c 'settings put global airplane_mode_on 0; am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false'"
AIRPLANE_ON_CMD = "settings put global airplane_mode_on 1; am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true"
AIRPLANE_OFF_CMD = "settings put global airplane_mode_on 0; am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false"
WIFI_STATUS_CMD = "adb -s {} shell dumpsys wifi | grep 'mNetworkInfo'"
WAKEUP_DISPLAY = "adb -s {} shell input keyevent 26"
BACK = "adb -s {} shell input keyevent 4"
DISPLAY_STATUS = "adb -s {} shell dumpsys power | grep 'Display Power'"
AIRPLANE_MODE_WINDOW = "adb -s {} shell am start -a android.settings.AIRPLANE_MODE_SETTINGS"
TETHER_SETTINGS = "adb -s {} shell am start -n com.android.settings/.TetherSettings"
ACTIVE_WINDOW = "adb -s {} shell dumpsys window windows | grep -E 'mCurrentFocus'"
ACTIVE_WINDOW_ANDROID_10 = "'adb -s {} shell dumpsys window displays | grep -E 'mCurrentFocus'"
AIRPLANE_STATUS = "adb -s {} shell settings get global airplane_mode_on"
SCREEN_INPUT = "adb -s {} shell input tap {} {}"
RNDIS_STATUS = "adb -s {} shell ip a | grep -E 'usb|rndis'"
WG_OPEN = "adb -s {} shell am start -n com.wireguard.android/com.wireguard.android.activity.MainActivity"
WG_STATUS = "adb -s {} shell ip a | grep 10.55.55"
PING = "adb -s {} shell 'ping -c4 10.55.55.1'"

ACT_PUT = 1
ACT_DEL = 0

def dispatcher(device_model, serial, action):
    func = MODEM_HANDLERS.get(device_model, {}).get(action)
    if func is not None:
        return func(serial)
    else:
        raise ValueError(f"No handler found for device {device} and action {action}")

def modem_toggle_coordinates_ON(serial, device_model):
    try:
        if TETHERING_COORDINATES is None:
            logger.error(f"TETHERING_COORDINATES is not defined, serial: {serial}, type: {device_model}")
            return

        if device_model not in TETHERING_COORDINATES:
            logger.error(f"Invalid device: serial: {serial}, type: {device_model}")
            return

        coordinates = TETHERING_COORDINATES.get(device_model)
        if coordinates is None:
            logger.error(f"No coordinates found for serial: {serial}")
            return
        x, y = coordinates

        wakeup_command = WAKEUP_DISPLAY.format(serial)
        go_back = BACK.format(serial)
        status_display = DISPLAY_STATUS.format(serial)
        open_settings_command = TETHER_SETTINGS.format(serial)
        screen_input_command = SCREEN_INPUT.format(serial, x, y)
        rndis_status = RNDIS_STATUS.format(serial)
        
        logger.debug(f'MODEM switching is started: {serial}, type: {device_model}')

        # Check modem status before next actions
        logger.debug(f'Checking RNDIS status 1: serial: {serial}, type: {device_model}')
        result = subprocess.run(rndis_status, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode()
        logger.debug(f'RESULT: {output}')

        # If the output is empty, we assume the interface is DOWN.
        match = None
        if output == "":
            logger.debug(f"Modem interface output is empty, RNDIS is DOWN, attempting to switch ON")
            interface_down = True
        else:
            match = re.search(r'(rndis0|usb0):.*state (DOWN)', output)
            interface_down = bool(match)

        #put info about change ip action to prevent interruption, like a lock
        manage_busy_info_in_redis(serial, ACT_PUT)

        if interface_down:
            # If modem DOWN - switch ON tethering
            if match:
                interface, state = match.groups()
                logger.debug(f"{interface} is DOWN")

            # Wake up display and check its status
            for attempt in range(3):  # Try up to 3 times
                logger.debug(f'Waking display UP: serial: {serial}, type: {device_model}')
                subprocess.run(wakeup_command, shell=True)  # Wake up the device
                time.sleep(1)

                result = subprocess.run(status_display, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if 'state=ON' in result.stdout.decode():
                    logger.debug(f'Display state is ON, proceeding')
                    break
                if attempt == 2:  # Last attempt
                    logger.error(f"Display did not turn on after 3 attempts, serial: {serial}")
                    return False

            # Open tethering settings
            logger.debug(f'Opening tethering settings: serial: {serial}, type: {device_model}')
            subprocess.run(open_settings_command, shell=True)
            time.sleep(2)  # Give the UI time to open
            
            # tap to turn on tethering
            logger.debug(f'Tap to UP tethering: serial: {serial}, type: {device_model}')
            subprocess.run(screen_input_command, shell=True)
            time.sleep(4)

            # Check RNDIS status after tapping
            logger.debug(f'Checking RNDIS status after tapping: serial: {serial}, type: {device_model}')
            result = subprocess.run(rndis_status, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode()
            logger.debug(f'RNDIS status RESULT: {output}')

            # If the output is empty, we still assume the interface is DOWN.
            if output == "":
                logger.error(f"Modem interface output is empty after tapping, assuming RNDIS failed to switch ON")
                logger.debug(f'GO HOME: {serial}, type: {device_model}')
                subprocess.run(go_back, shell=True)
                return False
            else:
                match = re.search(r'(rndis0|usb0):.*state (UP)', output)
                if match:
                    interface, state = match.groups()
                    logger.debug(f"{interface} is now UP after tapping")
                    logger.debug(f'GO HOME: {serial}, type: {device_model}')
                    subprocess.run(go_back, shell=True)
                else:
                    logger.error(f"Failed to enable RNDIS interface, status is not UP after tapping")
                    return False

        else:
            logger.debug(f"Modem interface is already UP or output is not as expected, no action needed")
            logger.debug(f'GO HOME: {serial}, type: {device_model}')
            subprocess.run(go_back, shell=True)

    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with error: {e}, serial: {serial}, type: {device_model}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}, serial: {serial}, type: {device_model}")
    
    finally:
        #delete info about change ip action to prevent interruption, like a unlock
        manage_busy_info_in_redis(serial, ACT_DEL)

def modem_toggle_coordinates_OFF(serial, device_model):
    try:
        if TETHERING_COORDINATES is None:
            logger.error(f"TETHERING_COORDINATES is not defined, serial: {serial}, type: {device_model}")
            return False

        if device_model not in TETHERING_COORDINATES:
            logger.error(f"Invalid device: serial: {serial}, type: {device_model}")
            return False

        coordinates = TETHERING_COORDINATES.get(device_model)
        if coordinates is None:
            logger.error(f"No coordinates found for serial: {serial}")
            return False
        x, y = coordinates

        wakeup_command = WAKEUP_DISPLAY.format(serial)
        go_back = BACK.format(serial)
        status_display = DISPLAY_STATUS.format(serial)
        open_settings_command = TETHER_SETTINGS.format(serial)
        screen_input_command = SCREEN_INPUT.format(serial, x, y)
        rndis_status = RNDIS_STATUS.format(serial)
        
        logger.debug(f'MODEM switching off started: serial: {serial}, type: {device_model}')

        # Check RNDIS status before next actions
        logger.debug(f'Checking RNDIS status before toggling off: serial: {serial}, type: {device_model}')
        result = subprocess.run(rndis_status, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode()
        logger.debug(f'RESULT: {output}')

        #put info about change ip action to prevent interruption, like a lock
        manage_busy_info_in_redis(serial, ACT_PUT)

        # If the output is empty, we assume the interface is DOWN (which is an error if we want to switch off).
        match = None
        if output == "":
            logger.error(f"Modem interface output is empty, assuming RNDIS is already DOWN")
            logger.debug(f'GO HOME: {serial}, type: {device_model}')
            subprocess.run(go_back, shell=True)
            return False
        else:
            match = re.search(r'(rndis0|usb0):.*state (UP)', output)
        if match:
            interface, state = match.groups()
            logger.debug(f"{interface} is UP, attempting to switch OFF")

            # The rest of the function mirrors the ON functionality but designed to switch OFF the interface
            # Wake up display, open settings, tap coordinates, check status...

            # Wake up display and check its status
            for attempt in range(3):  # Try up to 3 times
                logger.debug(f'Waking up display: serial: {serial}, type: {device_model}')
                subprocess.run(wakeup_command, shell=True)  # Wake up the device
                time.sleep(1)

                result = subprocess.run(status_display, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if 'state=ON' in result.stdout.decode():
                    logger.debug(f'Display state is ON, proceeding')
                    break
                if attempt == 2:  # Last attempt
                    logger.error(f"Display did not turn on after 3 attempts, serial: {serial}")
                    return False

            # Open tethering settings
            logger.debug(f'Opening tethering settings: serial: {serial}, type: {device_model}')
            subprocess.run(open_settings_command, shell=True)
            time.sleep(2)  # Give the UI time to open
            
            # Tap to switch off tethering
            logger.debug(f'Tapping to switch OFF tethering: serial: {serial}, type: {device_model}')
            subprocess.run(screen_input_command, shell=True)
            time.sleep(4)

            # Check RNDIS status after tapping
            logger.debug(f'Checking RNDIS status after tapping: serial: {serial}, type: {device_model}')
            result = subprocess.run(rndis_status, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode()
            logger.debug(f'RNDIS status RESULT: {output}')

            if output == "":
                logger.debug(f"Modem interface output is empty after tapping, assuming RNDIS is now DOWN")
            else:
                match = re.search(r'(rndis0|usb0):.*state (DOWN)', output)
                if match:
                    interface, state = match.groups()
                    logger.debug(f"{interface} is now DOWN after tapping")
                else:
                    logger.error(f"Failed to switch OFF RNDIS interface, status is not DOWN after tapping")
                    return False

            logger.debug(f'GO HOME: {serial}, type: {device_model}')
            subprocess.run(go_back, shell=True)
        else:
            logger.debug(f"Modem interface is already DOWN or output is not as expected, no action needed")
            logger.debug(f'GO HOME: {serial}, type: {device_model}')
            subprocess.run(go_back, shell=True)
            return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with error: {e}, serial: {serial}, type: {device_model}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}, serial: {serial}, type: {device_model}")
        return False
    
    finally:
        #delete info about change ip action to prevent interruption, like a unlock
        manage_busy_info_in_redis(serial, ACT_DEL)

def modem_toggle_cmd(serial, mode):
    try:
        if mode not in ['rndis', 'none']:
            logger.error(f"Invalid mode: {mode} for serial: {serial}. Valid: 'rndis' or 'none'")
            return
        
        command = f"adb -s {serial} shell svc usb setFunctions {mode}"
        logger.debug(f"Setting mode to {mode.upper()}: {command}")

        result = subprocess.run(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode != 0:
            logger.error(f"Failed to execute: {result.stderr.decode()}, serial: {serial}")
            return
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with error: {e}, serial: {serial}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}, serial: {serial}")

def modem_get_status(serial, device_model):
    logger.debug(f"Checking modem status: serial: {serial}, device model: {device_model}")

    # Базовая команда для запроса статуса модема
    base_command = f"adb -s {serial} shell svc usb getFunction"

    # Изменяем команду в зависимости от типа устройства
    if device_model in ('SM-A015F', 'J20', '5033D_RU', 'SM-J400F', 'Pixel 2'):
        base_command += "s"
        logger.debug(f'BASE COMMAND + S: {base_command}')
    
    logger.debug(f'BASE COMMAND: {base_command}')
    logger.debug(f'DEVICE: {device_model}')

    process = Popen(base_command.split(), stdout=PIPE, stderr=PIPE)

    try:
        stdout, stderr = process.communicate(timeout=10)  # 10 секунд таймаут
        error = stderr.decode()
        logger.debug(f'COMMAND OUTPUT: {error}')

        if f"device '{serial}' not found" in error:
            logger.error(f"Device not found: serial {serial} ")
            return "device_not_found"
        elif "rndis" in error:
            logger.debug(f"Device is MODEM: serial {serial}")
            return "rndis"
        else:
            logger.debug(f"Device is NOT MODEM: serial {serial}")
            return "rndis_off"

    except TimeoutExpired:
        process.kill()
        logger.error(f"Timeout modem status checking: serial {serial}")
        return "timeout"

MODEM_HANDLERS = {
    'SM-A015F': {
        'modem_on': lambda sn: modem_toggle_cmd(sn, 'rndis'),
        'modem_off': lambda sn: modem_toggle_cmd(sn, 'none'),
        'modem_status': lambda sn: modem_get_status(sn, 'SM-A015F'),
        'toggle_airplane': lambda sn: airplane_toggle_cmd_su(sn, 'SM-A015F'),
        'enable_airplane_mode': lambda sn: enable_airplane_mode_cmd_su(sn, 'SM-A015F'),
        'disable_airplane_mode': lambda sn: disable_airplane_mode_cmd_su(sn, 'SM-A015F'),
        'wg_switcher': lambda sn: wg_switcher(sn, 'SM-A015F')
    },
    'SM-A260G': {
        'modem_on': lambda sn: modem_toggle_coordinates_ON(sn, 'SM-A260G'),
        'modem_off': lambda sn: modem_toggle_coordinates_OFF(sn, 'SM-A260G'),
        'modem_status': lambda sn: modem_get_status(sn, 'SM-A260G'),
        'toggle_airplane': lambda sn: airplane_toggle_cmd_su(sn, 'SM-A260G'),
        'enable_airplane_mode': lambda sn: enable_airplane_mode_cmd_su(sn, 'SM-A260G'),
        'disable_airplane_mode': lambda sn: disable_airplane_mode_cmd_su(sn, 'SM-A260G'),
        'wg_switcher': lambda sn: wg_switcher(sn, 'SM-A260G')
    },
    '5033D_RU': {
        'modem_on': lambda sn: modem_toggle_cmd(sn, 'rndis'),
        'modem_off': lambda sn: modem_toggle_cmd(sn, 'none'),
        'modem_status': lambda sn: modem_get_status(sn, '5033D_RU'),
        'toggle_airplane': lambda sn: airplane_toggle_cmd_su(sn, '5033D_RU'),
        'enable_airplane_mode': lambda sn: enable_airplane_mode_cmd_su(sn, 'Pixel 2'),
        'disable_airplane_mode': lambda sn: disable_airplane_mode_cmd_su(sn, 'Pixel 2')
    },
    'Kingcomm C500': {
        'modem_on': lambda sn: modem_toggle_coordinates_ON(sn, 'Kingcomm C500'),
        'modem_off': lambda sn: modem_toggle_coordinates_OFF(sn, 'Kingcomm C500'),
        'modem_status': lambda sn: modem_get_status(sn, 'Kingcomm C500'),
        'toggle_airplane': lambda sn: airplane_toggle_coordinates(sn, 'Kingcomm C500'),
        'enable_airplane_mode': lambda sn: enable_airplane_mode(sn, 'Kingcomm C500'),
        'disable_airplane_mode': lambda sn: disable_airplane_mode(sn, 'Kingcomm C500'),
        'wg_switcher': lambda sn: wg_switcher(sn, 'Kingcomm C500')
    },
    'J20': {
        'modem_on': lambda sn: modem_toggle_cmd(sn, 'rndis'),
        'modem_off': lambda sn: modem_toggle_cmd(sn, 'none'),
        'modem_status': lambda sn: modem_get_status(sn, 'J20'),
        'toggle_airplane': lambda sn: airplane_toggle_cmd_su(sn, 'J20'),
        'enable_airplane_mode': lambda sn: enable_airplane_mode(sn, 'J20'),
        'disable_airplane_mode': lambda sn: disable_airplane_mode(sn, 'J20'),
        'wg_switcher': lambda sn: wg_switcher(sn, 'J20')
    },
    'Alpha 5G': {
        'modem_on': lambda sn: modem_toggle_coordinates_ON(sn, 'Alpha 5G'),
        'modem_off': lambda sn: modem_toggle_coordinates_OFF(sn, 'Alpha 5G'),
        'modem_status': lambda sn: modem_get_status(sn, 'Alpha 5G'),
        'toggle_airplane': lambda sn: airplane_toggle_coordinates(sn, 'Alpha 5G'),
        'enable_airplane_mode': lambda sn: enable_airplane_mode(sn, 'Alpha 5G'),
        'disable_airplane_mode': lambda sn: disable_airplane_mode(sn, 'Alpha 5G'),
        'wg_switcher': lambda sn: wg_switcher(sn, 'Alpha 5G')
    },
    'SM-J400F': {
        'modem_on': lambda sn: modem_toggle_coordinates_ON(sn, 'SM-J400F'),
        'modem_off': lambda sn: modem_toggle_coordinates_OFF(sn, 'SM-J400F'),
        'modem_status': lambda sn: modem_get_status(sn, 'SM-J400F'),
        'toggle_airplane': lambda sn: airplane_toggle_coordinates(sn, 'SM-J400F'),
        'enable_airplane_mode': lambda sn: enable_airplane_mode(sn, 'SM-J400F'),
        'disable_airplane_mode': lambda sn: disable_airplane_mode(sn, 'SM-J400F'),
        'wg_switcher': lambda sn: wg_switcher(sn, 'SM-J400F')
    },
    'Pixel 2': {
        'modem_on': lambda sn: modem_toggle_coordinates_ON(sn, 'Pixel 2'),
        'modem_off': lambda sn: modem_toggle_coordinates_OFF(sn, 'Pixel 2'),
        'modem_status': lambda sn: modem_get_status(sn, 'Pixel 2'),
        'toggle_airplane': lambda sn: airplane_toggle_coordinates(sn, 'Pixel 2'),
        'enable_airplane_mode': lambda sn: enable_airplane_mode(sn, 'Pixel 2'),
        'disable_airplane_mode': lambda sn: disable_airplane_mode(sn, 'Pixel 2'),
        'wg_switcher': lambda sn: wg_switcher(sn, 'Pixel 2')
    },
    'msm8916_32_512': {
        'modem_on': lambda sn: modem_toggle_cmd(sn, 'rndis'),
        'modem_off': lambda sn: modem_toggle_cmd(sn, 'none'),
        'modem_status': lambda sn: modem_get_status(sn, 'msm8916_32_512'),
        'toggle_airplane': lambda sn: airplane_toggle_cmd(sn, 'msm8916_32_512'),
        'enable_airplane_mode': lambda sn: enable_airplane_mode_cmd(sn, 'msm8916_32_512'),
        'disable_airplane_mode': lambda sn: disable_airplane_mode_cmd(sn, 'msm8916_32_512')
    },
    'UFI': {
        'modem_on': lambda sn: modem_toggle_cmd(sn, 'rndis'),
        'modem_off': lambda sn: modem_toggle_cmd(sn, 'none'),
        'modem_status': lambda sn: modem_get_status(sn, 'UFI'),
        'toggle_airplane': lambda sn: airplane_toggle_cmd(sn, 'UFI'),
        'enable_airplane_mode': lambda sn: enable_airplane_mode_cmd(sn, 'UFI'),
        'disable_airplane_mode': lambda sn: disable_airplane_mode_cmd(sn, 'UFI')
    }
}

def check_airplane(serial):
    try:
        status_airplane = AIRPLANE_STATUS.format(serial)
        result = subprocess.run(status_airplane, shell=True, capture_output=True, text=True, timeout=10)
        if '1' in result.stdout:
            return 1
        elif '0' in result.stdout:
            return 0
        else: 
            raise ValueError("unknown status")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing ADB command: {e}")
        raise

    except subprocess.TimeoutExpired as e:
        logger.error("Timeout occurred")
        raise

def airplane_toggle_cmd(serial, device_model):
    try:
        delay = 1
        adb_base_command = ["adb", "-s", serial, "shell"]
        logger.debug(f"Toggling airplane mode: type: {device_model}, {serial}")

        # Включаем режим в самолете
        airplane_on_command = adb_base_command + [AIRPLANE_ON_CMD]
        logger.debug(f"Executing airplane ON: serial: {serial}")
        result_on = subprocess.run(airplane_on_command, check=True, timeout=10, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.debug(f"Airplane ON stdout: {result_on.stdout}")
        logger.debug(f"Airplane ON stderr: {result_on.stderr}")
        
        logger.debug(f"Pause for {delay} seconds")
        time.sleep(delay)

        if check_airplane(serial) == 1:
            logger.debug(f"AIRPLANE ON")
        else:
            raise RuntimeError("Failed to turn ON airplane mode")

        # Выключаем режим в самолете
        airplane_off_command = adb_base_command + [AIRPLANE_OFF_CMD]
        logger.debug(f"Executing airplane OFF: serial: {serial}")
        result_off = subprocess.run(airplane_off_command, check=True, timeout=10, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.debug(f"Airplane OFF command stdout: {result_off.stdout}")
        logger.debug(f"Airplane OFF command stderr: {result_off.stderr}")
        
        if check_airplane(serial) == 0:
            logger.debug(f"AIRPLANE OFF")
        else:
            raise RuntimeError("Failed to turn OFF airplane mode")

        logger.debug(f"Airplane mode toggled: serial {serial}")
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing ADB command: {e}")
        return False
    except subprocess.TimeoutExpired as e:
        logger.error("Timeout occurred")
        return False

def enable_airplane_mode_cmd(serial, device_model):
    try:
        delay = 1
        adb_base_command = ["adb", "-s", serial, "shell"]
        logger.debug(f"Enabling airplane mode: type: {device_model}, {serial}")

        airplane_on_command = adb_base_command + [AIRPLANE_ON_CMD]
        logger.debug(f"Executing airplane ON: serial: {serial}")
        subprocess.run(airplane_on_command, check=True, timeout=10)

        logger.debug(f"Pause for {delay} seconds")
        time.sleep(delay)

        if check_airplane(serial) == 1:
            logger.debug(f"AIRPLANE ON")
            return True
        else:
            raise RuntimeError("Failed to turn ON airplane mode")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing ADB command: {e}")
        return False
    except subprocess.TimeoutExpired as e:
        logger.error("Timeout occurred")
        return False

def disable_airplane_mode_cmd(serial, device_model):
    try:
        delay = 1
        adb_base_command = ["adb", "-s", serial, "shell"]
        logger.debug(f"Disabling airplane mode: type: {device_model}, {serial}")

        airplane_off_command = adb_base_command + [AIRPLANE_OFF_CMD]
        logger.debug(f"Executing airplane OFF: serial: {serial}")
        subprocess.run(airplane_off_command, check=True, timeout=10)

        logger.debug(f"Pause for {delay} seconds")
        time.sleep(delay)

        if check_airplane(serial) == 0:
            logger.debug(f"AIRPLANE OFF")
            return True
        else:
            raise RuntimeError("Failed to turn OFF airplane mode")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing ADB command: {e}")
        return False
    except subprocess.TimeoutExpired as e:
        logger.error("Timeout occurred")
        return False

def airplane_toggle_cmd_su(serial, device_model):
    try:
        delay = 1
        adb_base_command = ["adb", "-s", serial, "shell"]
        logger.debug(f"Toggling airplane mode: type: {device_model}, {serial}")

        # Включаем режим в самолете
        airplane_on_command = adb_base_command + [AIRPLANE_ON_CMD_SU]
        logger.debug(f'NO SU: {airplane_on_command}')
        logger.debug(f"Executing airplane ON: serial: {serial}")
        result_on = subprocess.run(airplane_on_command, check=True, timeout=10, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.debug(f"Airplane ON stdout: {result_on.stdout}")
        logger.debug(f"Airplane ON stderr: {result_on.stderr}")
        
        logger.debug(f"Pause for {delay} seconds")
        time.sleep(delay)

        if check_airplane(serial) == 1:
            logger.debug(f"AIRPLANE ON")
        else:
            raise RuntimeError("Failed to turn ON airplane mode")

        # Выключаем режим в самолете
        airplane_off_command = adb_base_command + [AIRPLANE_OFF_CMD_SU]
        logger.debug(f"Executing airplane OFF: serial: {serial}")
        result_off = subprocess.run(airplane_off_command, check=True, timeout=10, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.debug(f"Airplane OFF command stdout: {result_off.stdout}")
        logger.debug(f"Airplane OFF command stderr: {result_off.stderr}")

        if check_airplane(serial) == 0:
            logger.debug(f"AIRPLANE OFF")
        else:
            raise RuntimeError("Failed to turn OFF airplane mode")

        logger.debug(f"Airplane mode toggled: serial {serial}")
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing ADB command: {e}")
        return False
    except subprocess.TimeoutExpired as e:
        logger.error("Timeout occurred")
        return False

def enable_airplane_mode_cmd_su(serial, device_model):
    try:
        delay = 1
        adb_base_command = ["adb", "-s", serial, "shell"]
        logger.debug(f"Enabling airplane mode SU: type: {device_model}, {serial}")

        airplane_on_command = adb_base_command + [AIRPLANE_ON_CMD_SU]
        logger.debug(f'NO SU: {airplane_on_command}')
        logger.debug(f"Executing airplane ON SU: serial: {serial}")
        subprocess.run(airplane_on_command, check=True, timeout=10)

        logger.debug(f"Pause for {delay} seconds")
        time.sleep(delay)

        if check_airplane(serial) == 1:
            logger.debug(f"AIRPLANE ON SU")
            return True
        else:
            raise RuntimeError("Failed to turn ON airplane mode SU")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing ADB SU command: {e}")
        return False
    except subprocess.TimeoutExpired as e:
        logger.error("SU command timeout occurred")
        return False

def disable_airplane_mode_cmd_su(serial, device_model):
    try:
        delay = 1
        adb_base_command = ["adb", "-s", serial, "shell"]
        logger.debug(f"Disabling airplane mode SU: type: {device_model}, {serial}")

        airplane_off_command = adb_base_command + [AIRPLANE_OFF_CMD_SU]
        logger.debug(f"Executing airplane OFF SU: serial: {serial}")
        subprocess.run(airplane_off_command, check=True, timeout=10)

        logger.debug(f"Pause for {delay} seconds")
        time.sleep(delay)

        if check_airplane(serial) == 0:
            logger.debug(f"AIRPLANE OFF SU")
            return True
        else:
            raise RuntimeError("Failed to turn OFF airplane mode SU")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing ADB SU command: {e}")
        return False
    except subprocess.TimeoutExpired as e:
        logger.error("SU command timeout occurred")
        return False

def airplane_toggle_coordinates(serial, device_model):
    try:
        logger.debug(f"AIRPLANE_MODE_SETTINGS: {AIRPLANE_MODE_SETTINGS}")
        if AIRPLANE_MODE_SETTINGS is None:
            logger.error(f"AIRPLANE_MODE_SETTINGS is not defined, serial: {serial}, type: {device_model}")
            return
        if device_model not in AIRPLANE_MODE_SETTINGS:
            logger.error(f"Invalid device: type: {device_model}, {serial}")
            return

        coordinates = AIRPLANE_MODE_SETTINGS.get(device_model)
        if coordinates is None:
            logger.error(f"No coordinates found for serial: {serial}")
            return
        x, y = coordinates

        wakeup_command = WAKEUP_DISPLAY.format(serial)
        go_back = BACK.format(serial)
        status_display = DISPLAY_STATUS.format(serial)
        open_settings_command = AIRPLANE_MODE_WINDOW.format(serial)
        active_window_command = ACTIVE_WINDOW.format(serial)
        screen_input_command = SCREEN_INPUT.format(serial, x, y)
        status_airplane = AIRPLANE_STATUS.format(serial)

        #put info about change ip action to prevent interruption, like a lock
        manage_busy_info_in_redis(serial, ACT_PUT)

        result = subprocess.run(status_display, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        is_display_on = 'state=ON' in result.stdout.decode()

        logger.debug(f'AIRPLANE switching is started: {serial}, type: {device_model}')

        if not is_display_on:
            for _ in range(3): # Wake up display and check its status
                logger.debug(f'Waking display UP: serial: {serial}, type: {device_model}')
                subprocess.run(wakeup_command, shell=True)  # Wake up the device
                time.sleep(1)
                start_time = time.time()
                # Check display status within a 5-second time limit
                logger.debug(f'Checking display STATE: serial: {serial}, type: {device_model}')
                while time.time() - start_time <= 3:
                    result = subprocess.run(status_display, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if 'state=ON' in result.stdout.decode():
                        break
                else:
                    continue  # Restart the loop to try again
                break  # Exit the loop if we successfully activated the display
            else:
                logger.error(f"Display did not turn on after 3 attempts, serial: {serial}")
                return False
        else:
            logger.debug("Display is already ON, skipping the wake-up cycle.")

        logger.debug(f'Opening Airplane settings: serial: {serial}, type: {device_model}')
        subprocess.run(open_settings_command, shell=True)
        logger.debug(f'Opened Airplane settings and wait 2 sec: {serial}, type: {device_model}')
        time.sleep(2)

        for _ in range(3):  # tap on coordinates to switch airplane mode ON and check status
            logger.debug(f'Tapping on coordinates 1: serial: {serial}, type: {device_model}')
            subprocess.run(screen_input_command, shell=True)
            time.sleep(1)
            start_time = time.time()
            logger.debug(f'Checking AIRPLANE status: serial: {serial}, type: {device_model}')
            while time.time() - start_time <= 3:
                result = subprocess.run(status_airplane, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if '1' in result.stdout.decode():
                    logger.debug(f"AIRPLANE ON")
                    break
            else:
                # Если режим самолета не включился, то переходим к следующей итерации цикла for
                continue  # Это continue здесь действительно необходимо, чтобы продолжить следующую итерацию цикла for
            # Если режим самолета включился, прерываем цикл for
            break
        else:
            # Этот блок else относится к циклу for и выполнится только если цикл for не был прерван
            logger.error(f"Airplane mode did not activate after 3 attempts, serial: {serial}")
            return False
        
        time.sleep(1) # wait 1 second before turn ARIPLANE OFF

        for _ in range(3): # tap on coordinates to switch airplane mode OFF and check status
            logger.debug(f'Tapping on coordinates 2: serial: {serial}, type: {device_model}')
            subprocess.run(screen_input_command, shell=True)
            time.sleep(1)
            start_time = time.time()
            while time.time() - start_time <= 3:
                result = subprocess.run(status_airplane, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if '0' in result.stdout.decode():
                    logger.debug(f"AIRPLANE OFF")
                    break
            else:
                continue
            break
        else:
            logger.error(f"Airplane mode did not DE-activate after 3 attempts, serial: {serial}")
            return False
        logger.debug(f'GO HOME: {serial}, type: {device_model}')
        subprocess.run(go_back, shell=True)
        subprocess.run(go_back, shell=True)
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with error: {e}, serial: {serial}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}, serial: {serial}")
        return False

    finally:
        #delete info about change ip action to prevent interruption, like a unlock
        manage_busy_info_in_redis(serial, ACT_DEL)

def get_airplane_mode_coordinates(serial, device_model):
    if AIRPLANE_MODE_SETTINGS is None:
        logger.error(f"AIRPLANE_MODE_SETTINGS is not defined, serial: {serial}, type: {device_model}")
        return None
    if device_model not in AIRPLANE_MODE_SETTINGS:
        logger.error(f"Invalid device: type: {device_model}, {serial}")
        return None
    coordinates = AIRPLANE_MODE_SETTINGS.get(device_model)
    if coordinates is None:
        logger.error(f"No coordinates found for serial: {serial}")
        return None
    return coordinates

def enable_airplane_mode(serial, device_model):
    try:
        coordinates = get_airplane_mode_coordinates(serial, device_model)
        if coordinates is None:
            logger.error(f'No coordinates found for serial: {serial}, model: {device_model}')
            return f'No coordinates found for serial: {serial}, model: {device_model}'
        x, y = coordinates

        wakeup_command = WAKEUP_DISPLAY.format(serial)
        go_back = BACK.format(serial)
        status_display = DISPLAY_STATUS.format(serial)
        open_settings_command = AIRPLANE_MODE_WINDOW.format(serial)
        active_window_command = ACTIVE_WINDOW.format(serial)
        screen_input_command = SCREEN_INPUT.format(serial, x, y)
        status_airplane = AIRPLANE_STATUS.format(serial)
        
        #put info about change ip action to prevent interruption, like a lock
        manage_busy_info_in_redis(serial, ACT_PUT)

        #wake up display and check it
        result = subprocess.run(status_display, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        is_display_on = 'state=ON' in result.stdout.decode()

        logger.debug(f'AIRPLANE switching is started: {serial}, type: {device_model}')

        if not is_display_on:
            for _ in range(3): # Wake up display and check its status
                logger.debug(f'Waking display UP: serial: {serial}, type: {device_model}')
                subprocess.run(wakeup_command, shell=True)  # Wake up the device
                time.sleep(1)
                start_time = time.time()
                # Check display status within a 5-second time limit
                logger.debug(f'Checking display STATE: serial: {serial}, type: {device_model}')
                while time.time() - start_time <= 3:
                    result = subprocess.run(status_display, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if 'state=ON' in result.stdout.decode():
                        break
                else:
                    continue  # Restart the loop to try again
                break  # Exit the loop if we successfully activated the display
            else:
                logger.error(f"Display did not turn on after 3 attempts, serial: {serial}")
                return False
        else:
            logger.debug("Display is already ON, skipping the wake-up cycle.")

        logger.debug(f'Opening Airplane settings: serial: {serial}, type: {device_model}')
        subprocess.run(open_settings_command, shell=True)
        logger.debug(f'Opened Airplane settings and wait 2 sec: {serial}, type: {device_model}')
        time.sleep(2)

        for _ in range(3):  # tap on coordinates to switch airplane mode ON and check status
            logger.debug(f'Tapping on coordinates 1: serial: {serial}, type: {device_model}')
            subprocess.run(screen_input_command, shell=True)
            time.sleep(1)
            start_time = time.time()
            logger.debug(f'Checking AIRPLANE status: serial: {serial}, type: {device_model}')
            while time.time() - start_time <= 3:
                result = subprocess.run(status_airplane, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if '1' in result.stdout.decode():
                    logger.debug(f"AIRPLANE ON")
                    break
            else:
                # Если режим самолета не включился, то переходим к следующей итерации цикла for
                continue  # Это continue здесь действительно необходимо, чтобы продолжить следующую итерацию цикла for
            # Если режим самолета включился, прерываем цикл for
            break
        else:
            # Этот блок else относится к циклу for и выполнится только если цикл for не был прерван
            logger.error(f"Airplane mode did not activate after 3 attempts, serial: {serial}")
            return False

        logger.debug(f'GO HOME: {serial}, type: {device_model}')
        subprocess.run(go_back, shell=True)
        subprocess.run(go_back, shell=True)
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with error: {e}, serial: {serial}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}, serial: {serial}")
        return False
    
    finally:
        #delete info about change ip action to prevent interruption, like a unlock
        manage_busy_info_in_redis(serial, ACT_DEL)

def disable_airplane_mode(serial, device_model):
    try:
        coordinates = get_airplane_mode_coordinates(serial, device_model)
        if coordinates is None:
            logger.error(f'No coordinates found for serial: {serial}, model: {device_model}')
            return f'No coordinates found for serial: {serial}, model: {device_model}'
        x, y = coordinates

        wakeup_command = WAKEUP_DISPLAY.format(serial)
        go_back = BACK.format(serial)
        status_display = DISPLAY_STATUS.format(serial)
        open_settings_command = AIRPLANE_MODE_WINDOW.format(serial)
        active_window_command = ACTIVE_WINDOW.format(serial)
        screen_input_command = SCREEN_INPUT.format(serial, x, y)
        status_airplane = AIRPLANE_STATUS.format(serial)

        #put info about change ip action to prevent interruption, like a lock
        manage_busy_info_in_redis(serial, ACT_PUT)

        result = subprocess.run(status_display, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        is_display_on = 'state=ON' in result.stdout.decode()

        logger.debug(f'AIRPLANE switching is started: {serial}, type: {device_model}')

        if not is_display_on:
            for _ in range(3): # Wake up display and check its status
                logger.debug(f'Waking display UP: serial: {serial}, type: {device_model}')
                subprocess.run(wakeup_command, shell=True)  # Wake up the device
                time.sleep(1)
                start_time = time.time()
                # Check display status within a 5-second time limit
                logger.debug(f'Checking display STATE: serial: {serial}, type: {device_model}')
                while time.time() - start_time <= 3:
                    result = subprocess.run(status_display, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if 'state=ON' in result.stdout.decode():
                        break
                else:
                    continue  # Restart the loop to try again
                break  # Exit the loop if we successfully activated the display
            else:
                logger.error(f"Display did not turn on after 3 attempts, serial: {serial}")
                return False
        else:
            logger.debug("Display is already ON, skipping the wake-up cycle.")

        logger.debug(f'Opening Airplane settings: serial: {serial}, type: {device_model}')
        subprocess.run(open_settings_command, shell=True)
        logger.debug(f'Opened Airplane settings and wait 2 sec: {serial}, type: {device_model}')
        time.sleep(2)

        for _ in range(3): # tap on coordinates to switch airplane mode OFF and check status
            logger.debug(f'Tapping on coordinates 2: serial: {serial}, type: {device_model}')
            subprocess.run(screen_input_command, shell=True)
            time.sleep(1)
            start_time = time.time()
            while time.time() - start_time <= 3:
                result = subprocess.run(status_airplane, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if '0' in result.stdout.decode():
                    logger.debug(f"AIRPLANE OFF")
                    break
            else:
                continue
            break
        else:
            logger.error(f"Airplane mode did not DE-activate after 3 attempts, serial: {serial}")
            return False
            
        logger.debug(f'GO HOME: {serial}, type: {device_model}')
        subprocess.run(go_back, shell=True)
        subprocess.run(go_back, shell=True)
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with error: {e}, serial: {serial}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}, serial: {serial}")
        return False
    
    finally:
        #delete info about change ip action to prevent interruption, like a unlock
        manage_busy_info_in_redis(serial, ACT_DEL)

def toggle_wifi(serial, action, delay=1, max_retries=10):
    try:
        logger.debug(f"Toggling WiFi for device {serial}")

        # Initial status check
        adb_command = f"adb -s {serial} shell dumpsys wifi | grep 'mNetworkInfo'"
        output = subprocess.getoutput(adb_command)
        status = output.split('state: ')[1].split('/')[0]
        logger.debug(f"Current WiFi status: {status}")

        if action == "on" and status == "CONNECTED":
            logger.debug("WiFi is already connected. No action needed.")
            return
        elif action == "off" and status == "DISCONNECTED":
            logger.debug("WiFi is already disconnected. No action needed.")
            return

        # Toggle WiFi
        toggle_command = "enable" if action == "on" else "disable"
        subprocess.run(f"adb -s {serial} shell svc wifi {toggle_command}", shell=True)
        logger.debug(f"Switched WiFi {action.upper()}. Waiting to update status...")

        # Re-check status with delay and retries
        retries = 0
        while retries < max_retries:
            time.sleep(delay)
            output = subprocess.getoutput(adb_command)
            new_status = output.split('state: ')[1].split('/')[0]

            if (action == "on" and new_status == "CONNECTED") or (action == "off" and new_status == "DISCONNECTED"):
                logger.debug(f"New WiFi status: {new_status}. Done!")
                return
            
            logger.debug(f"Status not updated yet. Retrying... ({retries + 1}/{max_retries})")
            retries += 1

        logger.warning("Max retries reached. Exiting function.")

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        raise

def get_ip_address(interface_name):
    try:
        ip_address = ni.ifaddresses(interface_name)[ni.AF_INET][0]['addr']
        logger.debug(f"IP address obtained: {interface_name} - {ip_address}")
        return ip_address
    except Exception as e:
        logger.error(f"Couldn't fetch IP for interface {interface_name}: {str(e)}")
        return '127.0.0.1'

def wait_for_ip(interface_name, retries=5, delay=3):
    logger.debug(f"Waiting for IP with {retries} retries and {delay}s delay: {interface_name}")
    for i in range(retries):
        ip = get_ip_address(interface_name)
        if ip != '127.0.0.1':
            logger.debug(f"Got a valid IP {ip} on attempt {i+1}")
            return ip
        logger.warning(f"Failed to get a valid IP on attempt {i+1}")
        time.sleep(delay)

    logger.error(f"Exceeded max retries for getting IP on interface {interface_name}")
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
                logger.debug(f"RNDIS iface is ACTIVE: id{device_id}, serial: {serial}")
                return True
        
        logger.warning(f"RNDIS iface is NOT ACTIVE: id{device_id}, serial: {serial}")
        return False

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: id{device_id}, serial: {serial}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred: id{device_id}, serial: {serial}: {e}")
        return False

def handle_adb_errors(stderr_output, device_id, serial):
    if "device '{}' not found".format(serial) in stderr_output:
        error_message = f"error: device '{serial}' not found"
    elif 'offline' in stderr_output:
        error_message = "ADB device offline"
    elif 'unauthorized' in stderr_output:
        error_message = "ADB unauthorized"
    else:
        error_message = "General ADB error"

    logger.error(f"{error_message}: {device_id}")
    return error_message

def get_wg_ip(serial, device_id):
    try:
        wg_status = WG_STATUS.format(serial)
        wg_status_result = subprocess.run(wg_status, shell=True, capture_output=True, text=True, timeout=10)

        if wg_status_result.stderr.strip():
            return handle_adb_errors(wg_status_result.stderr.strip(), device_id, serial)

        if not wg_status_result.stdout.strip():
            logger.debug(f'WG result: {wg_status_result}')
            logger.error(f"No output, seems WG disconnected: {device_id}")
            return False

        vpn_ip = re.search(r'10\.55\.55\.\d+', wg_status_result.stdout)
        if vpn_ip:
            logger.debug(f'WG result: {wg_status_result}')
            return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing command: {device_id}: {e}")
        raise Exception("Error executing WG status command")
    
    except subprocess.TimeoutExpired:
        logger.error(f'Timeout executing adb ping: {device_id} ({timeout} seconds)')
        return 'TIMEOUT adb ping'

    except subprocess.SubprocessError as e:
        logger.error(f'ADB connection error: {device_id}: {e}')
        return 'ERROR ADB'

def ping(serial, device_id, timeout=15):
    try:
        ping_command = PING.format(serial)
        ping_command_result = subprocess.run(ping_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        output = ping_command_result.stdout.decode()
        logger.debug(f"Ping output: {device_id}: {output}")

        if ping_command_result.stderr.strip():
            return handle_adb_errors(ping_command_result.stderr.strip(), device_id, serial)

        match = re.search(r'\d+%\s+packet\s+loss', output)
        if match:
            packet_loss = int(match.group().split('%')[0])
            logger.info(f"id{device_id}: {packet_loss}% packets loss")
            if packet_loss < 100:
                return True
            else:
                return False
        else:
            logger.warning(f"Unable to determine packet loss: {device_id}")
            return 'Unknown status'

    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing command: {device_id}: {e}")
        raise Exception("Error executing WG status command")
        
    except subprocess.TimeoutExpired:
        logger.error(f'Timeout executing adb ping: {device_id} ({timeout} seconds)')
        return 'TIMEOUT adb ping'

    except subprocess.SubprocessError as e:
        logger.error(f'ADB connection error: {device_id}: {e}')
        return 'ERROR ADB'

def wg_switcher(serial, device_model, device_id='unknown', timeout=15):
    try:
        coordinates = WG_COORDINATES.get(device_model)
        if coordinates is None:
            logger.error(f"No coordinates found for serial: {serial}")
            return False

        x, y = coordinates

        wakeup_command = WAKEUP_DISPLAY.format(serial)
        go_back = BACK.format(serial)
        status_display = DISPLAY_STATUS.format(serial)
        open_settings_command = WG_OPEN.format(serial)
        screen_input_command = SCREEN_INPUT.format(serial, x, y)

        logger.debug(f'params: {serial}, {device_model}, {device_id}, screen_input: {screen_input_command}')

        # Wake up display and check its status
        result = subprocess.run(status_display, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        is_display_on = 'state=ON' in result.stdout.decode()

        logger.debug(f'AIRPLANE switching is started: {serial}, type: {device_model}')

        if not is_display_on:
            for _ in range(3): # Wake up display and check its status
                logger.debug(f'Waking display UP: serial: {serial}, type: {device_model}')

                wakeup_command_result = subprocess.run(wakeup_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)  # Wake up the device
                if wakeup_command_result.stderr.strip():
                    return handle_adb_errors(wakeup_command_result.stderr.strip(), device_id, serial)

                time.sleep(1)
                start_time = time.time()

                # Check display status within a 5-second time limit
                logger.debug(f'Checking display STATE: serial: {serial}, type: {device_model}')

                while time.time() - start_time <= 3:
                    result = subprocess.run(status_display, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
                    if result.stderr.strip():
                        return handle_adb_errors(result.stderr.strip(), device_id, serial)
                    if 'state=ON' in result.stdout.decode():
                        break
                else:
                    continue  # Restart the loop to try again
                break  # Exit the loop if we successfully activated the display
            else:
                logger.error(f"Display did not turn on after 3 attempts, serial: {serial}")
                return False
        else:
            logger.debug("Display is already ON, skipping the wake-up cycle.")

        # Open WG settings
        logger.debug(f'Opening Wireguard: id{device_id}, type: {device_model}')
        open_result = subprocess.run(open_settings_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if open_result.stderr.strip():
            return handle_adb_errors(open_result.stderr.strip(), device_id, serial)

        time.sleep(1)  # Give the UI time to open
        
        # tap to switch WG
        logger.debug(f'Tap to switch WG: id{device_id}, type: {device_model}')
        tap_result = subprocess.run(screen_input_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if tap_result.stderr.strip():
            return handle_adb_errors(tap_result.stderr.strip(), device_id, serial)

        time.sleep(1)

        # Go back
        logger.debug(f'Go back: id{device_id}, type: {device_model}')
        back_result = subprocess.run(go_back, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if back_result.stderr.strip():
            return handle_adb_errors(back_result.stderr.strip(), device_id, serial)

        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing command: {device_id}: {e}")
        raise Exception("Error executing WG status command")

    except subprocess.TimeoutExpired:
        logger.error(f'Timeout executing adb ping: {device_id} ({timeout} seconds)')
        return 'TIMEOUT adb ping'

    except subprocess.SubprocessError as e:
        logger.error(f'ADB connection error: {device_id}: {e}')
        return 'ERROR ADB'