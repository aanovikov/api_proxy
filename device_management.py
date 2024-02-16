import logging
import subprocess
from subprocess import Popen, PIPE, TimeoutExpired, run
import time
from network_management import MODEM_HANDLERS, check_rndis_iface

ADB_DEVICES_TID = ['adb', 'devices', '-l']
ADB_GET_SERIAL = ['adb', '-t', '{tid}', 'shell', 'getprop', 'ro.serialno']

logger = logging.getLogger()

def check_device_ready(serial, device, device_id, tid=None):
    for i in range(3):
        status = os_boot_status(serial, device, device_id, enable_modem=False, tid=tid)
        if status == 'OK':
            logger.info(f"Device {serial} is READY!")  # Используйте logger.info для подтверждения готовности устройства
            return {'status': 'OK', 'message': 'Device is ready.'}, 200
        else:
            logger.warning(f"Device is not ready yet: {status}. Retry {i+1}/3")
            time.sleep(2)
    return {'status': 'in progress', 'message': 'Device not ready.'}, 200

def get_tid_usb_port():
    result = {}

    logging.debug("starting run subprocess cmd")
    try:
        adb_output = subprocess.check_output(ADB_DEVICES_TID).decode("utf-8")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running adb devices -l: {e}")
        raise e

    # Проверка наличия устройств
    logging.debug("starting get adb devices list")
    if "List of devices attached" in adb_output:
        adb_lines = adb_output.strip().split('\n')
    else:
        logging.warning("No devices found in adb devices output")
        return result

    # Регулярное выражение для поиска transport_id и usb
    pattern = re.compile(r'device usb:([^\s]+).*transport_id:(\d+)')

    for line in adb_lines:
        match = pattern.search(line)
        if match:
            usb_bus, transport_id = match.groups()
            result[transport_id] = usb_bus
        else:
            logging.debug(f"Skipping line, no match found: {line}")

    if not result:
        logging.warning("No devices with transport_id found in adb devices output")
    else:
        logging.info("Got adb devices list successfully.")

    return result

def adb_reboot_device(serial, device_id, tid=tid):
    adb_reboot = f"adb -s {serial} reboot"
    logger.debug(f"Executing reboot: id{device_id}, serial: {serial}")
    result = subprocess.run(adb_reboot.split(), stdout=subprocess.PIPE)
    logger.debug(f"ADB reboot output : {result.stdout.decode()}")

def get_adb_device_status(serial, device_id, max_retries=5, delay=3, tid=None):
    adb_command = ["adb", "-s", serial, "get-state"] if not tid else ["adb", "-t", tid, "get-state"]
    
    for i in range(max_retries):
        try:
            output = subprocess.check_output(adb_command, stderr=subprocess.STDOUT).decode('utf-8').strip()
            device_reference = serial if not tid else f"TID_{tid}"
            logger.info(f"Device status: {output}, id: {device_id}, reference: {device_reference}")
            
            if output == "device":
                return "device"
            elif output in ["offline", "unauthorized", "bootloader"]:
                return output
                
        except subprocess.CalledProcessError as e:
            error_output = e.output.decode('utf-8').strip()

            if "device not found" in error_output:
                return "device_not_found"
            logger.error(f"Attempt {i+1}: id: {device_id}, reference: {device_reference}, {error_output}")
            
        time.sleep(delay)
        delay *= 2  # Экспоненциальная задержка

    logger.error(f"Max retries reached. Device not stable: id: {device_id}, reference: {device_reference}")
    return "Unknown ADB status"

def os_boot_status(serial, device, device_id, enable_modem=False, tid=None):
    # Если tid предоставлен, работаем с ним, иначе используем serial
    adb_command_prefix = f"adb -s {serial}" if not tid else f"adb -t {tid}"

    # Проверяем статус ADB до выполнения команды getprop
    device_status = get_adb_device_status(serial, device_id, tid=tid) if tid else get_adb_device_status(serial, device_id)
    if device_status != "device":
        logger.warning(f"ADB NOT READY: {device_status} waiting 10s for next attempt")
        return f'ADB NOT READY: {device_status} waiting 10s for next attempt'
    logger.debug(f'ADB READY: {device_status}, id{device_id}, serial: {serial}')

    adb_get_boot_completed = f"{adb_command_prefix} shell getprop sys.boot_completed"
    logger.debug(f"OS BOOT checking: id{device_id}, serial: {serial}")

    try:
        process = Popen(adb_get_boot_completed.split(), stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate(timeout=10)
        output = stdout.decode('utf-8').strip()

        if output == '1':
            logger.debug(f"OS READY: id{device_id}, serial: {serial}")
            if enable_modem:
                logger.debug(f'Requires to turn modem ON: id{device_id}, serial: {serial}')

                if device not in MODEM_HANDLERS:
                    logger.error(f"Unknown device model: {device}. Can't reestablish rndis for ID: {device_id}, serial: {serial}")
                    return 'Device model not supported'
                            
                for attempt in range(3):
                    logger.debug(f'Calling MODEM_HANDLERS to turn modem ON: id{device_id}, serial: {serial}')
                    MODEM_HANDLERS[device]['on'](serial)
                    logger.debug(f'PAUSE 5s. before check RNDIS iface')
                    time.sleep(5)

                    logger.debug(f'Cheking RNDIS iface: id{device_id}, serial: {serial}')
                    if check_rndis_iface(device_id, serial):
                        logger.info(f"Modem turned on: id{device_id}, serial: {serial}")  # Вызываем функцию для включения режима модема
                        scheduler.remove_job(f"modem_{serial}")
                        break
                    else:
                        logger.warning(f"Attempt {attempt+1}: Failed to turn on modem. Retrying...")
                        logger.debug(f'PAUSE 3s. before next attempt to turn on modem')
                        time.sleep(3)
                else:
                    logger.error(f"Failed to turn on modem after 3 attempts: id{device_id}, serial: {serial}")

            return 'OK'
        else:
            logger.info(f'OS NOT READY: id{device_id}, serial: {serial if not tid else "using TID"}')
            return 'Reboot in progress'

    except TimeoutExpired:
        logger.error(f"Timeout reboot checking for ID: {device_id}, serial: {serial}")
        return 'Timeout reboot checking'
    except subprocess.CalledProcessError:
        logger.error(f"CalledProcessError reboot checking for ID: {device_id}, serial: {serial}")
        return 'Error checking boot status'