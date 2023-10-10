import logging
import subprocess
from subprocess import Popen, PIPE, TimeoutExpired, run
import time
from network_management import MODEM_HANDLERS
from schedule_management import scheduler

def adb_reboot_device(serial, device_id):
    adb_reboot = f"adb -s {serial} reboot"
    logging.info(f"Executing reboot for ID: {device_id}, serial: {serial}")
    result = subprocess.run(adb_reboot.split(), stdout=subprocess.PIPE)
    logging.debug(f"ADB reboot output : {result.stdout.decode()}")

def get_adb_device_status(serial, device_id):
    try:
        output = subprocess.check_output(["adb", "-s", serial, "get-state"], stderr=subprocess.STDOUT).decode('utf-8').strip()
        logging.info(f"Device ID: {device_id}, serial: {serial}, status: {output}")
    except subprocess.CalledProcessError as e:
        error_output = e.output.decode('utf-8').strip()
        if "not found" in error_output:
            logging.error(f"Device ID: {device_id}, serial: {serial} not found")
            return "device is not found"
        else:
            logging.error(f"Unexpected error for device {device_id}: {error_output}")
            return "Unexpected error"

    if output == "device":
        return "device"
    elif output == "offline":
        return "offline"
    elif output == "unauthorized":
        return "unauthorized"
    elif output == "bootloader":
        return "bootloader"
    else:
        logging.warning(f"Unknown ADB status for ID: {device_id}, serial: {serial}")
        return "Unknown ADB status"

def os_boot_status(serial, device, device_id, enable_modem=False):
    adb_get_boot_completed = f"adb -s {serial} shell getprop sys.boot_completed"
    logging.info(f"OS BOOT checking for ID: {device_id}, serial: {serial}")
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
                logging.info(f"Device is ONLINE, ID: {device_id}, serial: {serial}")
                if enable_modem:
                    MODEM_HANDLERS[device]['on'](serial)
                    logging.info(f"Modem turned on for ID: {device_id}, serial: {serial}")  # Вызываем функцию для включения режима модема
                    scheduler.remove_job(f"modem_{serial}")
                return 'OK'

            time.sleep(1)  # пауза 1 секунда между попытками

        except TimeoutExpired:
            logging.error(f"Timeout reboot checking for ID: {device_id}, serial: {serial}")
            return 'Timeout reboot checking'
        except subprocess.CalledProcessError:
            logging.error(f"CalledProcessError reboot checking for ID: {device_id}, serial: {serial}")
            return 'CalledProcessError reboot checking '

    return 'Reboot in progress'