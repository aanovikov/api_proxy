import logging
import subprocess
from subprocess import Popen, PIPE, TimeoutExpired, run
import time

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
        logging.warning(f"Unknown ADB status for device: {device_id}")
        return "unknown"

def os_boot_status(serial_number):
    adb_get_boot_completed = f"adb -s {serial_number} shell getprop sys.boot_completed"
    logging.info(f"Checking OS BOOT for device: {serial_number}")
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
            logging.error(f"Timeout during reboot check for device: {serial_number}")
            return 'Timeout during reboot check'
        except subprocess.CalledProcessError:
            logging.error(f"CalledProcessError during reboot check for device: {serial_number}")
            return 'Reboot in progress'

    logging.warning(f"Reboot in progress for device {serial_number}")
    return 'Reboot in progress'