import logging
import subprocess
from subprocess import Popen, PIPE, TimeoutExpired, run
import time
from network_management import MODEM_HANDLERS, check_rndis_iface

def adb_reboot_device(serial, device_id):
    adb_reboot = f"adb -s {serial} reboot"
    logging.info(f"Executing reboot: id{device_id}, serial: {serial}")
    result = subprocess.run(adb_reboot.split(), stdout=subprocess.PIPE)
    logging.debug(f"ADB reboot output : {result.stdout.decode()}")

def get_adb_device_status(serial, device_id, max_retries=5, delay=3):
    for i in range(max_retries):
        try:
            output = subprocess.check_output(["adb", "-s", serial, "get-state"], stderr=subprocess.STDOUT).decode('utf-8').strip()
            logging.info(f"Device status: {output}, id{device_id}, serial: {serial}")
            
            if output == "device":
                return "device"
            elif output in ["offline", "unauthorized", "bootloader"]:
                return output
                
        except subprocess.CalledProcessError as e:
            error_output = e.output.decode('utf-8').strip()
            logging.error(f"Attempt {i+1}: id{device_id}, {error_output}")
            
        time.sleep(delay)
        delay *= 2  # Экспоненциальная задержка

    logging.error(f"Max retries reached. Device not stable: id{device_id}, serial: {serial}")
    return "Unknown ADB status"

def os_boot_status(serial, device, device_id, enable_modem=False):
    device_status = get_adb_device_status(serial, device_id) # check adb connection status
    if device_status != "device":
        logging.warning(f"ADB NOT READY: {device_status} waiting 10s for next attempt")
        return f'ADB NOT READY: {device_status} waiting 10s for next attempt'
    logging.info(f'ADB READY: {device_status}, id{device_id}, serial: {serial}')

    adb_get_boot_completed = f"adb -s {serial} shell getprop sys.boot_completed"
    logging.debug(f"OS BOOT checking: id{device_id}, serial: {serial}")
    # consecutive_ok = 0  # счетчик подтверждений

    #for _ in range(3):  # три попытки подтверждения
    process = Popen(adb_get_boot_completed.split(), stdout=PIPE, stderr=PIPE)

    try:
        stdout, stderr = process.communicate(timeout=10)
        output = stdout.decode('utf-8').strip()

        if output == '1':
        #     consecutive_ok += 1  # увеличиваем счетчик
        # else:
        #     logging.debug(f'OS BOOT in progress: id{device_id}, serial: {serial}')
        #     consecutive_ok = 0  # сбрасываем счетчик

        # if consecutive_ok == 3:
            logging.info(f"OS READY: id{device_id}, serial: {serial}")
            if enable_modem:
                logging.debug(f'Requires to turn modem ON: id{device_id}, serial: {serial}')

                if device not in MODEM_HANDLERS:
                    logging.error(f"Unknown device model: {device}. Can't reestablish rndis for ID: {device_id}, serial: {serial}")
                    return 'Device model not supported'
                            
                for attempt in range(3):
                    logging.debug(f'Calling MODEM_HANDLERS to turn modem ON: id{device_id}, serial: {serial}')
                    MODEM_HANDLERS[device]['on'](serial)
                    logging.debug(f'PAUSE 5s. before check RNDIS iface')
                    time.sleep(5)

                    logging.debug(f'Cheking RNDIS iface: id{device_id}, serial: {serial}')
                    if check_rndis_iface(device_id, serial):
                        logging.info(f"Modem turned on: id{device_id}, serial: {serial}")  # Вызываем функцию для включения режима модема
                        scheduler.remove_job(f"modem_{serial}")
                        break
                    else:
                        logging.warning(f"Attempt {attempt+1}: Failed to turn on modem. Retrying...")
                        logging.debug(f'PAUSE 3s. before next attempt to turn on modem')
                        time.sleep(3)
                else:
                    logging.error(f"Failed to turn on modem after 3 attempts: id{device_id}, serial: {serial}")

            return 'OK'
        logging.info(f'OS NOT READY')

    except TimeoutExpired:
        logging.error(f"Timeout reboot checking for ID: {device_id}, serial: {serial}")
        return 'Timeout reboot checking'
    except subprocess.CalledProcessError:
        logging.error(f"CalledProcessError reboot checking for ID: {device_id}, serial: {serial}")
        return 'CalledProcessError reboot checking '

    return 'Reboot in progress'