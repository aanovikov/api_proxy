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