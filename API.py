from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from flask_restful import reqparse
import pexpect
import time
import subprocess
from subprocess import Popen, PIPE, TimeoutExpired, run
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
import datetime
from threading import Lock
import textwrap
import mysql.connector
from cryptography.fernet import Fernet
import netifaces as ni

config_lock = Lock()

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

# Device api manage:

def adb_reboot_device(serial_number):
    adb_reboot = f"adb -s {serial_number} reboot"
    print(f"Executing adb command: {adb_reboot}")
    
    result = subprocess.run(adb_reboot.split(), stdout=subprocess.PIPE)
    print(result.stdout.decode())

def check_reboot_status(serial_number):
    adb_get_boot_completed = f"adb -s {serial_number} shell getprop sys.boot_completed"
    process = Popen(adb_get_boot_completed.split(), stdout=PIPE, stderr=PIPE)

    try:
        stdout, stderr = process.communicate(timeout=10) # 10 секунд таймаута
        output = stdout.decode('utf-8').strip()

        if output == '1':
            return 'OK'
        else:
            return 'Reboot in progress'
    except TimeoutExpired:
        process.kill()
        return 'Timeout during reboot check'
    except subprocess.CalledProcessError:
        return 'Reboot in progress'

def get_ip_address(interface_name):
    try:
        return ni.ifaddresses(interface_name)[ni.AF_INET][0]['addr']
    except Exception: # Здесь можно указать конкретный тип исключения
        return '127.0.0.1'

def wait_for_ip(interface_name, retries=5, delay=2):
    for _ in range(retries):
        ip = get_ip_address(interface_name)
        if ip != '127.0.0.1':
            return ip
        time.sleep(delay)
    return '127.0.0.1'

#for alcatel
def modem_on_alcatel(serial_number):
    modem_on_alcatel = f"adb -s {serial_number} shell svc usb setFunctions rndis"
    print(f"Executing adb command: {modem_on_alcatel}")
    
    result = subprocess.run(modem_on_alcatel.split(), stdout=subprocess.PIPE)
    print(result.stdout.decode())

def modem_off_alcatel(serial_number):
    modem_off_alcatel = f"adb -s {serial_number} shell svc usb setFunctions none"
    print(f"Executing adb command: {modem_off_alcatel}")
    
    result = subprocess.run(modem_off_alcatel.split(), stdout=subprocess.PIPE)
    print(result.stdout.decode())

def modem_status_alcatel(serial_number):
    modem_status_alcatel_cmd = f"adb -s {serial_number} shell svc usb getFunctions"
    print(f"Executing adb command: {modem_status_alcatel_cmd}")
    
    process = Popen(modem_status_alcatel_cmd.split(), stdout=PIPE, stderr=PIPE)
    try:
        stdout, stderr = process.communicate(timeout=10) # 10 секунд таймаута
        error = stderr.decode()

        if f"device '{serial_number}' not found" in error:
            return "device_not_found"
        elif "rndis" in error:
            return "rndis"
        else:
            return "rndis_off"
    except TimeoutExpired:
        process.kill()
        return "timeout"

#for samsung
def modem_a2(serial_number):
    modem_a2 = f"adb -s {serial_number} shell 'input keyevent KEYCODE_WAKEUP && am start -n com.android.settings/.TetherSettings && sleep 1 && input tap 465 545'"
    print(f"Executing adb command: {modem_a2}")

    result = subprocess.run(modem_a2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print(result.stdout.decode())
    print(result.stderr.decode())

def modem_status_a2(serial_number):
    modem_status_a2_cmd = f"adb -s {serial_number} shell svc usb getFunction"
    print(f"Executing adb command: {modem_status_a2_cmd}")
    
    process = Popen(modem_status_a2_cmd.split(), stdout=PIPE, stderr=PIPE)
    try:
        stdout, stderr = process.communicate(timeout=10) # 10 секунд таймаута
        error = stderr.decode()

        if f"device '{serial_number}' not found" in error:
            return "device_not_found"
        elif "rndis" in error:
            return "rndis"
        else:
            return "rndis_off"
    except TimeoutExpired:
        process.kill()
        return "timeout"

MODEM_HANDLERS = {
    'alcatel': {
        'on': modem_on_alcatel,
        'off': modem_off_alcatel,
        'status': modem_status_alcatel
    },
    'a2': {
        'on': modem_a2,  # Assuming a similar 'modem_off_a2' function
        'off': modem_a2, # Same function can be used for on/off in this case
        'status': modem_status_a2
    }
}

#Device api manage functions end;

#3Proxy config apiment:

def add_user_to_acl(username, password):
    with open(ACL_PATH, 'a') as file:
        file.write(f"{username}:CL:{password}\n")

def remove_user_from_acl(username):
    with open(ACL_PATH, 'r') as file:
        lines = file.readlines()
    with open(ACL_PATH, 'w') as file:
        for line in lines:
            if username not in line:
                file.write(line)

def write_config_to_file(config):
    with open(CONFIG_PATH, 'a+') as file:
        file.seek(0)
        content = file.read()
        if content and not content.endswith('\n'):
            file.write('\n')
        file.write(config)

def add_user_config(username, mode, parent_ip, ext_ip, http_port, socks_port):
    config_parts = []

    # Common parts for HTTP and SOCKS
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
        raise ValueError("Invalid combination of mode, parent_ip, and ext_ip")

    proxy = f"proxy -n -a -p{http_port}" if ext_ip == "none" else f"proxy -n -a -p{http_port} -e{ext_ip}"
    socks = f"socks -n -a -p{socks_port}" if ext_ip == "none" else f"socks -n -a -p{socks_port} -e{ext_ip}"

    # Construct the HTTP and SOCKS parts
    http_parts = [
        f"# Start HTTP for {username}", 
        "flush", 
        auth_part, 
        allow_part, 
        parent_http, 
        proxy, 
        f"# End HTTP for {username}"
    ]
    socks_parts = [
        f"# Start SOCKS for {username}", 
        "flush", 
        auth_part, 
        allow_part, 
        parent_socks, 
        socks, 
        f"# End SOCKS for {username}"
    ]

    # Remove any None values
    http_parts = [part for part in http_parts if part is not None]
    socks_parts = [part for part in socks_parts if part is not None]

    # Join the parts together, adding a newline only at the end
    config = "\n".join(http_parts + socks_parts) + "\n"
    write_config_to_file(config)

def remove_user_config(username):
    with open(CONFIG_PATH, 'r') as file:
        lines = file.readlines()

    start_http_tag = f"# Start HTTP for {username}"
    end_http_tag = f"# End HTTP for {username}"

    start_socks_tag = f"# Start SOCKS for {username}"
    end_socks_tag = f"# End SOCKS for {username}"

    skip = False
    new_config = []
    for line in lines:
        stripped_line = line.strip()  # Remove whitespace characters
        if stripped_line == start_http_tag or stripped_line == start_socks_tag:
            skip = True
        elif stripped_line == end_http_tag or stripped_line == end_socks_tag:
            skip = False
            continue  # Skip the line for the end tag as well
        if not skip and stripped_line:  # Check if the line is not empty after stripping whitespace
            new_config.append(line)

    with open(CONFIG_PATH, 'w') as file:
        file.writelines(new_config)

def user_exists(username):
    with open(ACL_PATH, 'r') as file:
        lines = file.readlines()
        for line in lines:
            parts = line.split(":") # разбиваем строку на части по разделителю ':'
            if len(parts) > 0 and parts[0] == username: # если первая часть строки точно соответствует имени пользователя
                return True
    return False

def ip_exists_in_config(ip_address):
    with open(CONFIG_PATH, 'r') as file:
        content = file.read()
        return ip_address in content

def change_device_in_config(old_ip, new_ip):
    with open(CONFIG_PATH, 'r') as file:
        content = file.read()

    updated_content = content.replace(old_ip, new_ip)

    with open(CONFIG_PATH, 'w') as file:
        file.write(updated_content)

#3Proxy config apiment end;

class Reboot(Resource):
    def get(self, serial_number):
        print(f"Received serial number: {serial_number}")
        adb_reboot_device(serial_number)
        return {'reboot': 'in progress', 'message': 'Reboot command sent.'}, 202

class RebootStatus(Resource):
    def get(self, serial_number):
        status = check_reboot_status(serial_number)
        if status == 'OK':
            return {'status': 'OK', 'message': 'Device is ready.'}, 200
        else:
            return {'status': 'Reboot in progress', 'message': 'Device not ready.'}, 200

class ChangeIP(Resource):
    def get(self, serial_number):
        print(f"Received serial number: {serial_number}") 
        adb_command = f"adb -s {serial_number} shell"
        print(f"Executing adb command: {adb_command}") 
        
        try:
            child = pexpect.spawn(adb_command)
            child.expect('\$', timeout=10) # Ожидаем символ "$", увеличиваем timeout до 60 секунд
            
            airplane_on = "su -c 'settings put global airplane_mode_on 1; am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true'"
            print(f"Executing airplane command: {airplane_on}") 
            
            child.sendline(airplane_on)
            child.expect_exact('Broadcast completed: result=0', timeout=10) # Используем expect_exact

            # Делаем паузу в 1 секунду
            print("pause 1 second")
            time.sleep(1)
            
            airplane_off = "su -c 'settings put global airplane_mode_on 0; am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false'"
            print(f"Executing airplane command: {airplane_off}")
            
            child.sendline(airplane_off)
            child.expect_exact('Broadcast completed: result=0', timeout=10) 

            # Выходим из консоли
            child.sendline('exit')
            child.close()

            return {'status': 'success', 'message': 'Airplane mode activated and then deactivated'}, 200

        except Exception as e:
            print(f"Error: {str(e)}") 
            return {'status': 'failure', 'message': str(e)}, 500

class AutoChangeIP(Resource):
    def post(self, serial_number):
        args = parser.parse_args()
        interval_minutes = args['interval_minutes']

        # Если interval_minutes равен 'cancel' или 0, отменяем задание
        if interval_minutes == '0':
            try:
                scheduler.remove_job(serial_number)
                return {'status': 'success', 'message': f'Scheduled IP changes for device {serial_number} have been cancelled'}, 200

            except Exception as e:
                print(f"Error: {str(e)}")
                return {'status': 'failure', 'message': str(e)}, 500

        # В противном случае, устанавливаем задание
        else:
            interval_minutes = int(interval_minutes)  # конвертируем в int
            try:
                scheduler.add_job(func=ChangeIP().get, trigger='interval', minutes=interval_minutes, args=[serial_number], id=serial_number)
                return {'status': 'success', 'message': f'Airplane mode will be activated and then deactivated every {interval_minutes} minutes'}, 200

            except Exception as e:
                print(f"Error: {str(e)}")
                return {'status': 'failure', 'message': str(e)}, 500

class DeleteUser(Resource):
    def delete(self):
        username = request.json['username']
    
        # Check if user exists
        if not user_exists(username):
            return {"message": "User does not exist"}, 404

        remove_user_from_acl(username)
        remove_user_config(username)
        return {"message": "User deleted successfully"}, 200

class UpdateAuth(Resource):
    def patch(self):
        data = request.json
        username = data['username']
        protocol = data['protocol']  # Should be either 'http', 'socks', or 'both'
        auth_type = data['auth_type']

        if auth_type == "strong":
            allow_ip = username
        elif auth_type == "iponly":
            if 'allow_ip' not in data:
                return {"message": "allow_ip required for iponly auth_type"}, 400
            allow_ip = data['allow_ip']
        else:
            return {"message": "Invalid auth_type provided"}, 400

        if protocol not in ['http', 'socks', 'both']:
            return {"message": "Invalid protocol provided"}, 400

        if protocol == 'both':
            update_auth_in_file(username, 'http', auth_type, allow_ip)
            update_auth_in_file(username, 'socks', auth_type, allow_ip)
        else:
            update_auth_in_file(username, protocol, auth_type, allow_ip)

        return {"message": "User configuration updated successfully"}, 200

class AddUser(Resource):
    def post(self):
        try:
            data = request.json

            required_fields = ['username', 'password', 'mode', 'http_port', 'socks_port']
            if not all(field in data for field in required_fields):
                return {"message": "Missing required fields"}, 400

            username = data['username']
            if user_exists(username):
                return {"message": f"User with username {username} already exists"}, 400
            
            mode = data.get('mode')
            ext_ip = data.get('ext_ip', "none")
            parent_ip = data.get('parent_ip', "none")
            http_port = data.get('http_port', 8080)  # default port
            socks_port = data.get('socks_port', 1080)  # default port

            add_user_to_acl(username, data['password'])
            add_user_config(username, mode, parent_ip, ext_ip, http_port, socks_port)

            return {"message": "User added successfully"}, 201

        except Exception as e:
            return {"message": f"An error occurred: {str(e)}"}, 500

class UpdateUser(Resource):
    def patch(self):
        data = request.json
        old_username = data.get('old_username')
        new_username = data.get('new_username')
        new_password = data.get('new_password')
        
        # Checking for required data
        if not old_username or not new_username or not new_password:
            return {"message": "Required data missing"}, 400

        # Check for user existence
        if not user_exists(old_username):
            return {"message": f"User {old_username} does not exist"}, 404

        # Update user record in ACL
        with open(ACL_PATH, 'r') as file:
            users = file.readlines()

        updated_users = []
        for user in users:
            if user.startswith(f"{old_username}:"):
                updated_users.append(new_username + ":CL:" + new_password + "\n")
            else:
                updated_users.append(user)
        
        with open(ACL_PATH, 'w') as file:
            file.writelines(updated_users)

        # Update 3proxy configuration
        with open(CONFIG_PATH, 'r') as file:
            config = file.read()

        config = config.replace(f"#start http {old_username}", f"#start http {new_username}")
        config = config.replace(f"#end http {old_username}", f"#end http {new_username}")
        config = config.replace(f"#start socks {old_username}", f"#start socks {new_username}")
        config = config.replace(f"#end socks {old_username}", f"#end socks {new_username}")
        config = config.replace(f"allow {old_username}", f"allow {new_username}")

        with open(CONFIG_PATH, 'w') as file:
            file.write(config)

        return {"message": f"User {old_username} updated successfully"}, 200

class ChangeDevice(Resource):
    def patch(self):
        data = request.json
        old_ip = data['old_ip']
        new_ip = data['new_ip']
        
        if not ip_exists_in_config(old_ip):
            return {"message": f"IP address {old_ip} not found in config"}, 404

        change_device_in_config(old_ip, new_ip)
        return {"message": "IP address updated successfully"}, 200

class ModemToggle(Resource):
    def post(self):
        data = request.json
        serial_number = data['serial_number']
        device_model = data['device']
        mode = data['mode']
        interface_name = data.get('ifname')  # Необязательный параметр

        status_handler = MODEM_HANDLERS.get(device_model, {}).get('status')
        status = status_handler(serial_number) if status_handler else None

        if status == "device_not_found":
            return {"message": "Device not found, possibly it has lost connection"}, 500
        elif status == "timeout":
            return {"message": "Device timed out, possibly it has lost connection"}, 500

        if mode == "modem":
            if status == "rndis":
                ip_address = wait_for_ip(interface_name)
                if ip_address != '127.0.0.1':
                    return {"message": "Modem is already on", "ip_address": ip_address}, 200
                return {"message": "Interface not ready, unable to get IP address"}, 500
            else:
                handler = MODEM_HANDLERS.get(device_model, {}).get('on')
                try:
                    handler(serial_number)
                    ip_address = wait_for_ip(interface_name)
                    if ip_address != '127.0.0.1':
                        return {"message": "Modem turned on successfully", "ip_address": ip_address}, 200
                    return {"message": "Interface not ready, unable to get IP address"}, 500
                except Exception as e:
                    return {"message": str(e)}, 500

        elif mode == "parent":
            if status == "rndis":
                handler = MODEM_HANDLERS.get(device_model, {}).get('off')
                try:
                    handler(serial_number)
                    return {"message": "Modem turned off successfully"}, 200
                except Exception as e:
                    return {"message": str(e)}, 500
            else:
                return {"message": "Modem is already turned off"}, 200

        else:
            return {"message": "Invalid mode provided. Use either 'modem' or 'parent' as mode field."}, 400

class ModemStatus(Resource):
    def get(self, serial_number):
        handler = MODEM_HANDLERS.get(device_model, {}).get('status')

        if handler:
            try:
                status = handler(serial_number)
                return {"message": status}, 200
            except Exception as e:
                return {"message": str(e)}, 500
        else:
            return {"message": "Invalid device model provided. Use a correct 'device' field."}, 400

class ProxyCount(Resource):
    def get(self):
        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host="10.66.66.8",
            user="opz",
            password="Qwerty1@3",
            database="testbase"
        )

        #db = mysql.connector.connect(host=host, user=user, password=password, database=database)
        #cursor = db.cursor()
        cursor = connection.cursor(dictionary=True)

        try:
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
            results = cursor.fetchall() #sql_query
            return results, 200  # Return the results and a 200 OK status code
        except Exception as e:
            return {"error": str(e)}, 500  # Return the error message and a 500 Internal Server Error status code
        finally:
            cursor.close()
            connection.close()


#resources
api.add_resource(Reboot, '/api/reboot/<string:serial_number>')
api.add_resource(RebootStatus, '/api/rebootstatus/<string:serial_number>')
api.add_resource(ChangeIP, '/api/changeip/<string:serial_number>')
api.add_resource(AutoChangeIP, '/api/changeip/auto/<string:serial_number>')
api.add_resource(AddUser, '/api/add_user')
api.add_resource(DeleteUser, '/api/delete_user')
api.add_resource(UpdateAuth, '/api/update_auth')
api.add_resource(UpdateUser, '/api/update_user')
api.add_resource(ChangeDevice, '/api/change_device')
api.add_resource(ModemToggle, '/api/modem')
api.add_resource(ModemStatus, '/api/modemstatus/<string:serial_number>')
api.add_resource(ProxyCount, '/api/proxycount')

if __name__ == '__main__':
    app.run(debug=True)