from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from flask_restful import reqparse
import pexpect
import time
import subprocess
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
import datetime
from threading import Lock
import textwrap

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
    
    try:
        output = subprocess.run(adb_get_boot_completed.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False).stdout.decode('utf-8').strip()
        
        if output == '1':
            return 'OK'
        else:
            return 'Reboot in progress'
    except subprocess.CalledProcessError:
        return 'Reboot in progress'

def adb_modem_on(serial_number):
    adb_modem_on = f"adb -s {serial_number} shell svc usb setFunctions rndis"
    print(f"Executing adb command: {adb_modem_on}")
    
    result = subprocess.run(adb_modem_on.split(), stdout=subprocess.PIPE)
    print(result.stdout.decode())

def adb_modem_off(serial_number):
    adb_modem_off = f"adb -s {serial_number} shell svc usb setFunctions none"
    print(f"Executing adb command: {adb_modem_off}")
    
    result = subprocess.run(adb_modem_off.split(), stdout=subprocess.PIPE)
    print(result.stdout.decode())

def adb_modem_status(serial_number):
    adb_modem_status_cmd = f"adb -s {serial_number} shell svc usb getFunctions"
    print(f"Executing adb command: {adb_modem_status_cmd}")
    result = subprocess.run(adb_modem_status_cmd.split(), stderr=subprocess.PIPE)
    error = result.stderr.decode()

    if "rndis" in error:
        return "rndis"
    else:
        return "rndis_off"

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

def add_user_config(username, parent_ip, http_port, socks_port):
    config = textwrap.dedent(f"""
        #start http {username}
        flush
        auth strong
        allow {username}
        #parent 1000 http {parent_ip} 8080 android android
        proxy -n -a -p{http_port}
        #end http {username}

        #start socks {username}
        flush
        auth strong
        allow {username}
        #parent 1000 socks5 {parent_ip} 1080 android android
        socks -n -a -p{socks_port}
        #end socks {username}
    """)
    
    # Ensure the configuration starts on a new line
    with open(CONFIG_PATH, 'a+') as file:
        # Move to the start of the file to read
        file.seek(0)
        content = file.read()
        # Ensure that we start writing on a new line if the file is not empty and doesn't end with a newline
        if content and not content.endswith('\n'):
            file.write('\n')
        file.write(config)

def remove_user_config(username):
    with open(CONFIG_PATH, 'r') as file:
        lines = file.readlines()

    start_http_tag = f"#start http {username}"
    end_http_tag = f"#end http {username}"

    start_socks_tag = f"#start socks {username}"
    end_socks_tag = f"#end socks {username}"

    skip = False
    new_config = []
    for line in lines:
        stripped_line = line.strip()  # Remove whitespace characters
        if stripped_line == start_http_tag or stripped_line == start_socks_tag:
            skip = True
        elif stripped_line == end_http_tag or stripped_line == end_socks_tag:
            skip = False
            continue
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

def update_auth_in_file(username, protocol, auth_type, allow_ip):
    with open(CONFIG_PATH, 'r') as file:
        lines = file.readlines()

    start_tag = f"#start {protocol} {username}"
    end_tag = f"#end {protocol} {username}"

    within_block = False
    new_config = []

    for line in lines:
        if start_tag in line:
            within_block = True
        elif end_tag in line:
            within_block = False

        if within_block:
            if "auth" in line:
                line = f"auth {auth_type}\n"
            elif "allow" in line:
                if auth_type == "strong":
                    line = f"allow {username}\n"
                elif auth_type == "iponly":
                    line = f"allow * {allow_ip}\n"
        
        new_config.append(line)

    with open(CONFIG_PATH, 'w') as file:
        file.writelines(new_config)

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

class AddUser(Resource):
    def post(self):
        data = request.json
        username = data['username']
        
        if user_exists(username):
            return {"message": f"User with username {username} already exists"}, 400

        add_user_to_acl(username, data['password'])
        add_user_config(username, data['parent_ip'], data['http_port'], data['socks_port'])
        return {"message": "User added successfully"}, 201

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
        action = data['action']  # This should be either 'on' or 'off'
        
        if action == "on":
            try:
                adb_modem_on(serial_number)
                return {"message": "Modem turned on successfully"}, 200
            except Exception as e:
                return {"message": str(e)}, 500
        elif action == "off":
            try:
                adb_modem_off(serial_number)
                return {"message": "Modem turned off successfully"}, 200
            except Exception as e:
                return {"message": str(e)}, 500
        else:
            return {"message": "Invalid action provided. Use 'on' or 'off'."}, 400

class ModemStatus(Resource):
    def get(self, serial_number):
        try:
            status = adb_modem_status(serial_number)
            return {"message": status}, 200
        except Exception as e:
            return {"message": str(e)}, 500

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

if __name__ == '__main__':
    app.run(debug=True)