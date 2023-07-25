from flask import Flask
from flask_restful import Resource, Api
import pexpect
import time
import subprocess

app = Flask(__name__)
api = Api(app)

def adb_reboot_device(serial_number):
    adb_reboot = f"adb -s {serial_number} reboot"
    print(f"Executing adb command: {adb_reboot}")
    subprocess.Popen(adb_reboot.split(), stdout=subprocess.PIPE)

def check_reboot_status(serial_number):
    adb_get_state = f"adb -s {serial_number} get-state"
    try:
        output = subprocess.run(adb_get_state.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False).stdout.decode('utf-8')
        if 'device' in output and 'not found' not in output:
            return 'OK'
        else:
            return 'Reboot in progress'
    except subprocess.CalledProcessError:
        return 'Reboot in progress'

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

api.add_resource(Reboot, '/api/reboot/<string:serial_number>')
api.add_resource(RebootStatus, '/api/rebootstatus/<string:serial_number>')

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

api.add_resource(ChangeIP, '/api/changeip/<string:serial_number>')

if __name__ == '__main__':
    app.run(debug=True)
