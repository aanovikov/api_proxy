from flask import Flask, request, jsonify

app = Flask(__name__)

ACL_PATH = '/etc/3proxy/users.txt'
CONFIG_PATH = '/etc/3proxy/3proxy.cfg'

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
    config = f"""#start http {username}
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
"""
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
            if username in line:
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

@app.route('/admin/add_user', methods=['POST'])
def add_user():
    data = request.json
    username = data['username']
    
    if user_exists(username):
        return jsonify(message=f'User with username {username} already exists'), 400

    add_user_to_acl(username, data['password'])
    add_user_config(username, data['parent_ip'], data['http_port'], data['socks_port'])
    return jsonify(message='User added successfully'), 201

@app.route('/admin/delete_user', methods=['DELETE'])
def delete_user():
    username = request.json['username']
    
    # Check if user exists
    if not user_exists(username):
        return jsonify(message='User does not exist'), 404

    remove_user_from_acl(username)
    remove_user_config(username)
    return jsonify(message='User deleted successfully'), 200

@app.route('/admin/update_auth', methods=['PATCH'])
def update_auth():
    data = request.json
    username = data['username']
    protocol = data['protocol']  # Should be either 'http', 'socks', or 'both'
    auth_type = data['auth_type']

    if auth_type == "strong":
        allow_ip = username
    elif auth_type == "iponly":
        if 'allow_ip' not in data:
            return jsonify(message='allow_ip required for iponly auth_type'), 400
        allow_ip = data['allow_ip']
    else:
        return jsonify(message='Invalid auth_type provided'), 400

    if protocol not in ['http', 'socks', 'both']:
        return jsonify(message='Invalid protocol provided'), 400

    if protocol == 'both':
        update_auth_in_file(username, 'http', auth_type, allow_ip)
        update_auth_in_file(username, 'socks', auth_type, allow_ip)
    else:
        update_auth_in_file(username, protocol, auth_type, allow_ip)

    return jsonify(message='User configuration updated successfully'), 200

@app.route('/admin/change_device', methods=['PATCH'])
def change_device():
    data = request.json
    old_ip = data['old_ip']
    new_ip = data['new_ip']
    
    if not ip_exists_in_config(old_ip):
        return jsonify(message=f'IP address {old_ip} not found in config'), 404

    change_device_in_config(old_ip, new_ip)
    return jsonify(message='IP address updated successfully'), 200

if __name__ == '__main__':
    app.run(debug=True)