from textwrap import dedent
import logging
import re
import os
from dotenv import load_dotenv
import storage_management as sm

load_dotenv()

ACL_PATH = os.getenv('ACL_PATH')
CONFIG_PATH = os.getenv('CONFIG_PATH')
CHECKER_IP = '91.107.207.227'

def read_file(filepath):
    try:
        with open(filepath, 'r') as file:
            return file.readlines()
    except Exception as e:
        logging.error(f"Can't read the file {filepath}: {str(e)}")
        raise e

def write_file(filepath, data):
    try:
        #logging.info(f"Writing to file at {filepath}")
        with open(filepath, 'w') as file:
            file.writelines(data)
            #logging.info(f"Successfully wrote to file at: {filepath}")
        return True
    except Exception as e:
        logging.error(f"Can't write to the file: {filepath}: {str(e)}")
        return False

def add_user_to_acl(username, password):
    try:
        #logging.info(f"Adding user to ACL: {username}.")
        with open(ACL_PATH, 'a') as file:
            file.write(f"{username}:CL:{password}\n")
        logging.info(f"Added ACL: {username}")
        return True
    except Exception as e:
        logging.error(f"Failed to ACL: {username}, error: {str(e)}")
        return False

def remove_user_from_acl(username):
    try:
        logging.info(f"Removing user ACL: {username}")
        lines = read_file(ACL_PATH)
        logging.debug(lines)

        if lines is None:
            return False

        found = False
        for index, line in enumerate(lines):
            logging.debug(f'index: {index}, line: {line.strip()}')
            if line.strip().startswith(f"{username}:"):
                del lines[index]
                found = True
                break

        if not found:
            logging.warning(f"User's ACL not found: {username}")
            return False

        if write_file(ACL_PATH, lines):
            logging.info(f"User's ACL removed: {username}")
            return True
        else:
            return False

    except Exception as e:
        logging.error(f"An error occurred while removing user ACL: {username}, error: {str(e)}")
        return False

def update_user_in_acl(old_username, new_username, old_password, new_password, proxy_id):
    try:
        logging.info(f"Updating user in ACL: {old_username} --> {new_username}, {old_password} --> {new_password}")

        users = read_file(ACL_PATH)
        if users is None:
            logging.error("Failed to read ACL file")
            return False

        logging.debug(f"Current ACL: {users}")

        updated_users = []
        user_found = False
        
        if old_username and new_username and old_password and new_password: # change logopass
            for user in users:
                logging.debug(f"Checking logopass line: {user.strip()}")
                if re.match(f"^{old_username}:CL:{old_password}", user):
                    new_user_line = f"{new_username}:CL:{new_password}\n"
                    updated_users.append(new_user_line)
                    logging.debug(f"Updated users so far: {updated_users}")
                    user_found = True
                    logging.debug(f"LOGOPASS match found. Updated line: {new_user_line.strip()}")
                else:
                    updated_users.append(user)

        elif old_username and new_username: # change only username
            for user in users:
                logging.debug(f"Checking logopass line: {user.strip()}")
                if re.match(f"^{old_username}:CL:", user):
                    new_user_line = f"{new_username}{user[len(old_username):]}"
                    updated_users.append(new_user_line)
                    logging.debug(f"Updated users so far: {updated_users}")
                    user_found = True
                    logging.debug(f"LOGOPASS match found. Updated line: {new_user_line.strip()}")
                else:
                    updated_users.append(user)

        elif old_password and new_password: # change only password
            for user in users:
                logging.info(f"Checking password line: {user.strip()}")
                if f":CL:{old_password}" in user:
                    new_user_line = user.replace(f":CL:{old_password}", f":CL:{new_password}")
                    updated_users.append(new_user_line)
                    logging.info(f"Updated users so far: {updated_users}")
                    user_found = True
                    logging.info(f"Password match found. Updated line: {new_user_line.strip()}")
                else:
                    updated_users.append(user)
        
        else:
            logging.info(f"Something wrong with parameters")
            updated_users = users

        if not user_found:
            logging.warning(f"User not found in ACL: id{proxy_id}: {old_username if old_username else old_password}")
            updated_users = []
            return False

        logging.debug(f"Attempting to write to file with updated_users: {updated_users}")
        if not write_file(ACL_PATH, updated_users):
            logging.error("Failed to write to ACL file")
            return False

        logging.info(f"Updated LOGOPASS in ACL: id{proxy_id}: {old_username if old_username else old_password} --> {new_username if new_username else new_password}")
        return True
    except Exception as e:
        logging.error(f"An error occurred while updating user in ACL: {str(e)}")
        return False

def write_config_to_file(config):
    try:
        #logging.info("Attempting to write config to file.")
        
        content = read_file(CONFIG_PATH)
        if content is None:
            logging.error("Failed to read config file")
            return False
        
        content_str = "".join(content)
        if content_str and not content_str.endswith('\n'):
            content.append('\n')
        
        content.append(config)
        
        if not write_file(CONFIG_PATH, content):
            logging.error("Failed to write to config file")
            return False

        logging.info(f"Config successfully written to {CONFIG_PATH}")
        return True
    except Exception as e:
        logging.error(f"Failed to write config to file: {str(e)}")
        return False

def add_user_config(username, mode, http_port, socks_port, id, parent_ip, tgname):
    try:
        logging.debug(f"ADDING CONFIG: id{id}.")
        ifname = id  # Interface name

        # Common parts for HTTP and SOCKS
        auth_part = "auth strong"
        allow_part = f"allow {username}"

        # Mode and IP-specific parts
        if mode == "android":
            parent_http = f"parent 1000 http {parent_ip} 8080 android android"
            parent_socks = f"parent 1000 socks5 {parent_ip} 1080 android android"
            proxy = f"proxy -n -a -p{http_port}"
            socks = f"socks -n -a -p{socks_port}"
        elif mode == "modem":
            parent_http = None
            parent_socks = None
            proxy = f"proxy -n -a -p{http_port} -Doid{ifname}"
            socks = f"socks -n -a -p{socks_port} -Doid{ifname}"

        # Construct the HTTP and SOCKS blocks
        if mode == "android":
            http_parts = [
                f"# Start http for {tgname}: id{id}, {username}",
                "flush",
                auth_part,
                allow_part,
                parent_http,  # 'parent' comes before 'proxy'
                proxy,
                f"# End http for {tgname}: id{id}, {username}"
            ]
            socks_parts = [
                f"# Start socks for {tgname}: id{id}, {username}",
                "flush",
                auth_part,
                allow_part,
                parent_socks,  # 'parent' comes before 'socks'
                socks,
                f"# End socks for {tgname}: id{id}, {username}"
            ]
        elif mode == "modem":
            http_parts = [
                f"# Start http for {tgname}: id{id}, {username}",
                "flush",
                auth_part,
                allow_part,
                proxy,  # No 'parent', so 'proxy' comes last before comment
                f"# End http for {tgname}: id{id}, {username}"
            ]
            socks_parts = [
                f"# Start socks for {tgname}: id{id}, {username}",
                "flush",
                auth_part,
                allow_part,
                socks,  # No 'parent', so 'socks' comes last before comment
                f"# End socks for {tgname}: id{id}, {username}"
            ]

        # Join the parts together, adding a newline only at the end
        config = "\n".join(http_parts + socks_parts) + "\n"
        write_result = write_config_to_file(config)
        if not write_result:
            raise IOError("Failed to write user config to file.")
        
        logging.info(f"Added CONFIG: id{id}")
        return True

    except ValueError as ve:
        logging.error(f"ValueError occurred: {str(ve)}")
        return False
    except IOError as io:
        logging.error(f"IOError occurred: {str(io)}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
        return False

def remove_user_config(username, proxy_id, tgname):
    try:
        logging.info(f"Removing config: id{proxy_id}")
        lines = read_file(CONFIG_PATH)
        if lines is None:
            logging.error("Failed to read config file")
            return False

        user_removed = False
        new_config = []
        start_http_tag = f"# Start http for {tgname}: id{proxy_id}, {username}"
        end_http_tag = f"# End http for {tgname}: id{proxy_id}, {username}"
        start_socks_tag = f"# Start socks for {tgname}: id{proxy_id}, {username}"
        end_socks_tag = f"# End socks for {tgname}: id{proxy_id}, {username}"

        skip = False
        for line in lines:
            stripped_line = line.strip()
            if stripped_line == start_http_tag or stripped_line == start_socks_tag:
                skip = True
                user_removed = True
            elif stripped_line == end_http_tag or stripped_line == end_socks_tag:
                skip = False
                continue

            if not skip and stripped_line:
                new_config.append(line)

        if not write_file(CONFIG_PATH, new_config):
            logging.error("Failed to write new config")
            return False

        if user_removed:
            logging.info(f"User's config removed: {username}")
            return True
        else:
            logging.warning(f"User {username} not found in config")
            return False

    except Exception as e:
        logging.error(f"An error occurred while removing user {username} from config: {str(e)}")
        return False

def update_user_in_config(old_username, new_username, proxy_id, tgname):
    logging.debug(f'DATA CONFIG: {old_username}, {new_username}, {proxy_id}, {tgname}')
    try:
        config = read_file(CONFIG_PATH)
        if config is None:
            logging.error("Failed to read config file")
            return False

        config = "".join(config)
        config_updates = {
            f"# Start http for {tgname}: id{proxy_id}, {old_username}": f"# Start http for {tgname}: id{proxy_id}, {new_username}",
            f"# End http for {tgname}: id{proxy_id}, {old_username}": f"# End http for {tgname}: id{proxy_id}, {new_username}",
            f"# Start socks for {tgname}: id{proxy_id}, {old_username}": f"# Start socks for {tgname}: id{proxy_id}, {new_username}",
            f"# End socks for {tgname}: id{proxy_id}, {old_username}": f"# End socks for {tgname}: id{proxy_id}, {new_username}",
            f"allow {old_username}": f"allow {new_username}"
        }

        for old, new in config_updates.items():
            config = re.sub(re.escape(old), new, config)

        if not write_file(CONFIG_PATH, config):
            logging.error("Failed to write new config")
            return False

        logging.info(f"Updated user's config: id{proxy_id}: {old_username} --> {new_username}")
        return True

    except Exception as e:
        logging.error(f"An error occurred while updating user in config: {str(e)}")
        return False

def username_exists_in_ACL(username):
    try:
        lines = read_file(ACL_PATH)
        if lines is None:
            logging.error("Failed to read ACL file")
            return False

        for line in lines:
            parts = line.split(":")
            if len(parts) > 1 and username == parts[0]:
                #logging.info(f"Username exists in ACL: {username}")
                return True

        logging.warning(f"Username doesn't exist in ACL: {username} .")
        return False

    except Exception as e:
        logging.error(f"An error occurred while checking if user exists: {str(e)}")
        return False

def password_exists_in_ACL(password):
    try:
        lines = read_file(ACL_PATH)
        if lines is None:
            logging.error("Failed to read ACL file")
            return False

        for line in lines:
            parts = line.split(":")
            if len(parts) > 1 and password == parts[2].strip():
                logging.info(f"Password exists in ACL: {password}")
                return True

        logging.warning(f"Password doesn't exist in ACL: {password}")
        return False
    except Exception as e:
        logging.error(f"An error occurred while checking if user exists: {str(e)}")
        return False

def user_count_in_ACL(username, proxy_id, tgname, config_lines):
    count = 0
    search_pattern = f"# Start http for {tgname}: id{proxy_id}, {username}"
    for line in config_lines:
        if search_pattern in line:
            count += 1
    return count

def update_auth_in_config(proxy_id, username, protocol, auth_type, allow_ip, tgname):
    try:
        lines = read_file(CONFIG_PATH)
        if lines is None:
            logging.error("Failed to read config file")
            return False, "Failed to read config file"

        start_tag = f"# Start {protocol} for {tgname}: id{proxy_id}, {username}"
        end_tag = f"# End {protocol} for {tgname}: id{id}, {username}"

        # search_pattern = f"# Start {protocol} for {tgname}: id{id}, {username}"
        # logging.debug(f'SEARCH PATTERN: {search_pattern}')
        # modem_id_exists_in_config_result = modem_id_exists_in_config(search_pattern, proxy_id, username)
        modem_id_exists_in_config_result = modem_id_exists_in_config(proxy_id, username, tgname)

        if not modem_id_exists_in_config_result:
            logging.error(f"No {username} or id{proxy_id} found in the config.")
            return False, f"No {username} or id{proxy_id} found in the config."

        within_block = False
        new_config = []
        current_auth_type = None

        for line in lines:
            stripped_line = line.strip()
            if start_tag in stripped_line:
                within_block = True
            elif end_tag in stripped_line:
                within_block = False

            if within_block:
                if "auth" in line:
                    current_auth_type = line.strip().split(" ")[1]  # auth strong -> strong
                    # if current_auth_type == auth_type:
                    #     return False, "Auth type is already set to " + auth_type
                    line = f"auth {auth_type}\n"
                elif "allow" in line:
                    if auth_type == "strong":
                        line = f"allow {username}\n"
                    elif auth_type == "iponly":
                        line = f"allow * {allow_ip},{CHECKER_IP}\n"
        
            new_config.append(line)

        if not write_file(CONFIG_PATH, new_config):
            logging.error("Failed to write new config")
            return False, "Failed to write new config"

        logging.info(f"Config updated: protocol: {protocol}, username: {username}, id{proxy_id}")
        return True, "Auth type updated"
    except Exception as e:
        logging.error(f"An error occurred while updating auth in config: {str(e)}")
        return False, "An error occurred"

def update_mode_in_config(new_mode, parent_ip, device_token, http_port, socks_port):
    try:
        logging.info(f"Updating MODE in config: new_mode: {new_mode}, parent_ip: {parent_ip}, device_token: {device_token}")

        device_data = sm.get_data_from_redis(device_token)
        if not device_data:
            logging.error(f"No data for token: {device_token}. Exiting.")
            return {"message": f"No data for token: {device_token}", "status_code": 500}

        current_mode = device_data.get('mode', '')
        device_id = device_data.get('id', '')
        username = device_data.get('username', '')

        logging.debug(f"Current device_id: {device_id}, current_mode: {current_mode}, USER: {username}")

        if str(new_mode) == str(current_mode):
            logging.info(f"Mode for device id{device_id} is already set to {new_mode}. Exiting.")
            return {"message": f"Mode for device id{device_id} is already set to {new_mode}", "status_code": 200}

        new_lines = []
        inside_user_block = False

        logging.debug(f"Ports info: HTTP: {http_port}, SOCKS: {socks_port}")

        with open(CONFIG_PATH, "r") as f:
            lines = f.readlines()

        for line in lines:
            new_line = line.strip()
            logging.debug(f"NEWLINE: {new_line}")

            if f"# Start http for {tgname}: id{device_id}, {username}" in line.strip():
                inside_user_block = True
                logging.debug(f"Entering user block: {tgname}: id{device_id}, {username}")

            if f"# End socks for {tgname}: id{device_id}, {username}" in line.strip():
                inside_user_block = False
                logging.debug(f"Exiting user block: {tgname}: id{device_id}, {username}")

            if inside_user_block:
                logging.debug(f"Processing line within user block: {line.strip()}")

                if new_mode == 'modem':
                    if 'parent' in line.strip():
                        logging.debug("Skipping 'parent' line for 'modem' mode.")
                        continue  # Просто пропустим эту строку, и она не попадет в новый конфиг
                    elif 'proxy -n -a -p' in line.strip():
                        new_line = re.sub(r'-p\d+', f'-p{http_port}', line)
                        new_line = new_line.rstrip() + f' -Doid{device_id}\n'
                    elif 'socks -n -a -p' in line.strip():
                        new_line = re.sub(r'-p\d+', f'-p{socks_port}', line)
                        new_line = new_line.rstrip() + f' -Doid{device_id}\n'

                elif new_mode == 'android':
                    if 'proxy -n -a -p' in line.strip():
                        new_lines.append(f'parent 1000 http {parent_ip} 8080 android android\n')
                        new_line = re.sub(r'-p\d+', f'-p{http_port}', line).strip()
                        new_line = re.sub(r' -Doid\w+', '', new_line)
                    elif 'socks -n -a -p' in line.strip():
                        new_lines.append(f'parent 1000 socks5 {parent_ip} 8080 android android\n')
                        new_line = re.sub(r'-p\d+', f'-p{socks_port}', line).strip()
                        new_line = re.sub(r' -Doid\w+', '', new_line)

            if new_line:
                logging.debug(f"Appending new line: {new_line}")
                new_lines.append(new_line.strip() + '\n')  # Добавляем новую строку, если она не пуста

        with open(CONFIG_PATH, "w") as f:
            f.writelines(new_lines)

        # Обновляем значение в Redis
        if not sm.update_data_in_redis(device_token, {'mode': new_mode, 'username': username}):
            logging.error(f"Failed to update data in Redis: {device_token}, {'new_mode': new_mode, 'username': username})")
            raise Exception("Failed to update data in Redis")

        logging.info(f"Mode changed: id{device_id}, mode = {new_mode}")
        return {"message": f"Mode changed: id{device_id}, mode = {new_mode}", "status_code": 200}

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return {"message": f"An error occurred: {e}", "status_code": 500}

def android_ip_exists_in_config(old_ip):
    try:
        content = read_file(CONFIG_PATH)
        if content is None:
            logging.error("An error occurred while reading the config file.")
            return False

        if old_ip in ''.join(content):
            logging.info(f"IP address {old_ip} exists in 3proxy config.")
            return True

        logging.info(f"IP address {old_ip} does not exist in 3proxy config.")
        return False

    except Exception as e:
        logging.error(f"An error occurred while checking IP in config: {str(e)}")
        return False

def replace_android_in_config(old_ip, new_ip, old_id, new_id, username, tgname):
    try:
        logging.info(f"Changing ID and IP in config: old_ip: {old_ip}, new_ip: {new_ip}, old_id: {old_id}, new_id: {new_id}")
        
        new_lines = []
        inside_user_block = False

        with open(CONFIG_PATH, "r") as f:
            lines = f.readlines()
        
        for line in lines:
            logging.debug(f'LINE: {line}')
            new_line = line

            if f"# Start http for {tgname}: id{old_id}, {username}" in line.strip():
                inside_user_block = True
                logging.debug(f"Entering user block: {inside_user_block}")
                
            elif f"# End socks for {tgname}: id{old_id}, {username}" in line.strip():
                new_line = re.sub(r'(?<= id)\d+(?![\w\d])', str(new_id), new_line)
                inside_user_block = False
                logging.debug(f"Exiting user block: {inside_user_block}")

            if inside_user_block:
                logging.debug(f"Replacing ID inside user block: {old_id} --> {new_id}")
                new_line = re.sub(r'(?<= id)\d+(?![\w\d])', str(new_id), new_line)
                logging.debug(f"Replacing ANDROID IP inside user block: {old_ip} --> {new_ip}")
                new_line = new_line.replace(old_ip, new_ip)

            new_lines.append(new_line)

        with open(CONFIG_PATH, "w") as f:
            f.writelines(new_lines)

        return True

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return {"message": f"An error occurred: {e}", "status_code": 500}

def modem_id_exists_in_config(proxy_id, username, tgname):
    try:
        content = read_file(CONFIG_PATH)
        if content is None:
            logging.error("An error occurred while reading the config file.")
            return False
        # search_patterns = search_pattern
        search_patterns = [
            f"# Start http for {tgname}: id{proxy_id}, {username}",
            f"# Start socks for {tgname}: id{proxy_id}, {username}"
        ]

        for search_pattern in search_patterns:
            if search_pattern in ''.join(content):
                logging.debug(f"Config exists: {username}, id{proxy_id}")
                return True

        logging.info(f"Config DOES NOT exist: username: {username}, id{proxy_id}")
        return False

    except Exception as e:
        logging.error(f"An error occurred while checking ID in config: {str(e)}")
        return False

def replace_modem_in_config(old_id, new_id, tgname, username):
    try:
        logging.info(f"Changing ID in config: old_id: {old_id}, new_id: {new_id}")

        new_lines = []
        inside_user_block = False

        with open(CONFIG_PATH, "r") as f:
            lines = f.readlines()

        for line in lines:
            new_line = line

            if f"# Start http for {tgname}: id{old_id}, {username}" in line.strip():
                inside_user_block = True
                logging.debug(f"Entering user block: {inside_user_block}")
                                
            elif f"# End socks for {tgname}: id{old_id}, {username}" in line.strip():
                new_line = re.sub(r'(?<= id)\d+(?![\w\d])', str(new_id), new_line)
                inside_user_block = False
                logging.debug(f"Exiting user block: {inside_user_block}")          
                
            if inside_user_block:
                logging.debug(f"Replacing MODEM ID inside user block: {old_id} --> {new_id}")
                new_line = re.sub(r'(?<=-Doid)\d+', str(new_id), line)
                logging.debug(f"Replacing ID inside user block: {old_id} --> {new_id}")
                new_line = re.sub(r'(?<= id)\d+(?![\w\d])', str(new_id), new_line)

            new_lines.append(new_line)
                
        with open(CONFIG_PATH, "w") as f:
            f.writelines(new_lines)

        return True

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return {"message": f"An error occurred: {e}", "status_code": 500}