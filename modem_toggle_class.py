class ModemToggle(Resource):
    @requires_role("admin")
    def post(self, admin_token):
        try:
            logging.info("Received request to SWITCH MODEM.")

            data = request.json
            if data is None:
                return {"message": "Invalid request: JSON body required"}, 400
            
            serial_number = data.get('serial_number')
            device_model = data.get('device')
            mode = data.get('mode')
            interface_name = data.get('ifname')

            logging.info(f"SWITCHING to {mode} for {interface_name} with serial {serial_number}")

            if not all([serial_number, device_model, mode]):
                return {"message": "Missing required fields"}, 400

            status_handler = MODEM_HANDLERS.get(device_model, {}).get('status')
            status = status_handler(serial_number) if status_handler else None

            if status == "device_not_found":
                logging.error("Device not found, possibly it has lost connection")
                return {"message": "Device not found, possibly it has lost connection"}, 500
            elif status == "timeout":
                logging.error("Device timed out, possibly it has lost connection")
                return {"message": "Device timed out, possibly it has lost connection"}, 500

            if mode == "modem":
                if status == "rndis":
                    ip_address = wait_for_ip(interface_name)
                    if ip_address != '127.0.0.1':
                        logging.info("Modem is already on")
                        return {"message": "Modem is already on", "ip_address": ip_address}, 200
                    logging.error("Interface not ready, unable to get IP address")
                    return {"message": "Interface not ready, unable to get IP address"}, 500
                else:
                    handler = MODEM_HANDLERS.get(device_model, {}).get('on')
                    handler(serial_number)
                    ip_address = wait_for_ip(interface_name)
                    if ip_address != '127.0.0.1':
                        logging.info("Modem turned on successfully")
                        return {"message": "Modem turned on successfully", "ip_address": ip_address}, 200
                    logging.error("Interface not ready, unable to get IP address")
                    return {"message": "Interface not ready, unable to get IP address"}, 500

            elif mode == "parent":
                if status == "rndis":
                    handler = MODEM_HANDLERS.get(device_model, {}).get('off')
                    handler(serial_number)
                    logging.info("Modem turned off successfully")
                    return {"message": "Modem turned off successfully"}, 200
                else:
                    logging.info("Modem is already turned off")
                    return {"message": "Modem is already turned off"}, 200
            else:
                logging.error("Invalid mode provided. Use either 'modem' or 'parent' as mode field.")
                return {"message": "Invalid mode provided. Use either 'modem' or 'parent' as mode field."}, 400

        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            return {"message": "Internal server error"}, 500