class ModemStatus(Resource):
    @requires_role("admin")
    def get(self, admin_token, serial_number, device_model):
        try:
            logging.info("Received request to CHECK MODEM STATUS.")

            handler = MODEM_HANDLERS.get(device_model, {}).get('status')
            if not handler:
                logging.error("Invalid device model provided. Use a correct 'device' field.")
                return {"message": "Invalid device model provided. Use a correct 'device' field."}, 400

            status = handler(serial_number)
            logging.info(f"Modem status for serial {serial_number}: {status}")
            return {"message": status}, 200

        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            return {"message": f"An error occurred: {str(e)}"}, 500
