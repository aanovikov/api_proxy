from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from network_management import MODEM_HANDLERS
from device_management import os_boot_status
import logging
import time
import atexit

atexit.register(lambda: scheduler.shutdown())

jobstores = {
    'default': SQLAlchemyJobStore(url='sqlite:///jobs.sqlite')
}

scheduler = BackgroundScheduler(jobstores=jobstores)
__all__ = ['scheduler']
scheduler.start()

def enable_modem(serial, device_model, device_id):
    try:
        logging.info(f"RNDIS is trying get up, ID: {device_id}, serial: {serial}, type: {device_model}")
        
        for attempt in range(40):  # Maximum number of reboot status checks         
            if status == "OK":
                logging.info(f"Removed job ID: {job_id}, for ID: {device_id}, serial: {serial}")
                break
            time.sleep(10)  # Waiting time between attempts
        else:
            logging.warning(f"Device ID: {device_id}, serial: {serial} did not reboot successfully after 40 attempts")
            #logging.info(f"Removed job ID {job_id}, reboot unsuccessful for ID: {device_id}, serial: {serial}")
            return

        if device_model not in MODEM_HANDLERS:
            logging.error(f"Unknown device model: {device_model}. Can't reestablish rndis for ID: {device_id}, serial: {serial}")
            return

        MODEM_HANDLERS[device_model]['on'](serial)
        logging.info(f"Modem turned on for ID: {device_id}, serial: {serial}")

    except Exception as e:
        logging.error(f"An error occurred while reestablishing rndis: {e}, for ID: {device_id}, serial: {serial}")

def schedule_job(serial, device, device_id):
    job_id = f"modem_{serial}"
    
    logging.info(f"Scheduling job ID: {job_id}, for ID: {device_id}, serial: {serial}")
    
    try:
        scheduler.add_job(
            os_boot_status,
            'interval', seconds=30,
            args=[serial, device, device_id, True],
            id=job_id,
            replace_existing=True
        )
        logging.info(f"Added job ID: {job_id} for ID: {device_id}, serial: {serial}")
    except Exception as e:
        logging.error(f"Failed to schedule job ID: {job_id} for ID: {device_id}, serial: {serial}, Error: {e}")