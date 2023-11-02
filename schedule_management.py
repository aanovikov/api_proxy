from rq import Queue, Callback
import storage_management as sm
import logging

redis_conn = sm.connect_to_redis(db=1)
q = Queue(connection=redis_conn)

def report_success(job, connection, result, *args, **kwargs):
    logging.info(f'SUCCESS: {job}, {result}')
    pass

def report_failure(job, connection, type, value, traceback):
    logging.info(f'FAIL: {job}, {connection}, {type}, {value}')
    pass

def report_stopped(job, connection):
    logging.info(f'STOPPED: {job}, {connection}')
    pass