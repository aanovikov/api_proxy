from dotenv import load_dotenv
import os

load_dotenv()

beat_scheduler = "redisbeat:RedisScheduler"
redis_url = f"redis://{os.environ.get('REDIS_HOST')}:{os.environ.get('REDIS_PORT')}/1"
CELERY_REDIS_SCHEDULER_URL = redis_url

broker_url = redis_url
result_backend = redis_url

# task_serializer='json'
# accept_content=['json']
# result_serializer='json'