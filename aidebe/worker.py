import os
import redis
from rq import Worker, Queue, Connection
listen = ['*']
redis_url = os.getenv('REDISTOGO_URL', 'redis://ai-api.googerit-ai.com/')

# Add the URL to the REDISTOGO_URL environment variable
if 'REDISTOGO_URL' not in os.environ:
    os.environ['REDISTOGO_URL'] = 'http://ai-api.googerit-ai.com/'
conn = redis.from_url(redis_url)
if __name__ == '__main__':
    with Connection(conn):
        worker = Worker(list(map(Queue, listen)))
        worker.work()