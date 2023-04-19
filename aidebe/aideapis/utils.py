
import requests
import rq
from worker import conn
from django.conf import settings
import time
queue = rq.Queue(connection=conn,default_timeout=3600)

def get_result(image):
    url = "http://127.0.0.1:8082/predict_liver_segment"#settings.AI_URL + "predict"
    print("URL: ", url)
    data = requests.get(url)
    time.sleep(10)
    return "getresult"

def worker_predict(image):
    data = queue.enqueue(get_result, image)
    print("data: ", data)
    return {"data": "Success"}