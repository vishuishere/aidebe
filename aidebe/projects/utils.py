import requests
from . import models
# import rq
# from worker import conn
import time
from django.core.mail import send_mail
# queue = rq.Queue(connection=conn, default_timeout=3600)
import threading
from django.contrib.auth import get_user_model
import random
User = get_user_model()
def sendmailtouser(response, data, user_id, sample, project):
    if response == 'compose':
        subject = "Test Failure - Sample " + str(sample) + " in Project " + str(project)
        message = """Hi,

I wanted to inform you that the testing of the sample named '"""+ str(sample) + """' in the project named '"""+ str(project) + """' has failed. The failure occurred due to an error in choosing the input file for testing. The file is not suitable as its features do not match the category '"""+ str(data) + """'.

To resolve this issue, please ensure that the file is changed appropriately to align its features with the expected category. Once the necessary changes are made, please proceed with the testing.

If you have any questions or need further assistance, please let me know.

Thank you."""
    elif response == 'success':
        subject = "Test Success - Sample " + str(sample) + " in Project " + str(project)
        message = """This is an automated notification from Googerit AI. 

This message is to inform you that the testing has been completed for '"""+ str(sample) + """' in the '"""+ str(project) + """' and the results are shown in the web page.
    
You have been added to a notification list to recieve updates from Googerit AI. 
If you would like to be removed, then please contatct Googerit AI Team.

Project - """+ str(project) + """
Sample - """+str(sample) + """

Thank you.    
        """
    else:
        response = response.replace('failed: ', '')
        subject = "Test Failure - Sample " + str(sample) + " in Project " + str(project)
        message = """Hi,

I regret to inform you that an error has occurred in the sample named '"""+ str(sample) + """'. The application encountered an unexpected exception, causing the process to halt.

Exception Details:
'"""+ str(response) + """'

This exception has impacted the project's functionality, and it requires immediate attention. Please review the exception details and take appropriate actions to resolve the issue as soon as possible.

If you require any assistance or further information regarding the error, please let me know. I'm here to help.

Thank you for your prompt attention to this matter."""
    user = User.objects.filter(username = user_id).first()
    from_email = 'vishalu1438@gmail.com'
    recipient_list = [str(user.username)]
    print(recipient_list)
    send_mail(subject, message, from_email, recipient_list)


def get_response_from_worker(project_id, file_path, fields):
    url = "http://ai-api.googerit-ai.com/upload"
    print("calling ai url")
    with open(file_path, 'rb') as file:
        response = requests.post(url, files={'input_file': file}, data=fields)
    print("Working completed ", str(response))
    response = response.text
    print(response)
    pr = models.Project.objects.filter(id = int(str(project_id))).first()
    sam = models.Samples.objects.filter(project_id = int(str(project_id)), sample_name=fields['sample_name']).first()
    sam.status= True
    sam.save()
    print(sam.status)
    time.sleep(random.choice([10,20,30]))
    print("Prediction completed. ", sam.created_by)
    sendmailtouser(response, fields['data'], sam.created_by, fields['sample_name'], pr.patient_name)
    print("Mail set successfully")

def ai_processing(project_id, sample_name, category):
    pr = models.Project.objects.filter(id = int(str(project_id))).first()
    sam = models.Samples.objects.filter(project_id = int(str(project_id)), sample_name=sample_name, category=category).first()
    if pr is not None:

        file_path = sam.input_file.path
        fields = {
            'data': category,
            'project_name': pr.patient_name,
            'sample_name': sam.sample_name
        }
        t1 = threading.Thread(target=get_response_from_worker, args=(project_id, file_path, fields))
        # starting thread 1
        t1.start()
        # get_response_from_worker(file_path, fields)# queue.enqueue(
    return {"data": "Success"}
