from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid
from generics import mixins
# Create your models here.
import os
import datetime
from django.contrib.auth import get_user_model
from django.core.files.storage import FileSystemStorage
fs = FileSystemStorage(location="/home/ubuntu/mystorage")

User = get_user_model()

def upload_to(instance, filename):
    # folder = instance.get_folder_name()  # Call your method to get the folder name
    # print("--> ", folder)
    print(instance.patient_name)
    folder = 'media/' + instance.patient_name 
    try:
        os.makedirs(folder, exist_ok=True)
    except Exception as ex:
        print("Exception: ", ex)
    return os.path.join(folder, filename)

def upload_to_path(instance, filename):
    # folder = 'media/' + instance.patient_name 
    folder = 'media/' + instance.project_id.patient_name + '/' + instance.category+ '/' + instance.sample_name
    print("folder", folder)
    try:
        os.makedirs(folder, exist_ok=True)
    except Exception as ex:
        print("Exception: ", ex)
    return os.path.join(folder, filename)

class Project(mixins.GenericModelMixin):
    patient_name = models.CharField(null=False, max_length=50, unique=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    image = models.FileField(upload_to=upload_to, storage=fs, null=True)
    description = models.CharField(max_length=5000, null=True)

    def __str__(self):
        return str(self.id)
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    def get_folder_name(self):
        return 'media/' + self.patient_name 

    class Meta:
        verbose_name_plural = "Project"


class Samples(mixins.GenericModelMixin):
    class Categories(models.TextChoices):
        """
        -----------
        Categories
        -----------
        
        """
        brain        = "brain", "Brain"
        heart       = "heart", "Heart"
        liver  = "liver", "Liver"

    category = models.CharField(null=True,
                            max_length=50,
                            choices=Categories.choices,
                            default=Categories.brain)
    project_id = models.ForeignKey(Project, on_delete=models.CASCADE)
    sample_name = models.CharField(null=False, max_length=50)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    input_file = models.FileField(upload_to=upload_to_path, storage=fs, null=True)
    iteration_count = models.IntegerField(default=31)
    description = models.CharField(max_length=5000, null=True)
    status = models.BooleanField(default=False)

    def __str__(self):
        return str(self.id)
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    def get_folder_name(self):
        # patient = Project.objects.filter(id = self.project_id).first()
        # print("**********", patient)
        return 'media/' + self.project_id.patient_name + '/' + self.category+ '/' + self.sample_name
    

    class Meta:
        verbose_name_plural = "Samples"