from django.conf import settings
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from . import models
# from . import functions
# from . import configurations
from generics import exceptions
import requests
import json
import os

def get_response_data(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.content
        else:
            return None
    except requests.exceptions.RequestException as e:
        # Handle any request exceptions
        print(f"An error occurred: {e}")
        return None


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Project
        fields = ('id','patient_name','created_by', 'image', 'description')
    def create(self, validated_data):
        proj = models.Project.objects.create(patient_name =validated_data['patient_name'], created_by = validated_data['created_by'],
                                             image = validated_data['image'], description = validated_data['description'])
        return proj
    
class GetProjectSerializer(serializers.ModelSerializer):
    def get_samples_count(self, instance):
        return models.Samples.objects.filter(project_id = instance).count()
    def get_image_path(self, instance):
        data = models.Project.objects.filter(id = instance.id).first()
        print(data.image.path, "--")
        directory, filename = os.path.split(data.image.path)
        file_name = 'http://ai-api.googerit-ai.com/static/media/'+ data.patient_name  +'/' + filename
        return file_name
    samples_count = serializers.SerializerMethodField(method_name = "get_samples_count")
    image = serializers.SerializerMethodField(method_name = "get_image_path")
    class Meta:
        model = models.Project
        fields = ('id','patient_name','created_by', 'samples_count', 'image', 'description')

class SamplesSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Samples
        fields = ('id','category', 'sample_name', 'created_by', 'input_file', 'description', 'created_date_time')#'__all__'#
    def create(self, validated_data):
        print("validated_data", validated_data)
        print("validated_data['input_file']", validated_data['input_file'])
        

        proj = models.Samples.objects.create(category =validated_data['category'], sample_name =validated_data['sample_name'], 
                                             created_by = validated_data['created_by'], project_id = validated_data['project_id'],
                                             description =validated_data['description'], input_file = validated_data['input_file'])
        return proj
    
class GetStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Samples
        fields = ('id', 'project_id', 'sample_name', 'status')


class GetSamplesSerializer(serializers.ModelSerializer):
    def get_url_data(self, instance):
        print("data", instance.id)
        data_sample = models.Samples.objects.filter(id = instance.id).first()
        print("*****", data_sample.id, data_sample.project_id)
        data_project = models.Project.objects.filter(id = int(str(data_sample.project_id))).first()
        print("---")
        data = data_sample.category
        
        project_name = data_project.patient_name
        sample_name = data_sample.sample_name
        print(data, project_name, sample_name)
        # http://ai-api.googerit-ai.com/predict_result?data=brain&project_name=proj&sample_name=samp
        url_data = "http://ai-api.googerit-ai.com/predict_result?data="+ str(data) +"&project_name="+str(project_name)+"&sample_name="+str(sample_name)
        print(url_data)
        response = requests.post(url_data)
        if response.status_code == 200:
            return response.json()
        else:
            return []
    output_image_urls =  serializers.SerializerMethodField(method_name = "get_url_data")
    class Meta:
        model = models.Samples
        fields = ('id','category', 'sample_name', 'created_by', 'created_date_time', 'input_file', 'description', 'output_image_urls', 'iteration_count')