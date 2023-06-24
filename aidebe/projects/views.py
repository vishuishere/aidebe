from django.shortcuts import render

# Create your views here.
from . import models
from . import serializers
from . import utils
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status



class ProjectList(APIView):
    """
    List all projects, or create a new project.
    """
    def get(self, request, format=None):
        proj = models.Project.objects.all()
        serializer = serializers.GetProjectSerializer(proj, many=True)
        return Response(serializer.data)

class CreateProjects(APIView):
    def post(self, request, format=None):
        print(request.data)
        serializer = serializers.ProjectSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
# Samples

class SamplesList(APIView):
    """
    List all Samples.
    """
    def get(self, request, format=None):
        proj = models.Samples.objects.all()
        serializer = serializers.GetSamplesSerializer(proj, many=True)
        return Response(serializer.data)


class GetSamplesList(APIView):
    """
    List single Sample.
    """
    def get(self, request, pk, format=None):
        project_id = models.Project.objects.filter(id = int(self.kwargs.get('pk'))).first()
        proj = models.Samples.objects.filter(project_id = project_id)
        serializer = serializers.GetSamplesSerializer(proj, many=True)
        return Response(serializer.data)
    

class CreateSamples(APIView):
    def post(self, request, pk, format=None):
        project_id = models.Project.objects.filter(id = int(self.kwargs.get('pk'))).first()
        print(request.data, "****************")
        serializer = serializers.SamplesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(project_id=project_id)
            utils.ai_processing(project_id, serializer.validated_data['sample_name'], serializer.validated_data['category'])
            # http://192.168.1.8:8095/predict_result?data=brain&project_name=proj&sample_name=samp
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class GetStatusList(APIView):
    """
    List status Sample.
    """
    def get(self, request, pk, format=None):
        project_id = models.Project.objects.filter(id = int(self.kwargs.get('pk'))).first()
        proj = models.Samples.objects.filter(project_id = project_id)
        serializer = serializers.GetStatusSerializer(proj, many=True)
        return Response(serializer.data)
    