from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from projects import models as projects_model
# Create your views here.

class GetDashboardValues(APIView):
    """
    List all projects, samples, brain, heart and liver segmentation.
    """
    def get(self, request, format=None):
        x_projects = projects_model.Project.objects.all().count()
        x_samples = projects_model.Samples.objects.all().count()
        x_brain_segmentations = projects_model.Samples.objects.filter(category = 'brain').count()
        x_heart_segmentations = projects_model.Samples.objects.filter(category = 'heart').count()
        x_liver_segmentations = projects_model.Samples.objects.filter(category = "liver").count()
        data = {"x_projects": x_projects, "x_samples": x_samples, "x_liver_segmentations": x_liver_segmentations,
                 "x_brain_segmentations": x_brain_segmentations, "x_heart_segmentations": x_heart_segmentations}
        return Response(data)