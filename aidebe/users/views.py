from django.shortcuts import render

from . import models
from . import serializers
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
# Create your views here.
from django.contrib.auth import get_user_model

User = get_user_model()
class UserList(APIView):
    """
    List all projects, or create a new project.
    """
    def get(self, request, format=None):
        user = User.objects.all()
        serializer = serializers.UserSerializer(user, many=True)
        return Response(serializer.data)