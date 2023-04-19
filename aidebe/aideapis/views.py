from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from aideapis import utils
# Create your views here.

class PredictLiver(APIView):
    def get(self,request):
        response_data = utils.worker_predict("image")
        print("response_data: ", response_data)
        return Response(response_data)