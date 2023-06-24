from django.conf.urls import url
from django.urls import path, include
from .api import RegisterApi
from . import views
urlpatterns = [
      path('register', RegisterApi.as_view()),
      path('list', views.UserList.as_view()),
]