from django.conf.urls import url
from django.urls import path, include
from . import views
urlpatterns = [
      path('', views.ProjectList.as_view()),
      path('create', views.CreateProjects.as_view()),
      path('<int:pk>/samples/create', views.CreateSamples.as_view()),
      path('samples', views.SamplesList.as_view()),
      path('<int:pk>/samples', views.GetSamplesList.as_view()),
      path('<int:pk>/status', views.GetStatusList.as_view()),
]