from django.urls import path, include
from rest_framework_simplejwt import views as jwt_views
from rest_framework.routers import DefaultRouter

from . import views

# router = DefaultRouter()
# router.register(r'organization', views.OrganisationCRUDView, basename='organization')

urlpatterns = [
    # path('',include(router.urls)),
    path("predict-liver", views.PredictLiver.as_view(), name="predict-liver"),
]
