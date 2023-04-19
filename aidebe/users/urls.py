from django.urls import path, include
from rest_framework_simplejwt import views as jwt_views
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
# router.register(r'organization', views.OrganisationCRUDView, basename='organization')
router.register(r'', views.UserView, basename='organization')

urlpatterns = [
    path('',include(router.urls)),
    path("user-info", views.SingleUserView.as_view({"get": "single_list"}), name="user-info"),
    path("organization", views.OrganisationCRUDView.as_view({"get": "list", "post": "create", "put": "update", "delete": "destroy"}), name="organization"),
    path("organization-delete/<pk>", views.OrganisationUpdateApi.as_view({"delete": "destroy"}), name="organization-delete"),
    path("login", jwt_views.TokenObtainPairView.as_view(), name="login"),
    path("refresh", jwt_views.TokenRefreshView.as_view(), name="refresh"),
    path("logout", views.LogoutView.as_view({"post": "create"}), name="logout"),
    path(
        "reset-password",
        view=views.ResetPasswordView.as_view({"post": "create", "put": "update"}),
        name="reset-password",
    ),
    path(
        "change-password",
        view=views.ChangePasswordView.as_view({"put": "update"}),
        name="change-password",
    ),
    path("role-data", views.RoleGetApi.as_view(), name='role-data'),
    path("profile-update/<pk>", views.ProfileUpdate.as_view({"put": "update"}), name='profile-update'),
]
