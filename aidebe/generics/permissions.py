from rest_framework.permissions import BasePermission
from rest_framework.permissions import IsAuthenticated

from users import models
from users import configurations

def is_authenticated(self, request, view):
    return IsAuthenticated.has_permission(self, request, view)



def is_user_permitted(request, role_name):
    if not request.user or request.user.is_staff:
        return False

    organization_role = models.Role.objects.filter(user__id=request.user.id, role=role_name).first()
    if organization_role is None:
        return False
    return True


class IsAdminUser(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        if not is_authenticated(self, request, view):
            return False

        return bool(request.user and request.user.is_superuser)


class IsSuperUser(BasePermission):
    """
    Allows access only to staff users.
    """

    def has_permission(self, request, view):
        if not is_authenticated(self, request, view):
            return False

        return bool(request.user and request.user.is_staff)


class IsNormalUser(BasePermission):
    """
    Allows access only to normal users.
    """

    def has_permission(self, request, view):
        if not is_authenticated(self, request, view):
            return False

        return bool(request.user and not request.user.is_staff)

class IsOrganizationAdmin(BasePermission):
    """
    Allows access only to organization admin users.
    """
    def has_permission(self, request, view):
        if not is_authenticated(self, request, view):
            return False
        return is_user_permitted(request, configurations.ORGANIZATION_ADMIN)

class IsOrganization(BaseException):
    """
    Allows access only to users in organization.
    """
    def has_permission(self,request,view):
        org = models.Role.objects.filter(user=request.user).first()
        
        
        return bool(org or request.user.is_superuser)
        # return bool(request.user and request.user.is_superuser)