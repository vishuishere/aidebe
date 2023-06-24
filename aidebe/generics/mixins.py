import uuid

from django.db import models


class GenericModelMixin(models.Model):
    created_date_time = models.DateTimeField(null=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, auto_now=True)

    objects = models.Manager()

    class Meta:
        abstract = True

class PermissionsPerMethodMixin(object):
    def get_permissions(self):
        """
        Allows overriding default permissions with @permission_classes
        """
        view = getattr(self, self.action)
        if hasattr(view, 'permission_classes'):
            return [permission_class() for permission_class in view.permission_classes]
        return super().get_permissions()