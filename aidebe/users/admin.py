from django.contrib import admin
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin

from . import models


class ActivityAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "name", "description")
    ordering = ["created_at"]


admin.site.unregister(Group)
admin.site.register(models.User, UserAdmin)
admin.site.register(models.Activity, ActivityAdmin)
