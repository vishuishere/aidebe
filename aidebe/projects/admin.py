from django.contrib import admin
from django.shortcuts import redirect
from django.urls import reverse
from . import models
from projects import views
# Register your models here.
admin.site.register(models.Project)
# admin.site.register(models.Samples)
@admin.register(models.Samples)
class SampleAdmin(admin.ModelAdmin):
    def response_add(self, request, obj, post_url_continue=None):
        print("url: ", post_url_continue)
        print("request: ", request.data)
        if post_url_continue == '/admin/projects/samples/add/':
            # Extract the project ID from the request
            project_id = request.GET.get('project_id')

            if project_id:
                # Create the API URL with the project ID
                api_url = reverse('/api/projects/' + str(project_id) + '/samples/create', args=[project_id])

                # Redirect to the API URL
                return redirect(api_url)

        return super().response_add(request, obj, post_url_continue)