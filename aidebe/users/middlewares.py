import json

from rest_framework_simplejwt.backends import TokenBackend

from . import models
from . import configurations


class ActivityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.content_type in [
            "multipart/form-data",
            "application/x-www-form-urlencoded",
        ]:
            request_body = request.POST
        elif request.content_type in ["json", "application/json"]:
            request_body = json.loads(request.body.decode("utf-8"))
        else:
            request_body = {}
        response = self.get_response(request)

        # If wrong request, then return response
        # If admin urls, return response
        if request.resolver_match is None or request.path_info.startswith("/admin/"):
            return response
        if request.resolver_match is None or request.path_info.startswith("/media/"):
            return response
        # No need to save activity if the request is for getting docs
        exceptional_urls = ("openapi-schema", "swagger", "redoc")
        if request.resolver_match.url_name in exceptional_urls:
            return response

        # No need to save activity if the request hit is not a successful
        if not str(response.status_code).startswith("2") or request.method == "OPTIONS":
            return response

        request_config = configurations.USER_ACTIONS.get(request.method, None)
        if request_config is None:
            raise ValueError(
                f"Please set the {request.method} (USER_ACTIONS) for the request in `users/configurations.py` file."
            )

        url_config = request_config.get(request.resolver_match.url_name, None)
        if url_config is None:
            raise ValueError(
                f"Please set the {request.resolver_match.url_name} (USER_ACTIONS) for the request in `users/configurations.py` file."
            )

        description = url_config.get("description", None)
        if description is None:
            raise ValueError(
                "Please set the description (USER_ACTIONS) for the request in `users/configurations.py` file."
            )
        if request.resolver_match is None or request.path_info.endswith('/user/reset-password'):
            return response
        

        user = request.user
        
        # Getting user for `login` and `refresh` (AnonymousUser)
        if request.resolver_match.url_name == "login":
            username = request_body.get("username", None)
            user = models.User.objects.filter(username=username).first()

        elif request.resolver_match.url_name == "refresh":
            refresh = request_body.get("refresh", None)
            valid_data = TokenBackend(algorithm="HS256").decode(refresh, verify=False)
            user_id = valid_data.get("user_id", None)
            user = models.User.objects.filter(id=user_id).first()

        if user is not None:
            try:
                models.Activity.objects.create(
                    user=user, name=request.resolver_match.url_name, description=description
                )
            except:
                print("el")

        return response
