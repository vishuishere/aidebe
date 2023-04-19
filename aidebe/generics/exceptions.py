from rest_framework import status
from rest_framework.exceptions import APIException


class NotAllowedError(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "You are not allowed to perform this operation."
    default_code = None


class ExistsError(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "This data already exists."
    default_code = None


class NotExistsError(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = "This data does not exist."
    default_code = None


class UnauthorizedError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "You are not authorized to perform this operation."
    default_code = None


class ContentExpired(APIException):
    status_code = status.HTTP_410_GONE
    default_detail = "This content has expired."
    default_code = None
