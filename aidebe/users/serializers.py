from django.conf import settings
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from . import models
from . import functions
from . import configurations
from generics import exceptions

def validate_role(role_value):
    for choice, value in models.Role.RoleName.choices:
        if choice == role_value:
            return choice
    raise serializers.ValidationError("role must be a valid OrganizationalRole")

def validate_organization(value):
    try:
        organization = models.Organization.objects.get(pk=value)
    except models.Organization.DoesNotExist:
        raise serializers.ValidationError("organization must be a valid OrganizationalRole id")
    return organization

def validate_user(value):
    try:
        user = models.User.objects.get(pk=value)
    except models.User.DoesNotExist:
        raise serializers.ValidationError("user must be a valid id")
    return user

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(min_length=100, max_length=300, required=True)

    def validate_refresh(self, refresh):
        try:
            token = RefreshToken(refresh)
        except TokenError:
            raise exceptions.UnauthorizedError(detail="Token is invalid or expired")
        return token

    def blacklist_token(self, validated_data):
        token = validated_data.get("refresh")
        token.blacklist()


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=8, max_length=100, required=True)

    def password_reset_email(self, validated_data):
        email = validated_data["email"]

        user = models.User.objects.filter(username=email).first()
        if user is None:
            raise exceptions.NotExistsError(detail="User account does not exist.")

        if not user.is_active:
            raise exceptions.NotAllowedError(
                detail="Please activate your account first."
            )

        key = functions.generate_key(email)
        # email_args = (
        #     {
        #         # "url": f"{settings.SITE_ORIGIN}/{configurations.RESET_PASSWORD_URL}?auth={key}",
        #         "url": f"oriel1-dev.logicplum.com/#/change-password?auth={key}",
        #     },
        # )

        email_args =  str(settings.WELCOME_EMAIL_URL)+"change-password?auth="+str(key)

                
        
        functions.send_email_as_thread(
            configurations.RESET_PASSWORD_EMAIL_SUBJECT,
            email,
            user.first_name,
            configurations.RESET_PASSWORD_EMAIL_TEMPLATE,
            args=email_args,
        )


class ResetPasswordUpdateSerializer(serializers.Serializer):
    key = serializers.CharField(min_length=100, max_length=300, required=True)
    password = serializers.CharField(
        max_length=36, required=True, validators=[validate_password]
    )

    def password_reset_done(self, validated_data):
        email = functions.is_link_expired(
            validated_data["key"],
            configurations.RESET_PASSWORD_EMAIL_TIMEOUT,
            "Password reset",
        )

        functions.update_password(email, validated_data["password"].strip())


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField()
    new_password = serializers.CharField(required=True, validators=[validate_password])

    def validate_current_password(self, current_password):
        self.user = self.context.get("user")
        if not check_password(current_password, self.user.password):
            raise serializers.ValidationError("Current password is invalid.")

    def update_password(self, validated_data):
        self.user.password = make_password(validated_data["new_password"])
        self.user.save()
class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=8, max_length=100, required=True)

class UserCreateSerializer(EmailSerializer):
    first_name = serializers.CharField(min_length=2, max_length=50, required=True)
    last_name = serializers.CharField(min_length=1, max_length=50, required=True)
    phone = serializers.CharField(min_length=3, max_length=50, required=True)


class UserInfoModelSerializer(serializers.ModelSerializer):
    def get_phone(self, query_set) -> str:
        profile = models.Profile.objects.filter(user=query_set).first()
        if profile is None:
            return profile
        return profile.phone

    def get_organization(self, queryset) -> dict:
        organization_role = models.Role.objects.filter(user=queryset).first()
        if organization_role is None:
            return organization_role
        if organization_role.organization is None:
            return {"role": organization_role.role, "name": None, "id":None}        
        return {"role": organization_role.role, "name": organization_role.organization.name, "id":organization_role.organization.id}

    def get_super_user(self,queryset) ->bool:
        val = queryset.is_superuser
        return val
    email = serializers.CharField(source='username')
    phone = serializers.SerializerMethodField(method_name='get_phone')
    organization = serializers.SerializerMethodField(method_name='get_organization')
    super_user = serializers.SerializerMethodField()
    class Meta:
        model  = models.User
        fields = ['id','first_name', 'last_name','email', 'organization', 'phone','super_user']

class SuperUserListModelSerializer(UserInfoModelSerializer):
    class Meta:
        model  = models.User
        fields = ['id', 'first_name', 'last_name', 'email']

class KeyPasswordSerializer(serializers.Serializer):
    key = serializers.CharField(min_length=100, max_length=300, required=True)
    password = serializers.CharField(min_length=8, max_length=30, required=True)


class UserIDSerializer(serializers.Serializer):
    user_id = serializers.IntegerField(
        min_value=1, max_value=None, required=True)

class UserUpdateSerializer(UserIDSerializer):
    first_name = serializers.CharField(min_length=2, max_length=50, required=True)
    last_name = serializers.CharField(min_length=1, max_length=50, required=True)
    phone = serializers.CharField(min_length=3, max_length=50, required=True)


class UserIdSerializer(serializers.Serializer):
    user_id = serializers.IntegerField(min_value=1, max_value=None, required=True)

class OrganizationResponseSerializer(UserCreateSerializer):
    name  = serializers.CharField(min_length=3, max_length=50, required=True)
    class Meta:
        model  = models.Organization
        fields =['first_name', 'last_name']


class OrganisationCreateSerializer(UserCreateSerializer):
    name  = serializers.CharField(min_length=3, max_length=50, required=True)
    class Meta:
        model  = models.Organization
        fields = ['first_name', 'last_name','name','email','phone']


class OrganizationUpdateSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(format='hex', required=True)
    class Meta:
        model  = models.Organization
        fields = ['id','name']

class OrganizationInfoUpdateSerializer(serializers.Serializer):
    id = serializers.UUIDField(format='hex', required=True)
    first_name = serializers.CharField(min_length=2, max_length=50, required=True)
    last_name = serializers.CharField(min_length=1, max_length=50, required=True)
    phone = serializers.CharField(min_length=3, max_length=50, required=True)
    name  = serializers.CharField(min_length=3, max_length=50, required=True)
    
class OrganizationDeleteSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(format='hex', required=True)
    class Meta:
        model  = models.Organization
        fields = ['id']

class ChangePasswordValidateSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        min_length=8, max_length=30, required=True)
    new_password = serializers.CharField(
        min_length=8, max_length=30, required=True)

class UserListModelSerializer(serializers.ModelSerializer):
    class Meta:
        model  = models.User
        fields = ['id', 'first_name', 'last_name', 'username']

class OrganizationNameListSerializer(serializers.ModelSerializer):
    class Meta:
        model  = models.Organization
        fields = ['id', 'name']

class CreateUserSerializer(UserCreateSerializer):     
    role         = serializers.CharField(required=True,validators=[validate_role])
    organization = serializers.UUIDField(required=False,validators=[validate_organization])

class CreateSuperUserSerializer(UserCreateSerializer):
    role         = serializers.CharField(required=True)
    # organization = serializers.CharField(required=False)

class UpdateSuperAdminSerializer(serializers.Serializer):
    role         = serializers.CharField(required=True,validators=[validate_role])
    # organization = serializers.UUIDField(required=False,validators=[validate_organization])
    first_name = serializers.CharField(min_length=2, max_length=50, required=True)
    last_name = serializers.CharField(min_length=1, max_length=50, required=True)
    phone = serializers.CharField(min_length=1, max_length=50, required=True)

class UpdateOrganizationUserSerializer(serializers.Serializer):
    role         = serializers.CharField(required=True,validators=[validate_role])
    organization = serializers.UUIDField(required=False,validators=[validate_organization])
    first_name = serializers.CharField(min_length=2, max_length=50, required=True)
    last_name = serializers.CharField(min_length=1, max_length=50, required=True)
    phone = serializers.CharField(min_length=1, max_length=50, required=True)


class ProfileUpadteSerializer(serializers.Serializer):
    first_name = serializers.CharField(min_length=2, max_length=50, required=True)
    last_name = serializers.CharField(min_length=1, max_length=50, required=True)
    phone = serializers.CharField(min_length=1, max_length=50, required=True)


class ListOrganizations(serializers.ModelSerializer):
    def get_contact(self,queryset):
        roles = models.Role.objects.filter(organization=queryset, role='admin')
        user_list = [i.user for i in roles]
        user = models.User.objects.filter(username__in=user_list).order_by('date_joined').first()
        if user:
            return UserListModelSerializer(user).data
        return {}

    contact = serializers.SerializerMethodField(method_name='get_contact')
    class Meta:
        model  = models.Organization
        fields = ['id', 'name', 'contact',]
