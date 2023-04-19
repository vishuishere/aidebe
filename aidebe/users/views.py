from rest_framework import status
from generics import permissions
from generics import exceptions
from rest_framework.response import Response
from rest_framework.permissions import AllowAny , IsAuthenticated
from rest_framework.viewsets import GenericViewSet
from rest_framework.schemas.openapi import AutoSchema
from rest_framework.decorators import permission_classes as _permission_classes
from rest_framework.views import APIView
from generics import mixins
from . import utils
from . import serializers
from . import models
from django.contrib.auth.hashers import make_password
from drf_spectacular.utils import extend_schema


class LogoutView(GenericViewSet):
    """
    API for Logout.
    """

    serializer_class = serializers.LogoutSerializer

    # schema = AutoSchema(
    #     tags=["Users"],
    #     operation_id_base=" Logout",
    # )

    @extend_schema(
        request=serializers.LogoutSerializer,
        responses={
            200: dict,
            409: dict,
        }
    )

    def create(self, request):
        """Logout an user account.
        Args:
            refresh: refresh token to be blacklisted.
        Returns:
            Response: status of the user logout.
        """
        serializer = serializers.LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.blacklist_token(serializer.validated_data)
        return Response(data={"detail": "Logout success."}, status=status.HTTP_200_OK)


class ResetPasswordView(GenericViewSet):
    """
    API to reset the password.
    """

    permission_classes = [AllowAny]

    # schema = AutoSchema(
    #     tags=["Users"],
    #     operation_id_base=" ResetPassword",
    # )

    def get_serializer_class(self):
        if self.action == "create":
            return serializers.ResetPasswordSerializer
        if self.action == "update":
            return serializers.ResetPasswordUpdateSerializer

    @extend_schema(
        request   = None,
        responses = {201: serializers.ResetPasswordSerializer})

    def create(self, request):
        serializer = serializers.ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.password_reset_email(serializer.validated_data)
        return Response(
            data={"detail": "Password reset email sent."},
            status=status.HTTP_201_CREATED,
        )
    
    @extend_schema(
        request   = None,
        responses = {201: serializers.ResetPasswordUpdateSerializer})

    def update(self, request):
        """
        Resets a new password through the forgot-password link.

        Params:
        -------
        key: str
            key is the auth key retrieved from the reset-password email.
        password: str
            password is the new password to be set to the user account.
        """
        serializer = serializers.ResetPasswordUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.password_reset_done(serializer.validated_data)
        return Response(
            data={"detail": "Password reset success."}, status=status.HTTP_202_ACCEPTED
        )


class ChangePasswordView(GenericViewSet):
    """
    API to change the user password.
    """

    # schema = AutoSchema(
    #     tags=["Users"],
    #     operation_id_base=" ChangePassword",
    # )

    
    @extend_schema(
        request=serializers.ChangePasswordValidateSerializer,
        responses={
            200: dict,
            409: dict,
        }
    )


    def get_serializer_class(self):
        if self.action == "update":
            return serializers.ChangePasswordSerializer

    def update(self, request):
        serializer = serializers.ChangePasswordSerializer(
            data=request.data, context={"user": request.user}
        )
        if serializer.is_valid(raise_exception=True):
            request.user.password = make_password(request.data['new_password'])
            request.user.save()
        
        # serializer.update_password(serializer.validated_data)
        return Response(
            data={"detail": "Password is updated."}, status=status.HTTP_202_ACCEPTED
        )



class UserView(mixins.PermissionsPerMethodMixin,GenericViewSet):

    permission_classes  = [IsAuthenticated, ]
    # serializer_class    = serializers.UserInfoModelSerializer
    queryset            = models.User.objects.none()
    def get_serializer_class(self):
        if self.action == "create":
            return serializers.CreateUserSerializer
        if self.action == "list":
            return serializers.UserInfoModelSerializer
        if self.action == "update":
            return serializers.UpdateOrganizationUserSerializer
        if self.action == "destroy":
            return serializers.UserInfoModelSerializer

    def get_queryset(self):
        if self.request.user.is_superuser:
            return "NA"
        else:
            if models.Role.objects.get(user = self.request.user).role == models.Role.RoleName.superadmin:
                return models.User.objects.all()
            organization = models.Role.objects.filter(user=self.request.user).first()
            organization_ = models.Role.objects.filter(organization=organization.organization)
            user_list = [i.user for i in organization_]
            return models.User.objects.filter(username__in=user_list).exclude(id=self.request.user.id)
    def get_all_queryset(self):
        if self.request.user.is_superuser:
            return "NA"
        else:
            if models.Role.objects.get(user = self.request.user).role == models.Role.RoleName.superadmin:
                return models.User.objects.all()
            organization = models.Role.objects.filter(user=self.request.user).first()
            organization_ = models.Role.objects.filter(organization=organization.organization)
            user_list = [i.user for i in organization_]
            return models.User.objects.filter(username__in=user_list)

    @extend_schema(
        request   = None,
        responses = {201: serializers.UserInfoModelSerializer})
    @_permission_classes((permissions.IsAuthenticated,))
    def list(self, request):
        """
        Lists all Users
        @TODO: Add pagination
        """
        querset     = self.get_all_queryset()
        if querset=="NA":
            user_data =  models.User.objects.all()
            serializer = serializers.UserInfoModelSerializer(user_data, many=bool)
            return Response(serializer.data)
        else:
            serializer  = serializers.UserInfoModelSerializer(querset, many=bool)
            return Response(serializer.data)
    
    @extend_schema(
        request   = None,
        responses = {200: dict})
    # @action(detail=False)
    def options(self, request):
        """Necessary data for user creation"""

        if models.Role.objects.get(user = self.request.user).organization == None:
            organizations = models.Organization.objects.all()
        else:
            organizations = models.Organization.objects.filter(id=utils.get_current_orgainzation(request.user.id).id)
        result= {
            "roles": [{"code":choice, "name":value} for choice, value in models.Role.RoleName.choices],
            "organizations": serializers.OrganizationNameListSerializer(organizations, many=True).data,
        }
        return Response(data=result, status=status.HTTP_200_OK)

    @extend_schema(
        request   = serializers.CreateUserSerializer,
        responses = {200: dict, 400: dict, 403: dict, 409: dict})
    @_permission_classes((permissions.IsSuperUser|permissions.IsOrganizationAdmin,))
    def create(self,request):
        """Creating users for organizations
         - API allowed by super admins or organizational admins only
         - If an organizational admin try to create a user in another organization,
            - Returns 403
        """
        # if request.user.is_staff:
        if request.data["role"] == "superadmin" or request.data["role"] == "Super Admin":
            serializer = serializers.CreateSuperUserSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            first_name  : str = serializer.validated_data.get('first_name', None)
            last_name   : str = serializer.validated_data.get('last_name', None)
            email       : str = serializer.validated_data.get('email', None)
            phone       : str = serializer.validated_data.get('phone', None)
            role        : str = serializer.validated_data.get('role', None)
            org_id      : str = serializer.validated_data.get('organization', None)
            organization = None
        else:

            serializer = serializers.CreateUserSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            first_name  : str = serializer.validated_data.get('first_name', None)
            last_name   : str = serializer.validated_data.get('last_name', None)
            email       : str = serializer.validated_data.get('email', None)
            phone       : str = serializer.validated_data.get('phone', None)
            role        : str = serializer.validated_data.get('role', None)
            org_id      : str = serializer.validated_data.get('organization', None)
            
            try:
                if self.request.user.is_superuser:
                    print(role)
                    # current_role = models.Role.objects.filter(role=role).first()
                    organization = models.Organization.objects.filter(id=org_id).first()
                    
                else:
                    current_role = models.Role.objects.get(user=request.user)
                    if not ((current_role.role == models.Role.RoleName.superadmin) or (current_role.role == models.Role.RoleName.admin)):
                        Response(data={"detail": "You do not have permission to access this."}, status=status.HTTP_403_FORBIDDEN)

                    if (org_id == None) and (current_role.role == models.Role.RoleName.admin):
                        Response(data={"detail": "You do not have permission to access this."}, status=status.HTTP_403_FORBIDDEN)

                    if current_role.role == models.Role.RoleName.superadmin:
                        organization = models.Organization.objects.filter(id=org_id).first()
                    elif current_role.role == models.Role.RoleName.admin:
                        organization = current_role.organization
                        if organization.id != org_id:
                            return Response(data={"detail": "You are not part of this organization"}, status=status.HTTP_403_FORBIDDEN)
                        if organization is None:
                            return Response(data={"detail": "You are not part of any organization"}, status=status.HTTP_403_FORBIDDEN)
                    else:
                        Response(data={"detail": "You do not have permission to access this."}, status=status.HTTP_403_FORBIDDEN)
            except models.Role.DoesNotExist:
                
                Response(data={"detail": "You do not have permission to access this."}, status=status.HTTP_403_FORBIDDEN)

        

        try:
           utils.create_user(first_name, last_name, organization, email.lower(), phone, role)
        except exceptions.ExistsError as e:
            return Response(data={"detail": e}, status=status.HTTP_409_CONFLICT)
        return Response(data={'detail': f'{role} created successfully'}, status=status.HTTP_201_CREATED)

    @extend_schema(
        request   = serializers.UpdateOrganizationUserSerializer,
        responses = {200: dict, 400: dict, 403: dict, 409: dict})
    def update(self, request, pk):
        """Updating a user_id
         - if SuperAdmin:
            - Update role, org, fname, lname, phone
         - else if OrganizationAdmin:
            - Check if org_id and current_org_id match
            - Check if user_id is in current organization
            - Cannot modify other organizations
            - Update role, fname, lname, phone
         - else:
            - Check if org_id and current_org_id match
            - Check modify other users
            - Cannot change organization, role
            - Update fname, lname, phone
        
        """
        if request.data["role"] == "superadmin" or request.data["role"] == "Super Admin":
            serializer = serializers.UpdateSuperAdminSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            # org_id_data      : str = serializer.validated_data.get('organization', None)
            role        : str = serializer.validated_data.get('role', None)
            first_name  : str = serializer.validated_data.get('first_name', None)
            last_name   : str = serializer.validated_data.get('last_name', None)
            phone       : str = serializer.validated_data.get('phone', None)
            org_id_data = None
        else:
            serializer = serializers.UpdateOrganizationUserSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            org_id_data      : str = serializer.validated_data.get('organization', None)
            role        : str = serializer.validated_data.get('role', None)
            role_data        : str = serializer.validated_data.get('role', None)
            first_name  : str = serializer.validated_data.get('first_name', None)
            last_name   : str = serializer.validated_data.get('last_name', None)
            phone       : str = serializer.validated_data.get('phone', None)
        if self.request.user.is_superuser:
                # current = models.Role.objects.filter(role=role).first()
                requested = utils.get_current_org_role(pk)
                if requested != None: #check super passed id is super admin or not
                    if role == "superadmin":
                        try:
                            user = models.User.objects.get(id=pk)
                            utils.update_to_super_admin(user, first_name, last_name, phone)
                            return Response(data={"detail": "User details has been updated."}, status=status.HTTP_200_OK)
                        except:
                            return Response(data={"detail": "Requested user does not exists"}, status=status.HTTP_404_NOT_FOUND)
                    else:
                        
                        # organization = models.Organization.objects.filter(id=org_id).first()
                        
                        try:
                            
                            user = models.User.objects.get(id=pk)
                            utils.update_user_detail(user, first_name, last_name, phone)
                            models.Role.objects.filter(user=user).update(role=role)
                            return Response(data={"detail": "User details has been updated."}, status=status.HTTP_200_OK)
                        except:
                            return Response(data={"detail": "Requested user does not exists"}, status=status.HTTP_404_NOT_FOUND)
                else: #for organization admin or user
                    if role == "superadmin":
                        try:
                            user = models.User.objects.get(id=pk)
                            utils.update_user_detail(user, first_name, last_name, phone)
                            return Response(data={"detail": "User details has been updated."}, status=status.HTTP_200_OK)
                        except:
                            return Response(data={"detail": "Requested user does not exists"}, status=status.HTTP_404_NOT_FOUND)

                    else:
                        try:
                            
                            user = models.User.objects.get(id=pk)
                            utils.update_to_admin(user, first_name, last_name, phone, role, org_id_data)

                            return Response(data={"detail": "User details has been updated."}, status=status.HTTP_200_OK)
                        except:
                            return Response(data={"detail": "Requested user does not exists"}, status=status.HTTP_404_NOT_FOUND)
        else:
            current = utils.get_current_org_role(request.user.id)
            requested = utils.get_current_org_role(pk)
            org_id = utils.get_organization(pk)
            role_obj = utils.get_current_org_role(pk)
            role = role_obj.role
        try:
            user = models.User.objects.get(id=pk)
        except:
            return Response(data={"detail": "Requested user does not exists"}, status=status.HTTP_404_NOT_FOUND)
        if org_id == None: organization = None
        # else: organization = models.Organization.objects.get(id=0)
        else: organization = org_id
      
        if (role != 'admin') and (requested.role=='admin') and len(requested.organization.role_set.filter(role='admin'))<=1:
            return Response(data={"detail": "organization must contain atleast one admin"}, status=status.HTTP_400_BAD_REQUEST)
        if current.role == models.Role.RoleName.superadmin:
            utils.update_user_detail(user, first_name, last_name, phone)
            models.Role.objects.filter(user=user).update(role=role)
            # utils.update_user_org_role(user,organization,role)       
            return Response(data={"detail": "User details has been updated."}, status=status.HTTP_200_OK)
        
        elif current.role == models.Role.RoleName.admin:
            if organization is None:
                # if organization is None, it means thats a enterprise user. Specify organization_id in request
                return Response(data={"detail": "You do not have the permission to modify enterprise users"}, status=status.HTTP_403_FORBIDDEN)
            if current.organization.id != org_id:
                return Response(data={"detail": "You do not have permission to modify this organization"}, status=status.HTTP_403_FORBIDDEN)
            if str(utils.get_current_org_role(pk).organization.id) != str(current.organization.id):
                return Response(data={"detail": "User does not belong to your organization"}, status=status.HTTP_400_BAD_REQUEST)
            if (role != 'admin') and (requested.role=='admin') and len(requested.organization.role_set.filter(role='admin'))<=1:
                return Response(data={"detail": "organization must contain atleast one admin"}, status=status.HTTP_400_BAD_REQUEST)
            utils.update_user_detail(user, first_name, last_name, phone)
            # print(role_data)
            models.Role.objects.filter(user=user).update(role=role_data)
            # utils.update_user_role(user, role)
            
            return Response(data={"detail": "User details has been updated."}, status=status.HTTP_200_OK)
        
        else:
            if pk != request.user.id:
                return Response(data={"detail": "You do not have permission to modify another users"}, status=status.HTTP_403_FORBIDDEN)            
            if str(current.organization.id) != org_id:
                return Response(data={"detail": "You do not have permission to change your organization"}, status=status.HTTP_403_FORBIDDEN)
            if current.role != role:
                return Response(data={"detail": "You do not have permission to change your role"}, status=status.HTTP_403_FORBIDDEN)

            utils.update_user_detail(user, first_name, last_name, phone)
            
            return Response(data={"detail": "User details has been updated."}, status=status.HTTP_200_OK)
    
    @extend_schema(responses = {202: dict,400: dict, 403: dict, 404: dict})
    @_permission_classes((permissions.IsSuperUser|permissions.IsOrganizationAdmin,))
    def destroy(self, request, pk):
        if pk==request.user.id: return Response(data={"detail": "You cannot delete yourself"}, status=status.HTTP_403_FORBIDDEN)
        if self.request.user.is_superuser:
                # requested = utils.get_current_org_role(pk)
                utils.delete_user(pk)
                return Response(data={"status": "User deleted successfully"}, status=status.HTTP_202_ACCEPTED)
                # if (requested.role=='admin') and len(requested.organization.role_set.filter(role='admin'))<=1:
                #     return Response(data={"detail": "organization must contain atleast one admin"}, status=status.HTTP_400_BAD_REQUEST)
       
        else:
            requested = utils.get_current_org_role(pk)
            current   = utils.get_current_org_role(request.user.id)
            if (requested.role=='admin') and len(requested.organization.role_set.filter(role='admin'))<=1:
                return Response(data={"detail": "organization must contain atleast one admin"}, status=status.HTTP_400_BAD_REQUEST)
            if (current.role == models.Role.RoleName.admin) and (requested.organization != current.organization):
                return Response(data={"detail": "User does not belong to your organization"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            self.get_queryset()
        except models.User.DoesNotExist:
            return Response(data={"detail": f"{pk} not found"}, status=status.HTTP_404_NOT_FOUND)
        # user = functions.get_user_by_id(id=pk)
        utils.delete_user(pk)
        return Response(data={"status": "User deleted successfully"}, status=status.HTTP_202_ACCEPTED)


class SingleUserView(mixins.PermissionsPerMethodMixin,GenericViewSet):

    permission_classes  = [IsAuthenticated, ]
    serializer_class    = serializers.UserInfoModelSerializer
    queryset            = models.User.objects.none()

    def get_queryset(self):
        if self.request.user.is_superuser:
            return "NA"
        else:
            if models.Role.objects.get(user = self.request.user).role == models.Role.RoleName.superadmin:
                return models.User.objects.all()
            organization = models.Role.objects.filter(user=self.request.user).first()
            
            return models.User.objects.filter(username=organization.user).first()
    @extend_schema(
        request   = None,
        responses = {201: serializers.UserInfoModelSerializer})
    @_permission_classes((permissions.IsAuthenticated,))
    def single_list(self, request):
        """
        Lists all Users
        @TODO: Add pagination
        """
        querset     = self.get_queryset()
        if querset=="NA":
            user_data =  request.user
            serializer = serializers.UserInfoModelSerializer(user_data)
            return Response(serializer.data)
        else:
            serializer  = serializers.UserInfoModelSerializer(querset)
            return Response(serializer.data)

class OrganisationCRUDView(mixins.PermissionsPerMethodMixin,GenericViewSet):
    """

    APIs to create,retrieve,update and delete organization


    """

    permission_classes  = [IsAuthenticated, ]
    # serializer_class    = serializers.OrganizationResponseSerializer
    # queryset            = models.Organization.objects.none()
    
    # schema = AutoSchema(
    #     tags=["Organization"],
    #     operation_id_base=" Organization",
    # )

    def get_serializer_class(self):
        if self.action == "create":
            return serializers.OrganisationCreateSerializer
        if self.action == "list":
            return serializers.OrganizationResponseSerializer
        if self.action == "update":
            return serializers.OrganizationInfoUpdateSerializer
        if self.action == "destroy":
            return serializers.OrganizationDeleteSerializer
       
    def get_queryset(self):
        
        org_role = models.Role.objects.filter(user_id=self.request.user.id).first()
        # print(org_role)
      
        if org_role is None:
            
            return models.Organization.objects.all().order_by('-created_at')
        else:
            
            return models.Organization.objects.filter(id=org_role.organization.id).order_by('-created_at')
        # org_role = models.Role.objects.filter(user=self.request.user).first()
        # # org_role = models.Role.objects.filter(organization=org_role.Organization)
        # if org_role is None:
        #     return models.Organization.objects.all().order_by('-created_at')
        # else:
        #     return models.Organization.objects.filter(id=org_role.organization.id).order_by('-created_at')
        
        # return serializers.OrganisationCreateSerializer
        # if self.action == "list":
        #     return serializers.OrganizationesponseSerializer
    

    # def get_queryset(self):
    #     org_role = models.Role.objects.filter(user=self.request.user).first()
    #     if org_role.organization is None:
    #         return models.Organization.objects.all().order_by('-created_at')
    #     else:
    #         return models.Organization.objects.filter(id=org_role.organization.id).order_by('-created_at')

    @extend_schema(
        request   = serializers.OrganisationCreateSerializer,
        responses = {
            201: dict,
            404: dict,
            409: dict
        })
    @_permission_classes((permissions.IsSuperUser,))
    def create(self, request, *args, **kwargs):
        """
        Creates an account for Organization Admin

        Params:
        \tfirst_name : first_name of the user.
        \tlast_name  : last_name of the user.
        \temail      : email of the user.
        \tname       : name of the organization.
        \tphone      : phone number of the user.
        """
        serializer = serializers.OrganisationCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        first_name  : str = serializer.validated_data.get('first_name', None)
        last_name   : str = serializer.validated_data.get('last_name', None)
        email       : str = serializer.validated_data.get('email', None)
        name        : str = serializer.validated_data.get('name', None)
        phone       : str = serializer.validated_data.get('phone', None)

        try:
            utils.create_organization_admin(creator=request.user, first_name=first_name, last_name=last_name, email=email, name=name, phone=phone)
        except exceptions.ExistsError as error:
            return Response(data={"detail": str(error)}, status=status.HTTP_400_BAD_REQUEST)
        except exceptions.NotExistsError as error:
            return Response(data={"detail": str(error)}, status=status.HTTP_404_NOT_FOUND)

        return Response(data={'detail': 'Organization admin created successfully'}, status=status.HTTP_201_CREATED)

    @extend_schema(
        request   = None,
        responses = {201: serializers.OrganizationResponseSerializer})
    @_permission_classes((permissions.IsAuthenticated,))
    def list(self, request):
        """
        Lists all organizations
        @TODO: Add pagination
        """
        querset     = self.get_queryset()
        serializer  = serializers.ListOrganizations(querset, many=bool)
        return Response(serializer.data)

    @extend_schema(
        request   = serializers.OrganizationInfoUpdateSerializer,
        responses = {201: serializers.OrganizationResponseSerializer})
    @_permission_classes((permissions.IsSuperUser|permissions.IsOrganizationAdmin,))
    def update(self, request, pk=None):
        pk =request.data["id"]
        update_name= request.data["name"]
        update_first_name= request.data["first_name"]
        update_last_name= request.data["last_name"]
        update_phone= request.data["phone"]
        print(pk, type(update_phone), update_phone)
        try:
            instance = self.get_queryset().first()
            # for org in instance:
            org_id = instance.id
            models.Organization.objects.filter(id = org_id).update(name = update_name)
            models.User.objects.filter(id = pk).update(first_name=update_first_name, last_name=update_last_name)
            models.Profile.objects.filter(user_id=pk).update(phone=update_phone)
            resposne_data = models.Organization.objects.filter(id = org_id).first()
           
        except models.Organization.DoesNotExist:
           
            return Response({"detail": f"{pk} not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # if (not request.user.is_staff) and (not models.Role.objects.filter(user__id=request.user.id,organization__id=pk).exists()):
        #     print("24")
        #     return Response(data={"detail": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        # serializer = serializers.OrganizationUpdateSerializer(instance, data=request.data, partial=True,many=True)
        # serializer.is_valid(raise_exception=True)
        # serializer.save()
        
        return Response({"name":resposne_data.name}, status=status.HTTP_202_ACCEPTED)

    @extend_schema(
        request   = serializers.OrganizationDeleteSerializer,
        responses = {
            202: dict,
            404: dict})
    @_permission_classes((permissions.IsSuperUser,))
    def destroy(self, request, pk=None):
        try:
            pk= request.data["id"]
            instance = self.get_queryset().get(pk=pk)
        except models.Organization.DoesNotExist:
            return Response(data={"detail": f"{pk} not found"}, status=status.HTTP_404_NOT_FOUND)

        # finding the users in Hospital Group
        organization = models.Role.objects.filter(organization__id=pk)
        user_list = [i.user for i in organization]

        models.User.objects.filter(username__in=user_list).delete()
        instance.delete()
        return Response(data={"status": "success"}, status=status.HTTP_202_ACCEPTED)

    # @extend_schema(
    #     responses = {
    #         200: serializers.OrganizationResponseSerializer,
    #         404: dict, 403: dict})
    # @_permission_classes((permissions.IsAuthenticated,))
    # def retrieve(self, request, pk=None):
    #     org_role = models.Role.objects.get(organization__id=pk,user__id=request.user.id)
    #     if str(org_role.organization.id) != pk:
    #         return Response(data={"detail": "You are not part of this organization"}, status=status.HTTP_403_FORBIDDEN)

    #     querset = get_object_or_404(self.get_queryset(), pk=pk)
    #     serializer  = self.serializer_class(querset)
    #     return Response(serializer.data)

class OrganisationUpdateApi(mixins.PermissionsPerMethodMixin,GenericViewSet):
    serializer_class = serializers.OrganizationDeleteSerializer
    queryset = models.Organization
    def get_queryset(self):
        
        org_role = models.Role.objects.filter(user_id=self.request.user.id).first()
        # print(org_role)
            
        if org_role is None:
            
            return models.Organization.objects.all().order_by('-created_at')
        else:
            
            return models.Organization.objects.filter(id=org_role.organization.id).order_by('-created_at')

    @extend_schema(
        request   = serializers.OrganizationDeleteSerializer,
        responses = {
            202: dict,
            404: dict})
    @_permission_classes((permissions.IsSuperUser,))
    def destroy(self, request, pk):
        try:
            
            instance = self.get_queryset().get(pk=pk)
        except models.Organization.DoesNotExist:
            return Response(data={"detail": f"{pk} not found"}, status=status.HTTP_404_NOT_FOUND)

        # finding the users in Hospital Group
        organization = models.Role.objects.filter(organization__id=pk)
        user_list = [i.user for i in organization]

        models.User.objects.filter(username__in=user_list).delete()
        instance.delete()
        return Response(data={"status": "success"}, status=status.HTTP_202_ACCEPTED)


class RoleGetApi(APIView):
    def get(self,request):
        response_data = [{"code":"user","name":"User"},{"code":"admin","name":"Admin"},{"code":"superadmin","name":"Super Admin"}]
        
        return Response(response_data)


class ProfileUpdate(mixins.PermissionsPerMethodMixin,GenericViewSet):
    permission_classes  = [IsAuthenticated, ]
    serializer_class    = serializers.ProfileUpadteSerializer
    queryset            = models.User.objects.none()

    # @extend_schema(
    #     request   = serializers.ProfileUpadteSerializer,
    #     responses = {200: dict, 400: dict, 403: dict, 409: dict})
    schema = AutoSchema(
        tags=["api"],
        operation_id_base="profile",
    )
    def update(self, request, pk):
        serializer = serializers.ProfileUpadteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        first_name  : str = serializer.validated_data.get('first_name', None)
        last_name   : str = serializer.validated_data.get('last_name', None)
        phone       : str = serializer.validated_data.get('phone', None)

        try:
                            
            user = models.User.objects.get(id=pk)
            utils.update_user_detail(user, first_name, last_name, phone)
            
            return Response(data={"detail": "User details has been updated."}, status=status.HTTP_200_OK)
        except:
            return Response(data={"detail": "Requested user does not exists"}, status=status.HTTP_404_NOT_FOUND)