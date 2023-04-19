from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import ugettext_lazy as _
import uuid
from generics import mixins


class User(AbstractUser):
    # Changing default username field type `CharField` to `EmailField`
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.EmailField(
        _('email address'),
        unique=True,
        error_messages={'unique': "A user with that username already exists."})

    EMAIL_FIELD = 'username'
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.username

    class Meta:
        verbose_name_plural = "Users"


class Profile(mixins.GenericModelMixin):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    phone = models.CharField(null=True, max_length=50)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = "Profiles"


class Organization(mixins.GenericModelMixin):
    name = models.CharField(null=False, max_length=50, unique=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Organizations"


class Role(mixins.GenericModelMixin):
    class RoleName(models.TextChoices):
        """
        -----------
        Permissions
        -----------
        user      : see roadmaps
        admin     : everything in the organization
        """
        user        = "user", "User"
        admin       = "admin", "Organization Admin"
        superadmin  = "superadmin", "Super Admin"

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(null=True,
                            max_length=50,
                            choices=RoleName.choices,
                            default=RoleName.admin)
    # organization: Field to check if organization user or not
    organization = models.ForeignKey(Organization,
                                     null=True,
                                     on_delete=models.CASCADE)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = "Roles"


class Activity(mixins.GenericModelMixin):
    class Action(models.TextChoices):
        login = "login", "Login"
        logout = "logout", "Logout"

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=50,
                            choices=Action.choices,
                            default=Action.login)
    description = models.TextField(blank=True, null=True)
    arguments = models.JSONField(null=False, default=dict)
    organization = models.ForeignKey(Organization,null=True,on_delete=models.CASCADE)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = "Activities"


