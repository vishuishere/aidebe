from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password, check_password
from django.conf import settings
import threading
import datetime
from generics import exceptions
from . import functions
from . import configurations
from . import models
from . import serializers


def blacklist_token(refresh: str) -> None:
    try:
        token = RefreshToken(refresh)
        token.blacklist()
        return True
    except:
        return False

def get_user_info(user_id: int) -> dict:
    user = functions.get_user_by_id(id=user_id)
    if user is None:
        return False
    return functions.user_info(user)

def create_super_admin(first_name: str, last_name: str, email: str, phone:str, role: str):
    password_str, password_hash = functions.get_hashed_password(allowed_chars=configurations.ALLOWED_RANDOM_CHARS)
    user = models.User.objects.filter(username=email)
    if user.exists():
        raise exceptions.ExistsError("User already exists new")
    ce = models.User.objects.create(first_name=first_name, last_name=last_name, username=email, is_staff=True, is_superuser=True, password=password_hash)
    if not ce:
        return False
    profile = models.Profile.objects.create(user=ce, phone=phone)
    # models.Role.objects.create(user=ce, role=role)
    email_args = {
        'full_name' : f"{first_name.capitalize()} {last_name.capitalize()}".strip(),
        'email'     : email,
        'password'  : password_str,
        'origin'    : settings.SITE_ORIGIN,
    }
    # Send Email as non blocking thread. Reduces request waiting time.
    t = threading.Thread(target=functions.EmailService(email_args, [email, ]).send_welcome_email)
    t.start()
    return True

def create_enterprise_user(first_name: str, last_name: str, email: str, phone:str, role: str) -> bool:
    password_str, password_hash = functions.get_hashed_password(allowed_chars=configurations.ALLOWED_RANDOM_CHARS)
    user = models.User.objects.filter(username=email)
    if user.exists():
        raise exceptions.ExistsError("User already exists new")
    ce = functions.create_enterprise_user(first_name, last_name, email, phone, password_hash, role)
    if not ce:
        return False

    email_args = {
        'full_name' : f"{first_name} {last_name}".strip(),
        'email'     : email,
        'password'  : password_str,
        'origin'    : settings.SITE_ORIGIN,
    }
    # Send Email as non blocking thread. Reduces request waiting time.
    t = threading.Thread(target=functions.EmailService(email_args, [email, ]).send_welcome_email)
    t.start()
    return True

def list_super_user():
    users = models.User.objects.filter(is_staff=True)
    return serializers.SuperUserListModelSerializer(users, many=True).data

def password_reset_done(key: str, password: str) -> bool:
    password = password.strip()
    decrypted_message = functions.CryptoGraphy().crypto_decrypt_msg(key)
    if decrypted_message is None:
        return False

    data_list = decrypted_message.split('||')
    if len(data_list) < 3:
        return False

    email, date_string, user_id = data_list
    url_generated_time  = datetime.datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S.%f")
    current_time        = datetime.datetime.now()
    is_greater_15_mins: bool = functions.is_time_greater_15_mins(current_time=current_time, url_generated_time=url_generated_time)

    if is_greater_15_mins:
        return False

    return functions.update_password(user_id=user_id, email=email, password=password)

def password_reset_email(email: str) -> bool:
    password_str, password_hash = functions.get_hashed_password(allowed_chars=configurations.ALLOWED_RANDOM_CHARS)
    email = email.strip()
    # user  = functions.get_user_by_email(email=email)
    user = models.User.objects.filter(username=email).first()
    if user is None:
        return False
    user.password = password_hash
    user.save()
    message = f"{email}||{datetime.datetime.now()}||{user.id}"
    encrypted_message = functions.CryptoGraphy().crypto_encrypt_msg(data_string=message)

    # email_args = {
    #     'full_name': user.get_full_name(),
    #     'url': f"{settings.SITE_ORIGIN}/{configurations.CHANGE_PASSWORD_BROWSER_URL}?key={encrypted_message}",
    # }
    email_args = {
        'full_name' : user.get_full_name(),
        'email'     : email,
        'password'  : password_str,
        'origin'    : settings.SITE_ORIGIN,
    }

    # Send Email as non blocking thread. Reduces request waiting time.
    t = threading.Thread(target=functions.EmailService(email_args, [email, ]).send_password_reset_email)
    t.start()
    return True


def update_user_detail(user, first_name: str, last_name: str, phone: str) -> None:
    profile = models.Profile.objects.filter(user=user).update(phone=phone)
    if profile == 0: models.Profile.objects.create(user=user, phone=phone)
    models.User.objects.filter(id=user.id).update(first_name=first_name, last_name=last_name)

def update_to_super_admin(user, first_name: str, last_name: str, phone: str) -> None:
    profile = models.Profile.objects.filter(user=user).update(phone=phone)
    if profile == 0: models.Profile.objects.create(user=user, phone=phone)
    models.User.objects.filter(id=user.id).update(first_name=first_name, last_name=last_name, is_staff=True, is_superuser=True)
    models.Role.objects.filter(user_id=user.id).delete()

def update_to_admin(user, first_name: str, last_name: str, phone: str, role,org_id_data) -> None:
    profile = models.Profile.objects.filter(user=user).update(phone=phone)
    if profile == 0: models.Profile.objects.create(user=user, phone=phone)
    models.User.objects.filter(id=user.id).update(first_name=first_name, last_name=last_name, is_staff=False, is_superuser=False)
    models.Role.objects.create(user=user, organization_id=org_id_data, role=role)


def delete_user(user_id):
    # user = functions.get_user_by_id(id=user_id)
    user = models.User.objects.filter(id=user_id).first()
    models.Profile.objects.filter(user=user).delete()
    user.delete()


def create_organization_admin(creator, first_name: str, last_name: str, name: str, email: str, phone: str):
    password_str, password_hash = functions.get_hashed_password(allowed_chars=configurations.ALLOWED_RANDOM_CHARS)
    user = models.User.objects.filter(username=email)
    if user.exists():
        raise exceptions.ExistsError("Email already exists.")
    functions.create_organization(creator, first_name, last_name, name, email, phone, password_hash)

    email_args = {
        'full_name': f"{first_name} {last_name}".strip(),
        'email': email,
        'password': password_str,
        'origin': settings.SITE_ORIGIN,
    }
    # print(email_args,"AAAAAAAAAAAAAAAAAAAAAAAA")
    # Send Email as non blocking thread. Reduces request waiting time.
    t = threading.Thread(target=functions.EmailService(email_args, [email, ]).send_welcome_email)
    t.start()


def get_user_by_id(id: int, active: bool = True):
    return models.User.objects.filter(id=id, is_active=active).first()


def get_user_by_id_email(id: int, email: str, active: bool = True):
    return models.User.objects.filter(id=id, username=email, is_active=active)


def update_password(user_id: int, email: str, password: str) -> bool:
    users = get_user_by_id_email(id=user_id, email=email)

    if users.first() is None:
        raise exceptions.NotExistsError(message="User account does not exist.")

    password_hash = make_password(password)
    users.update(password=password_hash)
    return True


def change_password(user_id: int, email: str, old_password: str, new_password: str) -> bool:
    user = get_user_by_id(id=user_id)
    if user is None:
        raise exceptions.NotExistsError(message="User account does not exist.")
    if not check_password(password=old_password, encoded=user.password):
        return False
    return update_password(user_id=user_id, email=email, password=new_password)

def get_current_orgainzation(user_id: int):
    organization_role = models.Role.objects.filter(user__id=user_id).first()
    if organization_role is None:
        return organization_role
    return organization_role.organization

def get_current_org_role(user_id: int):
    organization_role = models.Role.objects.filter(user__id=user_id).first()
    if organization_role is None:
        return organization_role
    return organization_role
def get_organization(user_id: int):
    organization_role = models.Role.objects.filter(user__id=user_id).first()
    if organization_role is None:
        return "NA"
    else:
        org = organization_role.organization.id
        
        return org

def create_user(first_name: str, last_name: str, organization, email: str, phone: str, role: str):
    if organization is None:
        create_super_admin(first_name, last_name, email, phone, role)
    else:
        create_org_user(first_name, last_name, organization, email, phone, role)

def create_org_user(first_name: str, last_name: str, organization, email: str, phone: str, role: str):
    password_str, password_hash = functions.get_hashed_password(allowed_chars=configurations.ALLOWED_RANDOM_CHARS)
    user = models.User.objects.filter(username=email)
    if user.exists():
        raise exceptions.ExistsError("Email already exists.")

    functions.create_organization_user(first_name, last_name, email, phone, password_hash, role, organization)
    email_args = {
        'full_name': f"{first_name} {last_name}".strip(),
        'email': email,
        'password': password_str,
        'origin': settings.SITE_ORIGIN,
    }
    # Send Email as non blocking thread. Reduces request waiting time.
    t = threading.Thread(target=functions.EmailService(email_args, [email, ]).send_welcome_email)
    t.start()

def update_user_org_role(user, organization, role) -> None:
    if role == 'superadmin':
        user.is_staff = True
        user.is_superuser = True
        user.save()
        # models.Role.objects.filter(user=user).update(organization=None, role=role)
    else:
        user.is_staff = False
        user.is_superuser = False
        user.save()
        # models.Role.objects.filter(user=user).update(organization=organization, role=role)

def update_user_role(user, role) -> None:
    models.Role.objects.filter(user=user).update(role=role)