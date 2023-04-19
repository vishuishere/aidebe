import base64
import datetime
import threading

from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.auth.hashers import make_password
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.utils.crypto import get_random_string

from . import models
from . import configurations
from generics import exceptions


class CryptoGraphy:
    def __init__(self):
        password_provided = settings.SECRET_KEY
        password = password_provided.encode()  # Convert to bytes type

        salt = b"`y\xcdB`\xc8.\xb8J\xd5\xb6\xd5\xfb\x99X\x94"  # must be type bytes

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )

        self.key = base64.urlsafe_b64encode(
            kdf.derive(password)
        )  # Can only use kdf once

    def crypto_encrypt_msg(self, data_string):
        encoded_message = data_string.encode()
        return Fernet(self.key).encrypt(encoded_message).decode()

    def crypto_decrypt_msg(self, data_string):
        encoded_message = data_string.encode()

        try:
            decrypted = Fernet(self.key).decrypt(encoded_message)
        except InvalidToken:
            return None

        return decrypted.decode()

    def non_safe_base64_encode(self, data_string):
        encoded_message = data_string.encode()
        return base64.b64encode(encoded_message).decode()

    def non_safe_base64_decode(self, data_string):
        encoded_message = data_string.encode()
        return base64.b64decode(encoded_message).decode()


def generate_key(email):
    message = f"{email}{configurations.URL_MESSAGE_SPLITOR}{datetime.datetime.now()}"
    return CryptoGraphy().crypto_encrypt_msg(data_string=message)


class EmailService:
    def __init__(self, email_args, email_to_list):
        self.email_args     = email_args
        self.email_to_list  = email_to_list

    def send_custom_email(self, subject, html_body):
        send_mail(
            subject = subject,
            message = '',
            from_email      = settings.EMAIL_HOST_USER,
            recipient_list  = self.email_to_list,
            html_message    = html_body
        )
    
    def send_welcome_email(self):
        subject     = "Welcome to l3harris"
        full_name   = self.email_args['full_name']
        email       = self.email_args['email']
        password    = self.email_args['password']
        origin      = self.email_args['origin']
        primary_layout  = render_to_string('welcome.html', {'fullname': full_name, 'email': email, 'password': password, 'origin': origin,'url':settings.WELCOME_EMAIL_URL})
        html_body       = render_to_string('main.html', {'content': primary_layout})
        self.send_custom_email(subject, html_body)

    def send_password_reset_email(self):
        subject     = "l3harris: Reset Password"
        full_name   = self.email_args['full_name']
        email       = self.email_args['email']
        url         = self.email_args['args']
        primary_layout  = render_to_string('resetpassword.html', {'name': full_name, 'email': email,'url':url})
        html_body       = render_to_string('main.html', {'content': primary_layout})

        self.send_custom_email(subject, html_body)


def send_email_as_thread(subject, email, firstname, template, args):
    
    # t = threading.Thread(
    #     target=EmailService(subject, email, firstname, template).make_send_email,
    #     args=args,
    # )
    # t.start()
    email_args = {
        'full_name' : firstname ,
        'email'     : email,
        'args'      :args
    }

    t = threading.Thread(target=EmailService(email_args, [email, ]).send_password_reset_email)
    t.start()


def is_link_timeout(current_time, url_generated_time, minutes):
    time_diff = current_time - url_generated_time
    minutes_diff = time_diff.seconds / 60
    return True if minutes_diff > minutes else False


def is_link_expired(key, minutes, help_text, link_len=2):
    decrypted_message = CryptoGraphy().crypto_decrypt_msg(key)
    if decrypted_message is None:
        raise exceptions.ContentExpired(detail=f"Invalid {help_text.lower()} link.")

    data_list = decrypted_message.split(configurations.URL_MESSAGE_SPLITOR)
    if len(data_list) < link_len:
        raise exceptions.ContentExpired(detail=f"Invalid {help_text.lower()} link.")

    email, date_string = data_list

    url_gen_time = datetime.datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S.%f")
    current_time = datetime.datetime.now()

    is_timeout = is_link_timeout(current_time, url_gen_time, minutes)

    if is_timeout:
        raise exceptions.ContentExpired(detail=f"{help_text} link expired.")

    return email


def update_password(email, password):
    users = models.User.objects.filter(username=email, is_active=True)
    if not users.exists():
        raise exceptions.NotAllowedError(detail="Invalid password reset link.")

    password_hash = make_password(password)
    users.update(password=password_hash)

def get_hashed_password(allowed_chars: str) -> tuple:
    password_str = get_random_string(length=8, allowed_chars=allowed_chars)
    return password_str, make_password(password_str)

def get_user_by_email(email: str, active: bool = True, active_check: bool = True):
    if not active_check:
        return models.User.objects.filter(username=email).first()
    return models.User.objects.filter(username=email, is_active=active).first()

def is_organization_exists(organization_name: str):
    return models.Organization.objects.filter(name=organization_name).first()

# def is_email_exists(email_value: str):
   
#     return models.User.objects.filter(email=email_value).first()
    

def create_organization(creator, first_name: str, last_name: str, name: str, email: str, phone: str, password: str) -> bool:
    
    user = get_user_by_email(email=email, active_check=True)
    if user is not None:
        raise exceptions.ExistsError("The Email address is already being used.")
    organization = is_organization_exists(organization_name=name)
    if organization is not None:
        raise exceptions.ExistsError("The Organization name is already being used.")
    # or_email = is_email_exists(email_value=email)
    # if or_email is not None:
    #     raise exceptions.ExistsError(detail="Email already exists.")

    user = models.User.objects.create(first_name=first_name, last_name=last_name, username=email, email= email, is_staff=False, is_superuser=False, password=password)
    organization = models.Organization.objects.create(name=name, created_by=creator)
    models.Role.objects.create(user=user, organization=organization, role=models.Role.RoleName.admin)
    profile = models.Profile.objects.create(user=user, phone=phone)

def create_organization_user(first_name: str, last_name: str, email: str, phone: str, password: str,role: str,  organization) -> bool:
    user = models.User.objects.create(first_name=first_name, last_name=last_name, username=email, is_staff=False, is_superuser=False, password=password)
    profile = models.Profile.objects.create(user=user, phone=phone)
    models.Role.objects.create(user=user, organization=organization, role=role)
