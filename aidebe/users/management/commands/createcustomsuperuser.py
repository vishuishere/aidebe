from django.core.management.base import BaseCommand, CommandError
from users import models as user_models
from django.contrib.auth.hashers import make_password

class Command(BaseCommand):
    
    def create_super_admin(self, email, firstname, lastname, password1):
        user = user_models.User.objects.filter(username=email)
        if user.exists():
            return False, "User already exists."
        password_hash = make_password(password1)

        user = user_models.User.objects.create(first_name=firstname, last_name=lastname, username=email, is_staff=True, is_superuser=True, password=password_hash)

        return True, "Super Admin created successfully!"
    def handle(self, *args, **options):
        result, message = self.create_super_admin("jithin.j@logicplum.com","JITHIN", "J", "Sprnva@12345678")
        if result:
            self.stdout.write(self.style.SUCCESS(message))
        else:
            message="Superuser creation failed!"
            self.stdout.write(self.style.ERROR_OUTPUT(message))