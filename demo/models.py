from django.db import models
from django.conf import settings
from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager, PermissionsMixin)
from django.core.validators import RegexValidator, validate_email

phone_regex = RegexValidator(regex=r'^\d{10}', message="Phone number must be entered in the format")

class UserManager(BaseUserManager):
    def create_user(self, phone_number, password=None,):
        if not phone_number:
            raise ValueError('Users must have a phone number')
        user = self.model(
            phone_number=phone_number,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone_number, password):
        user = self.create_user(
            phone_number=phone_number,
            password=password,
        )
        user.is_active = True
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user

class UserModel(AbstractBaseUser ,PermissionsMixin):
    phone_number = models.CharField(validators=[phone_regex], max_length=10, unique=True,null=False, blank=False)
    # email = models.EmailField(max_length=50, blank= True, null=True, validators=[validate_email])
    otp = models.CharField(max_length=6)
    otp_expiry = models.DateTimeField(blank=True, null=True)
    max_otp_try = models.CharField(max_length=2, default=settings.MAX_OTP_TRY)
    otp_max_out = models.DateTimeField(blank=True, null=True)

    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    user_registered_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'phone_number'
    # REQUIRED_FIELDS = ['phone_number']

    objects = UserManager()
    def __str__(self):
        return self.phone_number
    

    