from datetime import datetime, timedelta
import random
from django.conf import settings
from rest_framework import serializers

from .models import UserModel
from .utils import send_otp

class UserSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(
        write_only=True,
        min_length=settings.MIN_PASSWORD_LENGTH,
        error_messages={
            'min_length': 'Password must be at least {min_length} characters long'
        },
        )
    
    password2 = serializers.CharField(
        write_only=True,
        min_length=settings.MIN_PASSWORD_LENGTH,
        error_messages={
            'min_length': 'Password must be at least {min_length} characters long'
        },
        )
    class Meta:
        model = UserModel
        fields = (
            'id',
            'phone_number',
            # 'email',
            'password1',
            'password2',)
        read_only_fields = ('id',)
    def validate(self, data):
        if data['password1'] != data['password2']:
            raise serializers.ValidationError("Passwords do not match")
        return data
    def create(self, validated_data):
        otp = random.randint(1000, 9999)
        otp_expiry = datetime.now() + timedelta(minutes=10)
        user = UserModel.objects.create(
            phone_number=validated_data['phone_number'],
            # email=validated_data['email'],
            otp=otp,
            otp_expiry=otp_expiry,
            max_otp_try=settings.MAX_OTP_TRY,
            
        )
        user.set_password(validated_data['password1'])
        user.save()
        send_otp(validated_data['phone_number'], otp)
        return user
    
    


