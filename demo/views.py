import random
import datetime
from django.conf import settings
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework import serializers
from .models import UserModel
from .serializers import UserSerializer
from .utils import send_otp
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User

class UserViewSet(viewsets.ModelViewSet):
    queryset = UserModel.objects.all()
    serializer_class = UserSerializer
    @action(detail=True, methods=['PATCH'])
    def verify_otp(self, request, pk=None):
        instance = self.get_object()
        if (
            not instance.is_active
            and instance.otp == request.data.get('otp')
            and instance.otp_expiry
            and timezone.now() < instance.otp_expiry):
            instance.is_active = True
            instance.otp_expiry = None
            instance.max_otp_try = settings.MAX_OTP_TRY
            instance.otp_max_out = None
            instance.save()
            return Response({'status': 'Sucessfully verified the User'}, status=status.HTTP_200_OK)
        return Response({'status': 'User active or Please enter the correct OTP'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['PATCH'])
    def regenerate_otp(self, request, pk=None):
        instance = self.get_object()
        if int(instance.max_otp_try) == 0 and timezone.now() < instance.otp_max_out:
            return Response(
                "Maximum OTP attempts reached. Please try after 10 minutes",
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        otp = random.randint(1000, 9999)
        otp_expiry = timezone.now() + datetime.timedelta(minutes=10)
        max_otp_try = int(instance.max_otp_try) - 1
        instance.otp = otp
        instance.otp_expiry = otp_expiry
        instance.max_otp_try = max_otp_try

        if max_otp_try == 0:
            instance.otp_max_out = timezone.now() + datetime.timedelta(hours=1)
        elif max_otp_try == -1:
            instance.otp_max_out = settings.MAX_OTP_TRY
        else:
            instance.otp_max_out = None
            instance.max_otp_try = max_otp_try

        instance.save()
        send_otp(instance.phone_number, otp)
        return Response({'status': 'OTP has been regenerated'}, status=status.HTTP_200_OK)
    


@api_view(['POST'])
def login_view(request):
    """
    API endpoint for user login.
    Expects 'phone_number' and 'password' in the request body.
    """
    phone_number = request.data.get('phone_number')
    password = request.data.get('password')

    if not phone_number or not password:
        return Response({'detail': 'Phone number and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

    # Authenticate the user
    user = authenticate(username=phone_number, password=password)

    if user:
        if user.is_active:
            return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
        return Response({'detail': 'User account is inactive.'}, status=status.HTTP_403_FORBIDDEN)

    return Response({'detail': 'Invalid phone number or password.'}, status=status.HTTP_401_UNAUTHORIZED)