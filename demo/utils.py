import requests
from django.conf import settings

def send_otp(mobile, otp):
    url = f"https://2factor.in/API/V1/{settings.SMS_API_KEY}/SMS/{mobile}/{otp}/Your OTP is"
    payload = ""
    headers = {
        'content-type': "application/x-www-form-urlencoded"
    }
    response = requests.request("GET", url, data=payload, headers=headers)

    return bool(response.ok)
