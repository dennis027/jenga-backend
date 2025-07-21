import requests
from django.conf import settings
from requests.auth import HTTPBasicAuth
import base64
from datetime import datetime

def get_access_token():
    url = f"{settings.MPESA_BASE_URL}/oauth/v1/generate?grant_type=client_credentials"
    res = requests.get(url, auth=HTTPBasicAuth(settings.MPESA_CONSUMER_KEY, settings.MPESA_CONSUMER_SECRET))
    return res.json().get("access_token")


def lipa_na_mpesa(phone_number, amount, account_reference="Test", transaction_desc="Payment"):
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode(
        f"{settings.MPESA_SHORTCODE}{settings.MPESA_PASSKEY}{timestamp}".encode()
    ).decode()

    payload = {
        "BusinessShortCode": settings.MPESA_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone_number,
        "PartyB": settings.MPESA_SHORTCODE,
        "PhoneNumber": phone_number,
        "CallBackURL": settings.MPESA_CALLBACK_URL,
        "AccountReference": account_reference,
        "TransactionDesc": transaction_desc
    }

    access_token = get_access_token()
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{settings.MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest"

    response = requests.post(url, json=payload, headers=headers)
    return response.json()

