import africastalking
from django.conf import settings

def send_sms(to, message):
    africastalking.initialize(settings.AT_USERNAME, settings.AT_API_KEY)
    sms = africastalking.SMS
    return sms.send(message=message, recipients=[to])
