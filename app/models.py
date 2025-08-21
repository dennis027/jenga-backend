
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
import datetime
import uuid
from django.utils import timezone
from datetime import timedelta


class User(AbstractUser):
    ACCOUNT_TYPE_CHOICES = (
        ('01', 'Fundi'),
        ('02', 'Contractor')
    )
    account_type = models.CharField(max_length=2, choices=ACCOUNT_TYPE_CHOICES)
    full_name = models.CharField(max_length=100, blank=True)
    national_id = models.CharField(max_length=30, blank=True)
    county = models.CharField(max_length=100, blank=True)  
    constituency = models.CharField(max_length=100, blank=True)  
    ward = models.CharField(max_length=100, blank=True)  
    phone = models.CharField(max_length=20, unique=True, blank=True, null=True)
    email = models.EmailField(unique=True, blank=False)
    profile_pic = models.ImageField(upload_to='MEDIA/profiles/', blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    credit_score = models.PositiveIntegerField(default=0)
    current_verification = models.OneToOneField(
        "VerificationRequest",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="active_for_user"
    )
    

    def increase_score(self, points):
        """Increase score by points, capped at 100""" 
        self.credit_score = min(100, self.credit_score + points)
        self.save()

    def __str__(self):
        return f"{self.username} - Score: {self.credit_score}"
    

  #verify ID  
class VerificationRequest(models.Model):
    STATUS_CHOICES = (
        ("pending", "Pending"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="verification_requests")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")

    # Uploaded docs
    id_front = models.ImageField(upload_to="MEDIA/verifications/id_front/")
    id_back = models.ImageField(upload_to="MEDIA/verifications/id_back/", blank=True, null=True)
    selfie = models.ImageField(upload_to="MEDIA/verifications/selfies/", blank=True, null=True)

    rejection_reason = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"VerificationRequest({self.user.username}, {self.status})"



class PhoneOTP(models.Model):
    phone = models.CharField(max_length=20)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=5)


class PasswordResetCode(models.Model):  #password reset
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)  # 6-digit code
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=30)  # valid 10 min
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expires_at


class JobType(models.Model):
    code = models.CharField(max_length=100, unique=True, editable=False)
    name = models.CharField(max_length=100)

    def save(self, *args, **kwargs):
        self.code = self.name.lower().replace(" ", "_")  # e.g., "Tile Fitting" → "TILE_FITTING"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.name} ({self.code})"



class Gig(models.Model):
    DURATION_UNITS = [
        ('days', 'Days'),
        ('weeks', 'Weeks'),
    ]

    worker = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='gigs')
    job_type = models.ForeignKey(JobType, on_delete=models.CASCADE, related_name='gigs')

    start_date = models.DateField(default=datetime.date.today) 

    duration_value = models.PositiveIntegerField()
    duration_unit = models.CharField(max_length=10, choices=DURATION_UNITS)

    client_name = models.CharField(max_length=255, blank=True, null=True)
    client_phone = models.CharField(max_length=20, blank=True, null=True)

    county = models.CharField(max_length=100)
    constituency = models.CharField(max_length=100)
    ward = models.CharField(max_length=100)

    logged_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='logged_gigs')

    is_verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='verified_gigs'
    )

    organization = models.ForeignKey('Organization', on_delete=models.CASCADE, related_name='gigs')

    created_at = models.DateTimeField(auto_now_add=True)


    is_complete = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.worker.username} - {self.job_type.name} - {self.start_date}"



    class Meta:
        db_table = 'app_gig' 



class Payment(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_code = models.CharField(max_length=100)
    payment_date = models.DateTimeField(auto_now_add=True)
    screenshot = models.ImageField(upload_to='MEDIA/payments/', null=True, blank=True)
    is_confirmed = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} - {self.transaction_code}"
    



class GigHistory(models.Model):
    worker = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    job_type = models.ForeignKey('JobType', on_delete=models.CASCADE)
    start_date = models.DateField()
    duration_value = models.IntegerField()
    duration_unit = models.CharField(max_length=20)
    client_name = models.CharField(max_length=100)
    client_phone = models.CharField(max_length=20)
    county = models.CharField(max_length=50)
    constituency = models.CharField(max_length=50)
    ward = models.CharField(max_length=50)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.worker.username} - {self.job_type.name} on {self.start_date}"
    

class GigsAvailable(models.Model):
    organization = models.ForeignKey(
        'Organization',
        on_delete=models.CASCADE,
        related_name='available_gigs'
    )
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    county = models.CharField(max_length=50)
    constituency = models.CharField(max_length=50)
    ward = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    worker = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='gigs_taken'
    )

    def __str__(self):
        return f"{self.title} - {self.organization.name}"






class Organization(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)

    # Supervisor who created the organization
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='organizations'
    )

    county = models.CharField(max_length=100)
    constituency = models.CharField(max_length=100)
    ward = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.name} ({self.owner.username})"

    @property
    def total_gigs(self):
        return self.gigs.count()

    @property
    def available_gigs(self):
        return self.gigs.filter(worker__isnull=True).count()





class MpesaNewTransaction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    phone_number = models.CharField(max_length=15)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    mpesa_receipt_number = models.CharField(max_length=20, unique=True)  # transaction code
    transaction_date = models.DateTimeField()
    merchant_request_id = models.CharField(max_length=50)
    checkout_request_id = models.CharField(max_length=50)
    result_code = models.IntegerField()
    result_desc = models.TextField()
    raw_callback = models.JSONField()

    def __str__(self):
        return f"{self.phone_number} - {self.mpesa_receipt_number}"
    

class UserPaymentSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=15)
    checkout_request_id = models.CharField(max_length=100, unique=True)
    merchant_request_id = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.checkout_request_id}"