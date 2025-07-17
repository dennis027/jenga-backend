
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
import datetime


class User(AbstractUser):
    ACCOUNT_TYPE_CHOICES = (
        ('01', 'Fundi'),
        ('02', 'Contractor')
    )
    account_type = models.CharField(max_length=2, choices=ACCOUNT_TYPE_CHOICES)
    full_name = models.CharField(max_length=100, blank=True)
    national_id = models.CharField(max_length=30, blank=True)
    location = models.CharField(max_length=100, blank=True)
    phone = models.CharField(max_length=20, unique=True, blank=False)  
    email = models.EmailField(unique=True, blank=False) 
    profile_pic = models.ImageField(upload_to='profiles/', blank=True, null=True)


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

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.worker.username} - {self.job_type.name} - {self.start_date}"



    class Meta:
        db_table = 'app_gig' 



class Payment(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_code = models.CharField(max_length=100)
    payment_date = models.DateTimeField(auto_now_add=True)
    screenshot = models.ImageField(upload_to='payments/', null=True, blank=True)
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
