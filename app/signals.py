# your_app/signals.py
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from app.defaults import DEFAULT_JOB_TYPES
from app.models import JobType, Organization
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


@receiver(post_save, sender=Organization)
def create_default_job_types(sender, instance, created, **kwargs):
    if not created:
        return

    job_types = [
        JobType(
            organization=instance,
            name=name,
            code=name.lower().replace(" ", "_")  # 🔥 MANUAL
        )
        for name in DEFAULT_JOB_TYPES
    ]

    JobType.objects.bulk_create(
        job_types,
        ignore_conflicts=True  # 🔥 SAFETY NET
    )