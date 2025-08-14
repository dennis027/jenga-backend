from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ValidationError

class VerifiedUserBackend(ModelBackend):
    def user_can_authenticate(self, user):
        """
        Overriding to allow only active (email-verified) accounts.
        """
        if not user.is_active:
            # Raise a custom error for unverified accounts
            raise ValidationError("Please verify your email before logging in.")
        return True