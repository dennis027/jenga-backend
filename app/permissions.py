# app/permissions.py
from rest_framework.permissions import BasePermission

class IsVerified(BasePermission):
    """
    Allows access only to authenticated users whose accounts are active (verified).
    """

    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.is_active
        )
