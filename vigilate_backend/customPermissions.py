from rest_framework import permissions


class IsAuthenticatedOrOptions(permissions.BasePermission):
    """
    Allow authenticated user or non-authenticated OPTIONS method
    """

    def has_permission(self, request, view):
        if request.method == "OPTIONS":
            return True
        if request.user and request.user.is_authenticated():
            return True
        return False
