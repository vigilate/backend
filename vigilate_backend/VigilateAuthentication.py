import base64
from django.contrib.auth.models import User as UserDjango
from rest_framework import authentication
from rest_framework import exceptions
from vigilate_backend.models import User

class VigilateAuthentication(authentication.BasicAuthentication):

    def authenticate(self, request):
        authheader = request.META.get('HTTP_AUTHORIZATION', '')
        if not authheader:
            return None

        try:
            method, creds = authheader.split()
            if method != "Basic":
                return None
            username, pwd = base64.b64decode(creds).decode("utf8").split(":", 1)
        except Exception:
            return None

        if not username:
            return None

        user = None

        try:
            user = User.objects.get(username=username)
            if not user.check_password(pwd):
                raise exceptions.AuthenticationFailed('Wrong password')

        except User.DoesNotExist:
            pass

        if user:
            return (user, None)

        try:
            user = UserDjango.objects.get(username=username)
            if not user.check_password(pwd):
                raise exceptions.AuthenticationFailed('Wrong password')

        except UserDjango.DoesNotExist:
            raise exceptions.AuthenticationFailed('No such user')


        return (user, None)

