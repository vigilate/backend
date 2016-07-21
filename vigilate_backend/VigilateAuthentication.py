import base64
from django.contrib.auth.models import User as UserDjango
from rest_framework import authentication
from rest_framework import exceptions
from vigilate_backend.models import User
from vigilate_backend.utils import get_query
class VigilateAuthentication(authentication.BasicAuthentication):
    """Vigilate authentication class using pyargon2
    """

    def authenticate(self, request):
        """Check authentication of each request
        """
        authheader = request.META.get('HTTP_AUTHORIZATION', '')
        if not authheader:
            return None

        try:
            method, creds = authheader.split()
            if method != "Basic":
                return None
            email, pwd = base64.b64decode(creds).decode("utf8").split(":", 1)
        except Exception:
            return None

        if not email:
            return None

        user = None

        try:
            query = get_query(request)
            user = User.objects.get(email=email)
            if not user.check_password(pwd) \
               and not (query \
                     and "poste" in query \
                     and (isinstance(query["poste"], int) or query["poste"].isnumeric()) \
                     and user.is_valid_scanner_token(int(query["poste"]), pwd) \
                     and request.path == "/api/v1/uprog/"):
                raise exceptions.AuthenticationFailed('Wrong password')

        except User.DoesNotExist:
            pass

        if user:
            return (user, None)

        try:
            user = UserDjango.objects.get(username=email)
            if not user.check_password(pwd):
                raise exceptions.AuthenticationFailed('Wrong password')

        except UserDjango.DoesNotExist:
            raise exceptions.AuthenticationFailed('No such user')


        return (user, None)

