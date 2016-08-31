import base64
from django.contrib.auth.models import User as UserDjango
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import authentication
from rest_framework import exceptions
from vigilate_backend.models import User, Session
from vigilate_backend.utils import get_query, avoid_id_falsfication, get_token, get_scanner_cred, check_expired_plan

class VigilateAuthentication(authentication.BasicAuthentication):
    """Vigilate authentication class using pyargon2
    """

    def security_check_then_return(self, user, request):
        if avoid_id_falsfication(user, request):
            return (user, None)
        raise exceptions.PermissionDenied()

    def authenticate(self, request):
        """Check authentication of each request
        """

        token = get_token(request)

        if token == None:
            return None

        user = None

        try:
            session = Session.objects.get(token=token)
        except ObjectDoesNotExist:
            return None

        if not session.is_valid:
            session.delete()
            return None

        #update data
        session.save()
        user = session.user

        ret = self.security_check_then_return(user, request)

        check_expired_plan(user)
        
        return ret

def ScannerAuthentication(request):
    (email, token) = get_scanner_cred(request)

    if not email or not token:
        return False

    if not email:
        return False

    query = get_query(request)
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return False

    if query and "poste" in query and\
       (isinstance(query["poste"], int) or query["poste"].isnumeric())\
       and user.is_valid_scanner_token(int(query["poste"]), token):
        return True

    return False
