#from django.contrib.auth.models import User
from rest_framework import authentication
from rest_framework import exceptions
from scanner_api.models import User
import base64

class VigilateAuthentication(authentication.BasicAuthentication):

    
    def authenticate(self, request):
        authheader = request.META.get('HTTP_AUTHORIZATION', '')

        if not authheader:
            return None
        
        try:
            method,creds = authheader.split()
            if method != "Basic":
                return None
            username,pwd = base64.b64decode(creds).decode("utf8").split(":", 1)
        except Exception as e:
            return None

        if not username:
            return None

        try:
            user = User.objects.get(username=username)
            if not user.check_password(pwd):
                raise exceptions.AuthenticationFailed('Wrong password')
            
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('No such user')

        
        return (user, None)

    # def authenticate_header(self, request):
    #     return "Api credentials"
