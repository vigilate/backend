import json
from django.http import HttpResponse
from django.db import IntegrityError
from django.db.models import Q
from django.contrib.auth.models import User as UserDjango
from rest_framework import viewsets, status
from rest_framework.decorators import list_route, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from pkg_resources import parse_version
from vigilate_backend.utils import get_query, parse_cpe
from vigilate_backend.models import User, UserPrograms, Alert
from vigilate_backend.serializers import UserSerializer, UserProgramsSerializer, AlertSerializer
from vulnerability_manager import cpe_updater

def home(request):
    """Vigilate root url content
    """
    text = """VIGILATE 1337"""
    return HttpResponse(text)

class UserViewSet(viewsets.ModelViewSet):
    """View for users
    """
    serializer_class = UserSerializer

    def get_permissions(self):
        """Allow non-authenticated user to create an account
        """

        if self.request.method == 'POST' and self.request.path == "/api/users/":
            return (AllowAny(),)
        return [perm() for perm in self.permission_classes]

    def get_queryset(self):
        """Get the queryset depending on the user permission
        """
        if self.request.user.is_superuser:
            return User.objects.all()
        else:
            return User.objects.filter(id=self.request.user.id)



class UserProgramsViewSet(viewsets.ModelViewSet):
    """View for users programs
    """

    serializer_class = UserProgramsSerializer

    def get_queryset(self):
        """Get the queryset depending on the user permission
        """
        if self.request.user.is_superuser:
            return UserPrograms.objects.all()
        else:
            return UserPrograms.objects.filter(user_id=self.request.user.id)

    # POST query{"programs_list": [{"program_name":"toto", "program_version":"1.2.4.1"}]}'
    # /api/uprog/submit_programs/
    @list_route(methods=['post'])
    def submit_programs(self, request):
        """Sens multiple program at once
        """
        result = set()
        query = get_query(request)
        if not query:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if "programs_list" in query:
            up_to_date = False
            for elem in query['programs_list']:
                if "program_name" in elem and "program_version" in elem:
                    prog = UserPrograms.objects.filter(user_id=request.user.id, program_name=elem['program_name'], poste=query['poste'])

                    # if prog , user is already monitoring the given program, update is needed
                    if prog:
                        prog = prog[0]
                        if prog.program_version != elem['program_version']:
                            prog.program_version = elem['program_version']
                            prog.cpe.clear()
                            (cpes, up_to_date) = cpe_updater.get_cpes_from_name_version(elem['program_name'], elem['program_version'], up_to_date)
                            prog.cpe.set(cpes)
                            prog.save()
                    else:
                        #else: add a new program

                        new_prog = UserPrograms(user_id=request.user, minimum_score=1, poste=query['poste'],
                                                program_name=elem['program_name'], program_version=elem['program_version'])
                        new_prog.save()
                        (cpes, up_to_date) =  cpe_updater.get_cpes_from_name_version(elem['program_name'], elem['program_version'], up_to_date)
                        new_prog.cpe.set(cpes)

            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)

class AlertViewSet(viewsets.ModelViewSet):
    """View for alerts
    """
    serializer_class = AlertSerializer

    def get_queryset(self):
        """Get the queryset depending on the user permission
        """
        if self.request.user.is_superuser:
            return Alert.objects.all()
        else:
            return Alert.objects.filter(user_id=self.request.user.id)
