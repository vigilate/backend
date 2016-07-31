import json
import os
from django.http import HttpResponse
from vigilate_backend.settings import TESTING, BASE_DIR
from django.db import IntegrityError
from django.db.models import Q
from django.contrib.auth.models import User as UserDjango
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from rest_framework import viewsets, status
from rest_framework.decorators import list_route, permission_classes, detail_route
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from pkg_resources import parse_version
from vigilate_backend.utils import get_query, parse_cpe
from vigilate_backend.models import User, UserPrograms, Alert, Station
from vigilate_backend.serializers import UserSerializer, UserProgramsSerializer, AlertSerializer, AlertSerializerDetail, StationSerializer
from vigilate_backend import alerts
from vulnerability_manager import cpe_updater
from vigilate_backend.VigilateAuthentication import VigilateAuthentication

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

        if self.request.method == 'POST' and self.request.path == "/api/v1/users/":
            return (AllowAny(),)
        return [perm() for perm in self.permission_classes]

    def get_queryset(self):
        """Get the queryset depending on the user permission
        """
        if self.request.user.is_superuser:
            return User.objects.all()
        else:
            return User.objects.filter(id=self.request.user.id)

    def perform_create(self, serializer):
        new_user = serializer.save()
        try:
            send_mail(
                'Vigilate account created',
                'Hello, your vigilate account has just been created.\nYou can now connect to the website with your mail address and your password.',
                'vigilate_2017@epitech.eu',
                [new_user.email],
                fail_silently=True,
            )
        except ConnectionRefusedError as e:
            print ("MAIL ERROR : ", e)

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
            return UserPrograms.objects.filter(user=self.request.user.id)

    def create(self, request):
        """Create one or multiple program at once
        """

        result = set()
        query = get_query(request)
        if not query:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if 'poste' not in query:
            return Response("Missing 'poste' field", status=status.HTTP_400_BAD_REQUEST)
        if not Station.objects.filter(user=request.user, id=int(query['poste'])).exists():
            return Response("Invalide station id", status=status.HTTP_400_BAD_REQUEST)

        station = Station.objects.get(id=int(query['poste']))

        only_one_program = False
        if not "programs_list" in query:
            if not all(x in query for x in ['program_version', 'program_name', 'minimum_score']):
                return Response(status=status.HTTP_400_BAD_REQUEST)

            only_one_program = True
            elem = {}
            elem['program_version'] = query['program_version']
            elem['program_name'] = query['program_name']
            elem['program_score'] = query['minimum_score']
            query['programs_list'] = [elem]
            if UserPrograms.objects.filter(user=request.user.id, program_name=elem['program_name']).exists():
                ret = {"detail": "Program %s already exists" % elem['program_name']}
                return Response(ret, status=status.HTTP_400_BAD_REQUEST)

        for elem in query['programs_list']:
            if not all(x in elem for x in ['program_version', 'program_name']):
                return Response(status=status.HTTP_400_BAD_REQUEST)
        
        up_to_date = False
        if TESTING:
            up_to_date = True

        for elem in query['programs_list']:
            prog = UserPrograms.objects.filter(user=request.user.id, program_name=elem['program_name'], poste=station)

            # if prog , user is already monitoring the given program, update is needed
            if prog:
                
                prog = prog[0]
                prog_changed = False
                if prog.program_version != elem['program_version']:
                    prog_changed = True
                    prog.program_version = elem['program_version']
                    (cpe, up_to_date) = cpe_updater.get_cpe_from_name_version(elem['program_name'], elem['program_version'], up_to_date)
                    prog.cpe = cpe
                if 'minimum_score' in elem and prog.minimum_score != int(elem['minimum_score']):
                    prog_changed = True
                    prog.minimum_score = int(elem['minimum_score'])
                if prog_changed:
                    prog.save()
                    alerts.check_prog(prog, request.user)
            else:
                #else: add a new program

                (cpe, up_to_date) =  cpe_updater.get_cpe_from_name_version(elem['program_name'], elem['program_version'], up_to_date)

                new_prog = UserPrograms(user=request.user, minimum_score=1, poste=station,
                                        program_name=elem['program_name'], program_version=elem['program_version'], cpe=cpe)
                if 'minimum_score' in elem:
                    new_prog.minimum_score = int(elem['minimum_score'])

                new_prog.save()
                alerts.check_prog(new_prog, request.user)

            if only_one_program:
                obj = UserPrograms.objects.get(user=request.user.id, program_name=elem['program_name'], poste=station)
                serializer = self.get_serializer(obj)
                return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(status=status.HTTP_200_OK)


    def perform_update(self, serializer):
        instance = serializer.save()
        (cpe, _) = cpe_updater.get_cpe_from_name_version(instance.program_name, instance.program_version, True)
        instance.cpe = cpe
        instance.save(update_fields=["cpe"])
        alerts.check_prog(instance, self.request.user)


class AlertViewSet(viewsets.ModelViewSet):
    """View for alerts
    """
    serializer_class = AlertSerializer
    def get_serializer_class(self):
        if self.action == 'retrieve':
            return AlertSerializerDetail
        return self.serializer_class

    def get_queryset(self):
        """Get the queryset depending on the user permission
        """
        if self.request.user.is_superuser:
            return Alert.objects.all()
        else:
            return Alert.objects.filter(user=self.request.user.id)

    @detail_route(methods=['get'], url_path='mark_read')
    def mark_read(self, request, pk=None):
        try:
            alert = Alert.objects.get(id=pk)
        except Alert.DoesNotExist:
            return HttpResponse(status=404)            
        alert.view = True
        alert.save()
        return Response(status=status.HTTP_200_OK)

    @detail_route(methods=['get'], url_path='mark_unread')
    def mark_unread(self, request, pk=None):
        try:
            alert = Alert.objects.get(id=pk)
        except Alert.DoesNotExist:
            return HttpResponse(status=404)            
        alert.view = False
        alert.save()
        return Response(status=status.HTTP_200_OK)

        
class StationViewSet(viewsets.ModelViewSet):
    """View for station
    """
    serializer_class = StationSerializer
    
    def get_queryset(self):
        """Get the queryset depending on the user permission
        """
        if self.request.user.is_superuser:
            return Station.objects.all()
        else:
            return Station.objects.filter(user=self.request.user.id)

@csrf_exempt
def get_scanner(request, station_id):

    auth = VigilateAuthentication()
    auth_result = auth.authenticate(request)
    if not auth_result:
        return HttpResponse(status=403)

    request.user = auth_result[0]

    try:
        station_id_int = int(station_id)
        Station.objects.filter(id=station_id_int)[0]
    except (ValueError, IndexError):
        return HttpResponse(status=404)
    
    with open(os.path.join(BASE_DIR, 'program_scanner/scanner.py'), 'r') as raw_scan:
        conf_scan = raw_scan.read()

    conf_scan = conf_scan.replace('DEFAULT_ID', station_id)
    conf_scan = conf_scan.replace('DEFAULT_USER', request.user.email)
    conf_scan = conf_scan.replace('DEFAULT_TOKEN', Station.objects.get(id=station_id_int).token)
    conf_scan = conf_scan.replace('DEFAULT_URL', request.get_host())
    conf_scan = conf_scan.replace('DEFAULT_SCHEME', request.scheme)

    rep = HttpResponse(content_type='text/x-python')
    rep['Content-Disposition'] = 'attachment; filename=scanner.py'
    rep.write(conf_scan)
    return rep
