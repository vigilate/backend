from django.http import HttpResponse
from django.db import IntegrityError
from django.db.models import Q

from rest_framework import serializers, viewsets, status
from rest_framework.decorators import detail_route, list_route
from rest_framework.response import Response

import json
from pkg_resources import parse_version

from scanner_api.utils import get_query, parse_cpe
from scanner_api.models import Vuln, User, UserPrograms, Alert
from scanner_api.serializers import VulnSerializer, UserSerializer, UserProgramsSerializer, AlertSerializer

from lib.core.methods import *


def home(request):
    text = """VIGILATE 1337"""
    return HttpResponse(text)

class VulnViewSet(viewsets.ModelViewSet):
    queryset = Vuln.objects.all()
    serializer_class = VulnSerializer

    # POST a program query={"program_name" :"", "version" : "", ...} -> return vulnerabilities concerning a given program
    #/api/vulnz/scan_program/
    @list_route(methods=['post'])
    def scan_program(self, request):

        result = set()
        query = get_query(request)
        if not query:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if "program_name" in query:
            for elem in self.queryset.filter(program_name=query['program_name']):
                if "program_version" in query:
                    if parse_version(elem.program_version) <= parse_version(query['program_version']): result.add(elem)
                else:
                    result.add(elem)
            return Response(self.get_serializer(result, many=True).data)

        return Response(status=status.HTTP_400_BAD_REQUEST)

    # POST a user ID and get vulnerabilities if prog version < vuln version
    # /api/vulnz/user_vulnerabilities ---> query={"user_id": 0}
    @list_route(methods=['post'])
    def user_vulnerabilities(self, request):

        user_vulns = set()
        query = get_query(request)
        if not query:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if "user_id" in query:
            for user in User.objects.filter(id=query['user_id']):
                for user_program in UserPrograms.objects.filter(user_id=user):
                    vulns = Vuln.objects.filter(program_name=user_program.program_name)
                    for elem in vulns:
                        if parse_version(elem.program_version) > parse_version(user_program.program_version):
                            user_vulns.add(elem)

            return Response(self.get_serializer(user_vulns, many=True).data)
        return Response(status=status.HTTP_400_BAD_REQUEST)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    # POST a vulnerability query={"program_name":"vigilate", "program_version":"54", "score":50} -> return concerned users
    # /api/users/scan_cve/
    @list_route(methods=['post'])
    def scan_cve(self, request):

        result = set()
        query = get_query(request)
        if not query:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if "program_version" not in query or "program_name" not in query or "score" not in query:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        for elem in UserPrograms.objects.filter(program_name=query['program_name']):
            if parse_version(elem.program_version) <= parse_version(query['program_version']) and \
               elem.minimum_score <= query['score']:
                result.add(elem.user_id)
        return Response(self.get_serializer(result, many=True).data)

class UserProgramsViewSet(viewsets.ModelViewSet):
    queryset = UserPrograms.objects.all()
    serializer_class = UserProgramsSerializer

    # POST query{"programs_list": [{"program_name":"toto", "program_version":"1.2.4.1"}]}'
    # /api/uprog/submit_programs/
    @list_route(methods=['post'])
    def submit_programs(self, request):
        result = set()
        query = get_query(request)
        if not query:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if "programs_list" in query:
            for elem in query['programs_list']:
                if "program_name" in elem and "program_version" in elem:
                    prog = UserPrograms.objects.filter(user_id=request.user.id, program_name=elem['program_name'])

                    # if prog , user is already monitoring the given program, update is needed
                    if prog:
                        prog = prog[0]
                        if prog.program_version != elem['program_version']:
                            prog.program_version = elem['program_version']
                            prog.save()
                    else:
                        #else: add a new program
                        elem['user_id'] = request.user
                        elem['minimum_score'] = 1 # default value
                        elem['id'] = UserPrograms.next_id()
                        new_prog = UserPrograms(**elem)
                        new_prog.save()

            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)

class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer

    # POST query{"cveid": "CVE-2015-XXXX}
    # /api/alerts/scan_cve/

    # get a CVE-ID, find CPE, and return alerts
    @list_route(methods=['post'])
    def scan_cve(self, request):
        result = set()
        progs = set()

        query = get_query(request)
        if not query:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        if "cveid" not in query:
            return Response(status=status.HTTP_404_NOT_FOUND)

        cpe_list = CveInfo(query['cveid']).get_cpe()
        cpe_json = json.loads(cpe_list)

        # Get users programs
        for elem in cpe_json:
            cpe = parse_cpe(elem['id'])
            for uprog in UserPrograms.objects.filter(
                    Q(program_name__icontains=cpe['software']) & Q(program_name__icontains=cpe['devlopper'])):
                if parse_version(cpe['version']) <= parse_version(uprog.program_version):
                    progs.add(uprog)
                
        # Create and return alerts if they do not already exists
        for uprog in progs:
            elem = Alert()
            elem.user = uprog.user_id
            elem.program = uprog
            elem.vuln = Vuln.objects.filter(cveid=query['cveid'])[0]
            try:
                elem.save()
                result.add(elem)
            except IntegrityError:
                continue

        # Save a vulnerability if it's actually not in db ?
        return Response(self.get_serializer(result, many=True).data)

