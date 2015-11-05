from django.http import HttpResponse

from rest_framework import serializers, viewsets, status
from rest_framework.decorators import detail_route, list_route
from rest_framework.response import Response

import json
from pkg_resources import parse_version

from scanner_api.utils import get_query
from scanner_api.models import Vuln, User, UserPrograms
from scanner_api.serializers import VulnSerializer, UserSerializer, UserProgramsSerializer



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
        print (query)
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

        current_user = User.objects.filter(username=request.user)
        if current_user:
            current_user = current_user[0]

        if "programs_list" in query:
            for elem in query['programs_list']:
                if "program_name" in elem and "program_version" in elem:
                    prog = UserPrograms.objects.filter(user_id=current_user, program_name=elem['program_name'])

                    # if prog , user is already monitoring the given program, update is needed
                    if prog:
                        prog = prog[0]
                        if prog.program_version != elem['program_version']:
                            prog.program_version = elem['program_version']
                            prog.save()
                        return Response(status=status.HTTP_200_OK)

                    #else: add a new program
                    elem['user_id'] = current_user
                    elem['minimum_score'] = 1 # default value
                    elem['id'] = UserPrograms.next_id()
                    new_prog = UserPrograms(**elem)
                    new_prog.save()
                    return Response(status=status.HTTP_201_CREATED)

        return Response(status=status.HTTP_400_BAD_REQUEST)
                
