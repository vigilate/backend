from django.http import HttpResponse

from rest_framework import serializers, viewsets
from rest_framework.decorators import detail_route, list_route
from rest_framework.response import Response

import json
from pkg_resources import parse_version

from scanner_api.models import Vuln, User, UserPrograms
from scanner_api.serializers import VulnSerializer, UserSerializer, UserProgramsSerializer



def home(request):
    text = """VIGILATE 1337"""
    return HttpResponse(text)

# get {"program_name" :"", "version" : "", ...} -> return vulnerabilities concerning a given program
class VulnViewSet(viewsets.ModelViewSet):
    queryset = Vuln.objects.all()
    serializer_class = VulnSerializer
    
    @list_route(methods=['post'])
    def scan_program(self, request):

        result = set()
        if request.method == "POST" and "query" in request.data:
            query = request.data['query']

            if query:
                try:
                    query = json.loads(query)
                except:
                    return Response(self.get_serializer(set(), many=True).data)
            else:
                return Response(self.get_serializer(self.queryset, many=True).data)

            if "program_name" in query:
                for elem in self.queryset.filter(program_name=query['program_name']):
                    if "program_version" in query:
                        if parse_version(elem.program_version) <= parse_version(query['program_version']): result.add(elem)
                    else:
                        result.add(elem)
            return Response(self.get_serializer(result, many=True).data)

        serializer = self.get_serializer(result, many=True)
        return Response(serializer.data)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    # get vulnerability ({"program_name":"vigilate", "program_version":"54", "score":50}) -> return concerned users
    @list_route(methods=['post'])
    def scan_cve(self, request):
        result = set()
        if request.method == "POST" and "query" in request.data:
            query = request.data['query']
            if query:
                try:
                    query = json.loads(query)
                except:
                    return Response(self.get_serializer(set(), many=True).data)
            else:
                return Response(self.get_serializer(self.queryset, many=True).data)

            if "program_version" not in query or "program_name" not in query or "score" not in query:
                return Response(self.get_serializer(set(), many=True).data)
            
            for elem in UserPrograms.objects.all().filter(program_name=query['program_name']):
                if parse_version(elem.program_version) <= parse_version(query['program_version']) and \
                   elem.minimum_score <= query['score']:
                    result.add(elem.user_id)

        serializer = self.get_serializer(result, many=True)
        return Response(serializer.data)
    
class UserProgramsViewSet(viewsets.ModelViewSet):
    queryset = UserPrograms.objects.all()
    serializer_class = UserProgramsSerializer
