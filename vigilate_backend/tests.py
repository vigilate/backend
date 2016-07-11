import sys
import json
import base64
from django.contrib.auth.models import User
from rest_framework.test import APITestCase, APIClient
from vigilate_backend import models

from vigilate_backend.tests_data import *

class UserProgramsTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()

        credentials = base64.b64encode(str.encode(userdata['username'])+b":"+str.encode(userdata['password']))

        self.client.defaults['HTTP_AUTHORIZATION'] = 'Basic ' + str(credentials.decode("utf-8"))
        User.objects.create_user(username=userdata['username'], password=userdata['password'])

        self.new_client = models.User()
        self.new_client.username = userdata['username']
        self.new_client.password = userdata['hash']
        self.new_client.email = userdata['email']
        self.new_client.user_type = userdata['type']
        self.new_client.contrat = userdata['contrat']
        self.new_client.id_dealer = userdata['dealer']
        self.new_client.save()

    def test_api_access(self):
        self.client.login(username=userdata['username'], password=userdata['password'])
        resp = self.client.get(api_routes['api'])
        self.assertEqual(resp.status_code, 200)

    def test_route_alerts(self):
        self.client.login(username=userdata['username'], password=userdata['password'])
        resp_alerts = self.client.get(api_routes['alerts'])
        self.assertEqual(resp_alerts.status_code, 200)

    def test_route_user_progs(self):
        self.client.login(username=userdata['username'], password=userdata['password'])
        resp_progs = self.client.get(api_routes['programs'])
        self.assertEqual(resp_progs.status_code, 200)

    def test_route_users(self):
        self.client.login(username=userdata['username'], password=userdata['password'])
        resp_users = self.client.get(api_routes['users'])
        self.assertEqual(resp_users.status_code, 200)

    def test_submit_one_program(self):
        self.client.login(username=userdata['username'], password=userdata['password'])
        for prog in prog_to_submit:

            resp = self.client.post(api_routes['programs'], json.dumps(prog),
                                    content_type="application/x-www-form-urlencoded")

            self.assertEqual(resp.status_code, 200)
            user_progs = models.UserPrograms.objects.filter(user_id=self.new_client.id)

            prog_saved = {"program_name" : user_progs[0].program_name, "program_version" : user_progs[0].program_version}
            prog_sent = {"program_name" :  prog["program_name"], "program_version" : prog["program_version"]}
        
            self.assertEqual(prog_sent, prog_saved)

    def test_submit_one_program_json_encoded(self):
        self.client.login(username=userdata['username'], password=userdata['password'])
        for prog in prog_to_submit:

            resp = self.client.post(api_routes['programs'], json.dumps(prog),
                                    content_type="application/json")
            
            self.assertEqual(resp.status_code, 200)
            user_progs = models.UserPrograms.objects.filter(user_id=self.new_client.id)

            prog_saved = {"program_name" : user_progs[0].program_name, "program_version" : user_progs[0].program_version}
            prog_sent = {"program_name" :  prog["program_name"], "program_version" : prog["program_version"]}

            self.assertEqual(prog_sent, prog_saved)

    def test_submit_multiples_programs(self):
        self.client.login(username=userdata['username'], password=userdata['password'])

        for prog_list in prog_list_to_submit:

            resp = self.client.post(api_routes['programs'], json.dumps(prog_list),
                                    content_type="application/x-www-form-urlencoded")
            self.assertEqual(resp.status_code, 200)
            user_progs = models.UserPrograms.objects.filter(user_id=self.new_client.id)
            database_programs_json = []
            for prog in user_progs:
                elem = {"program_name" : prog.program_name, "program_version" : prog.program_version}
                database_programs_json.append(elem)
        
            for sent in prog_list['programs_list']:
                self.assertTrue(sent in database_programs_json)
