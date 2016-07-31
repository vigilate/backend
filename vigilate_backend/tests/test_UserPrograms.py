import sys
import json
import base64
from rest_framework.test import APITestCase, APIClient
from vigilate_backend import models

from vigilate_backend.tests import basic_data
from vigilate_backend.tests import test_UserPrograms_data

class UserProgramsTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()

        resp = self.client.post(basic_data.api_routes['users'],
                                json.dumps({'email': basic_data.user['email'],
                                            'password': basic_data.user['password']}),
                                content_type='application/json')
        self.new_user = json.loads(resp.content.decode("utf-8"))
        
        credentials = base64.b64encode(str.encode(basic_data.user['email'])+
                                       b":"+str.encode(basic_data.user['password']))
        self.client.defaults['HTTP_AUTHORIZATION'] = 'Basic ' + str(credentials.decode("utf-8"))

        data = test_UserPrograms_data.scanner
        data["user"] = self.new_user["id"]
        resp = self.client.post(basic_data.api_routes['stations'],
                                json.dumps(data),
                                content_type='application/json')
        self.station = json.loads(resp.content.decode("utf-8"))
        for d in [test_UserPrograms_data.prog_to_submit,
                  test_UserPrograms_data.prog_list_to_submit]:
            for elem in d:
                elem["poste"] = self.station["id"]


    def test_submit_one_program(self):
        for prog in test_UserPrograms_data.prog_to_submit:

            resp = self.client.post(basic_data.api_routes['programs'], json.dumps(prog),
                                    content_type="application/x-www-form-urlencoded")

            self.assertEqual(resp.status_code, 200)
            user_progs = models.UserPrograms.objects.filter(user=self.new_user["id"])

            prog_saved = {"program_name" : user_progs[0].program_name, "program_version" : user_progs[0].program_version}
            prog_sent = {"program_name" :  prog["program_name"], "program_version" : prog["program_version"]}
        
            self.assertEqual(prog_sent, prog_saved)

    def test_submit_one_program_json_encoded(self):
        for prog in test_UserPrograms_data.prog_to_submit:

            resp = self.client.post(basic_data.api_routes['programs'], json.dumps(prog),
                                    content_type="application/json")
            
            self.assertEqual(resp.status_code, 200)
            user_progs = models.UserPrograms.objects.filter(user=self.new_user["id"])

            prog_saved = {"program_name" : user_progs[0].program_name, "program_version" : user_progs[0].program_version}
            prog_sent = {"program_name" :  prog["program_name"], "program_version" : prog["program_version"]}

            self.assertEqual(prog_sent, prog_saved)

    def test_submit_multiples_programs(self):
        for prog_list in test_UserPrograms_data.prog_list_to_submit:

            resp = self.client.post(basic_data.api_routes['programs'], json.dumps(prog_list),
                                    content_type="application/x-www-form-urlencoded")
            self.assertEqual(resp.status_code, 200)
            user_progs = models.UserPrograms.objects.filter(user=self.new_user["id"])
            database_programs_json = []
            for prog in user_progs:
                elem = {"program_name" : prog.program_name, "program_version" : prog.program_version}
                database_programs_json.append(elem)
        
            for sent in prog_list['programs_list']:
                self.assertTrue(sent in database_programs_json)
