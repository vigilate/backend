import sys
import json
import base64
from rest_framework.test import APITestCase, APIClient
from vigilate_backend import models

from vigilate_backend.tests import basic_data
from vigilate_backend.tests import test_UserPrograms_data, test_Alert_data
from vulnerability_manager.models import Cve, Cpe

class UserProgramsTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()

        resp = self.client.post(basic_data.api_routes['users'],
                                json.dumps({'email': basic_data.user['email'],
                                            'password': basic_data.user['password']}),
                                content_type='application/json')
        self.new_user = json.loads(resp.content.decode("utf-8"))

        session = self.client.post(basic_data.api_routes['sessions'],
                                   json.dumps({'password' : basic_data.user['password'],
                                               'email' : basic_data.user['email']}),
                                   content_type='application/json')
        self.client.defaults['HTTP_AUTHORIZATION'] = 'token ' + session.data['token'];

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

    def addVuln(self, check_prog = False):
        for cpe in test_Alert_data.cpes:
            Cpe.objects.get_or_create(**cpe)
        for cve in test_Alert_data.cves:
            new_cve = Cve.objects.create(**cve)
            new_cve.cpe.set(test_Alert_data.cve_cpe[cve["cveid"]])
            if check_prog:
                alerts.check_cve(new_cve)

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

    #Generate alert(s) and try to get them by the corresponding method
    def test_get_alerts_from_program(self):
        self.addVuln()
        resp = self.client.post(basic_data.api_routes['programs'],
                                json.dumps(test_UserPrograms_data.prog_vuln),
                                content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        prog = models.UserPrograms.objects.filter(program_name=test_UserPrograms_data.prog_vuln['program_name'])[0]

        resp = self.client.get(
            basic_data.api_routes['programs']+basic_data.api_routes['get_alerts'] % prog.id)
        self.assertEqual(resp.status_code, 200)

        data = json.loads(resp.content.decode('utf-8'))
        for elem in data:
            alert = models.Alert.objects.filter(id=elem['alert_id'])
            self.assertEqual(len(alert), 1)
