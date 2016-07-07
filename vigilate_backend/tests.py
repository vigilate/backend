import sys
import json
import base64
from django.contrib.auth.models import User
from rest_framework.test import APITestCase, APIClient
from vigilate_backend import models

class UserProgramsTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()

        credentials = base64.b64encode(b"test:test")

        self.client.defaults['HTTP_AUTHORIZATION'] = 'Basic ' + str(credentials.decode("utf-8"))
        User.objects.create_user(username="test", password="test")

        self.new_client = models.User()
        self.new_client.username = "test"
        self.new_client.password = "UCGeyUPEIw$711cbb3de43417805310ead8e3e4dca6ab5a5f669819a7a3373d9bebdc5986fedfaf8a19cc80f823794d4e14c98d75bad46e55e08aca651f3a2123c0546ad07270f22cb2e27f"
        self.new_client.email = "test@test.test"
        self.new_client.user_type = 1
        self.new_client.contrat = 1
        self.new_client.id_dealer = 1
        self.new_client.save()

    def test_api_access(self):
        self.client.login(username="test", password="test")
        resp = self.client.get("/api/")
        self.assertTrue(resp.status_code == 200)

    def test_route_alerts(self):
        self.client.login(username="test", password="test")
        resp_alerts = self.client.get("/api/alerts/")
        self.assertTrue(resp_alerts.status_code == 200)

    def test_route_user_progs(self):
        self.client.login(username="test", password="test")
        resp_progs = self.client.get("/api/uprog/")
        self.assertTrue(resp_progs.status_code == 200)

    def test_route_users(self):
        self.client.login(username="test", password="test")
        resp_users = self.client.get("/api/users/")
        self.assertTrue(resp_users.status_code == 200)

    def test_submit_one_program(self):
        self.client.login(username="test", password="test")

        prog = {"program_name" : "Google Chrome", "program_version" : "51.0", "minimum_score": 0, "poste": 1}

        resp = self.client.post("/api/uprog/", json.dumps(prog),
                                content_type="application/x-www-form-urlencoded")

        self.assertTrue(resp.status_code == 200)
        user_progs = models.UserPrograms.objects.filter(user_id=self.new_client.id)

        prog_saved = {"program_name" : user_progs[0].program_name, "program_version" : user_progs[0].program_version}
        prog_sent = {"program_name" :  prog["program_name"], "program_version" : prog["program_version"]}

        self.assertTrue(prog_sent == prog_saved)
        
    def test_submit_one_program_json_encoded(self):
        self.client.login(username="test", password="test")
        prog = {"program_name" : "Google Chrome", "program_version" : "51.0", "minimum_score": 0,"poste": 1}

        resp = self.client.post("/api/uprog/", json.dumps(prog),
                                content_type="application/json")

        self.assertTrue(resp.status_code == 200)
        user_progs = models.UserPrograms.objects.filter(user_id=self.new_client.id)

        prog_saved = {"program_name" : user_progs[0].program_name, "program_version" : user_progs[0].program_version}
        prog_sent = {"program_name" :  prog["program_name"], "program_version" : prog["program_version"]}

        self.assertTrue(prog_sent == prog_saved)


    def test_submit_multiples_programs(self):
        self.client.login(username="test", password="test")

        prog_list = {"programs_list" :
                     [
                         {"program_name" : "mozilla firefox", "program_version" : "31.0"},
                         {"program_name" : "blabla", "program_version" : "2.0.1"}
                     ],
                     "poste" : 1}

        resp = self.client.post("/api/uprog/", json.dumps(prog_list),
                                content_type="application/x-www-form-urlencoded")
        self.assertTrue(resp.status_code == 200)
        user_progs = models.UserPrograms.objects.filter(user_id=self.new_client.id)
        database_programs_json = []
        for prog in user_progs:
            elem = {"program_name" : prog.program_name, "program_version" : prog.program_version}
            database_programs_json.append(elem)

        
        for sent in prog_list['programs_list']:
            self.assertTrue(sent in database_programs_json)
