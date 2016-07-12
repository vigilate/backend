import sys
import json
import base64
from django.core import mail
from django.contrib.auth.models import User
from rest_framework.test import APITestCase, APIClient
from vigilate_backend.models import Alert
from vulnerability_manager.models import Cve, Cpe
from vigilate_backend import alerts
from vigilate_backend.tests import basic_data
from vigilate_backend.tests import test_Alert_data

class AlertTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()

        resp = self.client.post(basic_data.api_routes['users'],
                                json.dumps({'email': basic_data.user['email'],
                                            'password': basic_data.user['password']}),
                                content_type='application/json')
        self.new_user = json.loads(resp.content.decode("utf-8"))

        credentials = base64.b64encode(str.encode(basic_data.user['email'])+
                                       b":"+str.encode(basic_data.user['password'])).decode("utf8")
        self.client.credentials(HTTP_AUTHORIZATION='Basic ' + credentials)

    def addVuln(self, check_prog = False):
        Cpe.objects.get_or_create(**test_Alert_data.cpe)
        cve = Cve.objects.create(**test_Alert_data.cve)
        cve.cpe.set(test_Alert_data.cve_cpe)
        if check_prog:
            alerts.check_cve(cve)

    def test_no_alert_when_prog_not_vuln(self):
        self.addVuln()
        resp = self.client.post(basic_data.api_routes['programs'],
                                json.dumps(test_Alert_data.prog_not_vuln),
                                content_type="application/json")

        self.assertEqual(resp.status_code, 200)
        resp = self.client.get(basic_data.api_routes['alerts'])
        data = json.loads(resp.content.decode("utf8"))
        self.assertEqual(len(data), 0)


    def test_alert_when_prog_vuln(self):
        mail.outbox = []
        self.addVuln()
        resp = self.client.post(basic_data.api_routes['programs'],
                                json.dumps(test_Alert_data.prog_vuln),
                                content_type="application/json")

        self.assertEqual(resp.status_code, 200)
        resp = self.client.get(basic_data.api_routes['alerts'])
        data = json.loads(resp.content.decode("utf8"))
        self.assertEqual(len(data), 1)

        resp = self.client.get(basic_data.api_routes['alerts'] + str(data[0]["id"]) + "/")
        self.assertEqual(resp.status_code, 200)

        self.assertEqual(len(mail.outbox), 1)



    def test_alert_when_new_cve_and_prog_vuln(self):
        resp = self.client.post(basic_data.api_routes['programs'],
                                json.dumps(test_Alert_data.prog_vuln),
                                content_type="application/json")

        self.assertEqual(resp.status_code, 200)
        resp = self.client.get(basic_data.api_routes['alerts'])
        data = json.loads(resp.content.decode("utf8"))
        self.assertEqual(len(data), 0)

        self.addVuln(True)

        self.assertEqual(resp.status_code, 200)
        resp = self.client.get(basic_data.api_routes['alerts'])
        data = json.loads(resp.content.decode("utf8"))
        self.assertEqual(len(data), 1)


    def test_alert_when_prog_vuln_update(self):
        self.addVuln()
        resp = self.client.post(basic_data.api_routes['programs'],
                                json.dumps(test_Alert_data.prog_vuln_before_update),
                                content_type="application/json")

        data_prog = json.loads(resp.content.decode("utf8"))
        self.assertEqual(resp.status_code, 200)
        resp = self.client.get(basic_data.api_routes['alerts'])
        data = json.loads(resp.content.decode("utf8"))
        self.assertEqual(len(data), 0)

        resp = self.client.patch(basic_data.api_routes['programs'] + str(data_prog["id"]) + "/",
                                json.dumps(test_Alert_data.prog_vuln),
                                content_type="application/json")

        print(resp.content)

        self.assertEqual(resp.status_code, 200)
        resp = self.client.get(basic_data.api_routes['alerts'])
        data = json.loads(resp.content.decode("utf8"))
        self.assertEqual(len(data), 1)


    def test_alert_when_prog_vuln_update_proglist(self):
        self.addVuln()
        resp = self.client.post(basic_data.api_routes['programs'],
                                json.dumps(test_Alert_data.proglist_vuln_before_update),
                                content_type="application/json")


        self.assertEqual(resp.status_code, 200)
        resp = self.client.get(basic_data.api_routes['alerts'])
        data = json.loads(resp.content.decode("utf8"))
        self.assertEqual(len(data), 0)

        resp = self.client.post(basic_data.api_routes['programs'],
                                json.dumps(test_Alert_data.proglist_vuln),
                                content_type="application/json")

        print(resp.content)

        self.assertEqual(resp.status_code, 200)
        resp = self.client.get(basic_data.api_routes['alerts'])
        data = json.loads(resp.content.decode("utf8"))
        self.assertEqual(len(data), 1)
