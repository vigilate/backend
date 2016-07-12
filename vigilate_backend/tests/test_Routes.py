import sys
import json
import base64
from rest_framework.test import APITestCase, APIClient
from vigilate_backend import models

from vigilate_backend.tests import basic_data

class RoutesTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()

        resp = self.client.post(basic_data.api_routes['users'],
                                json.dumps({'email': basic_data.user['email'],
                                            'password': basic_data.user['password']}),
                                content_type='application/json')
        self.new_client = json.loads(resp.content.decode("utf-8"))
        
        self.credentials = base64.b64encode(str.encode(basic_data.user['email'])+
                                            b":"+str.encode(basic_data.user['password'])).decode('utf8')

    def login(self):
        self.client.credentials(HTTP_AUTHORIZATION='Basic ' + self.credentials)

    def test_can_access_api_logged(self):
        self.login()
        resp = self.client.get(basic_data.api_routes['api'])
        self.assertEqual(resp.status_code, 200)

    def test_can_access_alerts_route_logged(self):
        self.login()
        resp_alerts = self.client.get(basic_data.api_routes['alerts'])
        self.assertEqual(resp_alerts.status_code, 200)

    def test_can_access_userprogs_route_logged(self):
        self.login()
        resp_progs = self.client.get(basic_data.api_routes['programs'])
        self.assertEqual(resp_progs.status_code, 200)

    def test_can_access_users_route_logged(self):
        self.login()
        resp_users = self.client.get(basic_data.api_routes['users'])
        self.assertEqual(resp_users.status_code, 200)

    def test_cannot_access_api_not_logged(self):
        resp = self.client.get(basic_data.api_routes['api'])
        self.assertEqual(resp.status_code, 401)

    def test_cannot_access_alerts_route_not_logged(self):
        resp_alerts = self.client.get(basic_data.api_routes['alerts'])
        self.assertEqual(resp_alerts.status_code, 401)

    def test_cannot_access_userprogs_route_not_logged(self):
        resp_progs = self.client.get(basic_data.api_routes['programs'])
        self.assertEqual(resp_progs.status_code, 401)

    def test_cannot_access_users_route_not_logged(self):
        resp_users = self.client.get(basic_data.api_routes['users'])
        self.assertEqual(resp_users.status_code, 401)
