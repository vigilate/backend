import sys
import json
import base64
from rest_framework.test import APITestCase, APIClient
from vigilate_backend import models

from vigilate_backend.tests import basic_data
from vigilate_backend.tests import test_ScannerToken_data

class ScannerTokenTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()

        resp = self.client.post(basic_data.api_routes['users'],
                                json.dumps({'email': basic_data.user['email'],
                                            'password': basic_data.user['password']}),
                                content_type='application/json')
        self.new_user = json.loads(resp.content.decode("utf-8"))


    def login_user(self, email, password):
        session = self.client.post(basic_data.api_routes['sessions'], {'password' : password, 'email' : email})
        self.client.defaults['HTTP_AUTHORIZATION'] = 'token ' + json.loads(session.data)['token'];

    def login_scanner(self, email, token):
        credentials = base64.b64encode(str.encode(email)+
                                       b":"+str.encode(token)).decode("utf8")
        self.client.credentials(HTTP_AUTHORIZATION='Basic ' + credentials)
        
    def create_station(self, name):
        resp = self.client.post(basic_data.api_routes['stations'],
                                json.dumps({"user": self.new_user["id"], "name": name}),
                                content_type='application/json')
        return json.loads(resp.content.decode("utf-8"))
        
    def test_can_connect_with_good_token(self):
        self.login_user(basic_data.user['email'], basic_data.user['password'])

        station = self.create_station(test_ScannerToken_data.scanner["name"])
        print(station)
        self.login_scanner(basic_data.user['email'], models.Station.objects.get(id=station["id"]).token)
        test_ScannerToken_data.prog_list_to_submit["poste"] = station["id"]
        resp = self.client.post(basic_data.api_routes['programs'],
                                json.dumps(test_ScannerToken_data.prog_list_to_submit),
                                content_type="application/x-www-form-urlencoded")

        print(resp.content)
        self.assertEqual(resp.status_code, 200)

    def test_cannot_connect_with_bad_token(self):
        self.login_user(basic_data.user['email'], basic_data.user['password'])

        station = self.create_station(test_ScannerToken_data.scanner["name"])
        print(station)
        self.login_scanner(basic_data.user['email'], test_ScannerToken_data.bad_token)
        test_ScannerToken_data.prog_list_to_submit["poste"] = station["id"]
        resp = self.client.post(basic_data.api_routes['programs'],
                                json.dumps(test_ScannerToken_data.prog_list_to_submit),
                                content_type="application/x-www-form-urlencoded")

        print(resp.content)
        self.assertEqual(resp.status_code, 401)


    def test_cannot_connect_with_bad_id(self):
        self.login_user(basic_data.user['email'], basic_data.user['password'])

        station_bad = self.create_station(test_ScannerToken_data.scanner["name"])
        station = self.create_station(test_ScannerToken_data.scanner["name"])
        print(station)
        self.login_scanner(basic_data.user['email'], models.Station.objects.get(id=station["id"]).token)
        test_ScannerToken_data.prog_list_to_submit["poste"] = station_bad["id"]
        resp = self.client.post(basic_data.api_routes['programs'],
                                json.dumps(test_ScannerToken_data.prog_list_to_submit),
                                content_type="application/x-www-form-urlencoded")

        print(resp.content)
        self.assertEqual(resp.status_code, 401)

