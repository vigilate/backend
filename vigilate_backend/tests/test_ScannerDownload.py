import sys
import json
import base64
from rest_framework.test import APITestCase, APIClient
from vigilate_backend import models
from vigilate_backend import settings
from vigilate_backend.tests import basic_data
from vigilate_backend.tests import test_ScannerDownload_data

class ScannerTokenTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()

        resp = self.client.post(basic_data.api_routes['users'],
                                json.dumps({'email': basic_data.user['email'],
                                            'password': basic_data.user['password']}),
                                content_type='application/json')
        self.new_user = json.loads(resp.content.decode("utf-8"))

    def login(self, email, password):
        credentials = base64.b64encode(str.encode(email)+
                                       b":"+str.encode(password)).decode('utf8')
        self.client.credentials(HTTP_AUTHORIZATION='Basic ' + credentials)

    def create_station(self, name):
        resp = self.client.post(basic_data.api_routes['stations'],
                                json.dumps({"user": self.new_user["id"], "name": name}),
                                content_type='application/json')
        return json.loads(resp.content.decode("utf-8"))

    def test_download_scanner(self):
        self.login(basic_data.user['email'], basic_data.user['password'])

        station = self.create_station(test_ScannerDownload_data.scanner["id"])

        res = self.client.get(basic_data.api_routes['get_scanner']+str(test_ScannerDownload_data.scanner["id"])+"/");

        self.assertEqual(res.status_code, 200)
