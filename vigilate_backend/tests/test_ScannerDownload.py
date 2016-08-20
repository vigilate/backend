import sys
import json
import base64
from rest_framework.test import APITestCase, APIClient
from vigilate_backend import models
from vigilate_backend import settings
from vigilate_backend.tests import test_ScannerDownload_data, basic_data
class ScannerDownloadTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()

        resp = self.client.post(basic_data.api_routes['users'],
                                json.dumps({'email': basic_data.user['email'],
                                            'password': basic_data.user['password']}),
                                content_type='application/json')
        self.new_user = json.loads(resp.content.decode("utf-8"))

    def login(self, email, password):
        session = self.client.post(basic_data.api_routes['sessions'],
                                   json.dumps({'password' : password,'email' : email}),
                                   content_type='application/json')
        self.client.defaults['HTTP_AUTHORIZATION'] = 'token ' + session.data['token'];

    def create_station(self, name):
        resp = self.client.post(basic_data.api_routes['stations'],
                                json.dumps({"user": self.new_user["id"], "name": name}),
                                content_type='application/json')
        return json.loads(resp.content.decode("utf-8"))

    def test_download_scanner(self):
        self.login(basic_data.user['email'], basic_data.user['password'])

        # Existing station
        station = self.create_station(test_ScannerDownload_data.station["name"])
        res = self.client.get(basic_data.api_routes['get_scanner']+str(station['id'])+"/")
        self.assertEqual(res.status_code, 200)

        # Unknown station
        res =  self.client.get(basic_data.api_routes['get_scanner']+"1337/")
        self.assertEqual(res.status_code, 404)
