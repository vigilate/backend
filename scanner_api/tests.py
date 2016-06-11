import sys
import base64
from django.contrib.auth.models import User
from scanner_api import models
from rest_framework import status
from rest_framework.test import APITestCase, APIRequestFactory, force_authenticate, APIClient

def debug(msg):
    sys.stderr.write("\n%s\n"  % msg)

class UserProgramsTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()
        credentials = base64.b64encode(b"test:test")

        self.client.defaults['HTTP_AUTHORIZATION'] = 'Basic ' + str(credentials.decode("utf-8"))
        debug(self.client.defaults['HTTP_AUTHORIZATION'])
        res = User.objects.create_user(username="test", password="test")

    def test_submit_programs(self):
        res = self.client.login(username="test", password="test")
        
        debug("CONNECTION : %s" % res)
        resp = self.client.get('/api/vulnz/', format='json')
        debug("HTTP GET %s" % str(resp.status_code))
        self.assertTrue(resp.status_code == 200)
