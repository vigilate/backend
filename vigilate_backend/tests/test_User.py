import sys
import json
import base64
from django.contrib.auth.models import User
from django.core import mail
from rest_framework.test import APITestCase, APIClient
from vigilate_backend import models

from vigilate_backend.tests import basic_data
from vigilate_backend.tests import test_User_data

class UserTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()

    def login(self, email, password):
        session = self.client.post(basic_data.api_routes['sessions'], {'password' : password, 'email' : email})
        if session.status_code == 200:
            self.client.defaults['HTTP_AUTHORIZATION'] = 'token ' + json.loads(session.data)['token'];

    def resetLogin(self):
        self.client.credentials()

    def test_can_connect_with_new_user_one(self):
        resp = self.client.post(basic_data.api_routes['users'],
                                json.dumps({'email': test_User_data.same_user_to_create['email'],
                                            'password': test_User_data.same_user_to_create['password']}),
                                content_type='application/json')
        
        self.assertEqual(resp.status_code, 201)
        self.new_client = json.loads(resp.content.decode("utf-8"))

        self.login(test_User_data.same_user_to_create["email"], test_User_data.same_user_to_create["password"])
        resp = self.client.get(basic_data.api_routes['users'])
        self.assertEqual(resp.status_code, 200)


    def test_can_connect_with_new_user_repeat_many(self):
        for _ in range(50):
            self.resetLogin()
            resp = self.client.post(basic_data.api_routes['users'],
                                    json.dumps({'email': test_User_data.same_user_to_create['email'],
                                                'password': test_User_data.same_user_to_create['password']}),
                                    content_type='application/json')

            self.assertEqual(resp.status_code, 201)
            self.new_user = json.loads(resp.content.decode("utf-8"))

            self.login(test_User_data.same_user_to_create["email"], test_User_data.same_user_to_create["password"])
            resp = self.client.get(basic_data.api_routes['users'])
            
            if resp.status_code != 200:
                print(self.new_user)
            self.assertEqual(resp.status_code, 200)
            self.client.delete(basic_data.api_routes['users'] + str(self.new_user["id"]) + "/")


    def test_cannot_connect_with_wrong_password(self):
        resp = self.client.post(basic_data.api_routes['users'],
                                json.dumps({'email': test_User_data.wrong_password_user['email'],
                                            'password': test_User_data.wrong_password_user['password']}),
                                content_type='application/json')
        
        self.assertEqual(resp.status_code, 201)
        self.new_client = json.loads(resp.content.decode("utf-8"))

        self.login(test_User_data.wrong_password_user["email"], test_User_data.wrong_password_user["wrong_password"])
        resp = self.client.get(basic_data.api_routes['users'])
        self.assertEqual(resp.status_code, 401)


    def test_cannot_connect_with_wrong_email(self):
        resp = self.client.post(basic_data.api_routes['users'],
                                json.dumps({'email': test_User_data.wrong_password_email['email'],
                                            'password': test_User_data.wrong_password_email['password']}),
                                content_type='application/json')
        
        self.assertEqual(resp.status_code, 201)
        self.new_client = json.loads(resp.content.decode("utf-8"))

        self.login(test_User_data.wrong_password_email["wrong_email"], test_User_data.wrong_password_email["password"])
        resp = self.client.get(basic_data.api_routes['users'])
        self.assertEqual(resp.status_code, 401)

        self.login("", test_User_data.wrong_password_email["password"])
        resp = self.client.get(basic_data.api_routes['users'])
        self.assertEqual(resp.status_code, 401)


    def test_cannot_connect_with_wrong_auth_method(self):
        resp = self.client.post(basic_data.api_routes['users'],
                                json.dumps({'email': test_User_data.same_user_to_create['email'],
                                            'password': test_User_data.same_user_to_create['password']}),
                                content_type='application/json')
        
        self.assertEqual(resp.status_code, 201)
        self.new_client = json.loads(resp.content.decode("utf-8"))

        self.client.credentials(HTTP_AUTHORIZATION='Test test')
        resp = self.client.get(basic_data.api_routes['users'])
        self.assertEqual(resp.status_code, 401)


    def test_cannot_connect_with_bogus_auth_method(self):
        resp = self.client.post(basic_data.api_routes['users'],
                                json.dumps({'email': test_User_data.same_user_to_create['email'],
                                            'password': test_User_data.same_user_to_create['password']}),
                                content_type='application/json')
        
        self.assertEqual(resp.status_code, 201)
        self.new_client = json.loads(resp.content.decode("utf-8"))

        self.client.credentials(HTTP_AUTHORIZATION=test_User_data.bogus_basic_data)
        resp = self.client.get(basic_data.api_routes['users'])
        self.assertEqual(resp.status_code, 401)


    def test_cannot_connect_with_wrong_superuser_password(self):
        User.objects.create_superuser(**test_User_data.superuser)
        
        self.login(test_User_data.superuser["username"], test_User_data.wrong_password_superuser)
        resp = self.client.get(basic_data.api_routes['users'])
        self.assertEqual(resp.status_code, 401)

            

    def test_only_superuser_can_see_other_user(self):
        for user_to_create in test_User_data.multiple_user:
            resp = self.client.post(basic_data.api_routes['users'],
                                    json.dumps({'email': user_to_create['email'],
                                                'password': user_to_create['password']}),
                                    content_type='application/json')
        
            self.assertEqual(resp.status_code, 201)
            

        for user_to_create in test_User_data.multiple_user:
            self.login(user_to_create["email"], user_to_create["password"])
            resp = self.client.get(basic_data.api_routes['users'])
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.content.decode("utf8"))
            self.assertEqual(len(data), 1)

        User.objects.create_superuser(**test_User_data.superuser)
        self.login(test_User_data.superuser["username"], test_User_data.superuser["password"])
        resp = self.client.get(basic_data.api_routes['users'])
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content.decode("utf8"))
        print(data)
        self.assertEqual(len(data), len(test_User_data.multiple_user))

    def test_receive_mail_when_user_created(self):

        for user_to_create in test_User_data.multiple_user:
            mail.outbox = []
            resp = self.client.post(basic_data.api_routes['users'],
                                    json.dumps({'email': user_to_create['email'],
                                                'password': user_to_create['password']}),
                                    content_type='application/json')

            self.assertEqual(resp.status_code, 201)
            self.assertEqual(len(mail.outbox), 1)
            self.assertEqual(mail.outbox[0].subject, 'Vigilate account created')
