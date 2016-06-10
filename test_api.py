
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vigilate_backend.settings")
import django
django.setup()
from scanner_api import models
from unittest import TestCase
import requests
import json
from requests.auth import HTTPBasicAuth


def status_code(req, expected):
    print ("Status code (expected : %d):" % expected)
    if req.status_code ==  expected:
        print ("OK : %d" % req.status_code)
        return
    print ("Failed : %d" % req.status_code)

        

def alert(name):
    print (5*'-'+"Test : %s " % name+5*'-'+'\n')

class vigilate_tests(TestCase):

    def __init__(self):
        self.url_backend = "http://172.16.84.128:8000/api"
        self.user = "test"
        self.mdp = "test"
        self.userid = models.User.objects.filter(username="test")[0].id
        self.tests = [self.submit_program_list, self.get_user_programs]

    def submit_program_list(self):
        name = "submit_program_list"
        alert(name)

        prog_list = [{"program_name" : "Mozilla Firefox", "program_version" : "31.0"}, {"program_name" : "blabla", "program_version" : "2.0.1"}]

        data = json.dumps({"programs_list" : prog_list},)
        
        headers = {'Accept': 'application/json; indent=4', 'content-type': 'application/x-www-form-urlencoded'}
        r = requests.post("%s/uprog/submit_programs/" % self.url_backend, data=data, auth=(self.user, self.mdp), headers=headers)

        status_code(r, 200)
        try:
            print ("Result :")
            user_progs = models.UserPrograms.objects.filter(user_id=self.userid)
            for i in range(len(prog_list)):
                obj1 = user_progs[i]
                obj_test = user_progs[i]
                obj_test.program_name = prog_list[i]["program_name"]
                obj_test.program_version = prog_list[i]["program_version"]
                self.assertTrue(obj1 == obj_test)
            print ("OK")

        except AssertionError as e:
            print (e)

        else:
            models.UserPrograms.objects.filter(user_id=self.userid).delete()
            
    def get_user_programs(self):
        name = "get_user_programs"
        alert(name)
        print ("No tests for this method")

tests = vigilate_tests()


for i in range(len(tests.tests)):
    tests.tests[i]()
    print('\n')
