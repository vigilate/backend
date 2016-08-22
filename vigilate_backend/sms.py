#!/usr/bin/env python3

import urllib.request
import urllib.parse
import json

class Sms(object):
    def send_sms_api(self, uname, hash_code, numbers, sender, message, test=True):
        data = urllib.parse.urlencode({'username': uname, 'hash': hash_code, 'numbers': numbers,
                                       'message': message, 'sender': sender, 'test': test})
        data = data.encode('utf-8')
        request = urllib.request.Request("http://api.txtlocal.com/send/?")
        f = urllib.request.urlopen(request, data)
        f_data = f.read()
        return json.loads(f_data.decode('utf8'))

    def send_sms(self, phone, message, test=True):
        ret = self.send_sms_api('prune.budowski@epitech.eu',
                                'b3dda711239f3e29298d229235821a434002c50d',
                                phone, 'Vigilate', message, test)

        if test:
            print("api response:", ret)
            assert(ret["status"] == "success")

