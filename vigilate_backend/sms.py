#!/usr/bin/env python3

import urllib.request
import urllib.parse

class Sms(object):
    def send_sms_api(uname, hash_code, numbers, sender, message):
        data = urllib.parse.urlencode({'username': uname, 'hash': hash_code, 'numbers': numbers,
                                       'message': message, 'sender': sender})
        data = data.encode('utf-8')
        request = urllib.request.Request("http://api.txtlocal.com/send/?")
        f = urllib.request.urlopen(request, data)
        f_data = f.read()
        return f_data

    def send_sms(self, phone, message):
        return self.send_sms_api('prune.budowski@epitech.eu',
                          'b3dda711239f3e29298d229235821a434002c50d',
                          phone, 'test', message)

