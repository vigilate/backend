#!/usr/bin/env python3

import urllib.request
import urllib.parse

def send_sms(uname, hash_code, numbers, sender, message):
    data = urllib.parse.urlencode({'username': uname, 'hash': hash_code, 'numbers': numbers,
                                   'message': message, 'sender': sender})
    data = data.encode('utf-8')
    request = urllib.request.Request("http://api.txtlocal.com/send/?")
    f = urllib.request.urlopen(request, data)
    f_data = f.read()
    return f_data

resp = send_sms('prune.budowski@gmail.com',
                '59ba30da4aeb5161661e05b18290198ecc02d61f',
                '447746338441', 'test', 'This is your message')
print(resp)
