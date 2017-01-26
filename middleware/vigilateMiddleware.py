from django.core import mail
from vigilate_backend.models import User
from vigilate_backend.sms import Sms 
import threading
import pprint
from vigilate_backend.settings import TESTING
thread_locals = threading.local()

def vigilate_middleware_queue(queue_type, value):
    if not hasattr(thread_locals, "queue") or queue_type not in thread_locals.queue:
        return False
    thread_locals.queue[queue_type].append(value)

class VigilateMiddleware(object):
    
    def process_request(self, request):
        thread_locals.queue = {}
        thread_locals.queue[User.EMAIL] = []
        thread_locals.queue[User.SMS] = []
        return None

    def process_response(self, request, response):

        mail_subject = ""
        mail_content = ""
        mail_dest = ""
        if len(thread_locals.queue[User.EMAIL]) == 1:
            q = thread_locals.queue[User.EMAIL][0]
            mail_subject = "[Vigilate] Alert for program %s" % q["prog"].program_name
            mail_content = "A new vulnerability has been discovered on the program %s version %s" % (q["prog"].program_name, q["prog"].program_version)
            mail_dest = q["user"].email
        elif len(thread_locals.queue[User.EMAIL]) > 1:
            prog_list = "\n".join("%s version %s" % (v["prog"].program_name, v["prog"].program_version) for v in thread_locals.queue[User.EMAIL])
            prog_list = prog_list.split('\n')
            prog_list = list(set(prog_list))
            i = 0
            already_listed = []
            for alert in prog_list:
                if alert not in already_listed:
                    already_listed.append(alert)
                    continue
                else:
                    del prog_list[i]
                i+=1

            q = thread_locals.queue[User.EMAIL][0]
            mail_subject = "[Vigilate] Alert on %d programs" % len(prog_list)
            mail_content = "A new vulnerability has been discovered on theses programs\n" + "\n".join(prog_list)
            mail_dest = q["user"].email

        if mail_dest:
            try:
                mail.send_mail(mail_subject, mail_content, 'vigilate_2017@epitech.eu',
                               [mail_dest], fail_silently=True)
            except ConnectionRefusedError as e:
                print ("MAIL ERROR : ", e)

        sms_content = ""
        sms_dest = ""
        if len(thread_locals.queue[User.SMS]) == 1:
            q = thread_locals.queue[User.SMS][0]
            sms_content = "Vigilate: Alert on program %s version %s on station %s. Go to https://vilate.github.io to more informations." % (q['prog'].program_name, q['prog'].program_version, q["prog"].poste.name)
            sms_dest = q["user"].phone
        elif len(thread_locals.queue[User.SMS]) > 1:
            q = thread_locals.queue[User.SMS][0]
            sms_content = "Vigilate: Alert on %d programs on station %s. Go to https://vilate.github.io to more informations." % (len(thread_locals.queue[User.SMS]), q["prog"].poste.name)
            sms_dest = q["user"].phone

        if sms_dest:
            Sms().send_sms(sms_dest, sms_content, TESTING)
        
        self.cleanup()
        return response

    def cleanup(self):
        try:
            del thread_locals.queue
        except AttributeError:
            pass
