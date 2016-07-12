from django.core import mail
from vigilate_backend.settings import TESTING
from vigilate_backend import models
from vulnerability_manager import models as models_vuln
from django.db.models import Q
from vigilate_backend.sms import Sms

def create_alert(prog, cve, user):
    alert,_ = models.Alert.objects.get_or_create(user=user, program=prog)
    if not alert.cve.filter(cveid=cve.cveid).exists():
        alert.cve.add(cve.cveid)
    if prog.alert_type_default and user.default_alert_type == models.User.EMAIL or not prog.alert_type_default and prog.email_score <= cve.cvss_score:
        mail.send_mail(
            '[Vigilate] Alert for program %s' % prog.program_name, 'A new vulnerability has been discovered on the program %s version %s' % (prog.program_name, prog.program_version),
            'from@example.com', [user.email],
            fail_silently=False,
        )

    if prog.alert_type_default and user.default_alert_type == models.User.SMS or not prog.alert_type_default and prog.sms_score <= cve.cvss_score:
        if not TESTING:
            Sms().send_sms(user.phone,
                           "Vigilate alert on the program %s version %s" % (prog.program_name,
                                                                            prog.program_version))

def check_prog(prog, user):
    cves = models_vuln.Cve.objects.filter(cpe=prog.cpe)

    for cve in cves:
        create_alert(prog, cve, user)

def check_cve(cve):
    cpes = cve.cpe.all()
    progs = models.UserPrograms.objects.filter(cpe__in=cpes)

    for prog in progs:
        create_alert(prog, cve, prog.user_id)
