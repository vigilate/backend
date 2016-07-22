from django.core import mail
from vigilate_backend.settings import TESTING
from vigilate_backend import models
from vulnerability_manager import models as models_vuln
from django.db.models import Q
from vigilate_backend.sms import Sms
from middleware import vigilateMiddleware
from vigilate_backend.models import Alert

def create_alert(prog, cve, user):
    alert,_ = models.Alert.objects.get_or_create(user=user, program=prog)
    if not alert.cve.filter(cveid=cve.cveid).exists():
        alert.cve.add(cve.cveid)
    if prog.alert_type_default and user.default_alert_type == models.User.EMAIL or not prog.alert_type_default and prog.email_score <= cve.cvss_score:
        vigilateMiddleware.vigilate_middleware_queue("EMAIL", {"prog": prog, "user": user})

    if prog.alert_type_default and user.default_alert_type == models.User.SMS or not prog.alert_type_default and prog.sms_score <= cve.cvss_score:
        if not TESTING:
            vigilateMiddleware.vigilate_middleware_queue("SMS", {"prog": prog})

def check_prog(prog, user):
    cves = models_vuln.Cve.objects.filter(cpe=prog.cpe)

    for cve in cves:
        create_alert(prog, cve, user)

    remove_old_alerts(prog)

def check_cve(cve):
    cpes = cve.cpe.all()
    progs = models.UserPrograms.objects.filter(cpe__in=cpes)

    for prog in progs:
        create_alert(prog, cve, prog.user_id)


def remove_old_alerts(prog):
    alerts = Alert.objects.filter(program=prog)

    to_delete = []
    for alert in alerts:
        to_keep = []
        for cve in alert.cve.all():
            if cve.cpe.filter(cpe=prog.cpe.cpe).exists():
                to_keep.append(cve.cveid)
        alert.cve.clear()
        alert.cve.set(to_keep)
        if alert.cve.count() == 0:
            to_delete.append(alert)

    for alert in to_delete:
        alert.delete()
