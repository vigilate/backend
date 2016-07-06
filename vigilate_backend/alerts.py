from vigilate_backend import models
from vulnerability_manager import models as models_vuln
from django.db.models import Q

def create_alert(prog, cve, user):
    new_alert = models.Alert(user=user, program=prog, cve=cve)
    new_alert.save()
    #TODO take action to send alert

def check_prog(prog, user):
    cpes = prog.cpe.all()
    cves = models_vuln.Cve.objects.filter(cpe__in=cpes)

    for cve in cves:
        create_alert(prog, cve, user)
