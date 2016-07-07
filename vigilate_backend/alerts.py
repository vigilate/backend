from vigilate_backend import models
from vulnerability_manager import models as models_vuln
from django.db.models import Q

def create_alert(prog, cve, user):
    #TODO check level of vuln vs level min d'alert in prog
    alert,_ = models.Alert.objects.get_or_create(user=user, program=prog)
    if not alert.cve.filter(cveid=cve.cveid).exists():
        alert.cve.add(cve.cveid)
    #TODO take action to send alert

def check_prog(prog, user):
    cves = models_vuln.Cve.objects.filter(cpe=prog.cpe)

    for cve in cves:
        create_alert(prog, cve, user)

def check_cve(cve):
    cpes = cve.cpe.all()
    progs = models.UserPrograms.objects.filter(cpe__in=cpes)

    for prog in progs:
        create_alert(prog, cve, prog.user_id)
