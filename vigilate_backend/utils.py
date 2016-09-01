import json
import base64
from vigilate_backend.models import Station, User, Plans
from django.utils import timezone

def get_query(request):
    """Parse a query
    """
    if request.method == "POST":
        if "application/json" in request.content_type:
            return request.data
        query = list(request.data)[0]
        if query:
            try:
                query = json.loads(query)
            except:
                return None
            else:
                return query
        try:
            query = json.loads(query)
        except:
            return None
        else:
            return query
    return None

def parse_cpe(cpe):
    """Parse a cpe
    """
    res = {}
    cpe = [elem.split('_')[0] for elem in cpe.split(':') if elem]
    res['devlopper'] = cpe[2]
    res['software'] = cpe[3]
    res['version'] = cpe[4]
    return res

def avoid_id_falsfication(user, request):
    if request.method in ["POST","PATCH","PUT","DELETE"]:

        if not hasattr(request, "data") or "user" not in request.data:
            return True

        if user.is_superuser:
            return True
        try:
            request.data['user'] = int(request.data['user'])
        except ValueError:
            return False

        return request.data['user'] == user.id

    return True

def get_token(request):
    authheader = request.META.get('HTTP_AUTHORIZATION', '')
    if not authheader:
        return None

    try:
        method, token = authheader.split()
        if method != "token":
            return None
    except Exception:
        return None

    return token

def get_scanner_cred(request):
    authheader = request.META.get('HTTP_AUTHORIZATION', '')
    email = None
    token = None
    
    if not authheader:
        return (None, None)
    
    try:
        method, creds = authheader.split()

        if method != "Basic":
            return (None, None)
        (email, token) = base64.b64decode(creds).decode("utf8").split(':')
    except Exception as e:
        (None, None)

    return (email, token)

def can_add_station(nb_station, user):
    if not user.plan:
        return True
    if nb_station >= user.plan.max_stations:
        return False
    return True

def nb_station_over_quota(nb_station, user):
    if not user.plan:
        return 0
    if nb_station >= user.plan.max_stations:
        return nb_station - user.plan.max_stations
    return 0


def update_contrat(user):
    stations = Station.objects.filter(user=user.id)
    over = nb_station_over_quota(stations.count(), user)
    enable_stations = [s for s in stations][:-over]
    disable_stations = [s for s in stations][-over:]
    if over:
        for s in enable_stations:
            if s.disabled:
                s.disabled = False
                s.save()
                
        for s in disable_stations:
            if not s.disabled:
                s.disabled = True
                s.save()
    else:
        for s in stations:
            if s.disabled:
                s.disabled = False
                s.save()

def check_expired_plan(user):
    if not user.plan or not user.plan.validity_time:
        return

    expire_in = user.plan.validity_time - (timezone.now() - user.plan_purchase_date).total_seconds()
    if expire_in <= 0:
        user.plan = Plans.objects.filter(default=True).first()
        user.save()
        update_contrat(user)
