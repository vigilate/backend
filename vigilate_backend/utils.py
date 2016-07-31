import json

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
        if "user" not in request.data:
            return True
        if isinstance(request.data['user'], int)  and \
           (user.is_superuser or request.data['user'] == user.id):
            return True
        return False
    return True
