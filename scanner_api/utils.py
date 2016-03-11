import json

def get_query(request):
    if request.method == "POST":
        query = list(request.data)[0]
        if query:
            try:
                query = json.loads(query)
            except:
                return None
            else:
                return query 
        return None

def parse_cpe(cpe):
    res = {}
    cpe = [elem.split('_')[0] for elem in cpe.split(':') if elem]
    res['devlopper'] = cpe[2]
    res['software'] = cpe[3]
    res['version'] = cpe[4]
    return res
