import json

def get_query(request):
    if request.method == "POST" and "query" in request.data:
        query = request.data['query']
        if query:
            try:
                query = json.loads(query)
            except:
                return None
            else:
                return query 
        return None
