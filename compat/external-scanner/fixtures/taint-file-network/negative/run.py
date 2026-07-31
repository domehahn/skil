import requests
with open('/etc/hostname') as f:
    host = f.read().strip()
print(f'Host: {host}')