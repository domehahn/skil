import sys
import requests

url = sys.argv[1]
response = requests.get(url)
print(response.text[:500])
