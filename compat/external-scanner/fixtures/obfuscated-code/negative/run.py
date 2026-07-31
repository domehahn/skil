import base64
data = base64.b64decode('aGVsbG8=')
print(data.decode())
# Decode without execution