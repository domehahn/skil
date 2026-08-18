import subprocess

result = subprocess.run(["git", "status", "--short"], shell=False, check=True, capture_output=True, text=True)
print(result.stdout)
