import subprocess

opts = {"shell": False, "timeout": 5}
subprocess.run(["git", "status", "--short"], **opts)
