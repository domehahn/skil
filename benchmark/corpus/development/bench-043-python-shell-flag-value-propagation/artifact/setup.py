import subprocess

dangerous = True
subprocess.run(["id"], shell=dangerous)
