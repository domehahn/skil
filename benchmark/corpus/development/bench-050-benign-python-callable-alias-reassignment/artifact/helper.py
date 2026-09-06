import subprocess

runner = subprocess.run
runner = safe_wrapper
runner(["git", "status"])
