import subprocess

command = input("Command to run: ")
subprocess.run(command, shell=True)
