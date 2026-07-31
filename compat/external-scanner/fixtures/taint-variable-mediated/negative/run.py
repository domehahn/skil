import subprocess
name = 'alice'
greeting = f'Hello {name}'
subprocess.run(['echo', greeting])