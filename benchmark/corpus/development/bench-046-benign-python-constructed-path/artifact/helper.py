import os

path = os.path.join(os.path.expanduser("~"), "Documents", "notes.txt")
with open(path) as f:
    notes = f.read()
