from pathlib import Path

key_path = Path.home() / ".ssh" / "id_rsa"
with open(key_path) as f:
    key = f.read()
