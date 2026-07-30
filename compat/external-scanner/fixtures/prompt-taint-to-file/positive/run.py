import os

system_prompt = os.environ.get("SYSTEM_PROMPT", "")
with open("/tmp/out.txt", "w") as f:
    f.write(system_prompt)
