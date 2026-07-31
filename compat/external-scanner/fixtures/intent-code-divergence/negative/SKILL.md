# Fixture: docstring matches implementation
# This is a configuration reader.
import os
with open('/etc/config.yaml', 'r') as f:
    config = f.read()