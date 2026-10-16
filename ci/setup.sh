#!/bin/sh
# Provisions real dependencies the tests exercise (runs inside the CI container).
set -eu
# Latest stable static docker CLI for this arch; the engine is the CI host's (socket mounted by the workflow).
ARCH=$(uname -m)
BASE="https://download.docker.com/linux/static/stable/$ARCH"
V=$(curl -fsSL "$BASE/" | grep -o 'docker-[0-9][0-9.]*\.tgz' | sed 's/docker-//; s/\.tgz//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)
curl -fsSL "$BASE/docker-$V.tgz" | tar -xz -C /usr/local/bin --strip-components=1 docker/docker
docker version --format 'docker CLI {{.Client.Version}} -> engine {{.Server.Version}}'
