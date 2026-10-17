# docker-baseline-auditor

Read-only Docker security baseline checker for the host you run it on: the
daemon's configuration, the Docker host's files and every running container,
checked against the **CIS Docker Benchmark v1.6.0**. Every finding carries its
CIS recommendation id, so results line up with the benchmark (and with Docker
Bench for Security). Zero dependencies beyond a working `docker` CLI.

| Area | CIS ids |
|---|---|
| Daemon: icc on the default bridge, log level, insecure registries, aufs, TCP socket without TLS, user namespaces/rootless, centralized logging, no-new-privileges default, live restore, userland proxy, experimental features | 2.2 2.3 2.5 2.6 2.7 2.9 2.13 2.14 2.15 2.16 2.18 |
| Host files (local daemon only): docker.service/docker.socket units, /etc/docker, daemon.json, the Docker socket (owner + mode) | 3.1-3.6 3.15-3.18 |
| Docker Content Trust not enabled | 4.5 |
| Containers: configured to run as root, AppArmor/seccomp unconfined, added capabilities, privileged, sensitive host paths mounted (`/`, `/etc`, `/proc`, `/var/run`...), privileged host ports, host network, memory limit, writable root filesystem, ports published on every interface, restart policy without a retry cap (always/unless-stopped/on-failure over 5), host PID/IPC/UTS/user namespaces, host devices, shared mount propagation, no-new-privileges, health check, pids limit, Docker socket mounted | 4.1 5.2 5.4 5.5 5.6 5.8 5.10 5.11 5.13 5.14 5.15 5.16 5.17 5.18 5.20 5.21 5.22 5.26 5.27 5.29 5.31 5.32 |
| `:latest`/untagged images (ops hygiene) | - |

"Run as root" means the container's configured `USER` (what `docker inspect`
shows), not a live process listing.

## Install

```sh
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/docker-baseline-auditor.git        # latest release branch; puts `docker-baseline-auditor` on PATH
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/docker-baseline-auditor.git@v1.2.1  # a pinned release
brew install canutethegreat/errant-tools/docker-baseline-auditor   # after: brew tap canutethegreat/errant-tools https://git.canutethegreat.com/CanuteTheGreat/homebrew-errant-tools
scoop install errant-tools/docker-baseline-auditor                 # after: scoop bucket add errant-tools https://git.canutethegreat.com/CanuteTheGreat/scoop-errant-tools
```

Or download the single file (stdlib-only Python 3.8+) and run it directly:
`curl -fsSLO https://errant.solutions/downloads/docker_baseline_auditor.py && python3 docker_baseline_auditor.py --help`.
Every [release](https://git.canutethegreat.com/CanuteTheGreat/docker-baseline-auditor/releases) has a changelog, the wheel, the sdist and a `SHA256SUMS` file.
Not on PyPI yet, so plain `pipx install docker-baseline-auditor` doesn't work until it's published there.

## Usage

```
docker-baseline-auditor                       # text report
docker-baseline-auditor --json                # machine-readable, for CI
docker-baseline-auditor --fail-on medium      # CI gate: exit 1 on MEDIUM or worse
docker-baseline-auditor --exclude 5.27,2.13   # skip checks/sections by CIS id
docker-baseline-auditor --include 5 --all     # only container checks, including stopped containers
docker-baseline-auditor --version
```

Read-only: `docker info`, `docker network inspect bridge`, `docker ps` and
`docker inspect`, plus `stat()` on the local Docker files. Never modifies
anything. No network calls, no data leaves the host. With a remote
`DOCKER_HOST` the host-file checks (3.x) are skipped and the report says so.

Exit codes (same convention as every Errant Solutions tool):

| Code | Meaning |
|---|---|
| 0 | no finding at or above `--fail-on` (default `high`) |
| 1 | at least one finding at or above `--fail-on` |
| 2 | the `docker` CLI is missing, the daemon can't be reached, or bad usage |

`--json` prints `{"version", "engine", "daemon": [findings], "containers": [{"name", "image", "findings"}], "summary"}`
where each finding is `{"id": "5.5", "severity": "HIGH", "message": "..."}`.

## License / pricing

MIT — see LICENSE. Free, pay-what-you-want. If it's useful, there's a payment link on
https://errant.solutions. No obligation.

Part of the [Errant Solutions](https://errant.solutions) spare-capacity tools
series (see also: sshd-hardening-auditor, tls-cert-watchdog,
mail-security-auditor, aws-waste-finder).

## Tests

`tests/` exercises every option and check end-to-end (against real containers on a real Docker engine) in Forgejo CI on
Python 3.8 and current Python, then installs the package with pip and checks\n`--version`/`--help`; `sh ci/run-tests.sh 3.13` reproduces it locally (needs docker).
