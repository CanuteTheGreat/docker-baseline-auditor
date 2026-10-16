# docker-baseline-auditor

Read-only Docker security baseline checker. Zero dependencies beyond a working
`docker` CLI on the host you run it on (checks the containers already running
there -- it does not scan remote hosts or images).

Roughly CIS Docker Benchmark-adjacent checks:

- privileged mode
- host network / PID / IPC namespace sharing
- Docker socket mounted into a container (classic escape vector)
- containers running as root
- missing memory limits / restart policies
- `:latest` tag usage
- disabled AppArmor/Seccomp (`--security-opt ... unconfined`)
- added Linux capabilities (`--cap-add`)

## Usage

```
python3 docker-baseline-auditor.py          # human-readable
python3 docker-baseline-auditor.py --json   # machine-readable, for CI
```

Read-only. Runs `docker ps` / `docker inspect` only, never modifies
containers. No network calls, no data leaves the host.

Exit code: `0` after a normal run (informational), `2` if the `docker` CLI is
missing or the daemon can't be reached (instead of silently reporting
"0 containers checked").

## License / pricing

MIT — see LICENSE. Free, pay-what-you-want. If it's useful, there's a payment link on
https://errant.solutions. No obligation.

Part of the [Errant Solutions](https://errant.solutions) spare-capacity tools
series (see also: sshd-hardening-auditor, tls-cert-watchdog,
mail-security-auditor, aws-waste-finder).

## Tests

`tests/` exercises every option and check end-to-end (against real containers on a real Docker engine) in Forgejo CI on
Python 3.8 and current Python; `sh ci/run-tests.sh 3.13` reproduces it locally (needs docker).
