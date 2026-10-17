# Changelog

All notable changes. Versions are git tags; each tag has a Forgejo release with checksums.

## 1.2.0 - 2026-10-16

- **CI gate fixed:** the tool used to exit 0 after every run even with HIGH findings. It now exits 1 when
  any finding is at or above `--fail-on` (default `high`; `medium`, `low` or `never` also accepted).
- Every finding carries its CIS Docker Benchmark v1.6.0 id; `--include`/`--exclude` select checks by id or section.
- New daemon checks: icc on the default bridge (2.2), log level (2.3), insecure registries (2.5), aufs (2.6),
  TCP socket without TLS (2.7), user namespaces/rootless (2.9), centralized logging (2.13), no-new-privileges
  default (2.14), live restore (2.15), userland proxy (2.16), experimental features (2.18), read from
  `docker info`, the default bridge, `daemon.json` and the local dockerd command line.
- New host file checks (local daemon only): docker.service/docker.socket, /etc/docker, daemon.json and the
  Docker socket owner and mode (3.1-3.6, 3.15-3.18). Docker Content Trust (4.5).
- New container checks: sensitive host paths mounted (5.6), privileged host ports (5.8), writable root
  filesystem (5.13), ports published on every interface (5.14), host devices (5.18), shared mount propagation
  (5.20), host UTS/user namespaces (5.21/5.31), no-new-privileges (5.26), health check (5.27), pids limit (5.29).
- `--all` also audits stopped containers.
- **Breaking:** `--json` is now an object (`version`, `engine`, `daemon`, `containers`, `summary`) and each
  finding is `{"id", "severity", "message"}` instead of a `[severity, message]` pair.
- The script is now `docker_baseline_auditor.py` (an importable module name); the command is `docker-baseline-auditor`.
- Installable as a package: `pipx install git+https://git.canutethegreat.com/CanuteTheGreat/docker-baseline-auditor.git`
  puts a `docker-baseline-auditor` command on PATH (pyproject.toml, MIT license metadata).
- `--version` flag.
- Exit codes follow the shared convention: 0 = clean, 1 = findings at/above the gate, 2 = error or bad usage.
- Every tag now publishes a Forgejo release with this changelog, the wheel, the sdist and SHA256SUMS.
- CI installs the package with pip in a clean venv and checks `--version`/`--help` on every push.

## 1.1.0 - 2026-10-16

- Normalize CAP_-prefixed capability names reported by newer Docker engines
- Fix restart-policy, root-user and image-tag checks; add CI tests
- Add MIT LICENSE file

## 1.0.0 - 2026-09-30

- First public release.
