#!/usr/bin/env python3
"""
docker-baseline-auditor: read-only Docker security baseline checker.

Checks all running containers on a host against common misconfiguration
patterns (roughly CIS Docker Benchmark territory), with zero external
dependencies beyond the `docker` CLI already on the host. Never modifies
anything -- read-only `docker inspect` / `docker ps` calls only.

Usage:
    python3 docker-baseline-auditor.py [--json]

Checks performed per running container:
  - privileged mode
  - host network mode (--network=host)
  - host PID/IPC namespace sharing
  - Docker socket mounted into the container (classic container-escape vector)
  - running as root (no USER directive / uid 0)
  - no memory limit set (can starve the host)
  - no restart policy (silent-death risk, not security per se, but ops hygiene)
  - `:latest` tag in use (supply-chain / reproducibility risk)
  - AppArmor/SecComp explicitly set to "unconfined"
  - capabilities added beyond default (--cap-add)

Exit code is 0 on a normal run (informational tool) and 2 if the `docker`
CLI is missing or fails to respond (e.g. daemon unreachable) -- the audit
is skipped rather than silently reporting "0 containers checked". Use
--json for machine parsing in CI. No data leaves the host -- everything is
read via the local Docker socket/CLI.
"""
import json
import subprocess
import sys


class DockerUnavailableError(Exception):
    """Raised when the docker CLI can't be run or fails to list containers."""


def sh(*args):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise DockerUnavailableError(
            "`docker` CLI not found on PATH -- is Docker installed?"
        )
    return proc


def get_containers():
    proc = sh("docker", "ps", "-q")
    if proc.returncode != 0:
        stderr = proc.stderr.strip() or "(no error output)"
        raise DockerUnavailableError(
            f"`docker ps` failed (exit {proc.returncode}): {stderr}"
        )
    return [c for c in proc.stdout.strip().split("\n") if c]


def inspect(cid):
    proc = sh("docker", "inspect", cid)
    if proc.returncode != 0:
        return {}
    try:
        return json.loads(proc.stdout)[0]
    except Exception:
        return {}


def audit_container(data):
    findings = []
    name = data.get("Name", "").lstrip("/")
    image = data.get("Config", {}).get("Image", "unknown")
    host_config = data.get("HostConfig", {})
    config = data.get("Config", {})

    if host_config.get("Privileged"):
        findings.append(("HIGH", "privileged mode enabled (full host device/capability access)"))

    if host_config.get("NetworkMode") == "host":
        findings.append(("HIGH", "host network mode (bypasses container network isolation)"))

    if host_config.get("PidMode") == "host":
        findings.append(("HIGH", "host PID namespace shared (can see/signal host processes)"))

    if host_config.get("IpcMode") == "host":
        findings.append(("MEDIUM", "host IPC namespace shared"))

    for m in data.get("Mounts", []) or []:
        src = m.get("Source", "")
        if "docker.sock" in src:
            findings.append(("HIGH", f"Docker socket mounted in ({src}) -- effective root-equivalent host access"))

    user = config.get("User") or ""
    if user in ("", "0", "root"):
        findings.append(("MEDIUM", "container runs as root (no non-root USER set)"))

    if not host_config.get("Memory"):
        findings.append(("LOW", "no memory limit set"))

    if not host_config.get("RestartPolicy", {}).get("Name"):
        findings.append(("LOW", "no restart policy set"))

    if image.endswith(":latest") or ":" not in image:
        findings.append(("LOW", "using ':latest' or untagged image (non-reproducible, harder to pin/patch)"))

    sec_opts = host_config.get("SecurityOpt") or []
    for opt in sec_opts:
        if "unconfined" in opt:
            findings.append(("MEDIUM", f"security profile disabled: {opt}"))

    cap_add = host_config.get("CapAdd") or []
    if cap_add:
        findings.append(("MEDIUM", f"extra capabilities added: {', '.join(cap_add)}"))

    return {"name": name, "image": image, "findings": findings}


def main():
    as_json = "--json" in sys.argv
    results = []
    try:
        container_ids = get_containers()
    except DockerUnavailableError as exc:
        if as_json:
            print(json.dumps({"error": str(exc)}, indent=2))
        else:
            print(f"docker-baseline-auditor: ERROR -- {exc}", file=sys.stderr)
        sys.exit(2)

    for cid in container_ids:
        data = inspect(cid)
        if data:
            results.append(audit_container(data))

    if as_json:
        print(json.dumps(results, indent=2))
        return

    total_findings = sum(len(r["findings"]) for r in results)
    print(f"docker-baseline-auditor: {len(results)} running containers checked, "
          f"{total_findings} findings\n")
    for r in results:
        if not r["findings"]:
            continue
        print(f"== {r['name']} ({r['image']}) ==")
        for sev, msg in sorted(r["findings"], key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[x[0]]):
            print(f"  [{sev}] {msg}")
        print()

    clean = [r["name"] for r in results if not r["findings"]]
    if clean:
        print(f"Clean (no findings): {', '.join(clean)}")


if __name__ == "__main__":
    main()
