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

Exit code is 0 always (informational tool); use --json for machine parsing
in CI. No data leaves the host -- everything is read via the local Docker
socket/CLI.
"""
import json
import subprocess
import sys


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True, check=False).stdout


def get_containers():
    out = sh("docker", "ps", "-q")
    return [c for c in out.strip().split("\n") if c]


def inspect(cid):
    out = sh("docker", "inspect", cid)
    try:
        return json.loads(out)[0]
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
    for cid in get_containers():
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
