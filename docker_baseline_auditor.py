#!/usr/bin/env python3
"""
docker-baseline-auditor: read-only Docker security baseline checker.

Checks the Docker daemon, the Docker host's files and every running container
against the CIS Docker Benchmark v1.6.0. Every finding carries its CIS
recommendation id (e.g. 5.5 = privileged container), so results line up with
the benchmark and with Docker Bench for Security. Zero dependencies beyond the
`docker` CLI already on the host. Never modifies anything: `docker info`,
`docker network inspect`, `docker ps` and `docker inspect` plus local stat()
calls only.

Usage:
    docker-baseline-auditor [--json] [--fail-on high|medium|low|never]
                            [--include IDS] [--exclude IDS] [--all]

What is checked:
  daemon (2.x)   inter-container traffic on the default bridge (2.2), log level
                 (2.3), insecure registries (2.5), aufs (2.6), TLS on a TCP
                 socket (2.7), user namespaces / rootless (2.9), centralized
                 logging (2.13), no-new-privileges default (2.14), live restore
                 (2.15), userland proxy (2.16), experimental features (2.18)
  host files     docker.service / docker.socket units (3.1-3.4), /etc/docker
  (3.x)          (3.5/3.6), the Docker socket (3.15/3.16), daemon.json
                 (3.17/3.18); only when the daemon is local
  content trust  DOCKER_CONTENT_TRUST not enabled for this shell (4.5)
  containers     configured to run as root (4.1), AppArmor/seccomp unconfined
  (4.x/5.x)      (5.2/5.22), added capabilities (5.4), privileged (5.5),
                 sensitive host paths mounted (5.6), privileged host ports
                 (5.8), host network (5.10), memory limit (5.11), read-only
                 root filesystem (5.13), ports bound to every interface (5.14),
                 unbounded restart policy (5.15), host PID/IPC/UTS/user namespaces
                 (5.16/5.17/5.21/5.31), host devices (5.18), shared mount
                 propagation (5.20), no-new-privileges (5.26), health check
                 (5.27), pids limit (5.29), Docker socket mounted (5.32) and
                 ':latest'/untagged images (ops hygiene, no CIS id)

Exit codes: 0 = nothing at or above --fail-on (default: high), 1 = at least
one such finding, 2 = the docker CLI is missing or the daemon can't be reached
(the audit is skipped rather than reporting "0 containers checked") or bad
usage. No data leaves the host.
"""
__version__ = "1.2.0"

import argparse
import json
import os
import stat
import subprocess
import sys

try:  # not available on Windows (Docker Desktop): host file ownership checks are then skipped
    import grp
    import pwd
except ImportError:  # pragma: no cover
    grp = pwd = None

SEVERITIES = ("HIGH", "MEDIUM", "LOW", "INFO")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
SENSITIVE_PATHS = ("/", "/boot", "/dev", "/etc", "/lib", "/proc", "/sys", "/usr", "/var/run", "/run")
UNIT_DIRS = ("etc/systemd/system", "lib/systemd/system", "usr/lib/systemd/system")


class DockerUnavailableError(Exception):
    """Raised when the docker CLI can't be run or fails to list containers."""


def finding(cis, severity, message):
    return {"id": cis, "severity": severity, "message": message}


def sh(*args):
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, check=False)
    except FileNotFoundError:
        raise DockerUnavailableError("`docker` CLI not found on PATH -- is Docker installed?")
    return proc


def docker_json(*args):
    proc = sh("docker", *args)
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except ValueError:
        return None


def get_containers(include_stopped=False):
    proc = sh("docker", "ps", "-q", *(["-a"] if include_stopped else []))
    if proc.returncode != 0:
        stderr = proc.stderr.strip() or "(no error output)"
        raise DockerUnavailableError(f"`docker ps` failed (exit {proc.returncode}): {stderr}")
    return [c for c in proc.stdout.strip().split("\n") if c]


def inspect(cid):
    data = docker_json("inspect", cid)
    return data[0] if data else {}


# --------------------------------------------------------------------------- daemon

def dockerd_args(root="/"):
    """Command-line flags of a local dockerd process, if one is visible in /proc."""
    proc_dir = os.path.join(root, "proc")
    try:
        pids = [p for p in os.listdir(proc_dir) if p.isdigit()]
    except OSError:
        return None
    for pid in pids:
        try:
            with open(os.path.join(proc_dir, pid, "cmdline"), "rb") as f:
                argv = [a.decode("utf-8", "replace") for a in f.read().split(b"\0") if a]
        except OSError:
            continue
        if argv and os.path.basename(argv[0]) == "dockerd":
            return argv[1:]
    return None


def flag_value(args, name):
    """Value of --name / --name=value in dockerd args (True for a bare boolean flag)."""
    for i, a in enumerate(args or []):
        if a == "--" + name:
            nxt = args[i + 1] if i + 1 < len(args) else ""
            return nxt if nxt and not nxt.startswith("-") else True
        if a.startswith("--" + name + "="):
            return a.split("=", 1)[1]
    return None


def truthy(v):
    return v is True or str(v).lower() in ("true", "1")


def audit_daemon(info, bridge, daemon_json, args):
    """info = `docker info` JSON; bridge = `docker network inspect bridge` entry (or None);
    daemon_json = parsed daemon.json (or None if unreadable); args = dockerd flags (or None)."""
    out = []
    cfg = daemon_json or {}

    def setting(key):
        v = flag_value(args, key)
        return v if v is not None else cfg.get(key)

    opts = (bridge or {}).get("Options") or {}
    if bridge is not None and opts.get("com.docker.network.bridge.enable_icc", "true") == "true":
        out.append(finding("2.2", "MEDIUM",
                           "inter-container traffic is allowed on the default bridge (set \"icc\": false)"))

    level = setting("log-level")
    if level and str(level).lower() != "info":
        out.append(finding("2.3", "LOW", f"daemon log level is '{level}' (CIS recommends 'info')"))

    reg = info.get("RegistryConfig") or {}
    insecure = [c for c in reg.get("InsecureRegistryCIDRs") or [] if not c.startswith("127.") and c != "::1/128"]
    insecure += [name for name, ic in (reg.get("IndexConfigs") or {}).items()
                 if ic.get("Secure") is False and not name.startswith(("localhost", "127."))]
    if insecure:
        out.append(finding("2.5", "HIGH", f"insecure registries configured: {', '.join(sorted(set(insecure)))}"))

    if info.get("Driver") == "aufs":
        out.append(finding("2.6", "MEDIUM", "aufs storage driver in use"))

    hosts = setting("hosts") or flag_value(args, "host") or []
    if isinstance(hosts, str):
        hosts = [hosts]
    elif not isinstance(hosts, list):
        hosts = []
    tcp = [h for h in hosts if str(h).startswith("tcp://")]
    if tcp and not truthy(setting("tlsverify")):
        out.append(finding("2.7", "HIGH", f"daemon listens on {', '.join(tcp)} without --tlsverify"))

    secopts = " ".join(info.get("SecurityOptions") or [])
    if "name=userns" not in secopts and "name=rootless" not in secopts:
        out.append(finding("2.9", "LOW", "user namespace remapping is not enabled (and the daemon is not rootless)"))

    if info.get("LoggingDriver") in ("json-file", "local", "none", None):
        out.append(finding("2.13", "INFO",
                           f"logging driver is '{info.get('LoggingDriver')}' (no centralized/remote logging)"))

    if daemon_json is not None or args is not None:
        if not truthy(setting("no-new-privileges")):
            out.append(finding("2.14", "LOW",
                               "containers may acquire new privileges by default (set \"no-new-privileges\": true)"))
        up = setting("userland-proxy")
        if up is None or truthy(up):
            out.append(finding("2.16", "LOW", "userland proxy is enabled (set \"userland-proxy\": false)"))

    if not info.get("LiveRestoreEnabled"):
        out.append(finding("2.15", "LOW", "live restore is disabled (containers stop when dockerd restarts)"))

    if info.get("ExperimentalBuild"):
        out.append(finding("2.18", "MEDIUM", "experimental daemon features are enabled"))

    return out


# --------------------------------------------------------------------------- host files

def _mode_owner(path):
    st = os.lstat(path)
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return stat.S_IMODE(st.st_mode), owner, group


def _check_file(path, owner_id, perm_id, owners, max_mode, label):
    out = []
    if pwd is None or not os.path.lexists(path):
        return out
    try:
        mode, owner, group = _mode_owner(path)
    except OSError:
        return out
    if f"{owner}:{group}" not in owners:
        out.append(finding(owner_id, "MEDIUM",
                           f"{label} {path} is owned by {owner}:{group} (want {' or '.join(owners)})"))
    if mode & ~max_mode:
        out.append(finding(perm_id, "MEDIUM" if mode & 0o002 else "LOW",
                           f"{label} {path} has mode {mode:04o} (want {max_mode:04o} or stricter)"))
    return out


def audit_host_files(root="/", socket_path=None):
    def j(*p):
        return os.path.join(root, *p)
    out = []
    for unit, ids in (("docker.service", ("3.1", "3.2")), ("docker.socket", ("3.3", "3.4"))):
        for d in UNIT_DIRS:
            p = j(d, unit)
            if os.path.exists(p):
                out += _check_file(p, ids[0], ids[1], ("root:root",), 0o644, "unit file")
                break
    out += _check_file(j("etc/docker"), "3.5", "3.6", ("root:root",), 0o755, "directory")
    out += _check_file(j("etc/docker/daemon.json"), "3.17", "3.18", ("root:root",), 0o644, "daemon config")
    out += _check_file(socket_path or j("var/run/docker.sock"), "3.15", "3.16", ("root:docker", "root:root"),
                       0o660, "Docker socket")
    return out


def local_socket_path():
    host = os.environ.get("DOCKER_HOST", "")
    if not host:
        return "/var/run/docker.sock"
    if host.startswith("unix://"):
        return host[len("unix://"):]
    return None  # remote daemon: its host files aren't ours to stat


# --------------------------------------------------------------------------- containers

def audit_container(data):
    findings = []
    name = data.get("Name", "").lstrip("/")
    config = data.get("Config") or {}
    image = config.get("Image", "unknown")
    hc = data.get("HostConfig") or {}

    def add(cis, sev, msg):
        findings.append(finding(cis, sev, msg))

    # "User" may be "name", "uid", "name:group" or "uid:gid"; only the user part matters.
    user = (config.get("User") or "").split(":", 1)[0].strip()
    if user in ("", "0", "root"):
        add("4.1", "MEDIUM", "configured to run as root (no non-root USER set)")

    secopts = hc.get("SecurityOpt") or []
    for opt in secopts:
        if "unconfined" in opt:
            add("5.22" if opt.startswith("seccomp") else "5.2", "MEDIUM", f"security profile disabled: {opt}")

    # Newer engines report CapAdd as CAP_NET_ADMIN, older ones as NET_ADMIN.
    cap_add = [c[4:] if c.upper().startswith("CAP_") else c for c in (hc.get("CapAdd") or [])]
    if cap_add:
        add("5.4", "MEDIUM", f"extra capabilities added: {', '.join(cap_add)}")

    if hc.get("Privileged"):
        add("5.5", "HIGH", "privileged mode enabled (full host device/capability access)")

    for m in data.get("Mounts") or []:
        if m.get("Type", "bind") != "bind":
            continue
        src = (m.get("Source") or "").rstrip("/") or "/"
        rw = m.get("RW", True)
        if "docker.sock" in src:
            add("5.32", "HIGH", f"Docker socket mounted in ({src}) -- effective root-equivalent host access")
        elif src in SENSITIVE_PATHS:
            add("5.6", "HIGH" if rw else "MEDIUM",
                f"sensitive host path {src} mounted {'read-write' if rw else 'read-only'}")
        if (m.get("Propagation") or "") in ("shared", "rshared"):
            add("5.20", "MEDIUM", f"mount {src} uses {m['Propagation']} propagation")

    for cport, binds in sorted((hc.get("PortBindings") or {}).items()):
        for b in binds or []:
            hip, hport = b.get("HostIp") or "", b.get("HostPort") or ""
            if hport.isdigit() and 0 < int(hport) < 1024:
                add("5.8", "LOW", f"privileged host port {hport} mapped to {cport}")
            if hip in ("", "0.0.0.0", "::"):
                add("5.14", "LOW",
                    f"port {cport} published on every host interface ({hip or '0.0.0.0'}:{hport or 'random'})")

    if hc.get("NetworkMode") == "host":
        add("5.10", "HIGH", "host network mode (bypasses container network isolation)")
    if not hc.get("Memory"):
        add("5.11", "LOW", "no memory limit set")
    if not hc.get("ReadonlyRootfs"):
        add("5.13", "LOW", "root filesystem is writable (no --read-only)")

    # CIS 5.15: a policy that restarts without bound (always, unless-stopped, on-failure with no or a
    # >5 retry cap; MaximumRetryCount 0 means unlimited) can be abused to keep a crashing container
    # hammering the host. No policy at all is compliant. ("" is how old engines report "no".)
    rp = hc.get("RestartPolicy") or {}
    policy, retries = rp.get("Name") or "no", rp.get("MaximumRetryCount") or 0
    if policy in ("always", "unless-stopped"):
        add("5.15", "LOW", f"restart policy '{policy}' restarts without limit (CIS: on-failure with at most 5 retries)")
    elif policy == "on-failure" and not 0 < retries <= 5:
        add("5.15", "LOW", f"restart policy on-failure with {retries or 'unlimited'} retries (CIS: at most 5)")

    if hc.get("PidMode") == "host":
        add("5.16", "HIGH", "host PID namespace shared (can see/signal host processes)")
    if hc.get("IpcMode") == "host":
        add("5.17", "MEDIUM", "host IPC namespace shared")
    if hc.get("Devices"):
        add("5.18", "MEDIUM", "host devices exposed: " + ", ".join(d.get("PathOnHost", "?") for d in hc["Devices"]))
    if hc.get("UTSMode") == "host":
        add("5.21", "MEDIUM", "host UTS namespace shared")
    if not any(o.split("=")[0].split(":")[0] == "no-new-privileges" and not o.endswith(("false", "=0"))
               for o in secopts):
        add("5.26", "LOW", "no-new-privileges not set")
    test = (config.get("Healthcheck") or {}).get("Test")
    if not test or test == ["NONE"]:
        add("5.27", "LOW", "no health check configured")
    if not hc.get("PidsLimit") or hc["PidsLimit"] <= 0:
        add("5.29", "LOW", "no pids limit set")
    if hc.get("UsernsMode") == "host":
        add("5.31", "MEDIUM", "host user namespace shared")

    # Tag lives after the last "/" (a registry host:port also contains ":");
    # digest-pinned references (name@sha256:...) are fine.
    last = image.rsplit("/", 1)[-1]
    if "@" not in last and (":" not in last or last.endswith(":latest")):
        add("-", "LOW", "using ':latest' or untagged image (non-reproducible, harder to pin/patch)")

    return {"name": name, "image": image, "findings": findings}


# --------------------------------------------------------------------------- CLI

def _ids(s):
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def _selected(fid, include, exclude):
    def match(prefixes):
        return any(fid == p or fid.startswith(p + ".") for p in prefixes)
    if include and not match(include):
        return False
    return not match(exclude)


def run(args):
    container_ids = get_containers(args.all)  # proves the daemon answers before anything else
    info = docker_json("info", "--format", "{{json .}}") or {}
    bridge = (docker_json("network", "inspect", "bridge") or [None])[0]
    sock = local_socket_path()
    daemon_json, dargs, host = None, None, []
    if sock is not None:
        path = args.daemon_json or os.path.join(args.host_root, "etc/docker/daemon.json")
        try:
            with open(path) as f:
                daemon_json = json.load(f)
        except FileNotFoundError:
            # no daemon.json at all = every default applies (only knowable if /etc/docker is visible)
            daemon_json = {} if os.path.isdir(os.path.join(args.host_root, "etc/docker")) else None
        except (OSError, ValueError):
            daemon_json = None
        dargs = dockerd_args(args.host_root)
        host = audit_host_files(args.host_root, sock if args.host_root == "/" else None)
    daemon = audit_daemon(info, bridge, daemon_json, dargs)
    if os.environ.get("DOCKER_CONTENT_TRUST", "") != "1":
        daemon.append(finding("4.5", "INFO", "Docker Content Trust is not enabled (DOCKER_CONTENT_TRUST=1)"))
    containers = [audit_container(d) for d in (inspect(c) for c in container_ids) if d]

    inc, exc = _ids(args.include), _ids(args.exclude)
    daemon = [f for f in daemon + host if _selected(f["id"], inc, exc)]
    for c in containers:
        c["findings"] = [f for f in c["findings"] if _selected(f["id"], inc, exc)]
    return {"daemon": daemon, "containers": containers,
            "engine": info.get("ServerVersion"), "local_checks": sock is not None}


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="docker-baseline-auditor",
        description="Read-only Docker security baseline checker (CIS Docker Benchmark v1.6.0 ids): "
                    "audits the daemon, its host files and every running container.",
        epilog="Exit codes: 0 nothing at/above --fail-on, 1 findings at/above --fail-on, "
               "2 docker unavailable or bad usage.")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of the text report")
    parser.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high",
                        help="lowest severity that makes the exit code 1 (default: high)")
    parser.add_argument("--include", metavar="IDS", help="only these CIS ids/sections, comma-separated (e.g. 2,5.5)")
    parser.add_argument("--exclude", metavar="IDS", help="skip these CIS ids/sections, comma-separated (e.g. 5.27,2.13)")
    parser.add_argument("--all", action="store_true", help="also audit stopped containers")
    parser.add_argument("--daemon-json", metavar="PATH", help="daemon.json to read (default /etc/docker/daemon.json)")
    parser.add_argument("--host-root", default="/", metavar="DIR", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        res = run(args)
    except DockerUnavailableError as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}, indent=2))
        else:
            print(f"docker-baseline-auditor: ERROR -- {exc}", file=sys.stderr)
        return 2

    every = res["daemon"] + [f for c in res["containers"] for f in c["findings"]]
    counts = {s: sum(1 for f in every if f["severity"] == s) for s in SEVERITIES}
    gate = None if args.fail_on == "never" else RANK[args.fail_on.upper()]
    failing = gate is not None and any(RANK[f["severity"]] <= gate for f in every)
    res["summary"] = dict(counts, containers=len(res["containers"]), fail_on=args.fail_on, failed=failing)

    if args.json:
        print(json.dumps(dict(res, version=__version__), indent=2))
        return 1 if failing else 0

    def order(f):
        return RANK[f["severity"]], f["id"]
    print(f"docker-baseline-auditor {__version__}: engine {res['engine'] or '?'}, "
          f"{len(res['containers'])} {'' if args.all else 'running '}containers checked, {len(every)} findings "
          f"({', '.join('%d %s' % (counts[s], s) for s in SEVERITIES)})\n")
    if res["daemon"]:
        print("== daemon / host ==")
        for f in sorted(res["daemon"], key=order):
            print(f"  [{f['severity']}] {f['id']:<5} {f['message']}")
        print()
    if not res["local_checks"]:
        print("(remote DOCKER_HOST: host file checks 3.x skipped)\n")
    for r in res["containers"]:
        if not r["findings"]:
            continue
        print(f"== {r['name']} ({r['image']}) ==")
        for f in sorted(r["findings"], key=order):
            print(f"  [{f['severity']}] {f['id']:<5} {f['message']}")
        print()
    clean = [r["name"] for r in res["containers"] if not r["findings"]]
    if clean:
        print(f"Clean (no findings): {', '.join(clean)}")
    if failing:
        print(f"\nFAIL: findings at or above {args.fail_on.upper()} (exit 1)")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
