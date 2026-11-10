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
    docker-baseline-auditor --dockerfile PATH ... --compose PATH ... [--live]

Static scan (--dockerfile / --compose, repeatable, files or directories): the
same CIS ids are checked in Dockerfiles and Compose files before anything is
built or started, with no docker CLI or daemon needed. Dockerfile: root user
(4.1), no HEALTHCHECK (4.6), package index update on its own RUN line (4.7),
ADD instead of COPY (4.9), secrets in ENV/ARG (4.10), ':latest'/untagged base
images, a download piped into a shell, EXPOSE 22, world-writable chmod. Compose:
every container check a compose key can express (4.1, 5.2, 5.4-5.6, 5.8, 5.10,
5.11, 5.13-5.18, 5.20-5.22, 5.26, 5.27, 5.29, 5.31, 5.32), plus hardcoded
secrets in `environment`.

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
__version__ = "1.3.0"

import argparse
import json
import os
import re
import shlex
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


# --------------------------------------------------------------------------- static scan

class StaticScanError(Exception):
    """A --dockerfile/--compose path is missing or a compose file can't be parsed."""


SECRET_NAME = re.compile(r"PASS(WORD|WD)?|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL", re.I)
ARCHIVE_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|ash)\b")
WORLD_WRITABLE = re.compile(r"\bch" r"mod\s+(-\w+\s+)*(0?7" r"77|a\+rwx|ugo\+rwx)\b")
ENV_DEFAULT = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-?]([^}]*)\}")
DOCKERFILE_DIR_SKIP = (".git", "node_modules", ".venv", "venv", "__pycache__")
LATEST_MSG = "':latest' or untagged image (non-reproducible, harder to pin/patch)"


def untagged(image):
    """True for ':latest' or no tag; a tag lives after the last '/', digests are fine."""
    last = image.rsplit("/", 1)[-1]
    return "@" not in last and (":" not in last or last.endswith(":latest"))


def _is_secret(name, value):
    return bool(SECRET_NAME.search(name)) and value not in ("", None) and not str(value).startswith("$")


def _split_words(text):
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def dockerfile_instructions(text):
    """[(line, KEYWORD, args)]: comments skipped, backslash continuations joined."""
    out, buf, start = [], [], 0

    def flush():
        joined = " ".join(b for b in buf if b)
        kw, _, args = joined.partition(" ")
        out.append((start, kw.upper(), args.strip()))

    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("#") or (not line and not buf):
            continue
        if not buf:
            start = no
        if line.endswith("\\"):
            buf.append(line[:-1].strip())
            continue
        buf.append(line)
        flush()
        buf = []
    if buf:
        flush()
    return out


def audit_dockerfile(text):
    """Returns (final base image, findings) for one Dockerfile."""
    findings = []

    def add(cis, sev, no, msg):
        findings.append(finding(cis, sev, f"line {no}: {msg}"))

    stages, aliases = [], set()
    cur = None
    for no, kw, args in dockerfile_instructions(text):
        if kw == "FROM":
            words = [w for w in _split_words(args) if not w.startswith("--")]
            image = words[0] if words else ""
            if image and image != "scratch" and image.lower() not in aliases and "$" not in image \
                    and untagged(image):
                add("-", "LOW", no, f"base image {image} is " + LATEST_MSG)
            if len(words) >= 3 and words[1].upper() == "AS":
                aliases.add(words[2].lower())
            cur = {"image": image, "user": None, "user_line": no, "from_line": no, "health": False}
            stages.append(cur)
            continue
        if kw == "USER" and cur is not None:
            cur["user"], cur["user_line"] = args.split(":", 1)[0].strip(), no
        elif kw == "HEALTHCHECK" and cur is not None:
            cur["health"] = args.strip().upper() != "NONE"
        elif kw == "RUN":
            low = args.lower()
            if re.search(r"\b(apt-get|apt|apk)\s+update\b", low) and not re.search(r"\b(install|upgrade|add)\b", low):
                add("4.7", "LOW", no, "package index update on its own RUN line (cached stale; "
                    "combine update and install in one RUN)")
            if PIPE_TO_SHELL.search(args):
                add("-", "MEDIUM", no, "downloads a script and pipes it into a shell (unverified code)")
            if WORLD_WRITABLE.search(args):
                add("-", "LOW", no, "world-writable permissions (mode 0777)")
        elif kw == "ADD":
            try:
                words = json.loads(args)
                words = [str(w) for w in words] if isinstance(words, list) else _split_words(args)
            except ValueError:
                words = _split_words(args)
            srcs = [w for w in words if not w.startswith("--")][:-1]
            if any(w.startswith(("http://", "https://")) for w in srcs):
                add("4.9", "MEDIUM", no, "ADD fetches a remote URL (no checksum; use curl with a verified "
                    "digest, or COPY)")
            elif not any(w.lower().endswith(ARCHIVE_SUFFIXES) for w in srcs):
                add("4.9", "LOW", no, "use COPY instead of ADD (ADD only for local tar auto-extraction)")
        elif kw == "ENV":
            words = _split_words(args)
            if words and "=" in words[0]:
                pairs = [w.split("=", 1) for w in words]
            else:
                pairs = [[words[0], " ".join(words[1:])]] if words else []
            for pair in pairs:
                if len(pair) == 2 and _is_secret(pair[0], pair[1]):
                    add("4.10", "HIGH", no, f"secret baked into the image: ENV {pair[0]} has a literal value")
        elif kw == "ARG":
            name, eq, value = args.partition("=")
            if eq and _is_secret(name.strip(), value.strip().strip("\"'")):
                add("4.10", "MEDIUM", no, f"secret default in the image history: ARG {name.strip()} has a literal value")
        elif kw == "EXPOSE" and any(p.split("/")[0] == "22" for p in args.split()):
            add("-", "LOW", no, "EXPOSE 22: no SSH server should run in a container (use docker exec)")
    if not stages:
        return "", findings
    final = stages[-1]
    if final["user"] is None:
        add("4.1", "MEDIUM", final["user_line"], "final stage runs as root (no non-root USER)")
    elif final["user"] in ("", "0", "root"):
        add("4.1", "MEDIUM", final["user_line"], f"final stage switches to USER {final['user'] or 'root'} (root)")
    if not final["health"]:
        add("4.6", "LOW", final["from_line"], "no HEALTHCHECK instruction in the final stage")
    findings.sort(key=lambda f: int(f["message"].split(":", 1)[0].split()[1]))
    return final["image"], findings


# A YAML subset big enough for Compose files (block maps/sequences, flow lists/maps, quoted and
# plain scalars, anchors/aliases and `<<` merges, | and > block scalars). Anything else raises.

def _yaml_lines(text):
    out = []
    for no, raw in enumerate(text.splitlines(), 1):
        quote, cut = None, len(raw)
        for i, ch in enumerate(raw):
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "\"'" and (i == 0 or raw[i - 1] in " \t:[{,-"):
                quote = ch
            elif ch == "#" and (i == 0 or raw[i - 1] in " \t"):
                cut = i
                break
        body = raw[:cut].rstrip()
        if not body.strip() or body.strip() in ("---", "..."):
            continue
        if "\t" in body[:len(body) - len(body.lstrip())]:
            raise StaticScanError(f"line {no}: tab indentation is not valid YAML")
        out.append([len(body) - len(body.lstrip()), body.strip(), no, raw])
    return out


def _split_key(text):
    """(key, rest) for 'key: value' / 'key:', else None."""
    if text[:1] in ("\"", "'"):
        end = text.find(text[0], 1)
        if end > 0 and text[end + 1:end + 2] == ":" and text[end + 2:end + 3] in ("", " "):
            return text[1:end], text[end + 2:].strip()
        return None
    if text[:1] in ("[", "{", "*", "&", "|", ">"):
        return None
    depth = 0
    for i, ch in enumerate(text):
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == ":" and depth == 0 and text[i + 1:i + 2] in ("", " "):
            return text[:i].strip(), text[i + 1:].strip()
    return None


def _is_seq_item(text):
    return text == "-" or text.startswith("- ")


class _Yaml:
    def __init__(self, text):
        self.lines = _yaml_lines(text)
        self.anchors = {}

    def parse(self):
        if not self.lines:
            return {}
        val, pos = self.node(0, self.lines[0][0])
        if pos < len(self.lines):
            raise StaticScanError(f"line {self.lines[pos][2]}: unsupported or inconsistent YAML structure")
        return val

    def node(self, pos, ind):
        text = self.lines[pos][1]
        if _is_seq_item(text):
            return self.seq(pos, ind)
        if _split_key(text):
            return self.map(pos, ind)
        return self.scalar(text), pos + 1

    def nested(self, pos, ind):
        if pos < len(self.lines):
            nxt = self.lines[pos]
            if nxt[0] > ind or (nxt[0] == ind and _is_seq_item(nxt[1])):
                return self.node(pos, nxt[0])
        return None, pos

    def value(self, rest, pos, ind):
        anchor = None
        if rest.startswith("&"):
            anchor, _, rest = rest[1:].partition(" ")
            rest = rest.strip()
        if rest == "":
            val, pos = self.nested(pos, ind)
        elif rest[0] in "|>" and rest.strip("|>+-") == "":
            block = []
            while pos < len(self.lines) and self.lines[pos][0] > ind:
                block.append(self.lines[pos][3].strip())
                pos += 1
            val = ("\n" if rest[0] == "|" else " ").join(block)
        else:
            val = self.scalar(rest)
        if anchor:
            self.anchors[anchor] = val
        return val, pos

    def map(self, pos, ind):
        out = {}
        while pos < len(self.lines) and self.lines[pos][0] == ind and not _is_seq_item(self.lines[pos][1]):
            kv = _split_key(self.lines[pos][1])
            if kv is None:
                raise StaticScanError(f"line {self.lines[pos][2]}: expected 'key: value'")
            key, rest = kv
            val, pos = self.value(rest, pos + 1, ind)
            if key == "<<":
                for src in (val if isinstance(val, list) else [val]):
                    if isinstance(src, dict):
                        for k, v in src.items():
                            out.setdefault(k, v)
            else:
                out[key] = val
        return out, pos

    def seq(self, pos, ind):
        out = []
        while pos < len(self.lines) and self.lines[pos][0] == ind and _is_seq_item(self.lines[pos][1]):
            line = self.lines[pos]
            item = line[1][1:].lstrip()
            if item and _split_key(item):
                # "- key: value": the mapping continues at the column after "- "
                line[0], line[1] = ind + len(line[1]) - len(item), item
                val, pos = self.map(pos, line[0])
            else:
                val, pos = self.value(item, pos + 1, ind)
            out.append(val)
        return out, pos

    def scalar(self, s):
        s = s.strip()
        if s.startswith("*"):
            if s[1:] not in self.anchors:
                raise StaticScanError(f"unknown YAML alias {s}")
            return self.anchors[s[1:]]
        if s[:1] in ("\"", "'"):
            if len(s) < 2 or s[-1] != s[0]:
                raise StaticScanError(f"unterminated quoted string: {s}")
            body = s[1:-1]
            return body.replace("''", "'") if s[0] == "'" else body.replace('\\"', '"').replace("\\\\", "\\")
        if s[:1] in ("[", "{"):
            return self.flow(s)
        if s in ("~", "null", "Null", "NULL"):
            return None
        if s in ("true", "True", "TRUE"):
            return True
        if s in ("false", "False", "FALSE"):
            return False
        if re.fullmatch(r"-?\d+", s):
            return int(s)
        return s

    def flow(self, s):
        close = "]" if s[0] == "[" else "}"
        if not s.endswith(close):
            raise StaticScanError(f"unsupported multi-line flow collection: {s[:40]}")
        parts, depth, quote, cur = [], 0, None, ""
        for ch in s[1:-1]:
            if quote:
                quote = None if ch == quote else quote
            elif ch in "\"'":
                quote = ch
            elif ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append(cur)
                cur = ""
                continue
            cur += ch
        if cur.strip():
            parts.append(cur)
        if close == "]":
            return [self.scalar(p) for p in parts]
        out = {}
        for p in parts:
            kv = _split_key(p.strip())
            if kv is None:
                raise StaticScanError(f"bad flow mapping entry: {p.strip()}")
            out[kv[0]] = self.scalar(kv[1]) if kv[1] else None
        return out


def parse_yaml(text):
    return _Yaml(text).parse()


def _as_list(v):
    return v if isinstance(v, list) else [] if v is None else [v]


def _port_entries(svc):
    """[(host ip, published port, target)] from short and long port syntax."""
    out = []
    for p in _as_list(svc.get("ports")):
        if isinstance(p, dict):
            out.append((str(p.get("host_ip") or ""), str(p.get("published") or ""), str(p.get("target") or "?")))
            continue
        text = str(p).split("/", 1)[0]
        ip = ""
        if text.startswith("["):
            end = text.find("]")
            ip, text = text[1:end], text[end + 2:]
            rest = text.split(":")
        else:
            parts = text.split(":")
            if len(parts) >= 3:
                ip = parts[0]
            rest = parts[-2:] if len(parts) >= 2 else ["", parts[0]]
        out.append((ip, rest[0], rest[-1]))
    return out


def _mounts(svc):
    """[(source, read_only, propagation)] for bind-like volumes (short and long syntax)."""
    out = []
    for v in _as_list(svc.get("volumes")):
        if isinstance(v, dict):
            if v.get("type", "bind") == "bind":
                out.append((str(v.get("source") or ""), bool(v.get("read_only")),
                            str((v.get("bind") or {}).get("propagation") or "")))
            continue
        parts = ENV_DEFAULT.sub(r"\1", str(v)).split(":")  # ${VAR:-/default}: judge the default
        src = parts[0]
        if len(parts) < 2 or not src.startswith(("/", ".", "~", "$")):
            continue
        opts = parts[2].split(",") if len(parts) > 2 else []
        out.append((src, "ro" in opts, next((o for o in opts if o in ("shared", "rshared")), "")))
    return out


def audit_compose_service(svc):
    findings = []

    def add(cis, sev, msg):
        findings.append(finding(cis, sev, msg))

    image = str(svc.get("image") or "")
    user = str(svc.get("user") or "").split(":", 1)[0].strip()
    if user in ("", "0", "root"):
        add("4.1", "MEDIUM", "configured to run as root (no non-root user: set)")
    secopts = [str(o) for o in _as_list(svc.get("security_opt"))]
    for opt in secopts:
        if "unconfined" in opt:
            add("5.22" if opt.startswith("seccomp") else "5.2", "MEDIUM", f"security profile disabled: {opt}")
    caps = [str(c)[4:] if str(c).upper().startswith("CAP_") else str(c) for c in _as_list(svc.get("cap_add"))]
    if caps:
        add("5.4", "MEDIUM", f"extra capabilities added: {', '.join(caps)}")
    if svc.get("privileged") is True:
        add("5.5", "HIGH", "privileged mode enabled (full host device/capability access)")
    for src, ro, prop in _mounts(svc):
        norm = src.rstrip("/") or "/"
        if "docker.sock" in norm:
            add("5.32", "HIGH", f"Docker socket mounted in ({norm}) -- effective root-equivalent host access")
        elif norm in SENSITIVE_PATHS:
            add("5.6", "MEDIUM" if ro else "HIGH",
                f"sensitive host path {norm} mounted {'read-only' if ro else 'read-write'}")
        if prop:
            add("5.20", "MEDIUM", f"mount {norm} uses {prop} propagation")
    for ip, hport, cport in _port_entries(svc):
        first = hport.split("-")[0]
        if first.isdigit() and 0 < int(first) < 1024:
            add("5.8", "LOW", f"privileged host port {hport} mapped to {cport}")
        if ip in ("", "0.0.0.0", "::"):
            add("5.14", "LOW", f"port {cport} published on every host interface ({ip or '0.0.0.0'}:{hport or 'random'})")
    if svc.get("network_mode") == "host":
        add("5.10", "HIGH", "host network mode (bypasses container network isolation)")
    limits = ((svc.get("deploy") or {}).get("resources") or {}).get("limits") or {}
    if not (svc.get("mem_limit") or limits.get("memory")):
        add("5.11", "LOW", "no memory limit set")
    if svc.get("read_only") is not True:
        add("5.13", "LOW", "root filesystem is writable (no read_only: true)")
    name, _, cap = str(svc.get("restart") or "no").partition(":")
    if name in ("always", "unless-stopped"):
        add("5.15", "LOW", f"restart policy '{name}' restarts without limit (CIS: on-failure with at most 5 retries)")
    elif name == "on-failure" and not (cap.isdigit() and 0 < int(cap) <= 5):
        add("5.15", "LOW", f"restart policy on-failure with {cap or 'unlimited'} retries (CIS: at most 5)")
    if svc.get("pid") == "host":
        add("5.16", "HIGH", "host PID namespace shared (can see/signal host processes)")
    if svc.get("ipc") == "host":
        add("5.17", "MEDIUM", "host IPC namespace shared")
    if svc.get("devices"):
        add("5.18", "MEDIUM", "host devices exposed: " + ", ".join(
            str(d).split(":", 1)[0] for d in _as_list(svc.get("devices"))))
    if svc.get("uts") == "host":
        add("5.21", "MEDIUM", "host UTS namespace shared")
    if not any(o.split("=")[0].split(":")[0] == "no-new-privileges" and not o.endswith(("false", "=0"))
               for o in secopts):
        add("5.26", "LOW", "no-new-privileges not set")
    hc = svc.get("healthcheck")
    hc = hc if isinstance(hc, dict) else {}
    if not hc.get("test") or hc["test"] in ("NONE", ["NONE"]) or hc.get("disable") is True:
        add("5.27", "LOW", "no health check configured")
    pids = svc.get("pids_limit") or limits.get("pids")
    if not pids or str(pids).lstrip("-").isdigit() and int(pids) <= 0:
        add("5.29", "LOW", "no pids limit set")
    if svc.get("userns_mode") == "host":
        add("5.31", "MEDIUM", "host user namespace shared")
    env = svc.get("environment")
    pairs = list(env.items()) if isinstance(env, dict) else [str(e).split("=", 1) + [""] for e in _as_list(env)]
    for pair in pairs:
        if _is_secret(str(pair[0]), pair[1]):
            add("-", "MEDIUM", f"hardcoded secret in environment: {pair[0]} has a literal value "
                "(use secrets: or an env_file)")
    if image and "$" not in image and untagged(image):
        add("-", "LOW", "using " + LATEST_MSG)
    return image, findings


def audit_compose(text):
    """[(service, image, findings)] for one compose file."""
    data = parse_yaml(text)
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict) or not services:
        raise StaticScanError("no `services:` mapping found")
    out = []
    for name, svc in services.items():
        if not isinstance(svc, dict):
            raise StaticScanError(f"service {name} is not a mapping")
        image, findings = audit_compose_service(svc)
        out.append((str(name), image or "(build)", findings))
    return out


def _is_dockerfile_name(n):
    low = n.lower()
    return low in ("dockerfile", "containerfile") or low.startswith("dockerfile.") \
        or low.endswith((".dockerfile", ".containerfile"))


def _is_compose_name(n):
    low = n.lower()
    return low.endswith((".yml", ".yaml")) and low.startswith(("compose", "docker-compose"))


def collect_paths(paths, matcher, label):
    files = []
    for p in paths:
        if os.path.isdir(p):
            found = []
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in DOCKERFILE_DIR_SKIP)
                found += [os.path.join(root, n) for n in sorted(names) if matcher(n)]
            if not found:
                raise StaticScanError(f"no {label} found under {p}")
            files += found
        elif os.path.isfile(p):
            files.append(p)
        else:
            raise StaticScanError(f"{label} path not found: {p}")
    return files


def audit_static(dockerfiles, composes):
    out = []
    for path in collect_paths(dockerfiles, _is_dockerfile_name, "Dockerfile"):
        with open(path, encoding="utf-8", errors="replace") as f:
            image, findings = audit_dockerfile(f.read())
        out.append({"name": path, "kind": "dockerfile", "image": image, "findings": findings})
    for path in collect_paths(composes, _is_compose_name, "compose file"):
        with open(path, encoding="utf-8", errors="replace") as f:
            try:
                services = audit_compose(f.read())
            except StaticScanError as exc:
                raise StaticScanError(f"{path}: {exc}")
        for name, image, findings in services:
            out.append({"name": f"{path}:{name}", "kind": "compose", "image": image, "findings": findings})
    return out


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
    files = []
    if args.dockerfile or args.compose:
        files = audit_static(args.dockerfile or [], args.compose or [])
        inc, exc = _ids(args.include), _ids(args.exclude)
        for t in files:
            t["findings"] = [f for f in t["findings"] if _selected(f["id"], inc, exc)]
        if not args.live:
            return {"daemon": [], "containers": [], "files": files, "engine": None,
                    "local_checks": False, "live": False}
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
    return {"daemon": daemon, "containers": containers, "files": files, "live": True,
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
    parser.add_argument("--dockerfile", action="append", metavar="PATH",
                        help="static scan of a Dockerfile, or every Dockerfile under a directory (repeatable; "
                             "no docker daemon needed)")
    parser.add_argument("--compose", action="append", metavar="PATH",
                        help="static scan of a Compose file, or every compose*.y(a)ml under a directory "
                             "(repeatable; no docker daemon needed)")
    parser.add_argument("--live", action="store_true",
                        help="with --dockerfile/--compose: also audit the live daemon and containers")
    parser.add_argument("--daemon-json", metavar="PATH", help="daemon.json to read (default /etc/docker/daemon.json)")
    parser.add_argument("--host-root", default="/", metavar="DIR", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        res = run(args)
    except (DockerUnavailableError, StaticScanError) as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}, indent=2))
        else:
            print(f"docker-baseline-auditor: ERROR -- {exc}", file=sys.stderr)
        return 2

    every = res["daemon"] + [f for c in res["containers"] + res["files"] for f in c["findings"]]
    counts = {s: sum(1 for f in every if f["severity"] == s) for s in SEVERITIES}
    gate = None if args.fail_on == "never" else RANK[args.fail_on.upper()]
    failing = gate is not None and any(RANK[f["severity"]] <= gate for f in every)
    res["summary"] = dict(counts, containers=len(res["containers"]), files=len(res["files"]), fail_on=args.fail_on, failed=failing)

    if args.json:
        print(json.dumps(dict(res, version=__version__), indent=2))
        return 1 if failing else 0

    def order(f):
        return RANK[f["severity"]], f["id"]
    tally = f"{len(every)} findings ({', '.join('%d %s' % (counts[s], s) for s in SEVERITIES)})"
    static_part = f"{len(res['files'])} Dockerfiles/compose services checked"
    if res["live"]:
        print(f"docker-baseline-auditor {__version__}: engine {res['engine'] or '?'}, "
              f"{len(res['containers'])} {'' if args.all else 'running '}containers checked, "
              + (static_part + ", " if res["files"] else "") + f"{tally}\n")
    else:
        print(f"docker-baseline-auditor {__version__}: {static_part}, {tally}\n")
    if res["daemon"]:
        print("== daemon / host ==")
        for f in sorted(res["daemon"], key=order):
            print(f"  [{f['severity']}] {f['id']:<5} {f['message']}")
        print()
    if res["live"] and not res["local_checks"]:
        print("(remote DOCKER_HOST: host file checks 3.x skipped)\n")
    for r in res["containers"] + res["files"]:
        if not r["findings"]:
            continue
        print(f"== {r['name']} ({r['image']}) ==")
        for f in sorted(r["findings"], key=order):
            print(f"  [{f['severity']}] {f['id']:<5} {f['message']}")
        print()
    clean = [r["name"] for r in res["containers"] + res["files"] if not r["findings"]]
    if clean:
        print(f"Clean (no findings): {', '.join(clean)}")
    if failing:
        print(f"\nFAIL: findings at or above {args.fail_on.upper()} (exit 1)")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
