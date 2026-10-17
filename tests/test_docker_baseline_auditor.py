"""End-to-end tests for docker_baseline_auditor.py against a real Docker engine.

ci/run-tests.sh mounts the CI host's Docker socket into the test container
and ci/setup.sh installs the docker CLI, so the tool talks to a real daemon.
Every container this suite starts is resource-capped and removed in
tearDown; risky configurations (privileged, host namespaces, docker.sock
mount, sensitive host paths) are only ever *created*, never started, and
audited from their real `docker inspect` data.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "docker_baseline_auditor.py")
IMAGE = "alpine:3.20"
CAP = ["--memory", "64m", "--cpus", "0.2", "--pids-limit", "32"]
HARDENED = CAP + ["--user", "1000:1000", "--restart", "on-failure:5", "--network", "none", "--read-only",
                  "--security-opt", "no-new-privileges", "--health-cmd", "true"]

sys.path.insert(0, os.path.dirname(TOOL))
import docker_baseline_auditor as dba  # noqa: E402


def docker(*args, check=True):
    p = subprocess.run(["docker"] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} failed: {p.stderr}")
    return p.stdout.strip()


def run_tool(*args, env=None):
    return subprocess.run([sys.executable, TOOL] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, env=env, timeout=300)


def setUpModule():
    # named volumes of earlier runs that were killed mid-test (e.g. a mutation-testing timeout);
    # a volume still referenced by a container (a concurrent run's) is not dangling and stays
    for v in docker("volume", "ls", "-q", "--filter", "dangling=true", "--filter", "name=^dba-test-",
                    check=False).split():
        docker("volume", "rm", v, check=False)
    docker("pull", "-q", IMAGE)


class Base(unittest.TestCase):
    def setUp(self):
        self.prefix = f"dba-test-{uuid.uuid4().hex[:8]}"
        self.created, self.tags = [], []

    def tearDown(self):
        for c in self.created:
            docker("rm", "-f", "-v", c, check=False)
        for t in self.tags:
            docker("rmi", t, check=False)

    def container(self, suffix, *opts, image=IMAGE, start=True, cmd=("sleep", "300")):
        name = f"{self.prefix}-{suffix}"
        if start:
            docker("run", "-d", "--name", name, *opts, image, *cmd)
        else:
            docker("create", "--name", name, *opts, image, *cmd)
        self.created.append(name)
        return name

    def findings_of(self, name):
        data = json.loads(docker("inspect", name))[0]
        return {(f["id"], f["message"]) for f in dba.audit_container(data)["findings"]}

    def ids_of(self, name):
        return {i for i, _ in self.findings_of(name)}


class TestContainerChecks(Base):
    def test_hardened_container_is_clean(self):
        self.assertEqual(self.findings_of(self.container("clean", *HARDENED, start=False)), set())

    def test_privileged(self):
        f = self.findings_of(self.container("priv", *HARDENED, "--privileged", start=False))
        self.assertIn(("5.5", "privileged mode enabled (full host device/capability access)"), f)

    def test_host_namespaces(self):
        name = self.container("ns", *[o for o in HARDENED if o not in ("--network", "none")], "--network", "host",
                              "--pid", "host", "--ipc", "host", "--uts", "host", "--userns", "host", start=False)
        self.assertTrue({"5.10", "5.16", "5.17", "5.21", "5.31"} <= self.ids_of(name), self.findings_of(name))

    def test_docker_socket_and_sensitive_mounts(self):
        name = self.container("mounts", *HARDENED, "-v", "/var/run/docker.sock:/var/run/docker.sock",
                              "-v", "/etc:/host-etc:ro", "-v", "/:/host-root", start=False)
        f = self.findings_of(name)
        self.assertIn(("5.32", "Docker socket mounted in (/var/run/docker.sock) -- effective root-equivalent host access"), f)
        self.assertIn(("5.6", "sensitive host path /etc mounted read-only"), f)
        self.assertIn(("5.6", "sensitive host path / mounted read-write"), f)
        # an ordinary data directory and a named volume are fine
        d = tempfile.mkdtemp()
        # cleanups run after tearDown has removed the container, and also when an assertion fails
        self.addCleanup(docker, "volume", "rm", "-f", f"{self.prefix}-vol", check=False)
        ok = self.container("datadir", *HARDENED, "-v", f"{d}:/data", "-v", f"{self.prefix}-vol:/vol", start=False)
        self.assertEqual(self.findings_of(ok), set())

    def test_shared_mount_propagation(self):
        # --mount checks that the source exists on the engine's host, so use one that always does
        f = self.findings_of(self.container("prop", *HARDENED, "--mount", "type=bind,src=/tmp,dst=/d,bind-propagation=rshared",
                                            start=False))
        self.assertIn("5.20", {i for i, _ in f})

    def test_ports_privileged_and_all_interfaces(self):
        name = self.container("ports", *[o for o in HARDENED if o not in ("--network", "none")],
                              "-p", "80:8080", "-p", "127.0.0.1:18080:8081", start=False)
        f = self.findings_of(name)
        self.assertIn(("5.8", "privileged host port 80 mapped to 8080/tcp"), f)
        self.assertIn(("5.14", "port 8080/tcp published on every host interface (0.0.0.0:80)"), f)
        self.assertFalse(any("8081" in m for _, m in f), f)

    def test_devices(self):
        f = self.findings_of(self.container("dev", *HARDENED, "--device", "/dev/null:/dev/xnull", start=False))
        self.assertIn(("5.18", "host devices exposed: /dev/null"), f)

    def test_root_user_forms(self):
        base = [o for o in HARDENED if o not in ("--user", "1000:1000")]
        for i, user in enumerate(["", "0", "root", "0:0", "root:root"]):
            with self.subTest(user=user):
                opts = ["--user", user] if user else []
                self.assertIn(("4.1", "configured to run as root (no non-root USER set)"),
                              self.findings_of(self.container(f"root{i}", *base, *opts, start=False)))

    def test_missing_limits_and_hardening_flags(self):
        f = self.ids_of(self.container("bare", "--user", "1000", "--network", "none", start=False))
        self.assertTrue({"5.11", "5.13", "5.26", "5.27", "5.29"} <= f, f)
        self.assertNotIn("5.15", f)  # no restart policy at all is CIS-compliant
        no_restart = [o for o in HARDENED if o not in ("--restart", "on-failure:5")]
        for i, (policy, flagged) in enumerate([("on-failure:3", False), ("on-failure:5", False), ("on-failure", True),
                                               ("on-failure:6", True), ("always", True), ("unless-stopped", True)]):
            f = self.ids_of(self.container("restart%d" % i, *no_restart, "--restart", policy, start=False))
            self.assertEqual("5.15" in f, flagged, policy)

    def test_image_tag_rules(self):
        latest_msg = ("-", "using ':latest' or untagged image (non-reproducible, harder to pin/patch)")
        digest = json.loads(docker("image", "inspect", IMAGE))[0]["RepoDigests"][0]
        port_ref = f"localhost:5000/{self.prefix}"
        docker("tag", IMAGE, port_ref)
        self.tags.append(port_ref)
        latest_ref = f"{self.prefix}-img:latest"  # private tag: never retag a shared image on the CI host
        docker("tag", IMAGE, latest_ref)
        self.tags.append(latest_ref)
        for suffix, image, flagged in [("tagged", IMAGE, False), ("latest", latest_ref, True),
                                       ("digest", digest, False), ("regport", port_ref, True)]:
            with self.subTest(image=image):
                self.assertEqual(latest_msg in self.findings_of(self.container(suffix, *HARDENED, image=image,
                                                                               start=False)), flagged)

    def test_unconfined_security_profiles(self):
        f = self.findings_of(self.container("unconf", *HARDENED, "--security-opt", "seccomp=unconfined",
                                            "--security-opt", "apparmor=unconfined", start=False))
        self.assertIn(("5.22", "security profile disabled: seccomp=unconfined"), f)
        self.assertIn(("5.2", "security profile disabled: apparmor=unconfined"), f)

    def test_added_capabilities(self):
        f = self.findings_of(self.container("caps", *HARDENED, "--cap-add", "NET_ADMIN", "--cap-add", "SYS_TIME",
                                            start=False))
        self.assertIn(("5.4", "extra capabilities added: NET_ADMIN, SYS_TIME"), f)


class TestDaemonChecks(unittest.TestCase):
    """Daemon checks against the real engine's `docker info`/bridge data, plus fixed inputs."""

    def test_real_engine_info_matches_findings(self):
        info = json.loads(docker("info", "--format", "{{json .}}"))
        bridge = json.loads(docker("network", "inspect", "bridge"))[0]
        ids = {f["id"] for f in dba.audit_daemon(info, bridge, None, None)}
        self.assertEqual("2.15" in ids, not info.get("LiveRestoreEnabled"))
        icc = (bridge.get("Options") or {}).get("com.docker.network.bridge.enable_icc", "true") == "true"
        self.assertEqual("2.2" in ids, icc)
        userns = any(n in " ".join(info.get("SecurityOptions") or []) for n in ("name=userns", "name=rootless"))
        self.assertEqual("2.9" in ids, not userns)
        # no daemon.json and no dockerd flags visible: 2.14/2.16 can't be judged, so aren't reported
        self.assertNotIn("2.14", ids)
        self.assertNotIn("2.16", ids)

    def test_daemon_json_and_flags(self):
        info = {"LiveRestoreEnabled": True, "SecurityOptions": ["name=userns"], "LoggingDriver": "syslog",
                "Driver": "aufs", "ExperimentalBuild": True,
                "RegistryConfig": {"InsecureRegistryCIDRs": ["127.0.0.0/8", "10.0.0.0/8"],
                                   "IndexConfigs": {"docker.io": {"Secure": True}, "reg.lan:5000": {"Secure": False}}}}
        bridge = {"Options": {"com.docker.network.bridge.enable_icc": "false"}}
        ids = {f["id"]: f for f in dba.audit_daemon(info, bridge, {"log-level": "debug"},
                                                       ["-H", "fd://", "--host=tcp://0.0.0.0:2375"])}
        self.assertEqual(set(ids), {"2.3", "2.5", "2.6", "2.7", "2.14", "2.16", "2.18"})
        self.assertIn("10.0.0.0/8", ids["2.5"]["message"])
        self.assertIn("reg.lan:5000", ids["2.5"]["message"])
        good = {"no-new-privileges": True, "userland-proxy": False, "icc": False, "log-level": "info",
                "hosts": ["tcp://0.0.0.0:2376"], "tlsverify": True}
        info2 = dict(info, Driver="overlay2", ExperimentalBuild=False, RegistryConfig={})
        self.assertEqual(dba.audit_daemon(info2, bridge, good, []), [])

    def test_host_file_permissions(self):
        root = tempfile.mkdtemp()
        os.makedirs(os.path.join(root, "etc/docker"))
        os.makedirs(os.path.join(root, "lib/systemd/system"))
        os.makedirs(os.path.join(root, "var/run"))
        svc = os.path.join(root, "lib/systemd/system/docker.service")
        open(svc, "w").close()
        os.chmod(svc, 0o666)
        cfg = os.path.join(root, "etc/docker/daemon.json")
        open(cfg, "w").write("{}")
        os.chmod(cfg, 0o600)
        os.chmod(os.path.join(root, "etc/docker"), 0o777)
        sock_path = os.path.join(root, "var/run/docker.sock")
        s = socket.socket(socket.AF_UNIX)
        s.bind(sock_path)
        os.chmod(sock_path, 0o666)
        try:
            ids = {f["id"]: f["message"] for f in dba.audit_host_files(root)}
        finally:
            s.close()
        self.assertIn("3.2", ids)
        self.assertIn("mode 0666", ids["3.2"])
        self.assertIn("3.6", ids)
        self.assertIn("3.16", ids)
        self.assertNotIn("3.18", ids)  # 0600 is stricter than 0644
        expect_owner = os.getuid() == 0 and os.getgid() == 0
        self.assertEqual("3.1" in ids, not expect_owner)


class TestCli(Base):
    def test_json_and_text_reports_and_exit_codes(self):
        clean = self.container("run-clean", *HARDENED)
        risky = self.container("run-risky", *HARDENED, "--cap-add", "NET_ADMIN")
        stopped = self.container("never-started", *HARDENED, "--privileged", start=False)

        p = run_tool("--json", "--fail-on", "medium")
        self.assertEqual(p.returncode, 1, p.stderr)  # risky's 5.4 is MEDIUM
        out = json.loads(p.stdout)
        res = {r["name"]: r for r in out["containers"]}
        self.assertIn(clean, res)
        self.assertNotIn(stopped, res)
        self.assertEqual(res[clean]["findings"], [])
        self.assertEqual(res[clean]["image"], IMAGE)
        self.assertIn({"id": "5.4", "severity": "MEDIUM", "message": "extra capabilities added: NET_ADMIN"},
                      res[risky]["findings"])
        self.assertEqual(out["version"], dba.__version__)
        self.assertTrue(out["summary"]["failed"])
        self.assertTrue(all(f["id"] for f in out["daemon"]))

        # the privileged container only counts with --all; HIGH is the default gate
        p = run_tool("--json", "--exclude", "2")
        res = json.loads(p.stdout)
        high = [f for c in res["containers"] for f in c["findings"] if f["severity"] == "HIGH"]
        self.assertEqual(p.returncode, 1 if high else 0, p.stdout[-500:])
        p = run_tool("--json", "--all", "--include", "5.5")
        self.assertEqual(p.returncode, 1, p.stdout[-500:])
        res = {r["name"]: r for r in json.loads(p.stdout)["containers"]}
        self.assertEqual([f["id"] for f in res[stopped]["findings"]], ["5.5"])
        self.assertEqual(res[clean]["findings"], [])
        self.assertEqual(json.loads(p.stdout)["daemon"], [])
        self.assertEqual(run_tool("--all", "--fail-on", "never").returncode, 0)

        p = run_tool("--fail-on", "never")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertRegex(p.stdout, r"docker-baseline-auditor [\d.]+: engine \S+, \d+ running containers checked, \d+ findings")
        self.assertIn(f"== {risky} ({IMAGE}) ==", p.stdout)
        self.assertIn("[MEDIUM] 5.4   extra capabilities added: NET_ADMIN", p.stdout)
        self.assertIn(clean, p.stdout.split("Clean (no findings):", 1)[1])
        p = run_tool("--fail-on", "low")
        self.assertEqual(p.returncode, 1)
        self.assertIn("FAIL: findings at or above LOW (exit 1)", p.stdout)

    def test_docker_cli_missing_exits_2(self):
        p = run_tool(env=dict(os.environ, PATH=tempfile.mkdtemp()))
        self.assertEqual(p.returncode, 2)
        self.assertIn("`docker` CLI not found", p.stderr)

    def test_daemon_unreachable_exits_2(self):
        env = dict(os.environ, DOCKER_HOST="unix:///nonexistent/docker.sock")
        p = run_tool(env=env)
        self.assertEqual(p.returncode, 2)
        self.assertIn("`docker ps` failed", p.stderr)
        p = run_tool("--json", env=env)
        self.assertEqual(p.returncode, 2)
        self.assertIn("docker ps", json.loads(p.stdout)["error"])

    def test_help_version_and_bad_option(self):
        p = run_tool("--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("--fail-on", p.stdout)
        p = run_tool("--version")
        self.assertEqual(p.stdout.strip(), "docker-baseline-auditor " + dba.__version__)
        self.assertEqual(run_tool("--bogus").returncode, 2)
        self.assertEqual(run_tool("--fail-on", "nope").returncode, 2)


class TestContentTrustAndRemoteHost(unittest.TestCase):
    def test_content_trust_flag(self):
        env = {k: v for k, v in os.environ.items() if k != "DOCKER_CONTENT_TRUST"}
        ids = [f["id"] for f in json.loads(run_tool("--json", "--include", "4.5", env=env).stdout)["daemon"]]
        self.assertEqual(ids, ["4.5"])
        env["DOCKER_CONTENT_TRUST"] = "1"
        ids = [f["id"] for f in json.loads(run_tool("--json", "--include", "4.5", env=env).stdout)["daemon"]]
        self.assertEqual(ids, [])

    def test_remote_docker_host_skips_host_file_checks(self):
        # a real TCP endpoint in front of the real engine: the tool must treat it as remote
        import threading
        sock_path = (os.environ.get("DOCKER_HOST") or "unix:///var/run/docker.sock")[len("unix://"):]
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(16)
        port = srv.getsockname()[1]

        def pipe(a, b):
            try:
                while True:
                    data = a.recv(65536)
                    if not data:
                        break
                    b.sendall(data)
            except OSError:
                pass
            finally:
                for s_ in (a, b):
                    try:
                        s_.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                u = socket.socket(socket.AF_UNIX)
                u.connect(sock_path)
                threading.Thread(target=pipe, args=(c, u), daemon=True).start()
                threading.Thread(target=pipe, args=(u, c), daemon=True).start()

        threading.Thread(target=serve, daemon=True).start()
        try:
            env = dict(os.environ, DOCKER_HOST="tcp://127.0.0.1:%d" % port)
            p = run_tool("--include", "2,3", "--fail-on", "never", env=env)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("(remote DOCKER_HOST: host file checks 3.x skipped)", p.stdout)
            data = json.loads(run_tool("--json", "--include", "3", "--fail-on", "never", env=env).stdout)
            self.assertEqual([f["id"] for f in data["daemon"]], [])
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()
