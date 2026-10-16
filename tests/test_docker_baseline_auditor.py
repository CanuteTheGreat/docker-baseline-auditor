"""End-to-end tests for docker-baseline-auditor.py against a real Docker engine.

ci/run-tests.sh mounts the CI host's Docker socket into the test container
and ci/setup.sh installs the docker CLI, so the tool talks to a real daemon.
Every container this suite starts is resource-capped and removed in
tearDown; risky configurations (privileged, host namespaces, docker.sock
mount, no memory limit) are only ever *created*, never started, and audited
from their real `docker inspect` data.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "docker-baseline-auditor.py")
IMAGE = "alpine:3.20"
CAP = ["--memory", "64m", "--cpus", "0.2", "--pids-limit", "32"]

sys.path.insert(0, os.path.dirname(TOOL))
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("dba", TOOL)
dba = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(dba)  # type: ignore[union-attr]


def docker(*args, check=True):
    p = subprocess.run(["docker"] + list(args), capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} failed: {p.stderr}")
    return p.stdout.strip()


def run_tool(*args, env=None):
    return subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True,
                          env=env, timeout=300)


def setUpModule():
    docker("pull", "-q", IMAGE)


class Base(unittest.TestCase):
    def setUp(self):
        self.prefix = f"dba-test-{uuid.uuid4().hex[:8]}"
        self.created = []
        self.tags = []

    def tearDown(self):
        for c in self.created:
            docker("rm", "-f", "-v", c, check=False)
        for t in self.tags:
            docker("rmi", t, check=False)

    def container(self, suffix, *opts, image=IMAGE, start=True, cmd=("sleep", "300")):
        name = f"{self.prefix}-{suffix}"
        docker("run", "-d", "--name", name, *opts, image, *cmd) if start else \
            docker("create", "--name", name, *opts, image, *cmd)
        self.created.append(name)
        return name

    def findings_of(self, name):
        data = json.loads(docker("inspect", name))[0]
        return [msg for _, msg in dba.audit_container(data)["findings"]]


class TestChecksOnInspectData(Base):
    def test_hardened_container_is_clean(self):
        name = self.container("clean", *CAP, "--user", "1000:1000", "--restart", "unless-stopped",
                              "--network", "none", start=False)
        self.assertEqual(self.findings_of(name), [])

    def test_privileged(self):
        f = self.findings_of(self.container("priv", *CAP, "--privileged", start=False))
        self.assertTrue(any("privileged mode" in m for m in f), f)

    def test_host_network_pid_ipc(self):
        f = self.findings_of(self.container("ns", *CAP, "--network", "host", "--pid", "host", "--ipc", "host",
                                            start=False))
        joined = " | ".join(f)
        self.assertIn("host network mode", joined)
        self.assertIn("host PID namespace", joined)
        self.assertIn("host IPC namespace", joined)

    def test_docker_socket_mount(self):
        f = self.findings_of(self.container("sock", *CAP, "-v", "/var/run/docker.sock:/var/run/docker.sock",
                                            start=False))
        self.assertTrue(any("Docker socket mounted" in m for m in f), f)

    def test_root_user_forms(self):
        for i, user in enumerate(["", "0", "root", "0:0", "root:root"]):
            with self.subTest(user=user):
                opts = ["--user", user] if user else []
                f = self.findings_of(self.container(f"root{i}", *CAP, *opts, start=False))
                self.assertIn("container runs as root (no non-root USER set)", f)

    def test_no_memory_limit(self):
        f = self.findings_of(self.container("nomem", "--cpus", "0.2", start=False))
        self.assertIn("no memory limit set", f)

    def test_no_restart_policy(self):
        f = self.findings_of(self.container("norestart", *CAP, start=False))
        self.assertIn("no restart policy set", f)
        f = self.findings_of(self.container("restart", *CAP, "--restart", "on-failure:3", start=False))
        self.assertNotIn("no restart policy set", f)

    def test_image_tag_rules(self):
        latest_msg = "using ':latest' or untagged image (non-reproducible, harder to pin/patch)"
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
                name = self.container(suffix, *CAP, image=image, start=False)
                self.assertEqual(latest_msg in self.findings_of(name), flagged)

    def test_unconfined_security_profiles(self):
        f = self.findings_of(self.container("unconf", *CAP, "--security-opt", "seccomp=unconfined",
                                            "--security-opt", "apparmor=unconfined", start=False))
        self.assertIn("security profile disabled: seccomp=unconfined", f)
        self.assertIn("security profile disabled: apparmor=unconfined", f)

    def test_added_capabilities(self):
        f = self.findings_of(self.container("caps", *CAP, "--cap-add", "NET_ADMIN", "--cap-add", "SYS_TIME",
                                            start=False))
        self.assertIn("extra capabilities added: NET_ADMIN, SYS_TIME", f)


class TestCli(Base):
    def test_json_and_text_reports_cover_running_containers_only(self):
        clean = self.container("run-clean", *CAP, "--user", "1000:1000", "--restart", "unless-stopped",
                               "--network", "none")
        risky = self.container("run-risky", *CAP, "--user", "0:0", "--cap-add", "NET_ADMIN", "--network", "none")
        stopped = self.container("never-started", *CAP, start=False)

        p = run_tool("--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        res = {r["name"]: r for r in json.loads(p.stdout)}
        self.assertIn(clean, res)
        self.assertNotIn(stopped, res)
        self.assertEqual(res[clean]["findings"], [])
        self.assertEqual(res[clean]["image"], IMAGE)
        risky_msgs = [m for _, m in res[risky]["findings"]]
        self.assertIn("extra capabilities added: NET_ADMIN", risky_msgs)
        self.assertIn("container runs as root (no non-root USER set)", risky_msgs)
        self.assertIn("no restart policy set", risky_msgs)

        p = run_tool()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertRegex(p.stdout, r"docker-baseline-auditor: \d+ running containers checked, \d+ findings")
        self.assertIn(f"== {risky} ({IMAGE}) ==", p.stdout)
        self.assertIn("[MEDIUM] extra capabilities added: NET_ADMIN", p.stdout)
        self.assertIn(clean, p.stdout.split("Clean (no findings):", 1)[1])

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

    def test_help_and_bad_option(self):
        p = run_tool("--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("--json", p.stdout)
        self.assertEqual(run_tool("--bogus").returncode, 2)


if __name__ == "__main__":
    unittest.main()
