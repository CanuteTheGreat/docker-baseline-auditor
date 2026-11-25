"""Contract tests for the daemon, host-file and container checks (no docker daemon needed).

Each test pins exact behaviour (finding ids, severities, messages, boundaries, defaults) that mutation
testing showed no other test checked: the live-engine suite only compares verdicts per CIS id.
In-process calls on hand-built `docker info` / `docker inspect` data and temporary directory trees.
"""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "docker_baseline_auditor.py")
sys.path.insert(0, os.path.dirname(TOOL))
import docker_baseline_auditor as dba  # noqa: E402


def F(cis, sev, msg):
    return {"id": cis, "severity": sev, "message": msg}


def ids(findings):
    return [f["id"] for f in findings]


class TestDockerdArgs(unittest.TestCase):
    def proc(self, root, pid, argv_bytes):
        d = os.path.join(root, "proc", pid)
        os.makedirs(d)
        with open(os.path.join(d, "cmdline"), "wb") as f:
            f.write(argv_bytes)

    def test_reads_dockerd_flags_from_the_proc_tree_under_root(self):
        with tempfile.TemporaryDirectory() as root:
            self.proc(root, "7", b"sleep\x0060\x00")
            self.proc(root, "self", b"dockerd\x00--ignored\x00")  # not a pid directory
            self.proc(root, "42", b"/usr/bin/dockerd\x00--host=tcp://0.0.0.0:2375\x00--log-level\x00debug\x00")
            self.assertEqual(dba.dockerd_args(root), ["--host=tcp://0.0.0.0:2375", "--log-level", "debug"])

    def test_no_dockerd_process_or_no_proc_is_none(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertIsNone(dba.dockerd_args(root))  # no proc directory at all
            self.proc(root, "7", b"sleep\x0060\x00")
            self.assertIsNone(dba.dockerd_args(root))

    def test_unreadable_pid_is_skipped_and_the_scan_continues(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "proc", "5"))  # a pid dir without cmdline
            self.proc(root, "9", b"dockerd\x00--debug\x00")
            self.assertEqual(dba.dockerd_args(root), ["--debug"])

    def test_undecodable_bytes_are_replaced_not_fatal(self):
        with tempfile.TemporaryDirectory() as root:
            self.proc(root, "3", b"dockerd\x00--label=\xff\x00")
            self.assertEqual(dba.dockerd_args(root), ["--label=\ufffd"])

    def test_default_root_is_the_real_proc(self):
        with mock.patch.object(dba.os, "listdir", side_effect=OSError) as ld:
            self.assertIsNone(dba.dockerd_args())
        ld.assert_called_once_with(os.path.join("/", "proc"))


class TestFlagValue(unittest.TestCase):
    def test_separate_value_is_returned(self):
        self.assertEqual(dba.flag_value(["--log-level", "debug"], "log-level"), "debug")

    def test_bare_boolean_flag_is_true(self):
        self.assertIs(dba.flag_value(["--debug"], "debug"), True)
        self.assertIs(dba.flag_value(["--debug", "--other"], "debug"), True)
        self.assertIs(dba.flag_value(["--debug", ""], "debug"), True)

    def test_equals_form_and_absent(self):
        self.assertEqual(dba.flag_value(["--log-level=warn"], "log-level"), "warn")
        self.assertEqual(dba.flag_value(["--x=a=b"], "x"), "a=b")
        self.assertIsNone(dba.flag_value(["--other=1"], "log-level"))
        self.assertIsNone(dba.flag_value(None, "x"))

    def test_next_arg_starting_with_dash_is_not_a_value(self):
        self.assertIs(dba.flag_value(["--a", "-b"], "a"), True)


class TestTruthy(unittest.TestCase):
    def test_accepted_spellings(self):
        for v in (True, "true", "TRUE", "True", "1", 1):
            self.assertTrue(dba.truthy(v), v)
        for v in (False, None, "false", "0", 0, "", "yes", "no"):
            self.assertFalse(dba.truthy(v), v)


class TestAuditDaemon(unittest.TestCase):
    CLEAN = {"SecurityOptions": ["name=rootless"], "LoggingDriver": "syslog", "LiveRestoreEnabled": True}

    def test_clean_daemon_has_no_findings(self):
        self.assertEqual(dba.audit_daemon(self.CLEAN, {"Options": {"com.docker.network.bridge.enable_icc": "false"}},
                                          {"no-new-privileges": True, "userland-proxy": False}, None), [])

    def test_icc_is_flagged_by_default_and_when_true_but_not_when_false(self):
        want = [F("2.2", "MEDIUM",
                  'inter-container traffic is allowed on the default bridge (set "icc": false)')]
        self.assertEqual(dba.audit_daemon(self.CLEAN, {}, None, None), want)
        self.assertEqual(dba.audit_daemon(self.CLEAN, {"Options": None}, None, None), want)
        self.assertEqual(dba.audit_daemon(self.CLEAN, {"Options": {"com.docker.network.bridge.enable_icc": "true"}},
                                          None, None), want)
        self.assertEqual(dba.audit_daemon(self.CLEAN, {"Options": {"com.docker.network.bridge.enable_icc": "false"}},
                                          None, None), [])
        self.assertEqual(dba.audit_daemon(self.CLEAN, None, None, None), [])  # no bridge info: nothing to say

    def test_log_level_from_flag_and_from_daemon_json(self):
        bridge = {"Options": {"com.docker.network.bridge.enable_icc": "false"}}
        want = [F("2.3", "LOW", "daemon log level is 'debug' (CIS recommends 'info')")]
        got = dba.audit_daemon(self.CLEAN, bridge, {"no-new-privileges": True, "userland-proxy": False},
                               ["--log-level=debug", "--no-new-privileges", "--userland-proxy=false"])
        self.assertEqual(got, want)
        got = dba.audit_daemon(self.CLEAN, bridge, {"log-level": "DEBUG", "no-new-privileges": True,
                                                    "userland-proxy": False}, None)
        self.assertEqual(got, [F("2.3", "LOW", "daemon log level is 'DEBUG' (CIS recommends 'info')")])
        got = dba.audit_daemon(self.CLEAN, bridge, {"log-level": "INFO", "no-new-privileges": True,
                                                    "userland-proxy": False}, None)
        self.assertEqual(got, [])

    def test_flag_beats_daemon_json(self):
        bridge = {"Options": {"com.docker.network.bridge.enable_icc": "false"}}
        got = dba.audit_daemon(self.CLEAN, bridge, {"log-level": "info", "no-new-privileges": True,
                                                    "userland-proxy": False}, ["--log-level", "warn"])
        self.assertEqual(ids(got), ["2.3"])

    def test_insecure_registries_skip_loopback_cidrs_and_hosts(self):
        info = dict(self.CLEAN, RegistryConfig={
            "InsecureRegistryCIDRs": ["127.0.0.0/8", "::1/128", "192.168.1.0/24", "10.0.0.0/8"],
            "IndexConfigs": {"localhost:5000": {"Secure": False}, "127.0.0.1:5000": {"Secure": False},
                             "reg.example": {"Secure": False}, "ok.example": {"Secure": True},
                             "unset.example": {}}})
        got = dba.audit_daemon(info, None, None, None)
        self.assertEqual(got, [F("2.5", "HIGH",
                                 "insecure registries configured: 10.0.0.0/8, 192.168.1.0/24, reg.example")])

    def test_loopback_only_registries_are_fine(self):
        info = dict(self.CLEAN, RegistryConfig={"InsecureRegistryCIDRs": ["127.0.0.0/8", "::1/128"]})
        self.assertEqual(dba.audit_daemon(info, None, None, None), [])

    def test_aufs_driver(self):
        self.assertEqual(dba.audit_daemon(dict(self.CLEAN, Driver="aufs"), None, None, None),
                         [F("2.6", "MEDIUM", "aufs storage driver in use")])
        self.assertEqual(dba.audit_daemon(dict(self.CLEAN, Driver="overlay2"), None, None, None), [])

    def test_tcp_listener_without_tlsverify(self):
        msg = "daemon listens on tcp://0.0.0.0:2375, tcp://[::]:2376 without --tlsverify"
        hosts = ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375", "tcp://[::]:2376"]
        ok = {"no-new-privileges": True, "userland-proxy": False}  # keep 2.14/2.16 out of the way
        self.assertEqual(dba.audit_daemon(self.CLEAN, None, dict(ok, hosts=hosts), None), [F("2.7", "HIGH", msg)])
        self.assertEqual(dba.audit_daemon(self.CLEAN, None, dict(ok, hosts=hosts, tlsverify=True), None), [])
        # --host flag, string form of the setting, and a nonsense value
        self.assertEqual(dba.audit_daemon(self.CLEAN, None, ok, ["--host=tcp://1.2.3.4:2375"]),
                         [F("2.7", "HIGH", "daemon listens on tcp://1.2.3.4:2375 without --tlsverify")])
        self.assertEqual(dba.audit_daemon(self.CLEAN, None, dict(ok, hosts="tcp://5.6.7.8:2375"), None),
                         [F("2.7", "HIGH", "daemon listens on tcp://5.6.7.8:2375 without --tlsverify")])
        self.assertEqual(dba.audit_daemon(self.CLEAN, None, dict(ok, hosts=5), None), [])
        self.assertEqual(dba.audit_daemon(self.CLEAN, None, dict(ok, hosts=["unix:///x"]), None), [])

    def test_user_namespace_remapping(self):
        want = [F("2.9", "LOW", "user namespace remapping is not enabled (and the daemon is not rootless)")]
        self.assertEqual(dba.audit_daemon(dict(self.CLEAN, SecurityOptions=["name=seccomp,profile=builtin"]),
                                          None, None, None), want)
        self.assertEqual(dba.audit_daemon(dict(self.CLEAN, SecurityOptions=None), None, None, None), want)
        self.assertEqual(dba.audit_daemon(dict(self.CLEAN, SecurityOptions=["name=userns"]), None, None, None), [])

    def test_logging_driver_without_remote_logging(self):
        for drv in ("json-file", "local", "none"):
            self.assertEqual(dba.audit_daemon(dict(self.CLEAN, LoggingDriver=drv), None, None, None),
                             [F("2.13", "INFO", "logging driver is '%s' (no centralized/remote logging)" % drv)])
        info = dict(self.CLEAN)
        del info["LoggingDriver"]
        self.assertEqual(dba.audit_daemon(info, None, None, None),
                         [F("2.13", "INFO", "logging driver is 'None' (no centralized/remote logging)")])
        self.assertEqual(dba.audit_daemon(dict(self.CLEAN, LoggingDriver="journald"), None, None, None), [])

    def test_daemon_settings_checked_only_when_the_config_is_known(self):
        self.assertEqual(dba.audit_daemon(self.CLEAN, None, None, None), [])
        want = [F("2.14", "LOW", 'containers may acquire new privileges by default (set "no-new-privileges": true)'),
                F("2.16", "LOW", 'userland proxy is enabled (set "userland-proxy": false)')]
        self.assertEqual(dba.audit_daemon(self.CLEAN, None, {}, None), want)
        self.assertEqual(dba.audit_daemon(self.CLEAN, None, None, []), want)

    def test_userland_proxy_spellings(self):
        base = {"no-new-privileges": True}
        for v in (True, "true", "1"):
            self.assertEqual(ids(dba.audit_daemon(self.CLEAN, None, dict(base, **{"userland-proxy": v}), None)),
                             ["2.16"], v)
        for v in (False, "false", "0"):
            self.assertEqual(dba.audit_daemon(self.CLEAN, None, dict(base, **{"userland-proxy": v}), None), [], v)
        self.assertEqual(ids(dba.audit_daemon(self.CLEAN, None, base, None)), ["2.16"])  # unset = enabled

    def test_no_new_privileges_spellings(self):
        base = {"userland-proxy": False}
        for v in (True, "true", "1"):
            self.assertEqual(dba.audit_daemon(self.CLEAN, None, dict(base, **{"no-new-privileges": v}), None), [], v)
        self.assertEqual(ids(dba.audit_daemon(self.CLEAN, None, dict(base, **{"no-new-privileges": "false"}), None)),
                         ["2.14"])

    def test_live_restore_and_experimental(self):
        info = dict(self.CLEAN, LiveRestoreEnabled=False, ExperimentalBuild=True)
        self.assertEqual(dba.audit_daemon(info, None, None, None), [
            F("2.15", "LOW", "live restore is disabled (containers stop when dockerd restarts)"),
            F("2.18", "MEDIUM", "experimental daemon features are enabled")])
        info = dict(self.CLEAN, ExperimentalBuild=False)
        self.assertEqual(dba.audit_daemon(info, None, None, None), [])
        info = dict(self.CLEAN)
        del info["LiveRestoreEnabled"]
        self.assertEqual(ids(dba.audit_daemon(info, None, None, None)), ["2.15"])


class TestCheckFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "f")
        open(self.path, "w").close()

    def me(self):
        mode, owner, group = dba._mode_owner(self.path)
        return "%s:%s" % (owner, group)

    def test_owner_message_lists_every_accepted_owner(self):
        os.chmod(self.path, 0o600)
        got = dba._check_file(self.path, "3.15", "3.16", ("a:b", "c:d"), 0o660, "Docker socket")
        self.assertEqual(got, [F("3.15", "MEDIUM", "Docker socket %s is owned by %s (want a:b or c:d)"
                                 % (self.path, self.me()))])
        self.assertEqual(dba._check_file(self.path, "3.15", "3.16", ("x:y", self.me()), 0o660, "Docker socket"), [])

    def test_permission_severity_depends_on_world_write(self):
        owners = (self.me(),)
        os.chmod(self.path, 0o664)  # group-writable, not world-writable
        self.assertEqual(dba._check_file(self.path, "1", "2", owners, 0o644, "unit file"),
                         [F("2", "LOW", "unit file %s has mode 0664 (want 0644 or stricter)" % self.path)])
        os.chmod(self.path, 0o666)
        self.assertEqual(dba._check_file(self.path, "1", "2", owners, 0o644, "unit file"),
                         [F("2", "MEDIUM", "unit file %s has mode 0666 (want 0644 or stricter)" % self.path)])
        os.chmod(self.path, 0o640)  # stricter than the maximum is fine
        self.assertEqual(dba._check_file(self.path, "1", "2", owners, 0o644, "unit file"), [])

    def test_missing_path_has_no_findings(self):
        self.assertEqual(dba._check_file(self.path + ".nope", "1", "2", ("a:b",), 0o644, "x"), [])


class TestAuditHostFiles(unittest.TestCase):
    """Fixed owner/mode per file (the ownership lookup is stubbed), real directory tree."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def make(self, rel, directory=False):
        p = os.path.join(self.root, rel)
        if directory:
            os.makedirs(p, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").close()
        return p

    def audit(self, table, **kw):
        def fake(path):
            return table[os.path.relpath(path, self.root)]
        with mock.patch.object(dba, "_mode_owner", side_effect=fake):
            return dba.audit_host_files(self.root, **kw)

    def tree(self):
        self.make("usr/lib/systemd/system/docker.service")
        self.make("usr/lib/systemd/system/docker.socket")
        self.make("etc/docker", directory=True)
        self.make("etc/docker/daemon.json")
        self.make("var/run/docker.sock")

    def test_everything_compliant(self):
        self.tree()
        table = {"usr/lib/systemd/system/docker.service": (0o644, "root", "root"),
                 "usr/lib/systemd/system/docker.socket": (0o644, "root", "root"),
                 "etc/docker": (0o755, "root", "root"),
                 "etc/docker/daemon.json": (0o644, "root", "root"),
                 "var/run/docker.sock": (0o660, "root", "docker")}
        self.assertEqual(self.audit(table), [])
        table["var/run/docker.sock"] = (0o660, "root", "root")  # either accepted owner works
        self.assertEqual(self.audit(table), [])

    def test_every_file_checked_with_its_ids_and_labels(self):
        self.tree()
        bad = (0o777, "bob", "users")
        table = {k: bad for k in ("usr/lib/systemd/system/docker.service", "usr/lib/systemd/system/docker.socket",
                                  "etc/docker", "etc/docker/daemon.json", "var/run/docker.sock")}
        got = self.audit(table)
        r = self.root

        def pair(owner_id, perm_id, label, rel, want, maxmode):
            p = os.path.join(r, rel)
            return [F(owner_id, "MEDIUM", "%s %s is owned by bob:users (want %s)" % (label, p, want)),
                    F(perm_id, "MEDIUM", "%s %s has mode 0777 (want %s or stricter)" % (label, p, maxmode))]
        want = (pair("3.1", "3.2", "unit file", "usr/lib/systemd/system/docker.service", "root:root", "0644")
                + pair("3.3", "3.4", "unit file", "usr/lib/systemd/system/docker.socket", "root:root", "0644")
                + pair("3.5", "3.6", "directory", "etc/docker", "root:root", "0755")
                + pair("3.17", "3.18", "daemon config", "etc/docker/daemon.json", "root:root", "0644")
                + pair("3.15", "3.16", "Docker socket", "var/run/docker.sock", "root:docker or root:root", "0660"))
        self.assertEqual(got, want)

    def test_directory_limit_is_0755(self):
        self.tree()
        table = {"usr/lib/systemd/system/docker.service": (0o644, "root", "root"),
                 "usr/lib/systemd/system/docker.socket": (0o644, "root", "root"),
                 "etc/docker": (0o756, "root", "root"),
                 "etc/docker/daemon.json": (0o644, "root", "root"),
                 "var/run/docker.sock": (0o660, "root", "docker")}
        self.assertEqual(self.audit(table), [F("3.6", "MEDIUM",
                                               "directory %s has mode 0756 (want 0755 or stricter)"
                                               % os.path.join(self.root, "etc/docker"))])

    def test_first_unit_dir_that_has_the_unit_wins(self):
        self.make("etc/systemd/system/docker.service")
        self.make("lib/systemd/system/docker.service")
        table = {"etc/systemd/system/docker.service": (0o600, "root", "root")}
        self.assertEqual(self.audit(table), [])  # the lib/ copy is never looked at (not in the table)

    def test_explicit_socket_path_replaces_the_default(self):
        sock = self.make("custom/d.sock")
        table = {"custom/d.sock": (0o660, "root", "docker")}
        self.assertEqual(self.audit(table, socket_path=sock), [])
        table = {"custom/d.sock": (0o600, "bob", "bob")}
        self.assertEqual(ids(self.audit(table, socket_path=sock)), ["3.15"])


class TestLocalSocketPath(unittest.TestCase):
    def test_variants(self):
        with mock.patch.dict(os.environ, clear=False):
            os.environ.pop("DOCKER_HOST", None)
            self.assertEqual(dba.local_socket_path(), "/var/run/docker.sock")
            os.environ["DOCKER_HOST"] = "unix:///run/user/1000/docker.sock"
            self.assertEqual(dba.local_socket_path(), "/run/user/1000/docker.sock")
            os.environ["DOCKER_HOST"] = "tcp://10.0.0.5:2376"
            self.assertIsNone(dba.local_socket_path())


class TestAuditContainer(unittest.TestCase):
    def base(self, **hc):
        """A compliant container, with `hc` HostConfig overrides."""
        host = {"Memory": 64, "ReadonlyRootfs": True, "PidsLimit": 32, "SecurityOpt": ["no-new-privileges"],
                "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 5}}
        host.update(hc)
        return {"Name": "/app", "Config": {"Image": "app:1.0", "User": "1000:1000",
                                           "Healthcheck": {"Test": ["CMD", "true"]}}, "HostConfig": host}

    def audit(self, data):
        return dba.audit_container(data)["findings"]

    def test_compliant_container_is_clean(self):
        self.assertEqual(dba.audit_container(self.base()), {"name": "app", "image": "app:1.0", "findings": []})

    def test_defaults_for_missing_fields(self):
        got = dba.audit_container({})
        self.assertEqual((got["name"], got["image"]), ("", "unknown"))
        self.assertEqual(ids(got["findings"]), ["4.1", "5.11", "5.13", "5.26", "5.27", "5.29", "-"])

    def test_user_part_is_what_counts(self):
        for user, root in (("", True), ("0", True), ("root", True), ("0:0", True), ("root:wheel", True),
                           ("0:0:0", True), ("1000", False), ("app:0", False), ("app", False)):
            d = self.base()
            d["Config"]["User"] = user
            self.assertEqual("4.1" in ids(self.audit(d)), root, user)

    def test_security_profiles(self):
        got = self.audit(self.base(SecurityOpt=["no-new-privileges", "seccomp=unconfined", "apparmor=unconfined",
                                               "label=disable"]))
        self.assertEqual(got, [F("5.22", "MEDIUM", "security profile disabled: seccomp=unconfined"),
                               F("5.2", "MEDIUM", "security profile disabled: apparmor=unconfined")])

    def test_capabilities_have_the_cap_prefix_stripped_only_when_present(self):
        got = self.audit(self.base(CapAdd=["NET_ADMIN", "CAP_SYS_PTRACE", "cap_chown"]))
        self.assertEqual(got, [F("5.4", "MEDIUM", "extra capabilities added: NET_ADMIN, SYS_PTRACE, chown")])

    def test_privileged(self):
        self.assertEqual(self.audit(self.base(Privileged=True)),
                         [F("5.5", "HIGH", "privileged mode enabled (full host device/capability access)")])

    def test_mounts(self):
        d = self.base()
        d["Mounts"] = [
            {"Type": "volume", "Source": "/var/run/docker.sock"},     # not a bind mount: ignored
            {"Type": "volume", "Source": "/etc", "Propagation": "shared"},
            {"Source": "/var/run/docker.sock/"},                        # Type defaults to bind
            {"Type": "bind", "Source": "/etc/", "RW": False},
            {"Type": "bind", "Source": "/proc"},
            {"Type": "bind", "Source": "/", "RW": True, "Propagation": "rshared"},
            {"Type": "bind", "Source": "/data", "Propagation": "shared"},
            {"Type": "bind", "Source": "/data2", "Propagation": "private"},
            {"Type": "bind", "Source": "/data3", "Propagation": ""},
        ]
        self.assertEqual(self.audit(d), [
            F("5.32", "HIGH", "Docker socket mounted in (/var/run/docker.sock) -- effective root-equivalent host access"),
            F("5.6", "MEDIUM", "sensitive host path /etc mounted read-only"),
            F("5.6", "HIGH", "sensitive host path /proc mounted read-write"),
            F("5.6", "HIGH", "sensitive host path / mounted read-write"),
            F("5.20", "MEDIUM", "mount / uses rshared propagation"),
            F("5.20", "MEDIUM", "mount /data uses shared propagation")])

    def test_published_ports(self):
        d = self.base(PortBindings={
            "80/tcp": [{"HostIp": "", "HostPort": "80"}],
            "81/tcp": [{"HostIp": "0.0.0.0", "HostPort": "1023"}],
            "82/tcp": [{"HostIp": "::", "HostPort": "1024"}],
            "83/tcp": [{"HostIp": "127.0.0.1", "HostPort": "0"}],
            "84/tcp": [{"HostIp": "127.0.0.1", "HostPort": "1"}],
            "85/tcp": [{"HostIp": "", "HostPort": ""}],
            "86/tcp": None})
        self.assertEqual(self.audit(d), [
            F("5.8", "LOW", "privileged host port 80 mapped to 80/tcp"),
            F("5.14", "LOW", "port 80/tcp published on every host interface (0.0.0.0:80)"),
            F("5.8", "LOW", "privileged host port 1023 mapped to 81/tcp"),
            F("5.14", "LOW", "port 81/tcp published on every host interface (0.0.0.0:1023)"),
            F("5.14", "LOW", "port 82/tcp published on every host interface (:::1024)"),
            F("5.8", "LOW", "privileged host port 1 mapped to 84/tcp"),
            F("5.14", "LOW", "port 85/tcp published on every host interface (0.0.0.0:random)")])

    def test_namespaces_devices_and_limits(self):
        d = self.base(NetworkMode="host", PidMode="host", IpcMode="host", UTSMode="host", UsernsMode="host",
                      Devices=[{"PathOnHost": "/dev/sda"}, {"PathOnHost": "/dev/kvm"}, {}],
                      Memory=0, ReadonlyRootfs=False, PidsLimit=0, SecurityOpt=[])
        d["Config"]["Healthcheck"] = {"Test": ["NONE"]}
        self.assertEqual(self.audit(d), [
            F("5.10", "HIGH", "host network mode (bypasses container network isolation)"),
            F("5.11", "LOW", "no memory limit set"),
            F("5.13", "LOW", "root filesystem is writable (no --read-only)"),
            F("5.16", "HIGH", "host PID namespace shared (can see/signal host processes)"),
            F("5.17", "MEDIUM", "host IPC namespace shared"),
            F("5.18", "MEDIUM", "host devices exposed: /dev/sda, /dev/kvm, ?"),
            F("5.21", "MEDIUM", "host UTS namespace shared"),
            F("5.26", "LOW", "no-new-privileges not set"),
            F("5.27", "LOW", "no health check configured"),
            F("5.29", "LOW", "no pids limit set"),
            F("5.31", "MEDIUM", "host user namespace shared")])

    def test_pids_limit_boundaries(self):
        self.assertEqual(ids(self.audit(self.base(PidsLimit=-1))), ["5.29"])
        self.assertEqual(ids(self.audit(self.base(PidsLimit=None))), ["5.29"])
        self.assertEqual(self.audit(self.base(PidsLimit=1)), [])

    def test_restart_policies(self):
        def run(name, retries=None):
            rp = {"Name": name}
            if retries is not None:
                rp["MaximumRetryCount"] = retries
            return self.audit(self.base(RestartPolicy=rp))
        self.assertEqual(run("always"), [F("5.15", "LOW", "restart policy 'always' restarts without limit "
                                                           "(CIS: on-failure with at most 5 retries)")])
        self.assertEqual(run("unless-stopped"),
                         [F("5.15", "LOW", "restart policy 'unless-stopped' restarts without limit "
                                           "(CIS: on-failure with at most 5 retries)")])
        self.assertEqual(run("on-failure"), [F("5.15", "LOW", "restart policy on-failure with unlimited retries "
                                                              "(CIS: at most 5)")])
        self.assertEqual(run("on-failure", 6), [F("5.15", "LOW", "restart policy on-failure with 6 retries "
                                                                 "(CIS: at most 5)")])
        self.assertEqual(run("on-failure", 1), [])
        self.assertEqual(run("on-failure", 5), [])
        self.assertEqual(run("no"), [])
        self.assertEqual(run(""), [])

    def test_no_new_privileges_spellings(self):
        for opt, ok in (("no-new-privileges", True), ("no-new-privileges:true", True), ("no-new-privileges=true", True),
                        ("no-new-privileges=false", False), ("no-new-privileges:false", False),
                        ("no-new-privileges=0", False), ("other=1", False)):
            got = ids(self.audit(self.base(SecurityOpt=[opt])))
            self.assertEqual("5.26" not in got, ok, opt)

    def test_health_check_variants(self):
        for test, flagged in ((["NONE"], True), (None, True), ([], True), (["CMD", "true"], False),
                              (["CMD-SHELL", "true"], False)):
            d = self.base()
            d["Config"]["Healthcheck"] = {"Test": test}
            self.assertEqual("5.27" in ids(self.audit(d)), flagged, test)

    def test_image_tag_rules(self):
        for image, flagged in (("app", True), ("app:latest", True), ("reg:5000/app", True),
                               ("reg:5000/team/app", True), ("reg/team:1/app", True), ("app:1.0", False),
                               ("reg:5000/app:1.0", False), ("app@sha256:" + "a" * 64, False),
                               ("reg:5000/app@sha256:" + "a" * 64, False)):
            d = self.base()
            d["Config"]["Image"] = image
            got = self.audit(d)
            self.assertEqual(got, [F("-", "LOW", "using ':latest' or untagged image "
                                                 "(non-reproducible, harder to pin/patch)")] if flagged else [], image)
            self.assertEqual(dba.untagged(image), flagged, image)


class TestHelpHidesHostRoot(unittest.TestCase):
    def test_host_root_is_a_hidden_option(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as cm:
                dba.main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("--daemon-json", out.getvalue())
        self.assertNotIn("--host-root", out.getvalue())


if __name__ == "__main__":
    unittest.main()
