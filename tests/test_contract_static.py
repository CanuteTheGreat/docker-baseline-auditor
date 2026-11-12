"""Contract tests for the static-scan code (YAML subset parser, Compose/Dockerfile rules, CLI text).

Each test pins exact behaviour (values, messages, boundaries) that mutation testing showed
no other test checked. In-process calls only; no docker daemon is needed.
"""
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "docker_baseline_auditor.py")
sys.path.insert(0, os.path.dirname(TOOL))
import docker_baseline_auditor as dba  # noqa: E402


def yaml_error(text):
    try:
        dba.parse_yaml(text)
    except dba.StaticScanError as exc:
        return str(exc)
    raise AssertionError("no StaticScanError for %r" % (text,))


class P:  # a finished subprocess for a stubbed dba.sh
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class TestYamlLines(unittest.TestCase):
    def test_entries_are_indent_body_lineno_raw(self):
        self.assertEqual(dba._yaml_lines("a: 1\n\n  # note\n  b: 2  # tail\n"),
                         [[0, "a: 1", 1, "a: 1"], [2, "b: 2", 4, "  b: 2  # tail"]])

    def test_comment_needs_space_before_hash(self):
        self.assertEqual(dba._yaml_lines("a: b #c")[0][1], "a: b")
        self.assertEqual(dba._yaml_lines("a: b# c")[0][1], "a: b# c")
        self.assertEqual(dba._yaml_lines("a: b#c")[0][1], "a: b#c")

    def test_hash_inside_quotes_kept_even_at_column_zero(self):
        self.assertEqual(dba._yaml_lines('"a#b": 1')[0][1], '"a#b": 1')
        self.assertEqual(dba._yaml_lines("'a #b': 1")[0][1], "'a #b': 1")
        self.assertEqual(dba._yaml_lines('a: "x #y" # z')[0][1], 'a: "x #y"')

    def test_document_markers_dropped(self):
        self.assertEqual([l[1] for l in dba._yaml_lines("---\na: 1\n...\n")], ["a: 1"])

    def test_tab_indent_error_names_the_line(self):
        self.assertEqual(yaml_error("a: 1\n\tb: 2"), "line 2: tab indentation is not valid YAML")


class TestSplitKey(unittest.TestCase):
    def test_quoted_keys(self):
        self.assertEqual(dba._split_key('"a b": 1'), ("a b", "1"))
        self.assertEqual(dba._split_key("'a b': 1"), ("a b", "1"))
        self.assertEqual(dba._split_key('"": x'), ("", "x"))
        self.assertEqual(dba._split_key('"a":'), ("a", ""))
        self.assertEqual(dba._split_key('"a": "b"'), ("a", '"b"'))
        self.assertIsNone(dba._split_key('"a":x'))
        self.assertIsNone(dba._split_key('"a" x'))

    def test_indicator_starts_are_not_keys(self):
        for text in ("[a]: x", "{a}: x", "*a: x", "&a: x", "|a: x", ">a: x"):
            self.assertIsNone(dba._split_key(text), text)

    def test_colon_inside_brackets_does_not_split(self):
        self.assertEqual(dba._split_key("a[[1]]: x"), ("a[[1]]", "x"))
        self.assertEqual(dba._split_key("a{b: c}: x"), ("a{b: c}", "x"))
        self.assertEqual(dba._split_key("a[1]: x"), ("a[1]", "x"))
        self.assertEqual(dba._split_key("a: [b: c]"), ("a", "[b: c]"))
        self.assertIsNone(dba._split_key("a[1: x"))
        self.assertIsNone(dba._split_key("a]: x"))

    def test_letter_x_in_a_key_is_just_a_letter(self):
        self.assertEqual(dba._split_key("aXb: v"), ("aXb", "v"))
        self.assertEqual(dba._split_key("X: v"), ("X", "v"))

    def test_plain(self):
        self.assertEqual(dba._split_key("key:"), ("key", ""))
        self.assertEqual(dba._split_key("key:  v  "), ("key", "v"))
        self.assertIsNone(dba._split_key("http://x"))


class TestYamlParse(unittest.TestCase):
    def test_trailing_unindented_content_error(self):
        self.assertEqual(yaml_error("a: 1\n b: 2"), "line 2: unsupported or inconsistent YAML structure")

    def test_non_key_line_error_names_line_number(self):
        self.assertEqual(yaml_error("a: 1\nfoo"), "line 2: expected 'key: value'")
        self.assertEqual(yaml_error("# c\n\na: 1\nfoo"), "line 4: expected 'key: value'")

    def test_dash_and_block_indicator_lookalikes_are_scalars(self):
        self.assertEqual(dba.parse_yaml("a: -\nb: 1"), {"a": "-", "b": 1})
        self.assertEqual(dba.parse_yaml("a: |X\nb: 1"), {"a": "|X", "b": 1})
        self.assertEqual(dba.parse_yaml("a: |XX\nb: 1"), {"a": "|XX", "b": 1})
        self.assertEqual(dba.parse_yaml("a: >x\nb: 1"), {"a": ">x", "b": 1})

    def test_block_scalars(self):
        self.assertEqual(dba.parse_yaml("a: |\n  x\n  y\nb: >-\n  p\n  q\nc: 1"),
                         {"a": "x\ny", "b": "p q", "c": 1})

    def test_anchor_alias_and_merge(self):
        self.assertEqual(dba.parse_yaml("a: &x 5\nb: *x"), {"a": 5, "b": 5})
        self.assertEqual(dba.parse_yaml("base: &b\n  k: 1\nsvc:\n  <<: *b\n  j: 2"),
                         {"base": {"k": 1}, "svc": {"k": 1, "j": 2}})
        self.assertEqual(yaml_error("a: *nope"), "unknown YAML alias *nope")

    def test_sequences(self):
        self.assertEqual(dba.parse_yaml("a:\n  - 1\n  - x: 2\n    y: 3"),
                         {"a": [1, {"x": 2, "y": 3}]})
        self.assertEqual(dba.parse_yaml("a:\n- 1\n- 2"), {"a": [1, 2]})
        self.assertEqual(dba.parse_yaml("- a\n-   b"), ["a", "b"])

    def test_empty_document(self):
        self.assertEqual(dba.parse_yaml("# nothing\n"), {})


class TestYamlScalar(unittest.TestCase):
    def sc(self, s):
        return dba._Yaml("").scalar(s)

    def test_quoted_strings(self):
        self.assertEqual(self.sc('"a\\"b"'), 'a"b')
        self.assertEqual(self.sc('"a\\\\b"'), "a\\b")
        self.assertEqual(self.sc("\"a''b\""), "a''b")
        self.assertEqual(self.sc("'a''b'"), "a'b")
        self.assertEqual(self.sc("'a\\\\b'"), "a\\\\b")
        self.assertEqual(self.sc("'a\\\"b'"), 'a\\"b')
        with self.assertRaises(dba.StaticScanError) as cm:
            self.sc('"abc')
        self.assertEqual(str(cm.exception), 'unterminated quoted string: "abc')
        with self.assertRaises(dba.StaticScanError):
            self.sc('"')

    def test_null_and_bool_spellings(self):
        for s in ("~", "null", "Null", "NULL"):
            self.assertIsNone(self.sc(s), s)
        for s in ("true", "True", "TRUE"):
            self.assertIs(self.sc(s), True, s)
        for s in ("false", "False", "FALSE"):
            self.assertIs(self.sc(s), False, s)
        for s in ("nULL", "tRUE", "fALSE", "yes", "no"):
            self.assertEqual(self.sc(s), s)

    def test_ints_and_plain(self):
        self.assertEqual(self.sc("-12"), -12)
        self.assertEqual(self.sc("007"), 7)
        self.assertEqual(self.sc("1.5"), "1.5")
        self.assertEqual(self.sc("  pad  "), "pad")


class TestYamlFlow(unittest.TestCase):
    def test_lists(self):
        self.assertEqual(dba.parse_yaml('a: ["x,y", \'p,q\', 3]'), {"a": ["x,y", "p,q", 3]})
        self.assertEqual(dba.parse_yaml("a: [[1, 2], 3]"), {"a": [[1, 2], 3]})
        self.assertEqual(dba.parse_yaml("a: [[1], 2]"), {"a": [[1], 2]})
        self.assertEqual(dba.parse_yaml("a: [{b: 1, c: 2}, 3]"), {"a": [{"b": 1, "c": 2}, 3]})
        self.assertEqual(dba.parse_yaml("a: []"), {"a": []})
        self.assertEqual(dba.parse_yaml("a: [x, ]"), {"a": ["x"]})

    def test_letter_x_is_not_a_bracket(self):
        self.assertEqual(dba.parse_yaml("a: [X, Y]"), {"a": ["X", "Y"]})
        self.assertEqual(dba.parse_yaml("a: {X: 1, Y: X}"), {"a": {"X": 1, "Y": "X"}})

    def test_maps(self):
        self.assertEqual(dba.parse_yaml("a: {b: 1, c: [1, 2], d: x}"), {"a": {"b": 1, "c": [1, 2], "d": "x"}})
        self.assertEqual(dba.parse_yaml("a: {b:, c: 1}"), {"a": {"b": None, "c": 1}})
        self.assertEqual(dba.parse_yaml('a: {"k,1": 1}'), {"a": {"k,1": 1}})
        with self.assertRaises(dba.StaticScanError) as cm:
            dba.parse_yaml("a: {oops}")
        self.assertEqual(str(cm.exception), "bad flow mapping entry: oops")

    def test_multiline_flow_error_quotes_first_40_chars(self):
        text = "[" + "".join(chr(ord("a") + i % 26) for i in range(60))
        self.assertEqual(yaml_error("a: " + text), "unsupported multi-line flow collection: " + text[:40])


class TestHelpersAndDockerPlumbing(unittest.TestCase):
    def test_untagged_registry_port_is_not_a_tag(self):
        self.assertTrue(dba.untagged("localhost:5000/app"))
        self.assertTrue(dba.untagged("reg.io:5000/a/b"))
        self.assertFalse(dba.untagged("localhost:5000/app:1.2"))
        self.assertFalse(dba.untagged("a/b@sha256:abc"))
        self.assertTrue(dba.untagged("a/b:latest"))

    def test_get_containers_arguments_and_errors(self):
        calls = []

        def fake(*args):
            calls.append(args)
            return P(0, "abc\n\ndef\n")
        with mock.patch.object(dba, "sh", fake):
            self.assertEqual(dba.get_containers(), ["abc", "def"])
            self.assertEqual(dba.get_containers(True), ["abc", "def"])
        self.assertEqual(calls, [("docker", "ps", "-q"), ("docker", "ps", "-q", "-a")])
        with mock.patch.object(dba, "sh", lambda *a: P(1, "", "")):
            with self.assertRaises(dba.DockerUnavailableError) as cm:
                dba.get_containers()
        self.assertEqual(str(cm.exception), "`docker ps` failed (exit 1): (no error output)")
        with mock.patch.object(dba, "sh", lambda *a: P(3, "", " boom \n")):
            with self.assertRaises(dba.DockerUnavailableError) as cm:
                dba.get_containers()
        self.assertEqual(str(cm.exception), "`docker ps` failed (exit 3): boom")


class TestDockerfileContract(unittest.TestCase):
    def test_instructions_skip_blank_and_comment_lines(self):
        self.assertEqual(dba.dockerfile_instructions("FROM a\n\n# c\n  \nuser x\n"),
                         [(1, "FROM", "a"), (5, "USER", "x")])

    def test_instructions_join_continuations_incl_blank_inside(self):
        self.assertEqual(dba.dockerfile_instructions("RUN a \\\n  b \\\n  c\nUSER x"),
                         [(1, "RUN", "a b c"), (4, "USER", "x")])
        self.assertEqual(dba.dockerfile_instructions("RUN a \\\n\nUSER x"),
                         [(1, "RUN", "a"), (3, "USER", "x")])
        self.assertEqual(dba.dockerfile_instructions("RUN a \\"), [(1, "RUN", "a")])

    def test_env_secret_values_split_on_first_equals(self):
        _, f = dba.audit_dockerfile("FROM a:1\nENV API_TOKEN=abc=def\nUSER 1\nHEALTHCHECK CMD x\n")
        self.assertEqual(f, [{"id": "4.10", "severity": "HIGH",
                              "message": "line 2: secret baked into the image: ENV API_TOKEN has a literal value"}])
        _, f = dba.audit_dockerfile("FROM a:1\nENV A=1 API_KEY=x=y\nUSER 1\nHEALTHCHECK CMD x\n")
        self.assertEqual([x["message"] for x in f],
                         ["line 2: secret baked into the image: ENV API_KEY has a literal value"])

    def test_expose_22_only_for_expose(self):
        base = "FROM a:1\nUSER 1\nHEALTHCHECK CMD x\n"
        self.assertEqual(dba.audit_dockerfile(base + "EXPOSE 8080\n")[1], [])
        self.assertEqual(dba.audit_dockerfile(base + "WORKDIR 22\n")[1], [])
        self.assertEqual(dba.audit_dockerfile(base + "LABEL 22\n")[1], [])
        self.assertEqual(dba.audit_dockerfile(base + "EXPOSE 80 22/tcp\n")[1], [
            {"id": "-", "severity": "LOW", "message":
             "line 4: EXPOSE 22: no SSH server should run in a container (use docker exec)"}])

    def test_root_user_messages(self):
        for user, shown in (("0", "0"), ("root", "root"), ("0:0", "0")):
            _, f = dba.audit_dockerfile("FROM a:1\nUSER %s\nHEALTHCHECK CMD x\n" % user)
            want = "line 2: final stage switches to USER %s (root)" % shown
            self.assertEqual([x["message"] for x in f], [want], user)
        _, f = dba.audit_dockerfile("FROM a:1\nUSER\nHEALTHCHECK CMD x\n")
        self.assertEqual([x["message"] for x in f], ["line 2: final stage switches to USER root (root)"])

    def test_findings_sorted_by_line_number_past_nine(self):
        text = "FROM a:1\n" + "\n" * 8 + "RUN chmod 777 /x\nRUN apt-get update\n"
        _, f = dba.audit_dockerfile(text)
        self.assertEqual([x["message"].split(":")[0] for x in f],
                         ["line 1", "line 1", "line 10", "line 11"])


class TestComposeContract(unittest.TestCase):
    def svc(self, **kw):
        base = {"image": "a:1", "user": "1000", "read_only": True, "mem_limit": "1g", "pids_limit": 10,
                "security_opt": ["no-new-privileges:true"], "healthcheck": {"test": ["CMD", "x"]}}
        base.update(kw)
        return dba.audit_compose_service(base)[1]

    def test_clean_baseline(self):
        self.assertEqual(self.svc(), [])

    def test_user_is_judged_by_first_field_only(self):
        self.assertEqual(self.svc(user="root:foo:bar"), [
            {"id": "4.1", "severity": "MEDIUM", "message": "configured to run as root (no non-root user: set)"}])
        self.assertEqual(self.svc(user="1000:0:1"), [])
        self.assertEqual(self.svc(user="0:0")[0]["id"], "4.1")

    def test_no_user_finding_exact(self):
        _, f = dba.audit_compose_service({"image": "a:1"})
        self.assertEqual(f[0], {"id": "4.1", "severity": "MEDIUM",
                                "message": "configured to run as root (no non-root user: set)"})

    def test_exact_messages_of_namespace_and_limit_rules(self):
        self.assertEqual(self.svc(network_mode="host"), [
            {"id": "5.10", "severity": "HIGH", "message": "host network mode (bypasses container network isolation)"}])
        self.assertEqual(self.svc(pid="host"), [
            {"id": "5.16", "severity": "HIGH",
             "message": "host PID namespace shared (can see/signal host processes)"}])
        self.assertEqual(self.svc(uts="host"), [
            {"id": "5.21", "severity": "MEDIUM", "message": "host UTS namespace shared"}])
        self.assertEqual(self.svc(ipc="host"), [
            {"id": "5.17", "severity": "MEDIUM", "message": "host IPC namespace shared"}])
        self.assertEqual(self.svc(userns_mode="host"), [
            {"id": "5.31", "severity": "MEDIUM", "message": "host user namespace shared"}])
        s = self.svc()
        self.assertEqual(s, [])
        no_mem = dict(mem_limit=None)
        self.assertEqual(self.svc(**no_mem), [{"id": "5.11", "severity": "LOW", "message": "no memory limit set"}])

    def test_healthcheck_disabled_forms(self):
        want = [{"id": "5.27", "severity": "LOW", "message": "no health check configured"}]
        self.assertEqual(self.svc(healthcheck={"test": ["CMD", "x"], "disable": True}), want)
        self.assertEqual(self.svc(healthcheck={"test": ["NONE"]}), want)
        self.assertEqual(self.svc(healthcheck={"test": "NONE"}), want)
        self.assertEqual(self.svc(healthcheck={}), want)
        self.assertEqual(self.svc(healthcheck={"test": ["CMD", "x"], "DISABLE": True}), [])
        self.assertEqual(self.svc(healthcheck={"test": ["CMD", "x"], "disable": False}), [])

    def test_restart_default_and_policies(self):
        self.assertEqual(self.svc(restart="no"), [])
        self.assertEqual(self.svc(restart="always")[0]["message"],
                         "restart policy 'always' restarts without limit (CIS: on-failure with at most 5 retries)")

    def test_published_ports(self):
        f = self.svc(ports=["0.0.0.0:8080:80"])
        self.assertEqual(f, [{"id": "5.14", "severity": "LOW",
                              "message": "port 80 published on every host interface (0.0.0.0:8080)"}])
        self.assertEqual(self.svc(ports=["127.0.0.1:8080:80"]), [])
        self.assertEqual(self.svc(ports=["80:80"])[0]["message"], "privileged host port 80 mapped to 80")
        f = self.svc(ports=["9000:80"])
        self.assertEqual(f[0]["message"], "port 80 published on every host interface (0.0.0.0:9000)")

    def test_port_entries(self):
        self.assertEqual(dba._port_entries({"ports": ["127.0.0.1:8080:80", "8081:81/udp", "82", "[::1]:83:84"]}),
                         [("127.0.0.1", "8080", "80"), ("", "8081", "81"), ("", "", "82"), ("::1", "83", "84")])
        self.assertEqual(dba._port_entries({"ports": [{"host_ip": "10.0.0.1", "published": 90, "target": 91}, {}]}),
                         [("10.0.0.1", "90", "91"), ("", "", "?")])
        self.assertEqual(dba._port_entries({"ports": ["[::1]:80:80]"]}), [("::1", "80", "80]")])

    def test_mounts(self):
        self.assertEqual(dba._mounts({"volumes": ["/data", "named:/x", "/etc:/e:ro,rshared", "./a:/b:shared",
                                                  "/p:/q", "${D:-/var/run}:/z:ro", "~/h:/h:rw"]}),
                         [("/etc", True, "rshared"), ("./a", False, "shared"), ("/p", False, ""),
                          ("/var/run", True, ""), ("~/h", False, "")])
        self.assertEqual(dba._mounts({"volumes": [{"source": "/etc", "target": "/e"},
                                                  {"type": "bind", "source": "/a", "read_only": True,
                                                   "bind": {"propagation": "rshared"}},
                                                  {"type": "volume", "source": "vol"}]}),
                         [("/etc", False, ""), ("/a", True, "rshared")])
        self.assertEqual(dba._mounts({"volumes": ["/e:/e:ro,SHARED"]}), [("/e", True, "")])

    def test_device_message(self):
        f = self.svc(devices=["/dev/a:/dev/b:rwm", "/dev/c"])
        self.assertEqual(f, [{"id": "5.18", "severity": "MEDIUM",
                              "message": "host devices exposed: /dev/a, /dev/c"}])

    def test_environment_secrets(self):
        want = [{"id": "-", "severity": "MEDIUM", "message":
                 "hardcoded secret in environment: API_TOKEN has a literal value (use secrets: or an env_file)"}]
        self.assertEqual(self.svc(environment=["API_TOKEN==x"]), want)
        self.assertEqual(self.svc(environment=["API_TOKEN=a=b"]), want)
        self.assertEqual(self.svc(environment={"API_TOKEN": "x"}), want)
        self.assertEqual(self.svc(environment=["API_TOKEN=$X", "API_TOKEN", "API_TOKEN="]), [])

    def test_latest_tag_finding_exact(self):
        f = dba.audit_compose_service({"image": "nginx", "user": "1", "read_only": True, "mem_limit": 1,
                                       "pids_limit": 1, "security_opt": ["no-new-privileges:true"],
                                       "healthcheck": {"test": ["CMD", "x"]}})[1]
        self.assertEqual(f, [{"id": "-", "severity": "LOW", "message": "using " + dba.LATEST_MSG}])


class TestAuditStaticFiles(unittest.TestCase):
    def test_files_read_as_utf8_with_replacement(self):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        df = os.path.join(d, "Dockerfile")
        with open(df, "wb") as f:
            f.write(b"FROM a:1\n# caf\xc3\xa9 \xff\nUSER 1\nHEALTHCHECK CMD x\n")
        cf = os.path.join(d, "compose.yml")
        with open(cf, "wb") as f:
            f.write(b"services:\n  s:\n    image: a:1  # caf\xc3\xa9 \xff\n")
        seen = []
        real_open = open

        def spy(path, *a, **kw):
            seen.append((os.path.basename(path), kw.get("encoding"), kw.get("errors")))
            return real_open(path, *a, **kw)
        with mock.patch.object(dba, "open", spy, create=True):
            out = dba.audit_static([df], [cf])
        self.assertEqual(seen, [("Dockerfile", "utf-8", "replace"), ("compose.yml", "utf-8", "replace")])
        self.assertEqual([(o["kind"], o["image"]) for o in out], [("dockerfile", "a:1"), ("compose", "a:1")])


def fake_docker(info=None, bridge=None, log=None):
    def docker_json(*args):
        if log is not None:
            log.append(args)
        if args == ("info", "--format", "{{json .}}"):
            return info
        if args == ("network", "inspect", "bridge"):
            return bridge
        return None
    return docker_json


class Args:
    def __init__(self, **kw):
        self.dockerfile = self.compose = self.include = self.exclude = self.daemon_json = None
        self.live, self.all, self.host_root = False, False, "/"
        self.__dict__.update(kw)


class TestRunContract(unittest.TestCase):
    def test_static_only_result_shape(self):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        p = os.path.join(d, "Dockerfile")
        with open(p, "w") as f:
            f.write("FROM a:1\nUSER 1\nHEALTHCHECK CMD x\n")
        res = dba.run(Args(dockerfile=[p]))
        self.assertEqual(res, {"daemon": [], "containers": [], "files": [
            {"name": p, "kind": "dockerfile", "image": "a:1", "findings": []}],
            "engine": None, "local_checks": False, "live": False})

    def live(self, args, sock="/x/docker.sock", info=None, bridge=None, env=None):
        calls, daemon_calls, host_calls = [], [], []

        def audit_daemon(i, b, dj, da):
            daemon_calls.append((i, b, dj, da))
            return []

        def audit_host(root, s):
            host_calls.append((root, s))
            return []
        e = {"DOCKER_CONTENT_TRUST": "1"} if env is None else env
        with mock.patch.object(dba, "get_containers", lambda a: []), \
                mock.patch.object(dba, "docker_json", fake_docker(info, bridge, calls)), \
                mock.patch.object(dba, "local_socket_path", lambda: sock), \
                mock.patch.object(dba, "dockerd_args", lambda root: ["dockerd"]), \
                mock.patch.object(dba, "audit_daemon", audit_daemon), \
                mock.patch.object(dba, "audit_host_files", audit_host), \
                mock.patch.dict(os.environ, e, clear=False):
            if env == {}:
                os.environ.pop("DOCKER_CONTENT_TRUST", None)
            res = dba.run(args)
        return res, calls, daemon_calls, host_calls

    def test_live_queries_and_engine(self):
        res, calls, dcalls, hcalls = self.live(Args(live=True, host_root="/nonexistent"),
                                               info={"ServerVersion": "27.1"}, bridge=[{"Name": "bridge"}])
        self.assertEqual(calls, [("info", "--format", "{{json .}}"), ("network", "inspect", "bridge")])
        self.assertEqual(res["engine"], "27.1")
        self.assertIs(res["local_checks"], True)
        self.assertIs(res["live"], True)
        self.assertEqual(dcalls[0][0], {"ServerVersion": "27.1"})
        self.assertEqual(dcalls[0][1], {"Name": "bridge"})
        self.assertEqual(dcalls[0][3], ["dockerd"])

    def test_live_info_missing_is_empty_dict(self):
        res, _, dcalls, _ = self.live(Args(live=True, host_root="/nonexistent"), info=None, bridge=None)
        self.assertEqual(dcalls[0][0], {})
        self.assertIsNone(dcalls[0][1])
        self.assertIsNone(res["engine"])

    def test_remote_daemon_has_no_local_checks(self):
        res, _, dcalls, hcalls = self.live(Args(live=True), sock=None, info={})  # type: ignore
        self.assertIs(res["local_checks"], False)
        self.assertEqual((dcalls[0][2], dcalls[0][3], hcalls), (None, None, []))

    def test_daemon_json_read_from_given_path(self):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        p = os.path.join(d, "d.json")
        with open(p, "w") as f:
            json.dump({"icc": False}, f)
        _, _, dcalls, hcalls = self.live(Args(live=True, daemon_json=p, host_root=d), info={})
        self.assertEqual(dcalls[0][2], {"icc": False})
        self.assertEqual(hcalls, [(d, None)])

    def test_daemon_json_missing_means_defaults_only_when_etc_docker_visible(self):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        _, _, dcalls, _ = self.live(Args(live=True, host_root=d), info={})
        self.assertIsNone(dcalls[0][2])
        os.makedirs(os.path.join(d, "etc/docker"))
        cwd = os.getcwd()
        os.chdir(tempfile.gettempdir())
        try:
            _, _, dcalls, _ = self.live(Args(live=True, host_root=d), info={})
        finally:
            os.chdir(cwd)
        self.assertEqual(dcalls[0][2], {})
        with open(os.path.join(d, "etc/docker/daemon.json"), "w") as f:
            f.write("{not json")
        _, _, dcalls, _ = self.live(Args(live=True, host_root=d), info={})
        self.assertIsNone(dcalls[0][2])

    def test_host_files_get_socket_only_for_real_root(self):
        _, _, _, hcalls = self.live(Args(live=True, host_root="/", daemon_json="/nonexistent"), info={})
        self.assertEqual(hcalls, [("/", "/x/docker.sock")])

    def test_content_trust_finding(self):
        res, *_ = self.live(Args(live=True, host_root="/nonexistent"), info={}, env={})
        self.assertEqual(res["daemon"], [{"id": "4.5", "severity": "INFO", "message":
                                          "Docker Content Trust is not enabled (DOCKER_CONTENT_TRUST=1)"}])
        res, *_ = self.live(Args(live=True, host_root="/nonexistent"), info={}, env={"DOCKER_CONTENT_TRUST": "1"})
        self.assertEqual(res["daemon"], [])


def run_main(argv, result):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(dba, "run", lambda args: result), contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(err):
        rc = dba.main(argv)
    return rc, out.getvalue()


def sample(live=True, files=True):
    r = {"daemon": [dba.finding("2.1", "LOW", "daemon thing")],
         "containers": [{"name": "c1", "image": "i:1", "findings": [dba.finding("5.4", "MEDIUM", "caps")]}],
         "files": [], "live": live, "engine": "27.1", "local_checks": True}
    if files:
        r["files"] = [{"name": "Dockerfile", "kind": "dockerfile", "image": "a:1", "findings": []}]
    return r


class TestMainOutput(unittest.TestCase):
    def test_live_text_header_and_sections(self):
        rc, out = run_main([], sample())
        self.assertEqual(rc, 0)
        self.assertEqual(out, "docker-baseline-auditor %s: engine 27.1, 1 running containers checked, "
                              "1 Dockerfiles/compose services checked, 2 findings (0 HIGH, 1 MEDIUM, 1 LOW, 0 INFO)\n\n"
                              "== daemon / host ==\n  [LOW] 2.1   daemon thing\n\n"
                              "== c1 (i:1) ==\n  [MEDIUM] 5.4   caps\n\n"
                              "Clean (no findings): Dockerfile\n" % dba.__version__)

    def test_live_all_flag_drops_running_word_and_no_files_part(self):
        rc, out = run_main(["--all"], sample(files=False))
        self.assertEqual(out.splitlines()[0], "docker-baseline-auditor %s: engine 27.1, 1 containers checked, "
                         "2 findings (0 HIGH, 1 MEDIUM, 1 LOW, 0 INFO)" % dba.__version__)

    def test_remote_note_and_unknown_engine(self):
        r = sample(files=False)
        r["local_checks"], r["engine"] = False, None
        rc, out = run_main([], r)
        self.assertIn("engine ?, 1 running containers checked", out)
        self.assertIn("\n(remote DOCKER_HOST: host file checks 3.x skipped)\n\n", out)

    def test_static_text_header_and_fail_line(self):
        r = {"daemon": [], "containers": [], "live": False, "engine": None, "local_checks": False,
             "files": [{"name": "f:s", "kind": "compose", "image": "a:1",
                        "findings": [dba.finding("5.5", "HIGH", "priv")]}]}
        rc, out = run_main(["--fail-on", "high"], r)
        self.assertEqual(rc, 1)
        self.assertEqual(out, "docker-baseline-auditor %s: 1 Dockerfiles/compose services checked, "
                              "1 findings (1 HIGH, 0 MEDIUM, 0 LOW, 0 INFO)\n\n"
                              "== f:s (a:1) ==\n  [HIGH] 5.5   priv\n\n\n"
                              "FAIL: findings at or above HIGH (exit 1)\n" % dba.__version__)

    def test_json_output_is_two_space_indented(self):
        rc, out = run_main(["--json"], sample())
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["version"], dba.__version__)
        self.assertEqual(out, json.dumps(data, indent=2) + "\n")
        self.assertTrue(out.startswith('{\n  "daemon": ['))

    def test_fail_on_choices_are_lowercase_only(self):
        for bad in ("HIGH", "critical"):
            with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
                dba.main(["--fail-on", bad])
            self.assertEqual(cm.exception.code, 2)
        for ok in ("high", "medium", "low", "never"):
            self.assertEqual(run_main(["--fail-on", ok], sample())[0], 0 if ok in ("high", "never") else 1)

    def test_help_text(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"COLUMNS": "80"}), contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit):
                dba.main(["--help"])
        text = re.sub(r"\s+", " ", out.getvalue()).strip()
        text = text.replace("optional arguments:", "options:")
        self.assertIn("usage: docker-baseline-auditor [-h] [--version] [--json] [--fail-on {high,medium,low,never}] "
                      "[--include IDS] [--exclude IDS] [--all] [--dockerfile PATH] [--compose PATH] [--live] "
                      "[--daemon-json PATH]", text)
        self.assertIn("Read-only Docker security baseline checker (CIS Docker Benchmark v1.6.0 ids): "
                      "audits the daemon, its host files and every running container.", text)
        for frag in ("--json emit machine-readable JSON instead of the text report",
                     "--fail-on {high,medium,low,never} lowest severity that makes the exit code 1 (default: high)",
                     "--include IDS only these CIS ids/sections, comma-separated (e.g. 2,5.5)",
                     "--exclude IDS skip these CIS ids/sections, comma-separated (e.g. 5.27,2.13)",
                     "--all also audit stopped containers",
                     "--dockerfile PATH static scan of a Dockerfile, or every Dockerfile under a directory "
                     "(repeatable; no docker daemon needed)",
                     "--compose PATH static scan of a Compose file, or every compose*.y(a)ml under a directory "
                     "(repeatable; no docker daemon needed)",
                     "--live with --dockerfile/--compose: also audit the live daemon and containers",
                     "--daemon-json PATH daemon.json to read (default /etc/docker/daemon.json)",
                     "Exit codes: 0 nothing at/above --fail-on, 1 findings at/above --fail-on, "
                     "2 docker unavailable or bad usage."):
            self.assertIn(frag, text)


if __name__ == "__main__":
    unittest.main()
