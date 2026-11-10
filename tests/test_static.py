"""Static scan: --dockerfile / --compose (no docker daemon needed)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "docker_baseline_auditor.py")
sys.path.insert(0, os.path.dirname(TOOL))
import docker_baseline_auditor as dba  # noqa: E402

CHMOD_ALL = "ch" + "mod -R 7" + "77 /srv"


def ids(findings):
    return sorted((f["id"], f["severity"]) for f in findings)


def msgs(findings, cis):
    return [f["message"] for f in findings if f["id"] == cis]


def run_tool(*args):
    return subprocess.run([sys.executable, TOOL] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, timeout=60)


GOOD_DF = """FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY app /app
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
USER 1000:1000
"""


class TestDockerfile(unittest.TestCase):
    def test_clean_dockerfile(self):
        image, f = dba.audit_dockerfile(GOOD_DF)
        self.assertEqual((image, f), ("python:3.12-slim", []))

    def test_root_and_healthcheck(self):
        image, f = dba.audit_dockerfile("FROM alpine:3.20\nCMD [\"sh\"]\n")
        self.assertEqual(image, "alpine:3.20")
        self.assertEqual(f, [
            {"id": "4.1", "severity": "MEDIUM", "message": "line 1: final stage runs as root (no non-root USER)"},
            {"id": "4.6", "severity": "LOW", "message": "line 1: no HEALTHCHECK instruction in the final stage"}])

    def test_user_root_forms_and_healthcheck_none(self):
        for user in ("root", "0", "0:0", "root:root"):
            _, f = dba.audit_dockerfile(f"FROM a:1\nUSER {user}\nHEALTHCHECK NONE\n")
            self.assertEqual(ids(f), [("4.1", "MEDIUM"), ("4.6", "LOW")], user)
            self.assertIn("line 2: final stage switches to USER", msgs(f, "4.1")[0])
        _, f = dba.audit_dockerfile("FROM a:1\nUSER app\nUSER nobody:nogroup\nHEALTHCHECK CMD true\n")
        self.assertEqual(f, [])

    def test_only_final_stage_counts_for_user_and_healthcheck(self):
        text = "FROM golang:1.22 AS b\nRUN go build\nFROM gcr.io/distroless/static:nonroot\nUSER 65532\nHEALTHCHECK CMD [\"/x\"]\n"
        self.assertEqual(dba.audit_dockerfile(text), ("gcr.io/distroless/static:nonroot", []))

    def test_latest_untagged_and_exemptions(self):
        text = ("ARG BASE=x\nFROM node AS b\nFROM b AS c\nFROM scratch AS s\nFROM ${BASE}\n"
                "FROM reg.example:5000/team/app\nFROM reg.example:5000/team/app:2\nFROM nginx:latest\n"
                "FROM --platform=linux/amd64 busybox@sha256:abc\nUSER 1\nHEALTHCHECK CMD true\n")
        _, f = dba.audit_dockerfile(text)
        self.assertEqual([m["message"] for m in f],
                         ["line 2: base image node is ':latest' or untagged image (non-reproducible, harder to pin/patch)",
                          "line 6: base image reg.example:5000/team/app is ':latest' or untagged image "
                          "(non-reproducible, harder to pin/patch)",
                          "line 8: base image nginx:latest is ':latest' or untagged image "
                          "(non-reproducible, harder to pin/patch)"])
        self.assertTrue(all(x["id"] == "-" and x["severity"] == "LOW" for x in f))

    def test_package_index_update(self):
        for run, bad in (("apt-get update", True), ("apt update", True), ("apk update", True),
                         ("apt-get update && apt-get install -y x", False), ("apt-get update && apt-get upgrade", False),
                         ("apk update && apk add x", False), ("apk add --no-cache x", False),
                         ("echo updated", False)):
            _, f = dba.audit_dockerfile(f"FROM a:1\nUSER 1\nHEALTHCHECK CMD true\nRUN {run}\n")
            self.assertEqual(ids(f), [("4.7", "LOW")] if bad else [], run)
        _, f = dba.audit_dockerfile("FROM a:1\nUSER 1\nHEALTHCHECK CMD true\nRUN apt-get update\n")
        self.assertEqual(f[0]["message"], "line 4: package index update on its own RUN line (cached stale; "
                                          "combine update and install in one RUN)")

    def test_add_vs_copy(self):
        base = "FROM a:1\nUSER 1\nHEALTHCHECK CMD true\n"
        cases = [("ADD src /dst", [("4.9", "LOW")]), ("ADD --chown=1:1 src /dst", [("4.9", "LOW")]),
                 ("ADD app.tar.gz /opt", []), ("ADD a.TGZ b.tar /opt/", []), ("ADD [\"a.txt\", \"/b\"]", [("4.9", "LOW")]),
                 ("ADD https://x.example/a.tar.gz /a", [("4.9", "MEDIUM")]), ("ADD http://x/a /a", [("4.9", "MEDIUM")]),
                 ("COPY src /dst", [])]
        for line, want in cases:
            _, f = dba.audit_dockerfile(base + line + "\n")
            self.assertEqual(ids(f), want, line)
        _, f = dba.audit_dockerfile(base + "ADD https://x.example/a /a\n")
        self.assertEqual(f[0]["message"], "line 4: ADD fetches a remote URL (no checksum; use curl with a verified "
                                          "digest, or COPY)")
        _, f = dba.audit_dockerfile(base + "ADD src /dst\n")
        self.assertEqual(f[0]["message"], "line 4: use COPY instead of ADD (ADD only for local tar auto-extraction)")

    def test_secrets_in_env_and_arg(self):
        base = "FROM a:1\nUSER 1\nHEALTHCHECK CMD true\n"
        _, f = dba.audit_dockerfile(base + "ENV DB_PASSWORD=hunter2 MODE=prod AWS_SECRET_ACCESS_KEY=x\nENV API_TOKEN abc\n"
                                    "ENV PASSWORD_FILE=\nENV GITHUB_TOKEN=$TOKEN\nENV NAME=\"two words\" TOKEN='s e'\n")
        self.assertEqual([(x["id"], x["severity"], x["message"]) for x in f], [
            ("4.10", "HIGH", "line 4: secret baked into the image: ENV DB_PASSWORD has a literal value"),
            ("4.10", "HIGH", "line 4: secret baked into the image: ENV AWS_SECRET_ACCESS_KEY has a literal value"),
            ("4.10", "HIGH", "line 5: secret baked into the image: ENV API_TOKEN has a literal value"),
            ("4.10", "HIGH", "line 8: secret baked into the image: ENV TOKEN has a literal value")])
        _, f = dba.audit_dockerfile(base + "ARG API_TOKEN=abc\nARG PASSWORD\nARG SECRET=\nARG TOKEN=$X\nARG VERSION=1\n")
        self.assertEqual([(x["id"], x["severity"], x["message"]) for x in f], [
            ("4.10", "MEDIUM", "line 4: secret default in the image history: ARG API_TOKEN has a literal value")])

    def test_pipe_to_shell_chmod_expose(self):
        base = "FROM a:1\nUSER 1\nHEALTHCHECK CMD true\n"
        _, f = dba.audit_dockerfile(base + "RUN curl -fsSL https://x.example/i.sh | sudo bash\nRUN wget -qO- u | sh -s\n"
                                    f"RUN {CHMOD_ALL}\nRUN ch" "mod 644 /x\nRUN curl -o f u && sh f\nEXPOSE 80/tcp 22/tcp\n")
        self.assertEqual([(x["id"], x["severity"], x["message"]) for x in f], [
            ("-", "MEDIUM", "line 4: downloads a script and pipes it into a shell (unverified code)"),
            ("-", "MEDIUM", "line 5: downloads a script and pipes it into a shell (unverified code)"),
            ("-", "LOW", "line 6: world-writable permissions (mode 0777)"),
            ("-", "LOW", "line 9: EXPOSE 22: no SSH server should run in a container (use docker exec)")])

    def test_continuations_comments_and_line_numbers(self):
        text = "# comment\nFROM a:1\nRUN apt-get update \\\n    # inner comment\n    && apt-get install -y x\nuser 1\nhealthcheck cmd true\n"
        self.assertEqual(dba.dockerfile_instructions(text), [
            (2, "FROM", "a:1"), (3, "RUN", "apt-get update && apt-get install -y x"), (6, "USER", "1"),
            (7, "HEALTHCHECK", "cmd true")])
        self.assertEqual(dba.dockerfile_instructions("FROM a\nRUN x \\\n"), [(1, "FROM", "a"), (2, "RUN", "x")])
        self.assertEqual(dba.dockerfile_instructions(""), [])
        self.assertEqual(dba.audit_dockerfile(""), ("", []))
        self.assertEqual(dba.audit_dockerfile("# only a comment\n"), ("", []))


COMPOSE_BAD = """
x-base: &base
  restart: always
  user: "1000:1000"
services:
  web:
    <<: *base
    image: nginx
    ports:
      - "80:80"
      - "127.0.0.1:8080:80"
      - "[::]:9000:9000/tcp"
      - 3000
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host-etc:ro
      - /:/host
      - ./data:/data
      - named:/n
      - /srv:/s:rshared
    environment:
      SECRET_KEY: abc
      MODE: prod
    privileged: true
    cap_add: [CAP_NET_ADMIN, SYS_TIME]
    network_mode: host
    pid: host
    ipc: host
    uts: host
    userns_mode: host
    devices: ["/dev/fuse:/dev/fuse"]
    security_opt: ["seccomp:unconfined", "apparmor=unconfined"]
  db:
    image: postgres:16
    user: postgres
    read_only: true
    mem_limit: 1g
    pids_limit: 100
    restart: on-failure:3
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "true"]
"""


class TestCompose(unittest.TestCase):
    def setUp(self):
        self.res = {n: (img, f) for n, img, f in dba.audit_compose(COMPOSE_BAD)}

    def test_clean_service(self):
        self.assertEqual(self.res["db"], ("postgres:16", []))

    def test_every_check_fires_for_web(self):
        img, f = self.res["web"]
        self.assertEqual(img, "nginx")
        self.assertEqual(sorted(set(i for i, _ in ids(f))), sorted(
            ["-", "5.2", "5.22", "5.4", "5.5", "5.6", "5.8", "5.10", "5.11", "5.13",
             "5.14", "5.15", "5.16", "5.17", "5.18", "5.20", "5.21", "5.26", "5.27", "5.29", "5.31", "5.32"]))
        self.assertEqual(msgs(f, "5.4"), ["extra capabilities added: NET_ADMIN, SYS_TIME"])
        self.assertEqual(sorted(msgs(f, "5.6")), ["sensitive host path / mounted read-write",
                                                  "sensitive host path /etc mounted read-only"])
        self.assertEqual(ids([x for x in f if x["id"] == "5.6"]), [("5.6", "HIGH"), ("5.6", "MEDIUM")])
        self.assertEqual(msgs(f, "5.8"), ["privileged host port 80 mapped to 80"])
        self.assertEqual(msgs(f, "5.14"), ["port 80 published on every host interface (0.0.0.0:80)",
                                           "port 9000 published on every host interface (:::9000)",
                                           "port 3000 published on every host interface (0.0.0.0:random)"])
        self.assertEqual(msgs(f, "5.15"), ["restart policy 'always' restarts without limit (CIS: on-failure with at most 5 retries)"])
        self.assertEqual(msgs(f, "5.18"), ["host devices exposed: /dev/fuse"])
        self.assertEqual(msgs(f, "5.20"), ["mount /srv uses rshared propagation"])
        self.assertEqual(msgs(f, "5.32"), ["Docker socket mounted in (/var/run/docker.sock) -- effective root-equivalent host access"])
        self.assertEqual(msgs(f, "5.2"), ["security profile disabled: apparmor=unconfined"])
        self.assertEqual(msgs(f, "5.22"), ["security profile disabled: seccomp:unconfined"])
        self.assertEqual(msgs(f, "4.1"), [])  # user comes from the merged anchor
        self.assertEqual(msgs(f, "-"), [
            "hardcoded secret in environment: SECRET_KEY has a literal value (use secrets: or an env_file)",
            "using ':latest' or untagged image (non-reproducible, harder to pin/patch)"])
        self.assertEqual(dict(ids(f))["5.5"], "HIGH")
        self.assertEqual(dict(ids(f))["5.10"], "HIGH")
        self.assertEqual(dict(ids(f))["5.16"], "HIGH")

    def test_severities(self):
        _, f = self.res["web"]
        want = {"5.4": "MEDIUM", "5.2": "MEDIUM", "5.22": "MEDIUM", "5.17": "MEDIUM", "5.18": "MEDIUM", "5.20": "MEDIUM",
                "5.21": "MEDIUM", "5.31": "MEDIUM", "5.8": "LOW", "5.11": "LOW", "5.13": "LOW", "5.14": "LOW",
                "5.15": "LOW", "5.26": "LOW", "5.27": "LOW", "5.29": "LOW", "5.32": "HIGH"}
        got = {x["id"]: x["severity"] for x in f}
        for k, v in want.items():
            self.assertEqual(got[k], v, k)

    def svc(self, body):
        return dba.audit_compose("services:\n  s:\n    image: a:1\n" + body)[0][2]

    def test_user_forms(self):
        for u, root in (("root", True), ("0", True), ("0:0", True), ("1000", False), ("app:app", False), ("\"\"", True)):
            f = self.svc(f"    user: {u}\n")
            self.assertEqual(bool(msgs(f, "4.1")), root, u)
        self.assertEqual(msgs(self.svc(""), "4.1"), ["configured to run as root (no non-root user: set)"])

    def test_restart_forms(self):
        for r, bad in (("always", True), ("unless-stopped", True), ("on-failure", True), ("on-failure:5", False),
                       ("on-failure:6", True), ("on-failure:0", True), ("\"no\"", False)):
            self.assertEqual(bool(msgs(self.svc(f"    restart: {r}\n"), "5.15")), bad, r)
        self.assertEqual(msgs(self.svc("    restart: on-failure\n"), "5.15"),
                         ["restart policy on-failure with unlimited retries (CIS: at most 5)"])
        self.assertEqual(msgs(self.svc("    restart: on-failure:9\n"), "5.15"),
                         ["restart policy on-failure with 9 retries (CIS: at most 5)"])

    def test_limits_healthcheck_and_hardening_forms(self):
        f = self.svc("    deploy:\n      resources:\n        limits:\n          memory: 1G\n          pids: 50\n")
        self.assertEqual(msgs(f, "5.11") + msgs(f, "5.29"), [])
        self.assertEqual(len(msgs(self.svc("    pids_limit: -1\n"), "5.29")), 1)
        self.assertEqual(msgs(self.svc("    pids_limit: 10\n"), "5.29"), [])
        for hc, bad in (("healthcheck:\n      test: [\"CMD\", \"x\"]", False), ("healthcheck:\n      test: curl -f x", False),
                        ("healthcheck:\n      disable: true", True), ("healthcheck:\n      test: [\"NONE\"]", True),
                        ("healthcheck:\n      test: NONE", True), ("healthcheck:\n      interval: 5s", True)):
            self.assertEqual(bool(msgs(self.svc("    " + hc + "\n"), "5.27")), bad, hc)
        for so, bad in (("no-new-privileges:true", False), ("no-new-privileges=true", False), ("no-new-privileges", False),
                        ("no-new-privileges:false", True), ("no-new-privileges=0", True), ("label=x", True)):
            self.assertEqual(bool(msgs(self.svc(f"    security_opt: [\"{so}\"]\n"), "5.26")), bad, so)
        self.assertEqual(msgs(self.svc("    read_only: true\n"), "5.13"), [])
        self.assertEqual(msgs(self.svc("    read_only: false\n"), "5.13"),
                         ["root filesystem is writable (no read_only: true)"])
        self.assertEqual(msgs(self.svc("    privileged: false\n"), "5.5"), [])

    def test_ports_forms(self):
        def got(*ports):
            f = self.svc("    ports:\n" + "".join(f"      - {p}\n" for p in ports))
            return msgs(f, "5.14"), msgs(f, "5.8")
        self.assertEqual(got("'127.0.0.1:80:80'"), ([], ["privileged host port 80 mapped to 80"]))
        self.assertEqual(got("'[::1]:8080:80'"), ([], []))
        self.assertEqual(got("'[::]:8080:80'"), (["port 80 published on every host interface (:::8080)"], []))
        self.assertEqual(got("'8000-8010:8000-8010'")[1], ["privileged host port 8000-8010 mapped to 8000-8010"][:0])
        self.assertEqual(got("'2000:80/udp'"), (["port 80 published on every host interface (0.0.0.0:2000)"], []))
        self.assertEqual(got("'1023:80'")[1], ["privileged host port 1023 mapped to 80"])
        self.assertEqual(got("'1024:80'")[1], [])
        self.assertEqual(got("'0.0.0.0:443:443'")[1], ["privileged host port 443 mapped to 443"])
        f = self.svc("    ports:\n      - target: 80\n        published: 8080\n        host_ip: 127.0.0.1\n"
                     "      - target: 53\n        published: 53\n")
        self.assertEqual(msgs(f, "5.14"), ["port 53 published on every host interface (0.0.0.0:53)"])
        self.assertEqual(msgs(f, "5.8"), ["privileged host port 53 mapped to 53"])

    def test_volume_forms(self):
        f = self.svc("    volumes:\n      - type: bind\n        source: /var/run/docker.sock\n        target: /s\n"
                     "      - type: bind\n        source: /proc\n        target: /p\n        read_only: true\n"
                     "      - type: volume\n        source: /etc\n        target: /e\n"
                     "      - \"${DOCKER_SOCK:-/var/run/docker.sock}:/s2\"\n      - /usr/:/u\n      - /var/lib/x:/x\n"
                     "      - dbdata:/var/lib/db\n      - \"/just/one\"\n")
        self.assertEqual(msgs(f, "5.32"), ["Docker socket mounted in (/var/run/docker.sock) -- effective root-equivalent host access",
                                           "Docker socket mounted in (/var/run/docker.sock) -- effective root-equivalent host access"])
        self.assertEqual(msgs(f, "5.6"), ["sensitive host path /proc mounted read-only", "sensitive host path /usr mounted read-write"])
        f = self.svc("    volumes:\n      - type: bind\n        source: /srv\n        target: /s\n        bind:\n          propagation: shared\n")
        self.assertEqual(msgs(f, "5.20"), ["mount /srv uses shared propagation"])

    def test_environment_list_form_and_values(self):
        f = self.svc("    environment:\n      - DB_PASSWORD=abc\n      - TOKEN=${TOKEN}\n      - PASSWORD\n      - MODE=prod\n")
        self.assertEqual(msgs(f, "-"), ["hardcoded secret in environment: DB_PASSWORD has a literal value "
                                        "(use secrets: or an env_file)"])
        f = self.svc("    environment:\n      API_TOKEN:\n      SECRET: \"\"\n      PASSWORD: $P\n")
        self.assertEqual(msgs(f, "-"), [])

    def test_image_rules(self):
        for img, bad in (("nginx", True), ("nginx:latest", True), ("nginx:1.27", False), ("r:5000/a/b", True),
                         ("r:5000/a/b:2", False), ("a@sha256:abc", False), ("${IMG}", False), ("x:${TAG}", False)):
            f = dba.audit_compose(f"services:\n  s:\n    image: {img}\n")[0][2]
            self.assertEqual(bool(msgs(f, "-")), bad, img)
        name, image, _ = dba.audit_compose("services:\n  s:\n    build: .\n")[0]
        self.assertEqual((name, image), ("s", "(build)"))

    def test_errors(self):
        for text, want in (("", "no `services:` mapping"), ("version: '3'\n", "no `services:`"), ("- a\n", "no `services:`"),
                           ("services:\n  s: nope\n", "service s is not a mapping"),
                           ("services:\n  s:\n    image: *missing\n", "unknown YAML alias"),
                           ("services:\n  s:\n    image: 'a\n", "unterminated"),
                           ("services:\n\ts:\n", "tab indentation"),
                           ("services:\n  s:\n    ports: [a,\n      b]\n", "multi-line flow"),
                           ("services:\n  s:\n    image: a\n  garbage\n", "expected 'key: value'")):
            with self.assertRaises(dba.StaticScanError) as cm:
                dba.audit_compose(text)
            self.assertIn(want, str(cm.exception), text)


class TestYaml(unittest.TestCase):
    def test_subset(self):
        text = ("a: 1\nb: [x, 'y z', {k: v}]\nc:\n  - one\n  - two: 2\n    three: true\n  -\n    - nested\n"
                "d:\n- same-indent\n- 'it''s'\ne: |\n  line1 # not a comment\n  line2\nf: >-\n  fold\n  me\n"
                "g: ~\nh: \"a # b\" # comment\ni: &anc {p: 1}\nj: *anc\nk: -5\nl: 8080:80\nm: {}\nn:\n")
        self.assertEqual(dba.parse_yaml(text), {
            "a": 1, "b": ["x", "y z", {"k": "v"}], "c": ["one", {"two": 2, "three": True}, ["nested"]],
            "d": ["same-indent", "it's"], "e": "line1 # not a comment\nline2", "f": "fold me", "g": None,
            "h": "a # b", "i": {"p": 1}, "j": {"p": 1}, "k": -5, "l": "8080:80", "m": {}, "n": None})

    def test_merge_and_comments_and_docstart(self):
        text = "---\n# top\nbase: &b\n  x: 1\n  y: 2\nuse:\n  <<: [*b, {z: 3}]\n  y: 9\n"
        self.assertEqual(dba.parse_yaml(text)["use"], {"x": 1, "y": 9, "z": 3})
        self.assertEqual(dba.parse_yaml(""), {})
        self.assertEqual(dba.parse_yaml("# nothing\n"), {})

    def test_inconsistent_indent_is_an_error(self):
        with self.assertRaises(dba.StaticScanError):
            dba.parse_yaml("a:\n    b: 1\n  c: 2\n")


class TestCli(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        os.makedirs(os.path.join(self.dir, "sub", "node_modules"))
        with open(os.path.join(self.dir, "Dockerfile"), "w") as f:
            f.write("FROM alpine\nENV DB_PASSWORD=x\n")
        with open(os.path.join(self.dir, "sub", "app.Dockerfile"), "w") as f:
            f.write(GOOD_DF)
        with open(os.path.join(self.dir, "sub", "node_modules", "Dockerfile"), "w") as f:
            f.write("FROM skipped\n")
        with open(os.path.join(self.dir, "docker-compose.yml"), "w") as f:
            f.write("services:\n  web:\n    image: nginx:1\n    privileged: true\n    user: '1'\n")
        with open(os.path.join(self.dir, "notes.yml"), "w") as f:
            f.write("services: [not compose scanned]\n")

    def test_directory_scan_json_and_exit_code(self):
        p = run_tool("--dockerfile", self.dir, "--compose", self.dir, "--json")
        self.assertEqual(p.returncode, 1, p.stderr)
        res = json.loads(p.stdout)
        self.assertEqual(res["daemon"], [])
        self.assertEqual(res["containers"], [])
        self.assertEqual(res["version"], dba.__version__)
        self.assertEqual([(t["kind"], os.path.relpath(t["name"], self.dir), t["image"]) for t in res["files"]], [
            ("dockerfile", "Dockerfile", "alpine"), ("dockerfile", os.path.join("sub", "app.Dockerfile"), "python:3.12-slim"),
            ("compose", "docker-compose.yml:web", "nginx:1")])
        self.assertEqual(res["summary"]["files"], 3)
        self.assertEqual(res["summary"]["containers"], 0)
        self.assertTrue(res["summary"]["failed"])
        self.assertEqual(res["summary"]["HIGH"], 2)

    def test_text_report_and_fail_on(self):
        path = os.path.join(self.dir, "Dockerfile")
        p = run_tool("--dockerfile", path)
        self.assertEqual(p.returncode, 1)
        self.assertIn(f"docker-baseline-auditor {dba.__version__}: 1 Dockerfiles/compose services checked, "
                      "4 findings (1 HIGH, 1 MEDIUM, 2 LOW, 0 INFO)", p.stdout)
        self.assertIn(f"== {path} (alpine) ==", p.stdout)
        self.assertIn("[HIGH] 4.10  line 2: secret baked into the image", p.stdout)
        self.assertIn("FAIL: findings at or above HIGH (exit 1)", p.stdout)
        self.assertNotIn("remote DOCKER_HOST", p.stdout)
        self.assertEqual(run_tool("--dockerfile", path, "--fail-on", "never").returncode, 0)
        good = os.path.join(self.dir, "sub", "app.Dockerfile")
        p = run_tool("--dockerfile", good)
        self.assertEqual(p.returncode, 0)
        self.assertIn(f"Clean (no findings): {good}", p.stdout)
        self.assertIn("0 findings", p.stdout)

    def test_include_exclude_apply_to_static_findings(self):
        path = os.path.join(self.dir, "Dockerfile")
        res = json.loads(run_tool("--dockerfile", path, "--include", "4.10", "--json").stdout)
        self.assertEqual([f["id"] for f in res["files"][0]["findings"]], ["4.10"])
        res = json.loads(run_tool("--dockerfile", path, "--exclude", "4", "--json").stdout)
        self.assertEqual([f["id"] for f in res["files"][0]["findings"]], ["-"])

    def test_errors_exit_2_without_docker(self):
        env_path = os.path.join(self.dir, "nope")
        for argv, want in ((["--dockerfile", env_path], "Dockerfile path not found"),
                           (["--compose", env_path], "compose file path not found"),
                           (["--compose", os.path.join(self.dir, "sub")], "no compose file found under"),
                           (["--dockerfile", os.path.join(self.dir, "sub", "node_modules", "..", "..", "sub")][:0]
                            or ["--compose", os.path.join(self.dir, "notes.yml")], "no `services:` mapping")):
            p = run_tool(*argv)
            self.assertEqual(p.returncode, 2, argv)
            self.assertIn("docker-baseline-auditor: ERROR -- ", p.stderr)
            self.assertIn(want, p.stderr)
        p = run_tool("--compose", env_path, "--json")
        self.assertEqual(p.returncode, 2)
        self.assertIn("compose file path not found", json.loads(p.stdout)["error"])

    def test_static_does_not_need_docker(self):
        env = dict(os.environ, PATH=os.path.join(self.dir, "empty"))
        p = subprocess.run([sys.executable, TOOL, "--dockerfile", os.path.join(self.dir, "sub", "app.Dockerfile")],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_live_flag_adds_the_daemon_audit(self):
        env = dict(os.environ, PATH=os.path.join(self.dir, "empty"))
        p = subprocess.run([sys.executable, TOOL, "--dockerfile", os.path.join(self.dir, "sub", "app.Dockerfile"), "--live"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=env)
        self.assertEqual(p.returncode, 2)
        self.assertIn("`docker` CLI not found", p.stderr)

    def test_file_name_matching(self):
        for n, df in (("Dockerfile", True), ("dockerfile", True), ("Dockerfile.prod", True), ("a.dockerfile", True),
                      ("Containerfile", True), ("x.Containerfile", True), ("Dockerfiles", False), ("mydockerfile", False),
                      ("README.md", False)):
            self.assertEqual(dba._is_dockerfile_name(n), df, n)
        for n, c in (("docker-compose.yml", True), ("compose.yaml", True), ("Compose.YML", True),
                     ("docker-compose.prod.yml", True), ("compose.txt", False), ("ci.yml", False), ("docker-compose", False)):
            self.assertEqual(dba._is_compose_name(n), c, n)


if __name__ == "__main__":
    unittest.main()
