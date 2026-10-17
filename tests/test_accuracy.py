"""Detection accuracy against the reference implementation of the benchmark this tool cites:
Docker Bench for Security (github.com/docker/docker-bench-security, CIS Docker Benchmark v1.6.0,
pinned commit, cloned by ci/setup.sh) run against the same real containers.

A corpus of 18 running containers (every combination the suite can start safely: capabilities,
seccomp/AppArmor unconfined, host IPC/UTS, devices, memory/pids limits, read-only rootfs, ports on
every interface vs one, restart policies, health checks, no-new-privileges, users, /etc mounted
read-only) is audited by this tool and by Docker Bench. For every container and every CIS id both
implement, "the tool reports id X" must equal "Docker Bench WARNs X for that container"
-> false negatives and false positives in one suite. Where Docker Bench itself is known to deviate
from the CIS text, the CIS audit procedure is the reference and the deviation is spelled out:

* 5.4  Docker Bench tests an unset variable ($caps instead of $container_caps), so it WARNs every
       container; reference = CIS audit: HostConfig.CapAdd is non-empty.
* 5.6  Docker Bench only WARNs read-write mounts; CIS 5.6 covers read-only ones too ("especially
       read-write"), so Docker Bench's set must be a subset of the tool's.
* 5.15 Docker Bench only checks MaximumRetryCount > 5; the CIS audit also fails RestartPolicyName
       always (and unless-stopped / unlimited on-failure). Docker Bench's set must be a subset;
       the CIS rule decides the rest.
* 5.2  only compared when the engine has AppArmor at all (CIS: "if applicable").
"""
import calendar
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "docker_baseline_auditor.py")
BENCH = os.environ.get("DOCKER_BENCH_DIR", "/opt/docker-bench-security")
IMAGE = "alpine:3.20"
BASE = ["--cpus", "0.2"]

# suffix -> extra `docker run` options. Nothing here can hurt the CI host when started (no
# privileged, host PID/network, docker.sock or read-write sensitive mounts: the main suite only
# ever *creates* those).
CORPUS = {
    "bare": [],
    "hardened": ["--memory", "64m", "--pids-limit", "32", "--read-only", "--user", "1000:1000",
                 "--security-opt", "no-new-privileges", "--health-cmd", "true", "--restart", "on-failure:5"],
    "caps": ["--cap-add", "NET_ADMIN", "--cap-add", "SYS_TIME"],
    "capdrop": ["--cap-drop", "ALL"],
    "seccomp": ["--security-opt", "seccomp=unconfined"],
    "apparmor": ["--security-opt", "apparmor=unconfined"],
    "ipc": ["--ipc", "host"],
    "uts": ["--uts", "host"],
    "device": ["--device", "/dev/zero"],
    "allif": ["-p", "0:8080"],
    "loopback": ["-p", "127.0.0.1:0:8080"],
    "etcro": ["-v", "/etc:/host-etc:ro"],
    "always": ["--restart", "always"],
    "unless": ["--restart", "unless-stopped"],
    "onfail": ["--restart", "on-failure"],
    "onfail9": ["--restart", "on-failure:9"],
    "onfail2": ["--restart", "on-failure:2", "--memory", "32m"],
    "rootuser": ["--user", "root", "--pids-limit", "-1"],
}
COMPARED = ["4.1", "5.2", "5.4", "5.6", "5.10", "5.11", "5.13", "5.14", "5.15", "5.16", "5.17", "5.21", "5.22",
            "5.26", "5.27", "5.29", "5.31", "5.32"]
SUBSET = {"5.6", "5.15"}


def docker(*args, check=True):
    p = subprocess.run(["docker"] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if check and p.returncode != 0:
        raise RuntimeError("docker %s failed: %s" % (" ".join(args), p.stderr))
    return p.stdout.strip()


# A run killed before tearDownModule (mutmut's per-mutant timeout, a cancelled CI job) leaves its
# corpus behind, and the --restart always/unless-stopped ones never exit on their own. One mutation
# run leaked ~2000 containers on the arm64 runner this way (load 36 on 8 vCPUs, and every later
# run's tool/bench scan got slower, so more mutants timed out and leaked more). So each run first
# removes corpora older than any live run can be: setUpModule is bounded by the 300 s tool run plus
# the 900 s bench run, so 30 minutes never touches a concurrent run's containers.
STALE_AFTER = 30 * 60


# Under mutation testing (mutmut sets MUTANT_UNDER_TEST) the corpus and Docker Bench's verdicts are
# the reference, not the code under test, so they are built once per mutation run and every mutant
# reuses them (cache file in the mutation container's /tmp, shared by mutmut's forked children); only
# this tool's audit reruns per mutant. Building them per mutant (18 container starts + a bench run of
# up to 900 s) made a third of the mutants time out. The corpus is labelled with the mutation
# container's id (its hostname), runs until that container is gone, and is reaped after that.
MUTATION_RUN = socket.gethostname() if os.environ.get("MUTANT_UNDER_TEST") else ""
ORACLE_CACHE = os.path.join(tempfile.gettempdir(), "dba-acc-oracle.json")
OWNER_LABEL = "dba-acc-mutation-run"


def reap_stale_corpora():
    ids = docker("ps", "-aq", "--filter", "name=^dba-acc-", check=False).split()
    if not ids:
        return
    now = time.time()
    owners = {}
    for line in docker("inspect", "--format", "{{.Id}} {{.Created}} {{json .Config.Labels}}", *ids,
                       check=False).splitlines():
        cid, created, labels = (line.split(" ", 2) + ["", ""])[:3]
        try:
            owner = (json.loads(labels) or {}).get(OWNER_LABEL, "")
        except ValueError:
            owner = ""
        if owner:
            # a mutation run's corpus lives exactly as long as its mutation container runs
            if owner not in owners:
                owners[owner] = bool(docker("ps", "-q", "--filter", "id=" + owner, check=False))
            stale = not owners[owner]
        else:
            try:
                stale = now - calendar.timegm(time.strptime(created[:19], "%Y-%m-%dT%H:%M:%S")) > STALE_AFTER
            except ValueError:
                continue
        if stale:
            docker("rm", "-f", "-v", cid, check=False)


def build_oracle():
    """Start the corpus, inspect it and run Docker Bench over it (sets PREFIX/NAMES/INSPECT/APPARMOR/BENCH_IDS)."""
    global PREFIX, NAMES, INSPECT, APPARMOR, BENCH_IDS
    PREFIX = "dba-acc-%s" % uuid.uuid4().hex[:8]
    NAMES = {}
    reap_stale_corpora()
    docker("pull", "-q", IMAGE)
    # a mutation run can outlast 600 s by hours; its corpus is removed by the reaper instead
    extra, sleep = (["--label", "%s=%s" % (OWNER_LABEL, MUTATION_RUN)], "86400") if MUTATION_RUN else ([], "600")
    for suffix, opts in CORPUS.items():
        name = "%s-%s" % (PREFIX, suffix)
        docker("run", "-d", "--name", name, *(BASE + extra + opts), IMAGE, "sleep", sleep)
        NAMES[name] = suffix
    INSPECT = {d["Name"].lstrip("/"): d for d in json.loads(docker("inspect", *NAMES))}
    APPARMOR = any("apparmor" in o for o in json.loads(docker("info", "--format", "{{json .SecurityOptions}}")))
    BENCH_IDS = run_bench()


def load_or_build_oracle():
    global PREFIX, NAMES, INSPECT, APPARMOR, BENCH_IDS
    import fcntl  # mutation testing runs on Linux only
    with open(ORACLE_CACHE + ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if os.path.exists(ORACLE_CACHE):
            with open(ORACLE_CACHE) as f:
                c = json.load(f)
            PREFIX, NAMES, INSPECT, APPARMOR = c["prefix"], c["names"], c["inspect"], c["apparmor"]
            BENCH_IDS = {n: set(ids) for n, ids in c["bench"].items()}
            return
        build_oracle()
        with open(ORACLE_CACHE + ".tmp", "w") as f:
            json.dump({"prefix": PREFIX, "names": NAMES, "inspect": INSPECT, "apparmor": APPARMOR,
                       "bench": {n: sorted(ids) for n, ids in BENCH_IDS.items()}}, f)
        os.rename(ORACLE_CACHE + ".tmp", ORACLE_CACHE)


def setUpModule():
    global PREFIX, NAMES, TOOL_IDS
    PREFIX, NAMES = "", {}
    try:
        if MUTATION_RUN:
            load_or_build_oracle()
        else:
            build_oracle()
        p = subprocess.run([sys.executable, TOOL, "--json", "--include", "4.1,5"], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True, timeout=300)
        assert p.returncode in (0, 1), p.stderr
        TOOL_IDS = {c["name"]: {f["id"] for f in c["findings"]} for c in json.loads(p.stdout)["containers"]
                    if c["name"] in NAMES}
        TOOL_IDS = {n: TOOL_IDS.get(n, set()) for n in NAMES}
    except Exception:
        if not MUTATION_RUN:
            tearDownModule()
        raise


def run_bench():
    log = os.path.join(tempfile.mkdtemp(), "bench.log")
    p = subprocess.run(["bash", os.path.join(BENCH, "docker-bench-security.sh"), "-b", "-c",
                        "container_runtime,check_4_1", "-i", PREFIX, "-l", log],
                       cwd=BENCH, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=900)
    if not os.path.exists(log + ".json"):
        raise RuntimeError("Docker Bench wrote no report:\n" + p.stdout[-3000:])
    with open(log + ".json") as f:
        report = json.load(f)
    out = {n: set() for n in NAMES}
    for section in report["tests"]:
        # (a section header holds "results"; with -c the checks can also sit at the top level)
        for r in section.get("results", [section]):
            if r.get("result") != "WARN":
                continue
            for item in r.get("items") or []:
                name = item.split(":")[0].strip()
                if name in out:
                    out[name].add(r["id"])
    assert any(out.values()), "Docker Bench reported nothing:\n" + p.stdout[-3000:]
    return out


def tearDownModule():
    if MUTATION_RUN:
        return  # the next mutant reuses the corpus; reap_stale_corpora removes it after the run
    for n in list(NAMES):
        docker("rm", "-f", "-v", n, check=False)


def cis_5_15(hc):
    """CIS v1.6.0 5.15 audit: RestartPolicyName=always fails; on-failure must have <= 5 attempts."""
    rp = hc.get("RestartPolicy") or {}
    name, count = rp.get("Name") or "no", rp.get("MaximumRetryCount") or 0
    return name in ("always", "unless-stopped") or (name == "on-failure" and not 0 < count <= 5)


class TestAgainstDockerBench(unittest.TestCase):
    def test_corpus_triggers_both_outcomes_for_most_ids(self):
        both = [i for i in COMPARED if any(i in s for s in BENCH_IDS.values()) and not all(i in s for s in BENCH_IDS.values())]
        self.assertGreaterEqual(len(both), 9, both)

    def test_same_verdict_per_container_and_cis_id(self):
        wrong = []
        for name, suffix in NAMES.items():
            hc = INSPECT[name]["HostConfig"]
            for cid in COMPARED:
                if cid == "5.2" and not APPARMOR:
                    continue
                tool, bench = cid in TOOL_IDS[name], cid in BENCH_IDS[name]
                if cid == "5.4":
                    bench = bool(hc.get("CapAdd"))  # see module docstring: Docker Bench's 5.4 is broken
                if cid == "5.15":
                    if bench and not tool:
                        wrong.append((suffix, cid, "tool misses a Docker Bench WARN"))
                    bench = cis_5_15(hc)
                if cid in SUBSET and cid != "5.15":
                    if bench and not tool:
                        wrong.append((suffix, cid, "tool misses a Docker Bench WARN"))
                    continue
                if tool != bench:
                    wrong.append((suffix, cid, "tool=%s reference=%s" % (tool, bench)))
        self.assertEqual(wrong, [])

    def test_read_only_sensitive_mount_is_reported_at_lower_severity(self):
        name = PREFIX + "-etcro"
        p = subprocess.run([sys.executable, TOOL, "--json", "--include", "5.6"], stdout=subprocess.PIPE,
                           universal_newlines=True, timeout=300)
        c = [c for c in json.loads(p.stdout)["containers"] if c["name"] == name][0]
        self.assertEqual([(f["id"], f["severity"]) for f in c["findings"]], [("5.6", "MEDIUM")])
        self.assertNotIn("5.6", BENCH_IDS[name])


if __name__ == "__main__":
    unittest.main()
