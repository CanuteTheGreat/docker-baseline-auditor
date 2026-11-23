"""Shared CLI contract (docs/CLI-CONTRACT.md): exit codes, --json schema, --quiet, stderr for errors.

Static scans (--dockerfile) need no docker daemon, so the whole contract is exercised offline.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

import contract_support as cs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "docker_baseline_auditor.py")
sys.path.insert(0, ROOT)
import docker_baseline_auditor as tool  # noqa: E402

SCHEMA = cs.load_schema(ROOT, "docker-baseline-auditor")
GOOD = "FROM alpine:3.20\nUSER app\nHEALTHCHECK CMD true\n"
BAD = "FROM alpine\nADD http://example.invalid/y /y\nUSER root\n"  # MEDIUM + LOW findings, no HIGH


def cli(*args, env=None):
    return cs.run_cli(TOOL, args, env=env)


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.good = self.write("Dockerfile.good", GOOD)
        self.bad = self.write("Dockerfile.bad", BAD)

    def write(self, name, text):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            f.write(text)
        return path


class TestExitCodes(Files):
    def test_clean_is_0(self):
        self.assertEqual(cli("--dockerfile", self.good)[0], 0)

    def test_findings_is_1(self):
        self.assertEqual(cli("--dockerfile", self.bad, "--fail-on", "low")[0], 1)

    def test_findings_below_the_gate_are_0(self):
        self.assertEqual(cli("--dockerfile", self.bad)[0], 0)

    def test_bad_args_is_2_with_message_on_stderr(self):
        for a in (("--no-such-flag",), ("--fail-on", "bogus"), ("--dockerfile",)):
            rc, out, err = cli(*a)
            self.assertEqual(rc, 2, a)
            self.assertEqual(out, "", a)
            self.assertIn("usage:", err)

    def test_missing_dockerfile_is_2(self):
        rc, out, err = cli("--dockerfile", os.path.join(self.tmp, "nope"))
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("not found", err)

    def test_docker_unavailable_keeps_documented_legacy_code_2(self):
        rc, out, err = cli(env={"PATH": self.tmp})  # no docker binary on PATH
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("ERROR", err)

    def test_unexpected_error_is_3_on_stderr_not_a_traceback_exit_1(self):
        buf = io.StringIO()
        with mock.patch.object(tool, "_main", side_effect=RuntimeError("boom")), redirect_stderr(buf):
            self.assertEqual(tool.main(["--dockerfile", self.good]), 3)
        self.assertIn("RuntimeError: boom", buf.getvalue())


class TestJson(Files):
    def check(self, args, code):
        rc, out, err = cli("--json", *args)
        self.assertEqual(rc, code, err)
        doc = json.loads(out)  # exactly one JSON document, nothing else on stdout
        self.assertEqual(cs.validate(doc, SCHEMA), [])
        self.assertEqual(doc["exit_code"], rc)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["tool"], "docker-baseline-auditor")
        self.assertEqual(doc["version"], tool.__version__)
        return doc

    def test_clean(self):
        doc = self.check(("--dockerfile", self.good), 0)
        self.assertFalse(doc["summary"]["failed"])

    def test_findings(self):
        doc = self.check(("--dockerfile", self.bad, "--fail-on", "low"), 1)
        self.assertTrue(doc["summary"]["failed"])
        self.assertTrue(doc["files"][0]["findings"])

    def test_errors_leave_stdout_empty_even_with_json(self):
        rc, out, err = cli("--json", "--dockerfile", os.path.join(self.tmp, "nope"))
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("not found", err)
        rc, out, err = cli("--json", env={"PATH": self.tmp})  # no docker binary: never a JSON error document
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("ERROR", err)

    def test_schema_rejects_a_document_without_the_contract_keys(self):
        self.assertNotEqual(cs.validate({"daemon": []}, SCHEMA), [])
        good = {"schema_version": 1, "tool": "docker-baseline-auditor", "version": "1", "exit_code": 0,
                "daemon": [], "containers": [], "files": [],
                "summary": {"containers": 0, "files": 0, "fail_on": "high", "failed": False}}
        self.assertEqual(cs.validate(good, SCHEMA), [])
        self.assertNotEqual(cs.validate(dict(good, exit_code=9), SCHEMA), [])


class TestQuiet(Files):
    def test_quiet_prints_nothing_but_keeps_exit_code(self):
        for path, gate, code in ((self.good, "high", 0), (self.bad, "low", 1)):
            for extra in ((), ("--json",)):
                for flag in ("--quiet", "-q"):
                    rc, out, err = cli(flag, *(extra + ("--dockerfile", path, "--fail-on", gate)))
                    self.assertEqual((rc, out), (code, ""), (flag, extra, path))

    def test_without_quiet_the_report_is_printed(self):
        self.assertIn("Clean (no findings)", cli("--dockerfile", self.good)[1])


if __name__ == "__main__":
    unittest.main()
