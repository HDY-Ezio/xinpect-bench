# -*- coding: utf-8 -*-
"""端到端：造一份 mini 题库 + mini SARIF，跑真正的命令行，检查退出码与分数。

这条测试存在的原因：单测全绿但 CLI 跑不起来，是开源项目最常见的假绿。
"""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from xinpect_bench.cli import main

EXPECTED = """# test name,category,real vulnerability,cwe
BenchmarkTest00001,sqli,true,CWE-89
BenchmarkTest00002,sqli,false,CWE-89
BenchmarkTest00003,xss,true,CWE-79
BenchmarkTest00004,xss,false,CWE-79
"""


def _res(case, rule):
    return {"ruleId": rule, "message": {"text": ""},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "file:///t/%s.java" % case}}}]}


class TestCliEndToEnd(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "expectedresults-test.csv").write_text(EXPECTED, encoding="utf-8")
        self.mapping = self.dir / "mapping.json"
        self.mapping.write_text(json.dumps(
            {"rules": {"R-SQLI": "sqli", "R-XSS": "xss"}}), encoding="utf-8")

    def _sarif(self, results):
        p = self.dir / "out.sarif"
        p.write_text(json.dumps({"version": "2.1.0", "runs": [{"results": results}]}),
                     encoding="utf-8")
        return p

    def _run(self, sarif, *extra):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = main(["score", "--owasp-dir", str(self.dir), "--sarif", str(sarif),
                       "--mapping", str(self.mapping), *extra])
        return rc, buf.getvalue()

    def test_perfect_detection_exits_zero(self):
        s = self._sarif([_res("BenchmarkTest00001", "R-SQLI"),
                         _res("BenchmarkTest00003", "R-XSS")])
        rc, out = self._run(s)
        self.assertEqual(rc, 0)
        self.assertIn("TP=2 FP=0 FN=0 TN=2", out)
        self.assertIn("score=100.0%", out)

    def test_one_false_positive_fails_when_asked(self):
        s = self._sarif([_res("BenchmarkTest00001", "R-SQLI"),
                         _res("BenchmarkTest00002", "R-SQLI"),
                         _res("BenchmarkTest00003", "R-XSS")])
        rc, out = self._run(s, "--fail-on-fp")
        self.assertEqual(rc, 1)
        self.assertIn("FP=1", out)

    def test_unmapped_rules_are_fatal_by_default(self):
        s = self._sarif([_res("BenchmarkTest00001", "R-SQLI"),
                         _res("BenchmarkTest00003", "R-UNKNOWN")])
        rc, out = self._run(s)
        self.assertEqual(rc, 1)
        self.assertIn("R-UNKNOWN", out)

    def test_sarif_without_results_is_loud_not_silent(self):
        s = self._sarif([])
        rc, out = self._run(s, "--max-unmapped-ratio", "1.0")
        self.assertEqual(rc, 0)
        self.assertIn("TP=0 FP=0 FN=2 TN=2", out)

    def test_missing_sarif_returns_2(self):
        rc, _ = self._run(self.dir / "nope.sarif")
        self.assertEqual(rc, 2)

    def test_json_output_written(self):
        s = self._sarif([_res("BenchmarkTest00001", "R-SQLI"),
                         _res("BenchmarkTest00003", "R-XSS")])
        out_file = self.dir / "result.json"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = main(["score", "--owasp-dir", str(self.dir), "--sarif", str(s),
                       "--mapping", str(self.mapping), "--format", "json",
                       "--out", str(out_file)])
        self.assertEqual(rc, 0)
        data = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual(data["score"], 1.0)
        self.assertEqual(data["expect_cases"], 4)


if __name__ == "__main__":
    unittest.main()
