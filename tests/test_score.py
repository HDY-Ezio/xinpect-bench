# -*- coding: utf-8 -*-
"""打分与解析的正确性测试。这些断言就是「分数不可造假」的底线。"""
import json
import tempfile
import unittest
from pathlib import Path

from xinpect_bench.adapters.sarif import Mapping, extract_detections, load_sarif
from xinpect_bench.owasp import BenchmarkError, load_expected, normalize_case_name
from xinpect_bench.score import Case, apply_detections, score_cases


def cases(*specs):
    return [Case(name=n, category=c, real=r) for n, c, r in specs]


class TestScoring(unittest.TestCase):
    def test_perfect_run(self):
        cs = cases(("A", "sqli", True), ("B", "sqli", False))
        apply_detections(cs, {"A": {"sqli"}})
        r = score_cases(cs)
        self.assertEqual((r.tp, r.fp, r.fn, r.tn), (1, 0, 0, 1))
        self.assertAlmostEqual(r.tpr, 1.0)
        self.assertAlmostEqual(r.fpr, 0.0)
        self.assertAlmostEqual(r.score, 1.0)

    def test_miss_and_false_positive(self):
        cs = cases(("A", "sqli", True), ("B", "sqli", False), ("C", "xss", True))
        apply_detections(cs, {"B": {"sqli"}})  # 真漏洞全漏，非漏洞误报一条
        r = score_cases(cs)
        self.assertEqual((r.tp, r.fp, r.fn, r.tn), (0, 1, 2, 0))
        self.assertAlmostEqual(r.tpr, 0.0)
        self.assertAlmostEqual(r.fpr, 1.0)
        self.assertAlmostEqual(r.score, -1.0)
        self.assertIn("B", r.fp_samples["sqli"])

    def test_zero_detections_scores_zero_not_minus_one(self):
        # OWASP 的 score = TPR - FPR：什么都没报时 TPR=0 且 FPR=0，score 也是 0。
        # 这正好说明单一 score 有歧义，看结论必须同时看 TPR 和 FPR。
        cs = cases(("A", "sqli", True), ("B", "sqli", False))
        apply_detections(cs, {})
        r = score_cases(cs)
        self.assertEqual((r.tp, r.fp, r.fn, r.tn), (0, 0, 1, 1))
        self.assertAlmostEqual(r.tpr, 0.0)
        self.assertAlmostEqual(r.fpr, 0.0)
        self.assertAlmostEqual(r.score, 0.0)

    def test_empty_cases_refuses_to_score(self):
        with self.assertRaises(ValueError):
            score_cases([])

    def test_strict_fp_counts_any_finding_on_clean_case(self):
        cs = cases(("A", "xss", False),)
        apply_detections(cs, {"A": {"sqli"}})  # 干净用例报了个别的类别
        self.assertEqual(score_cases(cs).fp, 0)                     # OWASP 口径
        self.assertEqual(score_cases(cs, strict_fp=True).fp, 1)      # 严格口径

    def test_per_category_split(self):
        cs = cases(("A", "sqli", True), ("B", "xss", True), ("C", "xss", False))
        apply_detections(cs, {"A": {"sqli"}, "B": {"xss"}, "C": {"xss"}})
        d = score_cases(cs).as_dict()
        self.assertEqual(d["by_category"]["sqli"]["tp"], 1)
        self.assertEqual(d["by_category"]["xss"]["fp"], 1)
        self.assertEqual(d["by_category"]["xss"]["tpr"], 1.0)


class TestExpectedFile(unittest.TestCase):
    def _write(self, text):
        f = Path(tempfile.mkdtemp()) / "expectedresults-x.csv"
        f.write_text(text, encoding="utf-8")
        return f

    def test_parses_official_shape(self):
        f = self._write("# test name,category,real vulnerability,cwe\n"
                        "BenchmarkTest00001,pathtraver,true,CWE-22\n"
                        "BenchmarkTest00002,pathtraver,false,CWE-22\n")
        cs = load_expected(f)
        self.assertEqual(len(cs), 2)
        self.assertTrue(cs[0].real)
        self.assertFalse(cs[1].real)

    def test_rejects_bad_real_flag_instead_of_guessing(self):
        f = self._write("# x\nBenchmarkTest00001,sqli,yes,CWE-89\n")
        with self.assertRaises(BenchmarkError):
            load_expected(f)

    def test_refuses_score_card_when_benchmark_drifts(self):
        f = self._write("# x\nBenchmarkTest00001,sqli,true,CWE-89\n")
        with self.assertRaises(BenchmarkError):
            load_expected(f, expect_cases=2740)

    def test_rejects_duplicate_cases(self):
        f = self._write("# x\nBenchmarkTest00001,sqli,true,CWE-89\n"
                        "BenchmarkTest00001,sqli,false,CWE-89\n")
        with self.assertRaises(BenchmarkError):
            load_expected(f)

    def test_normalize_name(self):
        self.assertEqual(normalize_case_name("file:///a/b/BenchmarkTest00001.java"),
                         "BenchmarkTest00001")
        self.assertEqual(normalize_case_name("BenchmarkTest00001.java"), "BenchmarkTest00001")


class TestSarifMapping(unittest.TestCase):
    def _extract(self, results, mapping_dict=None):
        d = Path(tempfile.mkdtemp())
        sarif = d / "s.sarif"
        sarif.write_text(json.dumps({"version": "2.1.0", "runs": [{"results": results}]}),
                         encoding="utf-8")
        mp = None
        if mapping_dict is not None:
            m = d / "m.json"
            m.write_text(json.dumps(mapping_dict), encoding="utf-8")
            mp = Mapping.load(m)
        else:
            mp = Mapping()
        return extract_detections(load_sarif(sarif), mp)

    def _res(self, case, rule, msg=""):
        return {"ruleId": rule, "message": {"text": msg},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "file:///t/%s.java" % case}}}]}

    def test_exact_rule_beats_pattern(self):
        ex = self._extract([self._res("BenchmarkTest00001", "java/sql-injection")],
                           {"rules": {"java/sql-injection": "sqli"},
                            "patterns": [{"match": "*sql*", "category": "xss"}]})
        self.assertEqual(ex.detected["BenchmarkTest00001"], {"sqli"})

    def test_pattern_glob(self):
        ex = self._extract([self._res("BenchmarkTest00002", "java.lang.path-traversal.a")],
                           {"patterns": [{"match": "*path-traversal*", "category": "pathtraver"}]})
        self.assertEqual(ex.detected["BenchmarkTest00002"], {"pathtraver"})

    def test_keyword_fallback_on_message(self):
        ex = self._extract([self._res("BenchmarkTest00003", "W-1", "可能的 SQL 注入")],
                           {"keywords": [{"match": "sql 注入", "category": "sqli"}]})
        self.assertEqual(ex.detected["BenchmarkTest00003"], {"sqli"})

    def test_unmapped_is_reported_not_silently_dropped(self):
        ex = self._extract([self._res("BenchmarkTest00004", "unknown-rule")], {})
        self.assertEqual(ex.detected, {})
        self.assertEqual(ex.unmapped["unknown-rule"], 1)
        self.assertEqual(ex.mapped_hits, 0)

    def test_missing_location_is_counted(self):
        ex = self._extract([{"ruleId": "x", "message": {"text": ""}}],
                           {"rules": {"x": "sqli"}})
        self.assertEqual(ex.no_location, 1)


if __name__ == "__main__":
    unittest.main()
