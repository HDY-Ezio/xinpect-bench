# -*- coding: utf-8 -*-
"""The published benchmark artifact must stay internally consistent.

bench/ claims three things that are all checkable without owning the product or
downloading the corpus:

1. every rule ID in the published SARIF is mapped, so scoring cannot silently
   fall back to "unmapped" (which xinpect-bench treats as fatal, correctly);
2. rerunning the published transform on the published raw issues reproduces the
   published SARIF byte for byte;
3. the numbers in result-2026-11-08.txt, result-2026-11-08.json and the per-category
   table all agree with each other.

If any of these drifts, one of the claims on the front page is false, and nothing
downstream catches it. So they are pinned here rather than checked by hand once.

No numbers are hardcoded: the files are compared against each other, so updating
the artifact deliberately is allowed, and forgetting to update one of the files
is not.
"""
import gzip
import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "bench"
SARIF = BENCH / "xinpect-2026-11-08.sarif"
RAW_GZ = BENCH / "raw-2026-11-08.jsonl.gz"
MAPPING = BENCH / "mapping.json"
RESULT_TXT = BENCH / "result-2026-11-08.txt"
RESULT_JSON = BENCH / "result-2026-11-08.json"
TRANSFORM = BENCH / "collect.py"

MISSING = [p.name for p in (SARIF, RAW_GZ, MAPPING, RESULT_TXT, RESULT_JSON, TRANSFORM)
           if not p.exists()]


def _load_transform_module():
    spec = importlib.util.spec_from_file_location("bench_collect", TRANSFORM)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipIf(MISSING, "bench artifact not present: %s" % ", ".join(MISSING))
class TestBenchArtifact(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sarif = json.loads(SARIF.read_text(encoding="utf-8"))
        cls.run_data = cls.sarif["runs"][0]
        cls.results = cls.run_data["results"]
        cls.mapping = json.loads(MAPPING.read_text(encoding="utf-8"))["rules"]
        cls.result_data = json.loads(RESULT_JSON.read_text(encoding="utf-8"))
        cls.txt = RESULT_TXT.read_text(encoding="utf-8")

    def test_every_rule_id_in_the_sarif_is_mapped(self):
        used = {r["ruleId"].lower() for r in self.results}
        mapped = {k.lower() for k in self.mapping}
        unmapped = sorted(used - mapped)
        self.assertEqual(unmapped, [], "rules in the SARIF with no category: %r" % unmapped)

    def test_sarif_has_no_results_without_location(self):
        # A result without a location cannot be attributed to a case, so it would
        # be counted as "no location" and quietly vanish from the score.
        bad = [r for r in self.results
               if not (r.get("locations") and r["locations"][0].get("physicalLocation"))]
        self.assertEqual(bad, [])

    def test_declared_counts_match_the_actual_file(self):
        props = self.run_data["properties"]
        self.assertEqual(props["results_written"], len(self.results))
        # top-level + folded = written; the arithmetic is the whole point of the
        # transform, so a mismatch means the transform changed without the
        # published file being regenerated.
        self.assertEqual(
            props["top_level_issues"] + props["folded_entries"]
            - props["folded_duplicate_dropped"] - props["folded_without_rule"],
            props["results_written"],
        )

    def test_transform_from_raw_reproduces_the_published_sarif(self):
        mod = _load_transform_module()
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "raw.jsonl"
            with gzip.open(RAW_GZ, "rb") as src, open(raw, "wb") as dst:
                dst.write(src.read())
            out = Path(tmp) / "out.sarif"

            class Args:
                pass

            a = Args()
            a.raw = str(raw)
            a.out = str(out)
            rc = mod.cmd_sarif(a)
            self.assertEqual(rc, 0)
            self.assertEqual(
                out.read_bytes(), SARIF.read_bytes(),
                "rerunning bench/collect.py sarif on the published raw issues does not "
                "reproduce the published SARIF",
            )

    def test_console_and_json_agree(self):
        tot = re.search(r"Overall: TP=(\d+) FP=(\d+) FN=(\d+) TN=(\d+)", self.txt)
        self.assertIsNotNone(tot, "console output has no overall line")
        self.assertEqual(
            [int(x) for x in tot.groups()],
            [self.result_data["tp"], self.result_data["fp"], self.result_data["fn"], self.result_data["tn"]],
        )

        # Per-category rows must sum to that total; the published table is the
        # thing a reader compares against someone else's table.
        sums = [0, 0, 0, 0]
        for row in self.result_data["by_category"].values():
            for i, k in enumerate(("tp", "fp", "fn", "tn")):
                sums[i] += row[k]
        self.assertEqual(sums, [self.result_data["tp"], self.result_data["fp"],
                                self.result_data["fn"], self.result_data["tn"]])

        # And a single case must be in exactly one bucket.
        self.assertEqual(self.result_data["cases"],
                         self.result_data["tp"] + self.result_data["fp"]
                         + self.result_data["fn"] + self.result_data["tn"])

    def test_score_line_follows_from_the_counts(self):
        # Exact rates, not rounded percentages: see the note in test_readme_sample.py.
        m = re.search(r"TPR=([\d.]+)%\s+FPR=([\d.]+)%\s+score=([\d.]+)%", self.txt)
        self.assertIsNotNone(m, "console output has no TPR/FPR/score line")
        tpr_shown, fpr_shown, score_shown = (float(x) for x in m.groups())
        tp, fp, fn, tn = (self.result_data[k] for k in ("tp", "fp", "fn", "tn"))
        tpr_exact = tp / (tp + fn) * 100
        fpr_exact = fp / (fp + tn) * 100
        self.assertAlmostEqual(tpr_shown, tpr_exact, places=1)
        self.assertAlmostEqual(fpr_shown, fpr_exact, places=1)
        self.assertAlmostEqual(score_shown, tpr_exact - fpr_exact, places=1)


if __name__ == "__main__":
    unittest.main()
