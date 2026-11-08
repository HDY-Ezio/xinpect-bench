# -*- coding: utf-8 -*-
"""The sample block in the READMEs must equal the real output of the CLI.

This exists because it already went wrong once: the block at the top of README.md
once showed invented numbers whose per-category subtotals did not add up to the
total, while claiming to be a tool run. A benchmark tool whose own front page
cannot be reproduced is the exact failure it is built to catch, so the claim is
pinned by a test instead of by discipline.

The numbers are never written down here. The test runs the script, takes whatever
it prints, and compares. Changing the sample is allowed -- forgetting to update a
README is not.
"""
import contextlib
import io
import os
import re
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "docs" / "make_readme_sample.py"
READMES = ("README.md", "README.zh-CN.md")

# From the banner to the score line: the part a reader takes as "real output".
BLOCK = re.compile(r"OWASP Benchmark results.*?score=\d+\.\d+%", re.S)


def _real_output() -> str:
    buf = io.StringIO()
    cwd = os.getcwd()
    try:
        os.chdir(ROOT)
        with contextlib.redirect_stdout(buf):
            runpy.run_path(str(SCRIPT), run_name="__main__")
    finally:
        os.chdir(cwd)
    m = BLOCK.search(buf.getvalue())
    if not m:
        raise AssertionError("make_readme_sample.py printed no recognisable report block")
    return m.group(0)


class TestReadmeSampleIsReproducible(unittest.TestCase):
    def setUp(self):
        self.actual = [line.rstrip() for line in _real_output().splitlines()]

    def test_every_readme_shows_the_real_block(self):
        for name in READMES:
            with self.subTest(readme=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                m = BLOCK.search(text)
                self.assertIsNotNone(m, "%s has no sample block" % name)
                shown = [line.rstrip() for line in m.group(0).splitlines()]
                self.assertEqual(
                    shown, self.actual,
                    "%s shows a block that the tool does not actually print" % name,
                )

    def test_sample_rows_add_up_to_the_total(self):
        # The guard is here so that a hand-edited block that still *looks* fine
        # cannot pass: subtotals must sum to the total, and TPR/FPR must follow
        # from those integers.
        rows = [l for l in self.actual if re.match(r"^\S+\s+\d+\s+\d+\s+\d+\s+\d+\s+\|", l)]
        self.assertGreaterEqual(len(rows), 2, "expected at least two category rows")
        sums = [0, 0, 0, 0]
        for line in rows:
            nums = [int(x) for x in re.findall(r"\b\d+\b", line.split("|")[0])][-4:]
            for i, n in enumerate(nums):
                sums[i] += n
        total_line = next(l for l in self.actual if l.startswith("Overall:"))
        tot = [int(x) for x in re.findall(r"\d+", total_line)]
        self.assertEqual(sums, tot, "per-category subtotals do not sum to the total row")

        tp, fp, fn, tn = tot
        score_line = next(l for l in self.actual if "score=" in l)
        tpr = float(re.search(r"TPR=([\d.]+)%", score_line).group(1))
        fpr = float(re.search(r"FPR=([\d.]+)%", score_line).group(1))
        score = float(re.search(r"score=([\d.]+)%", score_line).group(1))

        # Exact rates, not the rounded percentages. The printed score is derived from
        # the exact rates, so subtracting the two rounded numbers can be off by 0.1
        # (here 88.5 - 7.2 = 81.3 while the true 88.46% - 7.25% = 81.2%). Comparing
        # against the exact values is the contract; comparing rounded-minus-rounded
        # would fail on correct output.
        tpr_exact = tp / (tp + fn) * 100
        fpr_exact = fp / (fp + tn) * 100
        self.assertAlmostEqual(tpr, tpr_exact, places=1)
        self.assertAlmostEqual(fpr, fpr_exact, places=1)
        self.assertAlmostEqual(score, tpr_exact - fpr_exact, places=1)


if __name__ == "__main__":
    unittest.main()
