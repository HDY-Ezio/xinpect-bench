#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Produce the "real tool output" block shown in the READMEs: a made-up mini corpus,
scored by xinpect-bench itself.

Why run it instead of writing the numbers by hand: the sample at the top of the
README has to satisfy two things
1) every row's TPR/FPR is consistent with that row's own TP/FP/FN/TN;
2) the total row equals the sum of the rows, and TPR/FPR/score come from those
   same integers.
Handwritten numbers drift. So this actually runs the CLI.

tests/test_readme_sample.py re-runs this and fails if either README's block no
longer matches the real output.
"""
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# Target totals: 95 cases, TP=23 FP=5 FN=3 TN=64.
# category      real (TP+FN)  clean (FP+TN)   want TP   want FP
PLAN = [
    ("cmdi", 12, 22, 10, 2),
    ("pathtraver", 8, 24, 8, 3),
    ("sqli", 6, 23, 5, 0),
]


def main():
    tmp = tempfile.mkdtemp(prefix="xb_toy_")
    rows = []
    detections = []
    n = 0
    for cat, n_real, n_clean, tp, fp in PLAN:
        n_fn = n_real - tp
        for i in range(n_real):
            n += 1
            name = "BenchmarkTest%05d" % n
            rows.append((name, cat, "true", "CWE-000"))
            if i < tp:
                detections.append(name)
        for _ in range(n_clean):
            n += 1
            name = "BenchmarkTest%05d" % n
            rows.append((name, cat, "false", "CWE-000"))
        for _ in range(fp):
            detections.append("BenchmarkTest%05d" % (n - _))
    # The FP cases above are taken from the tail of each category's clean cases,
    # so each false positive lands in the category it was reported as.
    with open(os.path.join(tmp, "expectedresults-toy.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["# test name", "category", "real vulnerability", "cwe"])
        w.writerows(rows)

    rule = {"cmdi": "R-CMDI", "pathtraver": "R-PATH", "sqli": "R-SQLI"}
    cat_of = {r[0]: r[1] for r in rows}
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "demo-scanner", "rules": [{"id": v} for v in rule.values()]}},
            "results": [{
                "ruleId": rule[cat_of[d]],
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///toy/%s.java" % d}}}],
            } for d in detections],
        }],
    }
    with open(os.path.join(tmp, "demo.sarif"), "w", encoding="utf-8") as fh:
        json.dump(sarif, fh)
    with open(os.path.join(tmp, "map.json"), "w", encoding="utf-8") as fh:
        json.dump({"rules": {v: k for k, v in rule.items()}}, fh)

    env = dict(os.environ, PYTHONPATH=HERE, PYTHONIOENCODING="utf-8")
    out = subprocess.run(
        [sys.executable, "-m", "xinpect_bench.cli", "score",
         "--owasp-dir", tmp, "--sarif", os.path.join(tmp, "demo.sarif"),
         "--mapping", os.path.join(tmp, "map.json"), "--expect-cases", str(len(rows))],
        capture_output=True, text=True, env=env,
    )
    print(out.stdout)
    print(out.stderr, file=sys.stderr)
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
