#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""给 README 造一段「真实工具输出」的示例：虚构小数据集，数字由 xinpect-bench 自己算出来。

目的：README 顶部示例必须能做到两件事
1) 每一行的 TPR/FPR 和它自己的 TP/FP/FN/TN 对得上；
2) 合计行等于上面各行相加，且 TPR/FPR/score 由同一组整数算出。
手写这些数字迟早出错，所以这里真跑一遍。
"""
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# 目标：三个类别，合计 TP=25 FP=5 FN=1 TN=64（共 95 个用例）
# 类别          真漏洞(TP+FN)  干净(FP+TN)   设 TP   FP
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
    # 上面 fp 取自该类别末尾的干净用例，确保落在正确类别
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
