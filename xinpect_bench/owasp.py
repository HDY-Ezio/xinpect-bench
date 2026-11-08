# -*- coding: utf-8 -*-
"""OWASP Benchmark 题库解析。

只做两件事：把 expectedresults CSV 读成用例列表；把用例名规范成统一形式。
不做任何「补数据」的动作 —— 缺列、类别未知、真实标记不合法，一律报错而不是猜。
"""
from __future__ import annotations

import csv
import os
from pathlib import Path

from .score import Case

# OWASP Benchmark v1.2 的 11 个漏洞类别（Java 版）。
# 这份清单用来校验「题库没被换掉」，不是用来补映射。
KNOWN_CATEGORIES = {
    "cmdi", "crypto", "hash", "header", "ldapi", "pathtraver", "redirect",
    "securecookie", "sqli", "trustbound", "weakrand", "xpathi", "xss",
    "deserialization",
}


class BenchmarkError(RuntimeError):
    """题库不可用时的显式失败，绝不降级成「部分用例继续打分」。"""


def normalize_case_name(name: str) -> str:
    """`BenchmarkTest00001.java` / `file:///x/BenchmarkTest00001.java` -> `BenchmarkTest00001`."""
    base = os.path.basename(name.strip())
    for ext in (".java", ".py", ".js", ".ts", ".go", ".php"):
        if base.endswith(ext):
            base = base[: -len(ext)]
            break
    return base


def find_expected_csv(owasp_dir: Path) -> Path:
    owasp_dir = Path(owasp_dir)
    candidates = sorted(owasp_dir.glob("expectedresults*.csv"))
    if not candidates:
        raise BenchmarkError(
            "在 %s 下找不到 expectedresults*.csv。请把 OWASP Benchmark 项目解压到这里，"
            "或显式用 --expected 指定文件。" % owasp_dir
        )
    return candidates[0]


def load_expected(path: Path, expect_cases: int | None = None) -> list[Case]:
    path = Path(path)
    if not path.is_file():
        raise BenchmarkError("期望文件不存在: %s" % path)

    cases: list[Case] = []
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        rows = list(csv.reader(fh))
    if not rows:
        raise BenchmarkError("期望文件是空的: %s" % path)

    # OWASP 官方文件首行是注释列头，以 # 开头；兼容没有注释行的变体。
    start = 1 if rows[0] and rows[0][0].lstrip().startswith("#") else 0
    for lineno, row in enumerate(rows[start:], start=start + 1):
        if not row or not row[0].strip():
            continue
        if len(row) < 3:
            raise BenchmarkError("第 %d 行少于 3 列，无法判定真实标签: %r" % (lineno, row))
        name = normalize_case_name(row[0])
        category = row[1].strip().lower()
        raw = row[2].strip().lower()
        if raw not in ("true", "false"):
            raise BenchmarkError(
                "第 %d 行真实标记不是 true/false: %r（拒绝猜）" % (lineno, row[2])
            )
        if not category:
            raise BenchmarkError("第 %d 行类别为空: %r" % (lineno, row))
        cases.append(Case(name=name, category=category, real=(raw == "true")))

    if not cases:
        raise BenchmarkError("期望文件里没有解析出任何用例: %s" % path)

    if expect_cases is not None and len(cases) != expect_cases:
        raise BenchmarkError(
            "题库漂移：解析出 %d 个用例，期望 %d 个。题库被换过或文件截断，"
            "拒绝出分（分数会不可比）。" % (len(cases), expect_cases)
        )

    dup = len(cases) - len({c.name for c in cases})
    if dup:
        raise BenchmarkError("用例名重复 %d 次，期望文件不可信" % dup)

    unknown = sorted({c.category for c in cases} - KNOWN_CATEGORIES)
    if unknown:
        # 不报错：允许用户用自定义题库；但要明确告知，避免「类别全不匹配 → 0 分」查不出原因。
        print("[warn] 出现非 OWASP 标准类别: %s（自定义题库可忽略）" % ", ".join(unknown))
    return cases
