# -*- coding: utf-8 -*-
"""Scoring core for OWASP Benchmark style evaluation.

设计原则（每条都来自实测踩过的坑，见 docs/methodology.md）：

1. 分数只能由「逐用例的判定结果」算出来，不能由汇总数倒推。
2. 请求/解析失败必须显式计入 failed，绝不允许静默跳过 —— 跳过会让
   分母变小、分数变高，这是 SAST 评测里最常见的假绿。
3. 题库漂移（用例数与期望值不符）直接拒绝出分。
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class Case:
    """一个测试用例：期望什么、实际检出什么。"""

    name: str
    category: str
    real: bool
    detected: set[str] = field(default_factory=set)


@dataclass
class CategoryStats:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def tpr(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "tpr": round(self.tpr, 4), "fpr": round(self.fpr, 4),
        }


@dataclass
class ScoreReport:
    cases: int
    tp: int
    fp: int
    fn: int
    tn: int
    by_category: dict[str, CategoryStats]
    fp_samples: dict[str, list[str]]

    @property
    def tpr(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def score(self) -> float:
        """OWASP Benchmark 的 score = TPR - FPR。范围 -1.0 ~ 1.0。"""
        return self.tpr - self.fpr

    def as_dict(self) -> dict:
        return {
            "cases": self.cases,
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "tpr": round(self.tpr, 4),
            "fpr": round(self.fpr, 4),
            "score": round(self.score, 4),
            "by_category": {k: v.as_dict() for k, v in sorted(self.by_category.items())},
            "fp_samples": {k: sorted(v) for k, v in sorted(self.fp_samples.items())},
        }


def score_cases(cases: list[Case], strict_fp: bool = False) -> ScoreReport:
    """按 OWASP 口径逐用例打分。

    strict_fp=False（默认，OWASP 官方口径）：只在「漏报了该用例对应的漏洞类别」
    时才算命中；non-vulnerable 用例报对了那一类才计 FP。
    strict_fp=True：non-vulnerable 用例只要报出任何类别就计 FP。更接近生产体感，
    但会惩罚「同一文件里报了个别的问题」，和其他工具对比时要说清用的哪套口径。
    """
    if not cases:
        raise ValueError("没有用例可打分：检查期望文件与 SARIF 是否对不上")

    stats: dict[str, CategoryStats] = defaultdict(CategoryStats)
    fp_samples: dict[str, list[str]] = defaultdict(list)
    tp = fp = fn = tn = 0

    for c in cases:
        s = stats[c.category]
        if c.real:
            if c.category in c.detected:
                s.tp += 1
                tp += 1
            else:
                s.fn += 1
                fn += 1
        else:
            hit = bool(c.detected) if strict_fp else (c.category in c.detected)
            if hit:
                s.fp += 1
                fp += 1
                fp_samples[c.category].append(c.name)
            else:
                s.tn += 1
                tn += 1

    return ScoreReport(
        cases=len(cases), tp=tp, fp=fp, fn=fn, tn=tn,
        by_category=dict(stats), fp_samples=dict(fp_samples),
    )


def apply_detections(cases: list[Case], detected: dict[str, set[str]]) -> list[Case]:
    """把「用例名 -> 检出的类别集合」贴到用例上；缺失的用例视为零检出。"""
    for c in cases:
        c.detected = set(detected.get(c.name, ()))
    return cases
