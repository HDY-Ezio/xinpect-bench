# -*- coding: utf-8 -*-
"""Scoring core for OWASP Benchmark style evaluation.

Design rules, each one the result of a failure mode seen in the wild
(see docs/methodology.md):

1. A score may only be computed from per-case verdicts, never back-derived from
   an aggregate.
2. A request or parse failure must be counted explicitly. Never skip silently --
   skipping shrinks the denominator and raises the score, which is the most
   common form of fake green in SAST benchmarking.
3. Corpus drift (case count disagrees with the expected value) refuses to score.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class Case:
    """One test case: what is expected, and what was actually detected."""

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
        """OWASP Benchmark convention: score = TPR - FPR, range -1.0 to 1.0."""
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
    """Score per case, using the OWASP convention.

    strict_fp=False (default, the official OWASP convention): a real case is a hit
    only if the finding lands in that case's own category; a non-vulnerable case
    counts as FP only if it was flagged with that same category.
    strict_fp=True: any finding on a non-vulnerable case counts as FP. Closer to how
    production feels, but it punishes "reported something else in the same file" --
    say which convention you used when comparing against other tools.
    """
    if not cases:
        raise ValueError("no cases to score: check that the expected-results file "
                         "and the SARIF actually refer to the same corpus")

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
    """Attach "case name -> detected categories" to the cases; a missing case means zero findings."""
    for c in cases:
        c.detected = set(detected.get(c.name, ()))
    return cases
