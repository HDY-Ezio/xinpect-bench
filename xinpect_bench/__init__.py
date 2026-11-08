# -*- coding: utf-8 -*-
"""xinpect-bench：按 OWASP Benchmark 口径给代码扫描器打分。

对外只需要三样东西：Case / score_cases / load_expected。
"""
from .owasp import BenchmarkError, find_expected_csv, load_expected, normalize_case_name
from .score import Case, CategoryStats, ScoreReport, apply_detections, score_cases

__version__ = "0.1.0"
__all__ = [
    "Case", "CategoryStats", "ScoreReport", "apply_detections", "score_cases",
    "BenchmarkError", "find_expected_csv", "load_expected", "normalize_case_name",
    "__version__",
]
