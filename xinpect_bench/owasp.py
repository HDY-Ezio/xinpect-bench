# -*- coding: utf-8 -*-
"""OWASP Benchmark corpus parsing.

Two jobs only: read expectedresults CSV into a list of cases; normalise case names.
It never "fills in" missing data -- a bad column count, an empty category or an
invalid real/not-real flag is an error, not a guess.
"""
from __future__ import annotations

import csv
import os
from pathlib import Path

from .score import Case

# The vulnerability categories of OWASP Benchmark v1.2 (Java edition).
# This list is used to detect that the corpus was swapped, not to fill in mappings.
KNOWN_CATEGORIES = {
    "cmdi", "crypto", "hash", "header", "ldapi", "pathtraver", "redirect",
    "securecookie", "sqli", "trustbound", "weakrand", "xpathi", "xss",
    "deserialization",
}


class BenchmarkError(RuntimeError):
    """Explicit failure when the corpus is unusable. Never degrades to partial scoring."""


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
            "no expectedresults*.csv found under %s. Unpack the OWASP Benchmark "
            "checkout there, or point --expected at the file." % owasp_dir
        )
    return candidates[0]


def load_expected(path: Path, expect_cases: int | None = None) -> list[Case]:
    path = Path(path)
    if not path.is_file():
        raise BenchmarkError("expected-results file does not exist: %s" % path)

    cases: list[Case] = []
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        rows = list(csv.reader(fh))
    if not rows:
        raise BenchmarkError("expected-results file is empty: %s" % path)

    # The official file starts with a commented header line (# ...); tolerate variants without it.
    start = 1 if rows[0] and rows[0][0].lstrip().startswith("#") else 0
    for lineno, row in enumerate(rows[start:], start=start + 1):
        if not row or not row[0].strip():
            continue
        if len(row) < 3:
            raise BenchmarkError("line %d has fewer than 3 columns: %r" % (lineno, row))
        name = normalize_case_name(row[0])
        category = row[1].strip().lower()
        raw = row[2].strip().lower()
        if raw not in ("true", "false"):
            raise BenchmarkError(
                "line %d: real-vulnerability flag must be true/false, got %r (refusing to guess)"
                % (lineno, row[2])
            )
        if not category:
            raise BenchmarkError("line %d has an empty category: %r" % (lineno, row))
        cases.append(Case(name=name, category=category, real=(raw == "true")))

    if not cases:
        raise BenchmarkError("no cases parsed from %s" % path)

    if expect_cases is not None and len(cases) != expect_cases:
        raise BenchmarkError(
            "corpus drift: parsed %d cases, expected %d. The corpus was swapped or the "
            "file was truncated, so scores would not be comparable. Refusing to score."
            % (len(cases), expect_cases)
        )

    dup = len(cases) - len({c.name for c in cases})
    if dup:
        raise BenchmarkError("%d duplicate case names: the expected-results file is unreliable" % dup)

    unknown = sorted({c.category for c in cases} - KNOWN_CATEGORIES)
    if unknown:
        # Not an error: a custom corpus is allowed. But say it out loud, so that
        # "categories never match, score is 0" is not a mystery later.
        print("[warn] non-OWASP categories present: %s (ignore if this is a custom corpus)"
              % ", ".join(unknown))
    return cases
