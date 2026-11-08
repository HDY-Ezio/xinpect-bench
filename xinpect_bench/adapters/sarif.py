# -*- coding: utf-8 -*-
"""SARIF 2.1.0 reading, and "rule -> OWASP category" mapping.

Why SARIF: CodeQL, Semgrep, SonarQube, Bandit, gosec and ESLint can all emit it.
A benchmark tool speaks the industry standard so that other people can point it at
their own scanner -- a tool that only understands one vendor's private JSON is
useful to its author and nobody else.

Unmapped rules are never dropped silently: they are counted and reported on their
own line. Low mapping coverage makes a score incomparable, so it has to be visible.
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path

from ..owasp import normalize_case_name


class SarifError(RuntimeError):
    pass


@dataclass
class Mapping:
    rules: dict[str, str] = field(default_factory=dict)
    patterns: list[tuple[str, str]] = field(default_factory=list)
    keywords: list[tuple[str, str]] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None) -> "Mapping":
        if path is None:
            return cls()
        path = Path(path)
        if not path.is_file():
            raise SarifError("mapping file does not exist: %s" % path)
        data = json.loads(path.read_text(encoding="utf-8"))
        m = cls()
        m.rules = {str(k).lower(): str(v) for k, v in (data.get("rules") or {}).items()}
        for item in (data.get("patterns") or []):
            m.patterns.append((str(item["match"]).lower(), str(item["category"])))
        for item in (data.get("keywords") or []):
            m.keywords.append((str(item["match"]).lower(), str(item["category"])))
        return m

    def resolve(self, rule_id: str, message: str = "") -> str | None:
        rid = (rule_id or "").strip().lower()
        msg = (message or "").strip().lower()
        if rid and rid in self.rules:
            return self.rules[rid]
        for pattern, category in self.patterns:
            if rid and fnmatch.fnmatch(rid, pattern):
                return category
        for kw, category in self.keywords:
            if kw and (kw in rid or kw in msg):
                return category
        return None


def load_sarif(path: Path) -> dict:
    path = Path(path)
    if not path.is_file():
        raise SarifError("SARIF file does not exist: %s" % path)
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        raise SarifError("SARIF is not valid JSON (%s): %s" % (path, e))
    if not isinstance(data, dict) or "runs" not in data:
        raise SarifError("not a SARIF 2.x document (no runs key): %s" % path)
    return data


@dataclass
class Extraction:
    detected: dict[str, set[str]] = field(default_factory=dict)
    unmapped: dict[str, int] = field(default_factory=dict)
    no_location: int = 0
    hits: int = 0

    @property
    def mapped_hits(self) -> int:
        return self.hits - sum(self.unmapped.values())


def extract_detections(sarif: dict, mapping: Mapping) -> Extraction:
    """Fold SARIF results into "case name -> set of detected categories"."""
    out = Extraction()
    for run in (sarif.get("runs") or []):
        for result in (run.get("results") or []):
            out.hits += 1
            rule_id = str(result.get("ruleId") or "")
            if not rule_id:
                rule_obj = result.get("rule") or {}
                rule_id = str(rule_obj.get("id") or "")
            message = ""
            msg = result.get("message")
            if isinstance(msg, dict):
                message = str(msg.get("text") or "")
            elif isinstance(msg, str):
                message = msg

            locations = result.get("locations") or []
            if not locations:
                out.no_location += 1
                continue
            loc = locations[0] or {}
            physical = loc.get("physicalLocation") or {}
            artifact = physical.get("artifactLocation") or {}
            uri = artifact.get("uri") or ""
            if not uri:
                out.no_location += 1
                continue
            case = normalize_case_name(str(uri))

            category = mapping.resolve(rule_id, message)
            if category is None:
                out.unmapped[rule_id or "(no-rule-id)"] = out.unmapped.get(rule_id or "(no-rule-id)", 0) + 1
                continue
            out.detected.setdefault(case, set()).add(category)
    return out
