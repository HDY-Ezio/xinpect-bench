# -*- coding: utf-8 -*-
"""SARIF 2.1.0 读取与「规则 -> OWASP 类别」映射。

为什么用 SARIF：CodeQL、Semgrep、SonarQube、Bandit、gosec、ESLint 等都能导出
SARIF。用行业标准格式当接口，评测工具才可能被别人拿去测自己的扫描器 ——
如果只认某一家私有 JSON，这个工具就只对作者自己有用。

未映射的规则不会被静默丢弃，而是统计出来单独汇报：映射覆盖率低，分数就没有
可比性，必须让人看见。
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
            raise SarifError("映射文件不存在: %s" % path)
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
        raise SarifError("SARIF 文件不存在: %s" % path)
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        raise SarifError("SARIF 不是合法 JSON (%s): %s" % (path, e))
    if not isinstance(data, dict) or "runs" not in data:
        raise SarifError("不是 SARIF 2.x 结构（缺 runs）: %s" % path)
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
    """把 SARIF 结果折算成「用例名 -> 检出的漏洞类别集合」。"""
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
