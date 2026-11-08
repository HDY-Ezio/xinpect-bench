# -*- coding: utf-8 -*-
"""命令行入口：对一个扫描器的 SARIF 输出，按 OWASP Benchmark 口径打分。"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from .adapters.sarif import Extraction, Mapping, SarifError, extract_detections, load_sarif
from .owasp import BenchmarkError, find_expected_csv, load_expected
from .score import apply_detections, score_cases

__version__ = "0.1.0"


def _print_report(report, extraction: Extraction, label: str, strict_fp: bool) -> None:
    d = report.as_dict()
    print("=" * 74)
    print("OWASP Benchmark 评测结果  ·  %s" % label)
    if strict_fp:
        print("口径：strict-fp（non-vulnerable 用例报出任何问题都计 FP）")
    print("=" * 74)
    print("%-16s %6s %6s %6s %6s | %7s %7s" % ("category", "TP", "FP", "FN", "TN", "TPR", "FPR"))
    print("-" * 74)
    for cat, s in d["by_category"].items():
        print("%-16s %6d %6d %6d %6d | %6.1f%% %6.1f%%"
              % (cat, s["tp"], s["fp"], s["fn"], s["tn"], s["tpr"] * 100, s["fpr"] * 100))
    print("-" * 74)
    print("总体: TP=%d FP=%d FN=%d TN=%d" % (d["tp"], d["fp"], d["fn"], d["tn"]))
    print("TPR=%.1f%%  FPR=%.1f%%  score=%.1f%%"
          % (d["tpr"] * 100, d["fpr"] * 100, d["score"] * 100))
    if d["fp_samples"]:
        print("\n误报样本（非漏洞用例被报了对应类别）:")
        for cat, names in d["fp_samples"].items():
            print("  %s (%d): %s" % (cat, len(names), ", ".join(names[:12]) +
                                     (" …" if len(names) > 12 else "")))
    print("\nSARIF 结果条数=%d  已映射=%d  未映射=%d  无定位=%d"
          % (extraction.hits, extraction.mapped_hits,
             sum(extraction.unmapped.values()), extraction.no_location))
    if extraction.unmapped:
        print("未映射的 ruleId（补到 mapping.json 的 rules 里，否则等于零检出）:")
        for rid, n in sorted(extraction.unmapped.items(), key=lambda kv: -kv[1])[:15]:
            print("  %-60s %d" % (rid, n))


def _markdown(report, extraction: Extraction, label: str) -> str:
    d = report.as_dict()
    lines = ["# OWASP Benchmark 评测结果", "", "- 被测对象：%s" % label,
             "- TP=%d FP=%d FN=%d TN=%d" % (d["tp"], d["fp"], d["fn"], d["tn"]),
             "- **TPR=%.1f%%　FPR=%.1f%%　score=%.1f%%**"
             % (d["tpr"] * 100, d["fpr"] * 100, d["score"] * 100), "",
             "| category | TP | FP | FN | TN | TPR | FPR |", "|---|---|---|---|---|---|---|"]
    for cat, s in d["by_category"].items():
        lines.append("| %s | %d | %d | %d | %d | %.1f%% | %.1f%% |"
                     % (cat, s["tp"], s["fp"], s["fn"], s["tn"], s["tpr"] * 100, s["fpr"] * 100))
    lines.append("")
    lines.append("未映射规则 %d 条，无定位结果 %d 条。"
                 % (sum(extraction.unmapped.values()), extraction.no_location))
    return "\n".join(lines) + "\n"


def cmd_score(args) -> int:
    expected = Path(args.expected) if args.expected else find_expected_csv(Path(args.owasp_dir))
    cases = load_expected(expected, args.expect_cases)
    mapping = Mapping.load(Path(args.mapping) if args.mapping else None)
    sarif = load_sarif(Path(args.sarif))
    extraction = extract_detections(sarif, mapping)
    apply_detections(cases, extraction.detected)
    report = score_cases(cases, strict_fp=args.strict_fp)

    label = args.label or Path(args.sarif).name
    _print_report(report, extraction, label, args.strict_fp)

    d = report.as_dict()
    if args.format == "json":
        payload = {"label": label, "expect_cases": len(cases),
                   "unmapped_rules": extraction.unmapped,
                   "no_location": extraction.no_location, **d}
        text = json.dumps(payload, ensure_ascii=False, indent=2)
    elif args.format == "markdown":
        text = _markdown(report, extraction, label)
    else:
        text = ""
    if text and args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print("\n结果已写入 %s" % args.out)

    rc = 0
    if args.fail_on_fp and d["fp"] > 0:
        print("\n[FAIL] 出现 %d 个误报（--fail-on-fp）" % d["fp"])
        rc = 1
    if args.fail_under is not None and d["score"] < args.fail_under:
        print("\n[FAIL] score=%.1f%% 低于阈值 %.1f%%"
              % (d["score"] * 100, args.fail_under * 100))
        rc = 1
    if args.max_unmapped_ratio is not None and extraction.hits:
        ratio = sum(extraction.unmapped.values()) / extraction.hits
        if ratio > args.max_unmapped_ratio:
            print("\n[FAIL] 未映射规则占比 %.1f%% 超过 %.1f%%，分数不可比"
                  % (ratio * 100, args.max_unmapped_ratio * 100))
            rc = 1
    return rc


def cmd_run(args) -> int:
    """先跑一条外部命令产出 SARIF，再打分。命令里用 {sarif} 占位输出路径。"""
    if "{sarif}" not in args.command:
        print("[error] --command 里必须包含 {sarif} 占位符，例如：\n"
              "  xinpect-bench run --command \"semgrep --sarif --output {sarif} <目标>\"", file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="xinpect-bench-")) / "out.sarif"
    cmd = args.command.replace("{sarif}", str(tmp))
    print("运行: %s" % cmd, flush=True)
    proc = subprocess.run(cmd, shell=True)
    if not tmp.is_file():
        print("[error] 命令结束但没有产出 SARIF（退出码 %d）" % proc.returncode, file=sys.stderr)
        return 2
    args.sarif = str(tmp)
    return cmd_score(args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="xinpect-bench",
        description="按 OWASP Benchmark 口径给代码扫描器打分（读 SARIF）。")
    p.add_argument("--version", action="version", version="xinpect-bench %s" % __version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--owasp-dir", default=".", help="OWASP Benchmark 项目根目录（含 expectedresults*.csv）")
        sp.add_argument("--expected", help="显式指定期望结果 CSV")
        sp.add_argument("--expect-cases", type=int, default=None,
                        help="锁定用例数；对不上直接拒绝出分（防题库漂移）")
        sp.add_argument("--mapping", help="规则到类别的映射 JSON")
        sp.add_argument("--strict-fp", action="store_true", help="更严格的口径：报任何问题都算 FP")
        sp.add_argument("--format", choices=["console", "json", "markdown"], default="console")
        sp.add_argument("--out", help="把 json/markdown 结果写到文件")
        sp.add_argument("--label", help="报告标题里的被测对象名称")
        sp.add_argument("--fail-under", type=float, default=None,
                        help="score 低于该值（0~1）则退出码 1")
        sp.add_argument("--fail-on-fp", action="store_true", help="有任何 FP 就退出码 1")
        sp.add_argument("--max-unmapped-ratio", type=float, default=0.0,
                        help="未映射规则占比上限，默认 0（有未映射就判失败）")

    sp_score = sub.add_parser("score", help="对已有的 SARIF 文件打分")
    common(sp_score)
    sp_score.add_argument("--sarif", required=True, help="扫描器导出的 SARIF 文件")
    sp_score.set_defaults(func=cmd_score)

    sp_run = sub.add_parser("run", help="跑一条扫描命令产出 SARIF 再打分")
    common(sp_run)
    sp_run.add_argument("--command", required=True, help="含 {sarif} 占位符的扫描命令")
    sp_run.set_defaults(func=cmd_run)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (BenchmarkError, SarifError) as e:
        print("[error] %s" % e, file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print("[error] %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
