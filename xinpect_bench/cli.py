# -*- coding: utf-8 -*-
"""Command line entry point: score a scanner's SARIF output against OWASP Benchmark."""
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
    print("OWASP Benchmark results  ·  %s" % label)
    if strict_fp:
        print("convention: strict-fp (any finding on a non-vulnerable case counts as FP)")
    print("=" * 74)
    print("%-16s %6s %6s %6s %6s | %7s %7s" % ("category", "TP", "FP", "FN", "TN", "TPR", "FPR"))
    print("-" * 74)
    for cat, s in d["by_category"].items():
        print("%-16s %6d %6d %6d %6d | %6.1f%% %6.1f%%"
              % (cat, s["tp"], s["fp"], s["fn"], s["tn"], s["tpr"] * 100, s["fpr"] * 100))
    print("-" * 74)
    print("Overall: TP=%d FP=%d FN=%d TN=%d" % (d["tp"], d["fp"], d["fn"], d["tn"]))
    print("TPR=%.1f%%  FPR=%.1f%%  score=%.1f%%"
          % (d["tpr"] * 100, d["fpr"] * 100, d["score"] * 100))
    if d["fp_samples"]:
        print("\nFalse-positive samples (clean cases flagged with their own category):")
        for cat, names in d["fp_samples"].items():
            print("  %s (%d): %s" % (cat, len(names), ", ".join(names[:12]) +
                                     (" ..." if len(names) > 12 else "")))
    print("\nSARIF results=%d  mapped=%d  unmapped=%d  no-location=%d"
          % (extraction.hits, extraction.mapped_hits,
             sum(extraction.unmapped.values()), extraction.no_location))
    if extraction.unmapped:
        print("Unmapped rule IDs (add them to rules in mapping.json, or they count as zero findings):")
        for rid, n in sorted(extraction.unmapped.items(), key=lambda kv: -kv[1])[:15]:
            print("  %-60s %d" % (rid, n))


def _markdown(report, extraction: Extraction, label: str) -> str:
    d = report.as_dict()
    lines = ["# OWASP Benchmark results", "", "- Target: %s" % label,
             "- TP=%d FP=%d FN=%d TN=%d" % (d["tp"], d["fp"], d["fn"], d["tn"]),
             "- **TPR=%.1f%%  FPR=%.1f%%  score=%.1f%%**"
             % (d["tpr"] * 100, d["fpr"] * 100, d["score"] * 100), "",
             "| category | TP | FP | FN | TN | TPR | FPR |", "|---|---|---|---|---|---|---|"]
    for cat, s in d["by_category"].items():
        lines.append("| %s | %d | %d | %d | %d | %.1f%% | %.1f%% |"
                     % (cat, s["tp"], s["fp"], s["fn"], s["tn"], s["tpr"] * 100, s["fpr"] * 100))
    lines.append("")
    lines.append("%d unmapped rules, %d results without a location."
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
        print("\nWrote %s" % args.out)

    rc = 0
    if args.fail_on_fp and d["fp"] > 0:
        print("\n[FAIL] %d false positive(s) (--fail-on-fp)" % d["fp"])
        rc = 1
    if args.fail_under is not None and d["score"] < args.fail_under:
        print("\n[FAIL] score=%.1f%% is below the threshold %.1f%%"
              % (d["score"] * 100, args.fail_under * 100))
        rc = 1
    if args.max_unmapped_ratio is not None and extraction.hits:
        ratio = sum(extraction.unmapped.values()) / extraction.hits
        if ratio > args.max_unmapped_ratio:
            print("\n[FAIL] unmapped rules are %.1f%% of all results, above %.1f%% "
                  "- the score is not comparable"
                  % (ratio * 100, args.max_unmapped_ratio * 100))
            rc = 1
    return rc


def cmd_run(args) -> int:
    """Run an external command to produce SARIF, then score it.

    The command must contain a {sarif} placeholder, which is replaced with a
    temporary output path.
    """
    if "{sarif}" not in args.command:
        print("[error] --command must contain the {sarif} placeholder, for example:\n"
              "  xinpect-bench run --command \"semgrep --sarif --output {sarif} <target>\"",
              file=sys.stderr)
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="xinpect-bench-")) / "out.sarif"
    cmd = args.command.replace("{sarif}", str(tmp))
    print("Running: %s" % cmd, flush=True)
    proc = subprocess.run(cmd, shell=True)
    if not tmp.is_file():
        print("[error] the command finished without producing SARIF (exit code %d)"
              % proc.returncode, file=sys.stderr)
        return 2
    args.sarif = str(tmp)
    return cmd_score(args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="xinpect-bench",
        description="Score any code scanner against the OWASP Benchmark methodology, from SARIF.")
    p.add_argument("--version", action="version", version="xinpect-bench %s" % __version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--owasp-dir", default=".",
                        help="OWASP Benchmark checkout (the directory holding expectedresults*.csv)")
        sp.add_argument("--expected", help="explicit path to the expected-results CSV")
        sp.add_argument("--expect-cases", type=int, default=None,
                        help="lock the number of cases; refuses to score if the corpus drifted")
        sp.add_argument("--mapping", help="JSON mapping from rule IDs to OWASP categories")
        sp.add_argument("--strict-fp", action="store_true",
                        help="stricter convention: any finding on a clean case counts as FP")
        sp.add_argument("--format", choices=["console", "json", "markdown"], default="console")
        sp.add_argument("--out", help="write the json/markdown report to this file")
        sp.add_argument("--label", help="name of the thing under test, used in the report title")
        sp.add_argument("--fail-under", type=float, default=None,
                        help="exit 1 if score is below this value (0 to 1)")
        sp.add_argument("--fail-on-fp", action="store_true",
                        help="exit 1 on any false positive")
        sp.add_argument("--max-unmapped-ratio", type=float, default=0.0,
                        help="max share of unmapped rules, default 0 (any unmapped rule fails)")

    sp_score = sub.add_parser("score", help="score an existing SARIF file")
    common(sp_score)
    sp_score.add_argument("--sarif", required=True, help="SARIF file exported by the scanner")
    sp_score.set_defaults(func=cmd_score)

    sp_run = sub.add_parser("run", help="run a scanner command that emits SARIF, then score it")
    common(sp_run)
    sp_run.add_argument("--command", required=True,
                        help="scanner command containing the {sarif} placeholder")
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
