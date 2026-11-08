# How our own number was produced

The README says the commercial scanner scores 100% on OWASP Benchmark v1.2. This
directory is the evidence, so that sentence does not have to be taken on trust.

**Result, 2026-11-08**

```text
corpus      OWASP Benchmark v1.2, 2740 cases
product     Xinpect 5.163.0, engines E1 + E2, production build
scan mode   free / brains 1,2 — the same request path a normal user hits

TP=1415  FP=0  FN=0  TN=1325      TPR=100.0%  FPR=0.0%  score=100.0%
```

## Reproduce it

You need the corpus and this tool. Nothing else, no Python packages.

```bash
# 1. the corpus (not redistributed here — it is OWASP's, and it is big)
git clone https://github.com/OWASP-Benchmark/BenchmarkJava

# 2. score the SARIF we published against that corpus
cd xinpect-bench
xinpect-bench score \
  --owasp-dir ../BenchmarkJava \
  --sarif bench/xinpect-2026-11-08.sarif \
  --mapping bench/mapping.json \
  --expect-cases 2740
```

That prints exactly the block above. `--expect-cases 2740` is there so the run
fails loudly instead of scoring quietly if the corpus has changed since.

To redo the transform as well — no product, no network — take the raw issues we
published and run it yourself:

```bash
gunzip -k bench/raw-2026-11-08.jsonl.gz
python bench/collect.py sarif --raw bench/raw-2026-11-08.jsonl --out /tmp/x.sarif
```

The SARIF you get is byte-identical to the one in this directory. That is on
purpose: the step which could quietly favour us is the one you can rerun.

## What is in here

| File | What it is |
|---|---|
| `collect.py` | The harness. `scan` talks to a running Xinpect engine and stores raw issues; `sarif` turns raw issues into SARIF. Two steps so the second one is auditable without the first. |
| `mapping.json` | Rule ID → OWASP category. Every rule ID that appears in the SARIF has an entry. |
| `xinpect-2026-11-08.sarif` | 2573 results, 21 distinct rule IDs, produced from the raw issues by `collect.py sarif`. |
| `raw-2026-11-08.jsonl.gz` | The raw per-case issues exactly as the engine returned them, 2740 lines. |
| `result-2026-11-08.txt` | Verbatim console output of the scoring command. |
| `result-2026-11-08.json` | The same result as machine-readable JSON. |

The corpus file itself (`expectedresults-1.2.csv`) is not redistributed: it comes
with the OWASP checkout, and keeping our copy out avoids the question of whether
our copy matches yours.

## What the transform does, in full

Read `collect.py` — the docstring says all of it, and the code is short. The three
decisions that could tilt a score, stated plainly:

1. **Qualified rule IDs.** `E3-TAINT-JAVA-001` is one check that reports nine
   different vulnerability types, so its SARIF rule ID gets the type appended:
   `E3-TAINT-JAVA-001/sql_injection`. `E2-SEC-JCRP-001` is split into `/hash` and
   `/crypto`. This is what SARIF rule IDs are for. Without it, one check ID cannot
   be mapped to a category without guessing.
2. **Folded findings are emitted, not hidden.** 692 findings arrived inside other
   issues' `also_detected_by` / `root_cause_merged` lists — real detections that
   the product folds together for display. They are emitted as their own results.
   Where such an entry had no `sink_kind`, the category would have been read from
   the title with a small keyword table; **that fallback was used 0 times** in this
   run, which the SARIF records in `runs[0].properties`.
3. **Nothing is filtered.** Rules that mean nothing under the OWASP categories
   (resource leaks, swallowed exceptions, NPE risks) map to the sentinel category
   `non-owasp`. They stay in the results and are still reported; they simply can
   never match a case's category, so they neither earn nor cost a point. Deleting
   them would have been a hidden filter, and a hidden filter is the failure this
   tool exists to catch.

Counts, from the SARIF properties: 1881 top-level issues + 692 folded findings =
2573 results, 0 duplicates dropped, 0 without a rule.

## What this does not prove

The five limits in [`../docs/methodology.md`](../docs/methodology.md) apply to this
number exactly as they apply to anyone else's. The two worth repeating:

- **Synthetic corpus, one language.** 2740 small Java files, one labelled flaw
  each. This says nothing about your PHP, Python or Dart repository.
- **Public corpus.** Everyone can tune against it. A perfect score here is
  evidence of work, not proof of generality — including ours.

And one limit specific to this directory: the raw issues were produced by a
commercial build of Xinpect. You can check the arithmetic, the transform and the
mapping without us, but you cannot take a scan without the product. If that makes
the result less useful to you than a number you can produce yourself, that is a
fair conclusion — run your own scanner through `xinpect-bench` and use your number.
