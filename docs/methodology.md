# Methodology

This document explains what the numbers mean, why the tool refuses to score in
certain situations, and what the result cannot tell you. If you publish a score
produced with `xinpect-bench`, cite this file alongside it.

## 1. The measurement

Corpus: **OWASP Benchmark v1.2**, 2,740 Java test cases. Each case is labeled
with exactly one vulnerability category and a `real vulnerability` flag
(`true` / `false`).

For every case:

|  | Scanner reported the labeled category | Scanner did not |
|---|---|---|
| **Labeled vulnerable (`true`)** | True Positive | False Negative |
| **Labeled safe (`false`)** | False Positive | True Negative |

Then:

```
TPR (detection rate) = TP / (TP + FN)
FPR (false positive rate) = FP / (FP + TN)
score = TPR - FPR                    # OWASP Benchmark convention, range -1..1
```

**Category match, not "any finding".** A case labeled `sqli` is only a TP if the
scanner reported something in the `sqli` category. Reporting a `weakrand`
finding on that file earns nothing.

That convention is generous to scanners: a tool that fires on everything still
gets full credit for the vulnerable half. `--strict-fp` switches to the harsher
convention where *any* finding on a `false` case counts as a FP. Publish which
one you used, because they are not comparable.

## 2. Five guards, and the failure each one prevents

Every guard below exists because the alternative produces a number that goes up
when the scanner gets worse.

### 2.1 Failed requests are counted, never skipped

If a scan request errors out and the case is silently dropped, the denominator
shrinks. Dropping the hard cases raises the score. There is no code path here
that removes a case from the denominator for any reason: a missing detection is
a FN, full stop.

### 2.2 Corpus drift refuses to score

`--expect-cases 2740` compares the parsed case count against the expected value
and exits non-zero on mismatch. A score from a 2,700-case corpus is not
comparable to one from 2,740, and nobody notices a 40-case difference by eye.

The parser also refuses to guess: a row whose `real vulnerability` column is
anything other than `true` / `false` is an error, not a `False`.

### 2.3 Unmapped rules are fatal by default

The most common silent failure in SAST benchmarking is a rule-ID mapping that
covers nothing. The scanner runs, finds 4,000 issues, none of them map to an
OWASP category, the tool reports "0 detections", and the reader concludes the
scanner is quiet rather than the mapping is empty.

`--max-unmapped-ratio` defaults to `0.0`: one unmapped rule fails the run, and
the offending rule IDs are printed with counts so you can fix the mapping.

### 2.4 TPR and FPR are always printed separately

A scanner that reports nothing scores `0`. A scanner that is perfectly accurate
on half the cases and fires on the other half also scores `0`. The single
`score` value cannot distinguish them, so it is never printed alone.

### 2.5 False positive samples are named

Every FP is listed by test-case name. A count tells you something is wrong; a
list tells you *what* is wrong, and lets someone else reproduce it.

## 3. What this cannot tell you

Stated plainly, because a benchmark pitch that omits these is a sales document:

1. **Synthetic corpus.** OWASP Benchmark cases are small, self-contained files
   with one planted flaw each. Real code has framework indirection, generated
   code, and no labels.
2. **Single language.** Java only. Nothing here transfers to a PHP or Dart
   codebase except the method.
3. **Public and saturated.** The corpus, the labels, and the expected results
   have been public for years. Rules can be tuned against it. A high score is
   evidence of effort on this corpus, not evidence of general accuracy —
   including the score we publish for our own scanner.
4. **No severity weighting.** A critical SQL injection and a missing security
   header count the same. Production triage does not work that way.
5. **Mapping sensitivity.** Change the glob in `mapping.json`, change the score.
   This is why the mapping file must be published with any claim.

If your goal is "how will this behave on my repository", a benchmark cannot
answer it. Run the scanner on your repository and measure the findings you
actually had to triage.

## 4. Reproducing a published result

A score is reproducible only if all four of these are published:

1. the scanner version,
2. the corpus version (`--expect-cases` value and the `expectedresults` file),
3. the `mapping.json`,
4. the strictness convention (`--strict-fp` or not).

Missing any one of them, the number is an anecdote.

## 5. The author's result

Xinpect's commercial scanner, E1+E2 engines, production build, on the full
v1.2 corpus:

```
TP=1415  FP=0  FN=0  TN=1325      TPR=100.0%  FPR=0.0%  score=100.0%
```

Produced by this tool from the exported SARIF. The corpus version and case count
are pinned at 2,740. Because the tool is public and the corpus is public, this
claim is checkable by anyone — including the parts we would rather not show.
That is the point.
