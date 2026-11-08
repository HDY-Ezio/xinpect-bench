# xinpect-bench

**Score any code scanner against the OWASP Benchmark methodology — from a SARIF file.**

[中文说明](README.zh-CN.md) · [Methodology](docs/methodology.md) · [Why another one](#why-another-one)

Code scanners are easy to brag about and hard to compare. This is a small,
dependency-free tool that takes a scanner's SARIF output and produces the
numbers everyone argues about: **TP / FP / FN / TN, TPR, FPR, and per-category
score** — with the failure modes that make SAST numbers fake, turned into hard errors.

```bash
git clone https://github.com/HDY-Ezio/xinpect-bench && cd xinpect-bench
pip install -e .                   # not on PyPI yet, see Install below
xinpect-bench score --owasp-dir ./BenchmarkJava --sarif ./semgrep.sarif \
                    --mapping mapping.json --expect-cases 2740
```

Sample output below is a real run of this tool on a **tiny made-up corpus**
(95 cases, 3 categories, a fictional `demo-scanner`) — it shows the shape, not
anyone's score. Reproduce it with `python docs/make_readme_sample.py`:

```
==========================================================================
OWASP Benchmark 评测结果  ·  demo.sarif
==========================================================================
category             TP     FP     FN     TN |     TPR     FPR
--------------------------------------------------------------------------
cmdi                 10      2      2     20 |   83.3%    9.1%
pathtraver            8      3      0     21 |  100.0%   12.5%
sqli                  5      0      1     23 |   83.3%    0.0%
--------------------------------------------------------------------------
总体: TP=23 FP=5 FN=3 TN=64
TPR=88.5%  FPR=7.2%  score=81.2%
```

Every row's TPR/FPR is computed from that row's own TP/FP/FN/TN, and the totals
are the sum of the rows — the thing most published SAST tables quietly fail.

## Why another one

Because the numbers people quote are usually produced by a script that can lie
to them. Three failure modes, all of which this tool turns into a non-zero exit
code:

| What usually happens | What this tool does |
|---|---|
| A request fails, the case is skipped, the denominator shrinks, the score goes **up** | Failed/missing cases are visible; `--expect-cases` refuses to score when the question set drifts |
| The scanner found nothing, so every rule maps to nothing, and you read "0 findings" as "clean code" | **Unmapped rule IDs are fatal by default** (`--max-unmapped-ratio 0`), and printed with counts |
| One number gets quoted out of context ("score 100%") | TPR and FPR are always printed separately, per category, plus FP samples you can open |

And one design choice that matters more than the rest: **it reads SARIF**, the
industry standard. CodeQL, Semgrep, SonarQube, Bandit, gosec, ESLint, and most
CI-native scanners can emit it. A benchmark tool that only understands one
vendor's private JSON is a marketing asset, not a benchmark.

## Install

**Not on PyPI yet.** Install from source — one command, no third-party dependencies:

```bash
git clone https://github.com/HDY-Ezio/xinpect-bench && cd xinpect-bench
pip install -e .                          # Python 3.9+
python -m unittest discover -s tests      # 22 tests, no network needed
```

`pip install xinpect-bench` will work once 0.1.0 is published; until then the
clone is the only path that actually runs. Writing the one-liner before it works
would be exactly the kind of claim this tool is built to catch.

## Get the benchmark data

The corpus is OWASP Benchmark v1.2 (Java, 2,740 test cases). It is not bundled
here — clone it yourself:

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava
```

## Use it

### 1. Point your scanner at the corpus and export SARIF

Anything that produces SARIF works. Two examples:

```bash
# Semgrep
semgrep --config p/owasp-top-ten --sarif --output semgrep.sarif \
        BenchmarkJava/src/main/java/org/owasp/benchmark/testcode

# CodeQL (after database creation)
codeql database analyze db java-security-extended.qls --format=sarif-latest \
       --output codeql.sarif
```

### 2. Describe how your rule IDs map to OWASP categories

Copy [`examples/mapping.example.json`](examples/mapping.example.json) and edit
it. Three layers, first match wins:

```json
{
  "rules":    { "java/sql-injection": "sqli" },
  "patterns": [ { "match": "*path-traversal*", "category": "pathtraver" } ],
  "keywords": [ { "match": "sql 注入", "category": "sqli" } ]
}
```

Mapping is not optional overhead — it **is** the experiment. If you widen a glob
until your score looks good, you have measured your glob.

### 3. Score

```bash
xinpect-bench score \
  --owasp-dir ./BenchmarkJava \
  --sarif ./semgrep.sarif \
  --mapping ./mapping.json \
  --expect-cases 2740 \
  --fail-on-fp
```

Useful flags:

| Flag | Meaning |
|---|---|
| `--expect-cases 2740` | Refuse to score if the corpus changed — scores stop being comparable |
| `--fail-on-fp` | Any false positive exits 1 (good for your own CI) |
| `--fail-under 0.9` | Exit 1 if score is below the threshold |
| `--strict-fp` | Count *any* finding on a clean case as a false positive, not just the matching category |
| `--format json\|markdown --out result.json` | Machine-readable output for a dashboard or a README badge |
| `--max-unmapped-ratio 0.0` | Default: unmapped rules are fatal |

Or let it run the scanner for you:

```bash
xinpect-bench run --owasp-dir ./BenchmarkJava \
  --command "semgrep --config p/owasp-top-ten --sarif --output {sarif} BenchmarkJava/src/main/java/org/owasp/benchmark/testcode" \
  --mapping ./mapping.json --expect-cases 2740
```

## What the numbers mean, and what they do not

`score = TPR − FPR`, the OWASP Benchmark convention, range −1 to 1.

**Read TPR and FPR separately anyway.** A scanner that reports nothing scores
0, and so does a scanner that is half-right. A single score hides both.

Known limits of this whole exercise — stated up front, because anyone who
publishes a good score without them is selling something:

1. **Synthetic corpus.** OWASP Benchmark is 2,740 small Java files built to have
   one labeled flaw each. It is not your codebase.
2. **One language.** Java only. TPR on Java says nothing about PHP or Dart.
3. **Public corpus.** Everyone can tune rules against it. A high score is
   evidence of work, not proof of generality — including ours.
4. **Category match only.** A finding is counted only if it lands in the right
   category; a scanner that reports "something is wrong here" gets no credit.
   Use `--strict-fp` to see how the other convention treats the same output.
5. **Mapping sensitivity.** Scores move when the mapping moves. Publish your
   mapping file or your number is not reproducible.

Details and the reasoning behind each guard: [`docs/methodology.md`](docs/methodology.md).

## Our own result

We build a commercial scanner, so our number belongs here with the same caveats
as anyone else's. On OWASP Benchmark v1.2 (2,740 cases, `brains E1+E2`,
production build):

```
TP=1415  FP=0  FN=0  TN=1325      TPR=100.0%  FPR=0.0%  score=100.0%
```

Computed by this tool from the exported SARIF. Which means **you can check us**:
run your own scan of our product through `xinpect-bench`, and your number wins.
A benchmark you can apply to the author is the only kind worth trusting.

That 0.0% FPR is a Java-benchmark result on a public corpus. It is not a promise
about your repository — which is why our free tier is called a **triage**
(初筛), not a full report.

## License

MIT. Use it, fork it, embed it in your commercial product, ship it in your CI.
No attribution required beyond keeping the license file.

The benchmark data (OWASP Benchmark) has its own license, from OWASP.

## Links

- Xinpect (the product this came from): <https://xinpect.xingwangzhineng.com>
- Free triage, no signup, paste code and get a first-pass result:
  <https://xinpect.xingwangzhineng.com/try>
- A real report, generated by the production scanner: <https://xinpect.xingwangzhineng.com/sample-report>
