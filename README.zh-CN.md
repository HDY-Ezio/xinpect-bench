# xinpect-bench

[![CI](https://github.com/HDY-Ezio/xinpect-bench/actions/workflows/ci.yml/badge.svg)](https://github.com/HDY-Ezio/xinpect-bench/actions/workflows/ci.yml)

**拿 OWASP Benchmark 的口径给任意代码扫描器打分——只要它能导出 SARIF。**

[English](README.md) · [方法学](docs/methodology.md)

代码扫描器的数字很少能对得上：有人报检出率，有人报误报率，有人报「提升了多少」。
这个工具只做一件事——读扫描器导出的 SARIF，算出真正能横向比较的那几个数：
**TP / FP / FN / TN、TPR、FPR、按漏洞类别的得分**。

```bash
git clone https://github.com/HDY-Ezio/xinpect-bench && cd xinpect-bench
pip install -e .                    # 还没上 PyPI，见下面「安装」
xinpect-bench score --owasp-dir ./BenchmarkJava --sarif ./semgrep.sarif \
                    --mapping mapping.json --expect-cases 2740
# BenchmarkJava、semgrep.sarif、mapping.json 要你自己准备，见下面几步。
```

下面这段是**这个工具真跑出来的输出**，跑的是一个虚构的小数据集
（95 个用例、3 个类别、一个不存在的 `demo-scanner`）——它只展示格式，
不是任何人的成绩。想复现：`python docs/make_readme_sample.py`。

```
==========================================================================
OWASP Benchmark results  ·  demo.sarif
==========================================================================
category             TP     FP     FN     TN |     TPR     FPR
--------------------------------------------------------------------------
cmdi                 10      2      2     20 |   83.3%    9.1%
pathtraver            8      3      0     21 |  100.0%   12.5%
sqli                  5      0      1     23 |   83.3%    0.0%
--------------------------------------------------------------------------
Overall: TP=23 FP=5 FN=3 TN=64
TPR=88.5%  FPR=7.2%  score=81.2%
```

（命令行输出统一用英文——这个工具是给国际同行拿去测自家扫描器的，输出标签就是
`category / TP / FP / FN / TN / TPR / FPR / score` 这几个通用词，没有第二套翻译。）

每一行的 TPR/FPR 都由这一行自己的 TP/FP/FN/TN 算出，合计行是各行相加。
同行发出来的表，恰恰最常在这两处对不上。

## 为什么值得装

因为常见的评测脚本会骗人，而且是往「好看」的方向骗。三种骗法，这里全变成非零退出码：

| 常见做法 | 这里怎么做 |
|---|---|
| 请求挂了就把这个用例跳过，分母变小，**分数反而升高** | 失败用例显式记账；`--expect-cases` 锁死用例数，题库一变就拒绝出分 |
| 规则没映射上，一条都没命中，于是「零发现」被当成「代码干净」 | **未映射的规则默认直接判失败**，并按条数打印出来，让你看见映射没覆盖 |
| 只引用一个总分「得分 100%」 | TPR 与 FPR 永远分开打印，按类别拆开，还给你误报样本的具体用例名 |

还有一个更重要的设计：**只读 SARIF**。CodeQL、Semgrep、SonarQube、Bandit、gosec、ESLint 都能导出。
只认某一家私有 JSON 的「评测工具」，本质是营销素材，不是评测。

## 安装

**还没发到 PyPI。** 从源码装，一条命令，没有任何第三方依赖：

```bash
git clone https://github.com/HDY-Ezio/xinpect-bench && cd xinpect-bench
pip install -e .                          # Python 3.9+
python -m unittest discover -s tests      # 不需要联网
```

等 0.1.0 正式发到 PyPI 之后，`pip install xinpect-bench` 才作数；
在那之前只有 clone 这条路真能跑。先把跑不通的一行写在最前面，
恰好是这个工具专门要抓的那种话。

## 准备题库

题库是 OWASP Benchmark v1.2（Java，2,740 个用例），本仓库不打包，自己拉：

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava
```

## 三步跑出分数

**第一步：让你的扫描器扫这个题库，导出 SARIF**

```bash
# Semgrep
semgrep --config p/owasp-top-ten --sarif --output semgrep.sarif \
        BenchmarkJava/src/main/java/org/owasp/benchmark/testcode
```

**第二步：写一张映射表，说明你的规则 ID 对应哪个漏洞类别**

复制 [`examples/mapping.example.json`](examples/mapping.example.json) 改就行。三层匹配，先命中先用：

```json
{
  "rules":    { "java/sql-injection": "sqli" },
  "patterns": [ { "match": "*path-traversal*", "category": "pathtraver" } ],
  "keywords": [ { "match": "sql 注入", "category": "sqli" } ]
}
```

这张表不是额外负担，**它就是实验本身**。「把通配符放宽到分数好看起来」——那你测的是通配符，不是扫描器。

**第三步：打分**

```bash
xinpect-bench score --owasp-dir ./BenchmarkJava --sarif ./semgrep.sarif \
                    --mapping ./mapping.json --expect-cases 2740 --fail-on-fp
```

常用参数：

| 参数 | 作用 |
|---|---|
| `--expect-cases 2740` | 用例数对不上就拒绝出分，防止分数不可比 |
| `--fail-on-fp` | 有一个误报就退出码 1（适合给自己的 CI 用） |
| `--fail-under 0.9` | 得分低于阈值退出码 1 |
| `--strict-fp` | 换一套更严格的口径：干净用例报出任何问题都算误报 |
| `--format json\|markdown --out result.json` | 出机器可读结果，方便做看板或 README 徽章 |

也可以让它自己跑扫描命令：

```bash
xinpect-bench run --owasp-dir ./BenchmarkJava \
  --command "semgrep --config p/owasp-top-ten --sarif --output {sarif} 目标目录" \
  --mapping ./mapping.json --expect-cases 2740
```

## 这些数字能说明什么，不能说明什么

`score = TPR − FPR`，OWASP Benchmark 的约定，取值 −1 到 1。

**但请把 TPR 和 FPR 分开看。**「一个都不报」的扫描器得 0 分，「报一半漏一半」的也得 0 分。
单一分数会把这两种情况藏成同一个数。

先说清这套评测本身的局限——不写这些就报喜的，都是在卖东西：

1. **合成题库**：2,740 个小 Java 文件，每个只埋一个标签明确的缺陷。它不是你的项目。
2. **只有一种语言**：Java。Java 上的 TPR 说明不了 PHP 或 Dart。
3. **题库是公开的**：谁都能对着它调规则。高分是「下过功夫」的证据，不是「通用性强」的证明——包括我们自己。
4. **只按类别算命中**：报的问题落在对的类别才算；只喊「这里有风险」不算。
5. **分数对映射表敏感**：换了映射表分数就变。所以**映射表必须一起公开**，否则数字不可复现。

## 我们自己的成绩

我们做商业扫描器，所以我们的数字也放在这里，跟所有人的数字吃同一套质疑。OWASP Benchmark v1.2 全量（2,740 个用例，E1+E2 引擎，生产版本 5.163.0，扫描于 2026-11-08）：

```
TP=1415  FP=0  FN=0  TN=1325      TPR=100.0%  FPR=0.0%  score=100.0%
```

**这一次你自己能查。** [`bench/`](bench/) 里是完整链条：扫描产出的 SARIF、拼出这个 SARIF 的原始明细、
规则到类别的映射表、以及原样的控制台输出。两条命令，公开题库，不用听我们的一面之词：

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava
xinpect-bench score --owasp-dir ../BenchmarkJava \
  --sarif bench/xinpect-2026-11-08.sarif --mapping bench/mapping.json \
  --expect-cases 2740
```

连我们的转换过程都不想信？`bench/collect.py sarif` 能从公开的原始明细把同一个 SARIF 重建出来，
一字不差，不联网、不用我们的产品。[`bench/README.md`](bench/README.md) 写清了转换到底做了什么——
包括两处「可以左右分数」的选择，以及这次实际各用了几次。

那个 0.0% 是 Java 公开题库上的结果，不是对你仓库的承诺。所以我们免费那档一直叫**初筛**，不叫完整报告。

## 许可

MIT。拿去用、拿去改、嵌进你的商业产品、放进你的 CI 都行，只要留着许可文件。

题库（OWASP Benchmark）的许可是 OWASP 自己的，不是我们的。

## 相关链接

- 煋鉴（这个工具的来源）：<https://xinpect.xingwangzhineng.com>
- 免费初筛，不用注册，贴代码就出结果：<https://xinpect.xingwangzhineng.com/try>
- 一份真实报告，生产扫描器真跑出来的：<https://xinpect.xingwangzhineng.com/sample-report>
