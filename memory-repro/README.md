# 煋思维 · LongMemEval 复算材料

> **In English** — the audit trail for one number. On LongMemEval-S (500 questions) our
> long-term-memory system scored **473/500 (94.6%)**, while the same model with plain
> retrieval scored 296/500 (59.2%). Everything needed to recompute those three figures is
> here: questions, gold answers, both systems' answers, and the judge. What is *not* here
> is the retrieval and evidence-assembly code — see [我们没给什么](#我们没给什么说清楚免得你白找).
> This folder lives in [xinpect-bench](../README.md) for lack of a better home; it has
> nothing to do with the SAST benchmark in the rest of that repository.

**两个地址，内容相同。** 国内镜像 <https://gitee.com/xingwangzhineng/xingmind-memory-repro>
（clone 快；但 Gitee 的内容过滤会挡住 `data/*.json` 的网页直链，返回 451
`The content may contain violation information`，**`git clone` 不受影响**）。
**本目录是主源**，两边不一致以这里为准。

**Claim（可被这份材料验）：**
LongMemEval-S 500 题，**煋思维 473/500 = 94.6%**，同场朴素 RAG **296/500 = 59.2%**，净胜 **+177**。
答问与判分用的是同一个便宜模型（DeepSeek V4.1 Flash），跑在 2026-11-19。

这份材料只做一件事：**让你独立验证上面这三个数**。

---

## 30 秒跑完（零成本，零调用）

```bash
git clone --depth 1 https://github.com/HDY-Ezio/xinpect-bench
cd xinpect-bench/memory-repro
python verify_repro.py data/longmemeval_s_500_answers.json
```

预期输出：

```
| 项 | 摘要里写的 | 逐题重算 | 一致 |
| total | 500 | 500 | ✅ |
| xingmind | 473 | 473 | ✅ |
| rag | 296 | 296 | ✅ |
| net | 177 | 177 | ✅ |
...
结论：✅ 摘要与逐题记录完全一致，这个分数不是手填的。
```

这一档验的是**账**：摘要里的数字是不是 500 行逐题记录加出来的。
500 行没人会去数，所以「分数算错」「摘要被改过」这类错一旦发生通常永远不会被发现。
1 秒钟消除它。**它不验判分判得对不对**——往下走。

---

## 更该跑的那一档：只重跑判分（约 ¥4 / 20 分钟）

全行业被质疑最多的不是"你答得准不准"，是"**你的判分器是不是在偏袒你自己的答案**"。

这份材料能验它，是因为**答案已经存在文件里了**：每道题的题干、金标、我方答案、RAG 答案都在。
所以复算者**不需要我们的检索代码、不需要数据集、不需要我们的提示串**，只要有判分器就能重判。

```bash
export ARK_API_KEY=<你自己的 key>

# 先抽 15 题（约 ¥0.15）
python rejudge_run.py data/longmemeval_s_500_answers.json --limit 15

# 全量两侧（1000 次判分，约 ¥4）
python rejudge_run.py data/longmemeval_s_500_answers.json

# 同口径对照：3 票多数，和我们的原始判定一致（成本 ×3，约 ¥12）
python rejudge_run.py data/longmemeval_s_500_answers.json --votes 3

# 盲判：两侧答案混在一起判
python rejudge_run.py data/longmemeval_s_500_answers.json --blind
```

我们用 15 题试跑过一次（30 次判分，约 ¥0.15），**零翻面**：

```
| 侧 | 原判对 | 重判对 | 原正确率 | 重判正确率 | 翻面 |
| xingmind | 14 | 14 | 93.3% | 93.3% | 0 |
| rag      | 11 | 11 | 73.3% | 73.3% | 0 |
净胜：原 +3 → 重判 +3（+0）
```

**但 15 题什么也证明不了。** 要真验，请跑全量，或者自己换判分模型跑。

### 三个口径，别混

1. **单票 vs 3 票。** 我们的原结果是 3 票多数。默认单票（省钱），差异里会混进"票数不同"。
   要同口径对照加 `--votes 3`。**想证明"我们没靠票数凑分"，就跑这一档。**
2. **同模型重判验不出「模型本身判错」。** 默认模型和原结果同一个。它验的是
   "同模型下判词稳不稳、有没有系统性偏袒"，不是"这个模型判得对不对"。
   要验后者，改 `llm_ark.py` 里的 `MODEL` 和 `BASE_URL` 换成任何 OpenAI 兼容接口。
3. **盲判才是关键对照。** 我们量到过：判分器约 5.8% 的判词与多数票不一致；
   金标实测假对 0 / 假错 6（方向单一，集中在 4 道题）。加 `--blind` 跑一遍，
   如果净胜明显缩水，说明原来的分里有判分偏好成分。

---

## 文件里有什么

| 文件 | 是什么 |
|---|---|
| `data/longmemeval_s_500_answers.json` | 500 题：`question` / `gold` / `xingmind_answer` / `rag_answer` / 两侧原始判定 / 原始票 |
| `verify_repro.py` | 零调用对账（A 档） |
| `rejudge_run.py` | 只重跑判分（B 档），带 `--blind` / `--votes` / `--limit` |
| `judge.py` | 判分器。提示串原样转录自 Memory Tax 论文（MIT），见文首注释 |
| `llm_ark.py` | 一个 OpenAI 兼容接口的薄封装。**不含任何密钥**，只从环境变量读 |

### 我们没给什么（说清楚，免得你白找）

| 不给 | 为什么 |
|---|---|
| 检索与证据组织的提示串 | **这是护城河。** 同样的模型下 473 vs 朴素 RAG 296，177 分差全在这层壳上 |
| `recall_context` / 证据精炼的实现 | 同上 |
| 每次喂了多少上下文、召回窗口多少条 | 竞品情报。**已从数据文件里剔除**——你不会在这里看到 `mem_chars`、`window` |

分界线是有意的：**你能验"473 这个分数是不是从这些答案算出来的"，
不能拿走"我们怎么让模型答出这些答案"。** 前者是你采购前该验的，后者是我们的东西。

---

## 环境

```
Python 3.10+（我们跑在 3.13.12）
依赖：无第三方包（只用标准库 + 一个 HTTPS POST）
key ：export ARK_API_KEY=...    你自己的，我们不提供
```

换模型：改 `llm_ark.py` 的 `BASE_URL` / `MODEL`。任何 OpenAI 兼容接口都行。

---

## 我们希望你复算之后公开说什么

对不上就说对不上，我们会把差异原样贴出来，包括对我们不利的。

这不是姿态。**自己出题自己判的系统，唯一能换信任的办法就是接受别人重算。**
Hindsight 被统一口径重跑掉 22 分（94.6 → 72.2）就是先例——
我们凭什么认为自己不会掉？**没测过就不能假设掉得少。**

---

## 已知的空白（别信任何二手转述）

- **长史没跑过。** BEAM（100 万 ~ 1000 万 token）我们一张牌都没出。
  这意味着「长史能力」这句话目前**没有证据**。
- **LoCoMo 我们输了。** 1,540 题上我们 85.06%，但那是「全文全给」；
  等预算对照后净胜 −1.62 点。**别拿它当我们能力强的证据。**
- **同分不可排序。** 前四名差 5 分以内，等于一次判分噪声。我们只能说
  "同一张卷子上打平"，不能说"我们更强"。

---

## 许可

本目录随 [xinpect-bench](../README.md) 一起发布，许可同上：MIT（见仓库根目录 `LICENSE`）。
`judge.py` 里的判分提示串原样转录自 Memory Tax 论文的参考实现（MIT），
原文署名保留在该文件头注释里。
