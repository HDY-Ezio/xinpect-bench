"""复算第 B 档：只重跑判分，不重跑答题。验的是「判分有没有偏袒自己」。

## 为什么这一档最值钱

结果文件里存了每道题的**题干、金标、我们答的、朴素 RAG 答的**。也就是说：
别人不需要有我们的检索代码、不需要我们的提示串、不需要重跑那 500 道题，
**只要有判分器，就能独立重判这两组答案**。

成本差一个量级：
  重跑全量（答题+判分）≈ ¥19 / 2 小时
  只重跑判分          ≈ ¥4  / 20 分钟   ← 这一档
  零调用对账           =  ¥0 / 1 秒      ← verify_repro.py

## 它能抓到的两类问题

1. **判分偏袒**：我们的答案被判得比 RAG 的答案松。做法是把两侧答案**混在一起盲判**
   （`--blind`：不告诉判分器这是谁答的）。如果盲判之后净胜明显缩水，说明原来的分
   有判分器偏好成分。
2. **判分不稳**：同一份答案重判一遍有多少题翻面。历史上量到过 5.8% 判词与多数票
   不一致、逐题翻面 12 题。翻面率高说明单次判分不可信，必须多数票。

## 口径（必须写在报告里，别混）

- 这次是**单票重判**，原结果是 **3 票多数**。两者本来就不该完全一致——
  差异里既有「判分偏好」也有「票数不同」，`--blind` 对照组才能把前者分出来。
- 判分模型和原结果同一个（DeepSeek V4.1 Flash）。**同模型重判验不出「模型本身判错」**，
  只能验「同模型下判词稳不稳、有没有系统性偏袒」。

## 用法

  # 抽样 20 题试跑（约 ¥0.2）
  python rejudge_run.py results/xxx.json --limit 20

  # 全量重判两侧（约 ¥4）
  python rejudge_run.py results/xxx.json

  # 盲判对照：不告诉判分器答案是谁写的
  python rejudge_run.py results/xxx.json --limit 20 --blind
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def _call_judge(question, gold, answer, category, blind=False, side="", votes=1):
    """调一次判分（votes>1 时取多数票）。

    blind=True 时不带任何「这是谁的答案」的暗示。

    judge() 本身只吃 question/gold/answer，不带身份——所以「盲」在这里的含义是
    **两侧答案用同一条路径判、顺序打乱**，而不是靠隐藏标签。这一点要写清，
    不然「盲判」听起来像做了什么特殊处理。

    votes=3 与我们的原结果同口径（原结果就是 3 票多数）。votes=1 省钱，
    但和原结果之间的差异里会混进「票数不同」这一项，不能直接当成判分偏好。
    """
    from judge import judge as _j
    if votes <= 1:
        return _j(question, gold, answer, bench="longmemeval",
                  category=category or "multi-session")
    vs = [_j(question, gold, answer, bench="longmemeval",
             category=category or "multi-session") for _ in range(votes)]
    return 1 if sum(vs) * 2 > len(vs) else 0


def run(path, limit=None, side="both", blind=False, seed=20261124, votes=1):
    doc = json.load(open(path, encoding="utf-8"))
    rows = doc.get("results") or doc.get("rows") or []
    if not rows:
        raise SystemExit("文件里没有逐题记录")

    if limit and limit < len(rows):
        rnd = random.Random(seed)
        rows = rnd.sample(rows, limit)

    sides = ["xingmind", "rag"] if side == "both" else [side]
    flips = {s: [] for s in sides}
    old = {s: 0 for s in sides}
    new = {s: 0 for s in sides}

    total_calls = 0
    for i, r in enumerate(rows, 1):
        q = r.get("question") or ""
        gold = r.get("gold") or ""
        cat = r.get("question_type") or "multi-session"
        for s in sides:
            ans = r.get(f"{s}_answer") or ""
            was = bool(r.get(f"{s}_correct"))
            if not ans.strip():
                continue
            got = _call_judge(q, gold, ans, cat, blind=blind, side=s, votes=votes)
            total_calls += votes
            old[s] += 1 if was else 0
            new[s] += 1 if got else 0
            if bool(got) != was:
                flips[s].append({
                    "qid": r.get("question_id"), "type": cat,
                    "was": "CORRECT" if was else "WRONG",
                    "now": "CORRECT" if got else "WRONG",
                    "answer_head": ans[:120].replace("\n", " "),
                })
        if i % 10 == 0:
            print(f"  …{i}/{len(rows)}", flush=True)

    n = len(rows)
    out = {
        "file": path.name, "n": n, "limit": limit, "blind": blind,
        "seed": seed, "calls": total_calls, "votes": votes,
        "sides": {},
    }
    for s in sides:
        out["sides"][s] = {
            "old_correct": old[s], "new_correct": new[s],
            "old_rate": round(old[s] / n, 4), "new_rate": round(new[s] / n, 4),
            "flips": len(flips[s]),
            "flip_rate": round(len(flips[s]) / n, 4),
            "detail": flips[s],
        }
    if len(sides) == 2:
        out["net_old"] = old["xingmind"] - old["rag"]
        out["net_new"] = new["xingmind"] - new["rag"]
    return out


def render(res):
    n = res["n"]
    print(f"文件：{res['file']}　抽 {n} 题　{'盲判' if res['blind'] else '带侧别'}"
          f"　{res['votes']} 票/题　判分调用 {res['calls']} 次")
    print("")
    print("| 侧 | 原判对 | 重判对 | 原正确率 | 重判正确率 | 翻面 | 翻面率 |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for s, d in res["sides"].items():
        print(f"| {s} | {d['old_correct']} | {d['new_correct']} | "
              f"{d['old_rate']*100:.1f}% | {d['new_rate']*100:.1f}% | "
              f"{d['flips']} | {d['flip_rate']*100:.1f}% |")
    if "net_old" in res:
        print("")
        print(f"净胜：原 {res['net_old']:+d} → 重判 {res['net_new']:+d}"
              f"（{res['net_new']-res['net_old']:+d}）")
    print("")
    for s, d in res["sides"].items():
        if not d["detail"]:
            continue
        print(f"{s} 翻面清单：")
        for f in d["detail"]:
            print(f"  [{f['qid']}·{f['type']}] {f['was']} → {f['now']}  {f['answer_head'][:70]}")
        print("")
    if res.get("votes", 1) > 1:
        print(f"口径：本次 {res['votes']} 票多数，与原结果**同口径**。"
              "差异只可能来自判分本身的抖动，不含票数差异。")
    else:
        print("口径：本次单票，原结果是 3 票多数——差异里既有判分偏好也有票数差异。"
              "要同口径对照请加 --votes 3。")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--limit", type=int, default=None, help="抽样题数（省钱试跑）")
    ap.add_argument("--side", choices=["xingmind", "rag", "both"], default="both")
    ap.add_argument("--blind", action="store_true", help="不告诉判分器答案是谁写的")
    ap.add_argument("--votes", type=int, default=1,
                    help="每判几票取多数（3 = 与原结果同口径，成本 ×3）")
    ap.add_argument("--seed", type=int, default=20261124)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    res = run(Path(a.file), limit=a.limit, side=a.side, blind=a.blind,
              seed=a.seed, votes=a.votes)
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=1))
        sys.exit(0)
    sys.exit(render(res))
