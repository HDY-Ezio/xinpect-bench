"""复算第 A 档：零调用对账。给定结果文件，重算分数，看摘要是不是自己算的。

**这一档验的是「账」，不是「本事」**：
  ✅ 能验：473 是不是 500 道题里 correct=True 的个数；分项、净胜是不是加得起来
  ❌ 不能验：判分判得对不对（那要 B 档，重跑判分）

为什么先做这一档：分数算错是「没人会发现」的那类错——摘要里的数字和逐题记录
如果有出入，谁都不会去数 500 行。这一档 1 秒跑完、零成本，任何人都能独立验。

用法：
  python verify_repro.py results/longmemeval_s_20261119_065219_full_20261119.json
  python verify_repro.py <file> --json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _summary_from_rows(rows):
    """从逐题记录重算摘要。不读原摘要——那正是要被验的东西。"""
    total = len(rows)
    x = sum(1 for r in rows if r.get("xingmind_correct"))
    g = sum(1 for r in rows if r.get("rag_correct"))
    benefit = sum(1 for r in rows if r.get("xingmind_correct") and not r.get("rag_correct"))
    tax = sum(1 for r in rows if r.get("rag_correct") and not r.get("xingmind_correct"))
    by_type = {}
    for r in rows:
        t = r.get("question_type") or "?"
        d = by_type.setdefault(t, {"x": 0, "r": 0, "n": 0})
        d["n"] += 1
        d["x"] += 1 if r.get("xingmind_correct") else 0
        d["r"] += 1 if r.get("rag_correct") else 0
    return {
        "total": total, "xingmind": x, "rag": g,
        "benefit": benefit, "tax": tax, "net": benefit - tax,
        "xingmind_rate": round(x / total, 4) if total else 0,
        "rag_rate": round(g / total, 4) if total else 0,
        "by_type": by_type,
    }


def verify(path: Path):
    doc = json.load(open(path, encoding="utf-8"))
    rows = doc.get("results") or doc.get("rows") or []
    if not rows:
        return {"file": path.name, "ok": False, "error": "文件里没有逐题记录（results/rows 都是空）"}

    claimed = doc.get("summary") or {}
    real = _summary_from_rows(rows)

    checks = []
    for key in ("total", "xingmind", "rag", "benefit", "tax", "net"):
        if key not in claimed:
            checks.append((key, None, real[key], None))
            continue
        checks.append((key, claimed[key], real[key], claimed[key] == real[key]))

    # 分项：逐类型比对
    type_mismatch = []
    for t, d in real["by_type"].items():
        c = (claimed.get("by_type") or {}).get(t)
        if not c:
            type_mismatch.append((t, None, d))
        elif (c.get("x"), c.get("r"), c.get("n")) != (d["x"], d["r"], d["n"]):
            type_mismatch.append((t, c, d))
    for t in (claimed.get("by_type") or {}):
        if t not in real["by_type"]:
            type_mismatch.append((t, claimed["by_type"][t], None))

    # 结构完整性：每条题都该有题干、金标、两侧答案
    missing = []
    for r in rows:
        qid = r.get("question_id", "?")
        for k in ("question", "gold", "xingmind_answer", "rag_answer"):
            if not str(r.get(k) or "").strip():
                missing.append((qid, k))

    # 判分票记录（有它才能做 B 档）
    with_votes = sum(1 for r in rows if r.get("votes"))
    with_judge_text = sum(1 for r in rows
                          if any(isinstance(v, str) and v.strip()
                                 for v in (r.get("judge_text"), r.get("xingmind_judge"))))

    return {
        "file": path.name,
        "total": real["total"],
        "claimed": claimed,
        "recomputed": real,
        "checks": checks,
        "type_mismatch": type_mismatch,
        "missing_fields": missing,
        "votes_coverage": with_votes,
        "judge_text_coverage": with_judge_text,
        "ok": all(c[3] in (True, None) for c in checks) and not type_mismatch,
    }


def render(res):
    if res.get("error"):
        print("❌", res["error"])
        return 1
    print(f"文件：{res['file']}（{res['total']} 题）")
    print("")
    print("| 项 | 摘要里写的 | 逐题重算 | 一致 |")
    print("|---|---:|---:|:--:|")
    for key, claimed, real, same in res["checks"]:
        c = "—" if claimed is None else claimed
        mark = "—" if same is None else ("✅" if same else "❌")
        print(f"| {key} | {c} | {real} | {mark} |")
    print("")

    if res["type_mismatch"]:
        print("❌ 分项对不上：")
        for t, c, d in res["type_mismatch"]:
            print(f"   {t}: 摘要 {c} vs 重算 {d}")
    else:
        print(f"✅ 分项全部一致（{len(res['recomputed']['by_type'])} 类）")

    if res["missing_fields"]:
        print(f"❌ 有 {len(res['missing_fields'])} 处字段缺失（题干/金标/答案），前 5 条：")
        for qid, k in res["missing_fields"][:5]:
            print(f"   {qid}: {k} 是空")
    else:
        print("✅ 每条都有题干、金标、两侧答案")

    print("")
    n = res["total"]
    print(f"判分票覆盖：{res['votes_coverage']}/{n}")
    if res["judge_text_coverage"] == 0:
        print("⚠️ 结果文件里没存判词——A 档只能验加总，要验判分判得对不对得走 B 档"
              "（重跑判分，约 ¥4 / 20 分钟，见 README.md）。")
    else:
        print(f"判词覆盖：{res['judge_text_coverage']}/{n}")

    print("")
    if res["ok"]:
        print("结论：✅ 摘要与逐题记录完全一致，这个分数不是手填的。")
        return 0
    print("结论：❌ 摘要与逐题记录不一致 —— 分数算错了，或者摘要被人改过。")
    return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    p = Path(sys.argv[1])
    r = verify(p)
    if "--json" in sys.argv:
        print(json.dumps(r, ensure_ascii=False, indent=1))
        sys.exit(0 if r.get("ok") else 1)
    sys.exit(render(r))
