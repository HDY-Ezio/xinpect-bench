"""评测判分器：复用 Memory Tax 论文的 LLM-as-Judge prompt（原样转录）。

论文用 Qwen3.6-27B 做 judge；我们第一版用火山方舟 DeepSeek 做 judge（先用现成
模型跑通链路，正式对表时再换论文同款）。判分口径与论文一致：
  - GENERAL：开放问答，判「对/错」，时间要换算、允许约等
  - PREF：偏好题，判「是否体现用户偏好」
  - 输出统一要求 {"label": "CORRECT"/"WRONG"}

来源：common/judge/prompts.py（MIT），已转录到本目录 MemoryTax_ref/judge_prompts.py。
"""
from __future__ import annotations

import re
from typing import List, Optional, Sequence

from llm_ark import chat

LETTERS = ("A", "B", "C", "D")

GENERAL = """
I will give you a question, a correct answer, and a response from a model. Please check whether the response is correct or not.
If the meaning of response is equivalent to the correct answer or the response contains all the intermediate steps to get the correct answer, you should also answer CORRECT.

Notes:
- For time related questions, both the gold answer and the generated answer can be a specific date, month, year, or a relative time reference (like "last Tuesday" or "next month"). Try your best to convert relative time reference to specific date/time and compare them in the same format - as long as the generated answer refers to the same date or time period as the gold answer, it should be counted as CORRECT.
- For rounding issues, such as the reference answer being 2 months and the generated answer being 2 months and 3 days; These cases should be counted as CORRECT.
- Entity equivalence: the same character/class may be named in different languages (e.g. ironclad=战士=the warrior, watcher=观者=the purple-spell seer, thesilent=静默者=the dual-dagger thief, defect=机器人=the robot). Treat these names as the SAME entity. Do not mark an answer WRONG just because it used the Chinese name while the gold used the English name, or vice versa.
- Do NOT penalize a correct answer merely because it adds an extra correct explanation or qualification. The answer is CORRECT if its core claim matches the gold, even if the wording differs or extra context is added.

Question: {question}
Gold answer: {gold_answer}
Model Response: {generated_answer}

Is the model response correct?

Just return the label CORRECT or WRONG in a json format with the key as "label".
"""

PREF = """
I will give you a question, a rubric for desired personalized response, and a response from a model. Please output CORRECT if the response satisfies the desired response. Otherwise, output WRONG.
The model does not need to reflect all the points in the rubric. The response is correct as long as it recalls and utilizes user's personal information correctly.

Question: {question}
Rubric: {gold_answer}
Model Response: {generated_answer}

You may provide reasoning, but you MUST end your response with your final answer following the format:
Just return the label CORRECT or WRONG in a json format with the key as "label".
"""

PREFERENCE_TYPES = frozenset({"single-session-preference", "single_session_preference"})


def _pick_prompt(bench: str, category: str = "") -> str:
    b = str(bench or "")
    if b.startswith("longmemeval") and str(category or "").strip().lower() in PREFERENCE_TYPES:
        return "PREF"
    return "GENERAL"


def format_gold(golds) -> str:
    if isinstance(golds, str):
        golds = [golds]
    elif isinstance(golds, (int, float)):
        golds = [str(golds)]
    elif isinstance(golds, list):
        golds = [str(g) for g in golds if str(g).strip()]
    else:
        golds = [str(golds)]
    if len(golds) > 1:
        return "\n".join(f"- {g}" for g in golds)
    return golds[0] if golds else ""


def judge(question: str, golds, generated: str, *, bench: str = "longmemeval",
          category: str = "") -> int:
    """判一条：返回 1(CORRECT) / 0(WRONG)。

    max_tokens 必须给足：judge 模型也会先"想"再给 label，配额太小会让思考
    吃光 token、label 输不出来，parse_verdict 解析失败 → 判 0（假错）。
    实测 256 时同一道单值题判分不稳定，提到 512 才稳定输出 {"label": ...}。
    """
    name = _pick_prompt(bench, category)
    text = (PREF if name == "PREF" else GENERAL).format(
        question=question, gold_answer=format_gold(golds),
        generated_answer=generated or "(empty)")
    raw = chat([{"role": "user", "content": text}],
               temperature=0.0, max_tokens=768)
    return parse_verdict(raw)


def parse_verdict(raw: Optional[str]) -> int:
    text = str(raw or "").strip()
    m = re.search(r'"label"\s*:\s*"?(CORRECT|WRONG)"?', text, re.I)
    if m:
        return 1 if m.group(1).upper() == "CORRECT" else 0
    up = text.upper()
    has_c, has_w = "CORRECT" in up, "WRONG" in up
    if has_c and not has_w:
        return 0 if "INCORRECT" in up else 1
    if has_w and not has_c:
        return 0
    if has_c and has_w:
        return 1 if up.rfind("CORRECT") > up.rfind("WRONG") and "INCORRECT" not in up else 0
    return 0  # 无法解析，按错处理（小样本内可接受，正式对表再单独统计）


if __name__ == "__main__":
    r = judge("How long ago did I adopt Biscuit?", "5 weeks ago",
              "You adopted Biscuit 5 weeks ago.", bench="longmemeval",
              category="multi-session")
    print("判分结果(应为1):", r)
