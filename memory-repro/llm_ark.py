"""火山方舟（字节 ARK）OpenAI 兼容的 chat/completions 调用器。

评测专用，独立于真机 bridge，避免耦合。复用真机已验证的接入参数：
  - base_url  = https://ark.cn-beijing.volces.com/api/v3
  - model     = deepseek-v4-1-flash-261017（DeepSeek V4.1 Flash，思考型）
  - max_tokens 必须给足，否则答案被内部思考吃掉、content 为空。

API key 读取：os.environ 优先，winreg 注册表兜底（真机踩过的坑：进程启动后
才设的环境变量对已运行进程不可见）。
"""
from __future__ import annotations

import os
import sys
import time

import requests

BASE_URL = "https://ark.cn-beijing.volces.com/api/v3"
MODEL = "deepseek-v4-1-flash-261017"


def read_api_key() -> str:
    key = os.environ.get("ARK_API_KEY", "").strip()
    if key:
        return key
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            val, _ = winreg.QueryValueEx(k, "ARK_API_KEY")
            if val:
                return str(val).strip()
    except Exception:
        pass
    return ""


def chat(messages, *, temperature=0.0, max_tokens=512, timeout=120,
         retries: int = 1, thinking: str = "auto"):
    """调用火山方舟 chat/completions，返回**正文**内容。

    messages: [{"role": "system"/"user", "content": "..."}]
    thinking: "auto" 保持模型自己的思考；"disabled" 关掉（正文直接出）。

    **什么时候必须关思考**：机械转换类调用——抽取条目、归并同一件事、判版本冲突。
    这些活不需要推理，但思考型模型会洋洋洒洒想几千字，把 max_tokens 吃光，
    正文变成空、或者返回半截推理。实测「把 43 句话里的条目抽成 JSON」这一件小事，
    开着思考 8192 都不够，关掉后 200 token 就出干净 JSON。
    需要推理的（答题、判分）保持 "auto"，关掉反而会答浅。

    踩过的坑（返回思考当答案）：
      该模型（DeepSeek V4.1 Flash）把思考放在 `reasoning_content`，正文在 `content`。
      当思考太长、把 max_tokens 吃光时，`content` 是**空的**，`finish_reason` 为
      "length"——此时旧代码兜底返回 `reasoning_content`，等于把「我还在想…」
      当成答案交给判分器，必然判错（v3 实测 5 题，其中 4 题被判错）。
      治本：检测到 `content` 为空且是长度截断，就**加大配额重试**；
      实在拿不到正文才退回思考内容，并在开头标明这是截断的思考。
    """
    api_key = read_api_key()
    if not api_key:
        raise RuntimeError("未读到 ARK_API_KEY（含注册表兜底）")

    budget = max_tokens
    msg, finish = {}, ""
    for attempt in range(retries + 1):
        body = {"model": MODEL, "temperature": temperature,
                "max_tokens": budget, "messages": messages}
        if thinking == "disabled":
            body["thinking"] = {"type": "disabled"}
        r = requests.post(
            f"{BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
            json=body,
            timeout=timeout,
        )
        r.raise_for_status()
        payload = r.json()
        choice = payload["choices"][0]
        # 成本台账：记 token 用量，以后能精算、能和账单逐笔对。
        # 记账失败不阻断答题，但不许静默（见 DEFECT_WORKFLOW 第 13 节）。
        try:
            from cost_guard import record_usage
            record_usage(payload.get("usage") or {})
        except Exception as e:
            print(f"[成本台账] 记录失败：{type(e).__name__}: {e}", file=sys.stderr)
        msg = choice.get("message") or {}
        finish = choice.get("finish_reason") or ""
        content = (msg.get("content") or "").strip()
        if content:
            return content
        # 正文为空：只有「长度截断」才值得加预算重试；其它情况重试也没用
        if finish == "length" and attempt < retries:
            budget = min(budget * 3, 8192)
            continue
        break

    reason = (msg.get("reasoning_content") or "").strip()
    if reason:
        return ("[模型思考被截断，以下是未完成的推理，不是结论]\n" + reason)
    return ""


def complete(prompt: str, *, temperature=0.0, max_tokens=512, timeout=120,
             thinking: str = "auto") -> str:
    """单条 user 消息的便捷封装。"""
    return chat([{"role": "user", "content": prompt}],
                temperature=temperature, max_tokens=max_tokens, timeout=timeout,
                thinking=thinking)


if __name__ == "__main__":
    print("key 存在:", bool(read_api_key()))
    t0 = time.time()
    print("应答:", complete("用一句话回答：1+1=？", max_tokens=32))
    print(f"耗时 {time.time() - t0:.1f}s")
