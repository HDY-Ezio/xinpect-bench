"""从 GitHub 机房探测煋鉴官网，出事就开单并 @ 人。

为什么是开单而不是发邮件：邮件要 SMTP 凭据，凭据要 Secrets，Secrets 要登录网页去设。
开单只需要 workflow 自带的那张临时令牌，零额外凭据、零额外账号。
而且 @ 到具体人是 GitHub 最确定的通知路径——被 @ 的人一定收到邮件。
附带好处：每次故障有案可查，不用靠人回忆。

本地自测：DRY_RUN=1 python3 probe.py   （真探测，但不碰 GitHub）
"""
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

BASE = os.environ.get("PROBE_BASE", "https://xinpect.xingwangzhineng.com")
MENTION = os.environ.get("ALERT_MENTION", "HDY-Ezio")
ISSUE_TITLE = "煋鉴官网失联"
API = "https://api.github.com"
DRY = os.environ.get("DRY_RUN") == "1"
UA = "xinpect-uptime/1.0"

ATTEMPTS = 3
RETRY_GAP = 20
COMMENT_COOLDOWN = 30 * 60


def now_cn():
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")


def fetch_text(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, r.read().decode("utf-8", "replace")


def gh(path, method="GET", body=None, token=None, timeout=30):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", UA)
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


# ---------- 三个入口 ----------

def check_home():
    st, body = fetch_text(BASE + "/")
    if st != 200:
        return "首页状态码 %d" % st
    if "煋鉴 Xinpect" not in body:
        return "首页没有品牌字样（可能是错误页）"
    return None


def check_health():
    st, body = fetch_text(BASE + "/health")
    if st != 200:
        return "健康接口状态码 %d" % st
    if "xinpect-website" not in body:
        return "健康接口认不出身份"
    if '"status":"ok"' not in body:
        return "健康接口自报不 ok：%s" % body[:120]
    return None


def check_login():
    st, _ = fetch_text(BASE + "/login")
    if st != 200:
        return "登录页状态码 %d" % st
    return None


CHECKS = [("首页", check_home), ("健康接口", check_health), ("登录页", check_login)]


def run_checks():
    problems = []
    for attempt in range(1, ATTEMPTS + 1):
        problems = []
        for label, fn in CHECKS:
            try:
                err = fn()
            except Exception as e:                      # noqa: BLE001
                err = "%s 连不上（%s）" % (label, type(e).__name__)
            if err:
                problems.append(err)
        if not problems:
            print("第 %d 轮：三个入口全通" % attempt)
            return []
        print("第 %d 轮失败：%s" % (attempt, "；".join(problems)))
        if attempt < ATTEMPTS:
            time.sleep(RETRY_GAP)
    return problems


# ---------- 开单 / 销单 ----------

def find_open_issue(token, repo):
    st, data = gh("/repos/%s/issues?state=open&per_page=100" % repo, token=token)
    if st != 200:
        print("查未结单失败：HTTP %s %s" % (st, str(data)[:200]))
        return None
    for it in data:
        if isinstance(it, dict) and it.get("title", "").startswith(ISSUE_TITLE):
            return it
    return None


def open_alert(problems, token, repo):
    body = "\n".join(
        ["@%s 官网打不开了，需要马上看。" % MENTION, ""]
        + ["- 探测时间（北京）：" + now_cn(), "- 探测点：GitHub 机房（不在我们自己的服务器上）", ""]
        + ["失败原因："]
        + ["- " + p for p in problems]
        + ["", "可能原因：整台服务器失联、nginx 挂了、证书过期、磁盘写满、服务被内存杀掉。"]
    )
    if DRY:
        print("[DRY] 会开单：%s\n%s" % (ISSUE_TITLE, body))
        return

    it = find_open_issue(token, repo)
    if it:
        updated = it.get("updated_at") or ""
        try:
            ts = datetime.strptime(updated, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - ts).total_seconds() < COMMENT_COOLDOWN:
                print("已有未结单 #%d 且 30 分钟内刚更新过，这次不重复打扰" % it["number"])
                return
        except ValueError:
            pass
        st, data = gh("/repos/%s/issues/%d/comments" % (repo, it["number"]), "POST", {"body": body}, token)
        print("在未结单 #%d 追加评论：HTTP %s" % (it["number"], st))
        return

    st, data = gh("/repos/%s/issues" % repo, "POST", {"title": ISSUE_TITLE, "body": body}, token)
    if st == 201:
        print("已开单 #%d：%s" % (data["number"], data["html_url"]))
    else:
        print("开单失败：HTTP %s %s" % (st, str(data)[:300]))
        raise SystemExit(1)


def close_alert(token, repo):
    if DRY:
        print("[DRY] 会销单（如果有无结单）")
        return
    it = find_open_issue(token, repo)
    if not it:
        return
    gh("/repos/%s/issues/%d/comments" % (repo, it["number"]), "POST",
       {"body": "已恢复正常。恢复确认时间（北京）：" + now_cn()}, token)
    st, _ = gh("/repos/%s/issues/%d" % (repo, it["number"]), "PATCH", {"state": "closed"}, token)
    print("已销单 #%d（HTTP %s）" % (it["number"], st))


def main():
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not DRY and not (token and repo):
        print("缺 GITHUB_TOKEN 或 GITHUB_REPOSITORY，无法通知")
        return 2

    problems = run_checks()
    if problems:
        print("判定故障：%s" % "；".join(problems))
        open_alert(problems, token, repo)
        return 1

    print("三个入口全通（%s）" % now_cn())
    close_alert(token, repo)
    return 0


if __name__ == "__main__":
    sys.exit(main())
