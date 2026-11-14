"""探活失败时发告警邮件。

为什么要单独一个文件：YAML 的 `run: |` 块对缩进极其敏感，多行正文写在里面
会被解析成新的 YAML 键，整份 workflow 直接失效（2026-11-14 栽过一次，
表现是 workflow 名字变成文件路径、GitHub 完全不跑）。
逻辑放独立文件，编排只留一行调用。

配置不全必须显式失败——静默跳过等于「以为有告警，其实没有」。
"""
import os
import smtplib
import ssl
import sys
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.utils import formataddr

REQUIRED = ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "ALERT_TO"]

BASE = "https://xinpect.xingwangzhineng.com"


def main() -> int:
    missing = [k for k in REQUIRED if not os.environ.get(k)]
    if missing:
        print("邮件配置不全，发不出来：" + ", ".join(missing))
        print("去仓库 Settings -> Secrets and variables -> Actions 补齐")
        return 1

    now = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    run_url = server + "/" + repo + "/actions" if repo else ""

    lines = [
        "探测时间（北京时间）：" + now,
        "",
        "从 GitHub 机房连续三轮访问煋鉴官网都失败，三个入口分别是：",
        "  首页    " + BASE + "/",
        "  健康接口 " + BASE + "/health",
        "  登录页   " + BASE + "/login",
        "",
        "可能原因：整台服务器失联、nginx 挂了、证书过期、服务被内存杀掉、磁盘写满。",
        "",
        "运行详情：" + (run_url or "见仓库 Actions 页面"),
        "",
        "这条邮件由 GitHub 机房发出。即使我们自己的机器死了，它也发得出来。",
    ]
    body = "\n".join(lines)

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = "煋鉴官网失联（外部探测告警）"
    msg["From"] = formataddr(("煋鉴外部探活", os.environ["SMTP_USER"]))
    msg["To"] = os.environ["ALERT_TO"]

    port = int(os.environ["SMTP_PORT"])
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(os.environ["SMTP_HOST"], port, timeout=30, context=ctx) as s:
        s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
        s.sendmail(os.environ["SMTP_USER"], [os.environ["ALERT_TO"]], msg.as_string())
    print("告警邮件已发送给 " + os.environ["ALERT_TO"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
