# -*- coding: utf-8 -*-
"""PCNT 签名抓取：注入 QQ → 挂钩 crypto.dll 的 AES / HMAC → 打印并保存记录。

用法：
    python tools/capture.py [秒数] [输出文件]
默认抓取 60 秒，追加写入 tools/capture.log。

前置：
    1. QQ（NTQQ）已运行且已登录；
    2. 已构建 native/build/XHQNative_x64.dll（见 native/build.ps1）；
    3. 已安装依赖：pip install pefile
    4. 建议以与 QQ 相同的权限运行（同为管理员或同为普通用户）。

注意：抓取到的记录里含**本次会话的真实密钥**，请勿提交到公开仓库。
"""
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "host"))

from core import qqnt          # noqa: E402
from core.bridge import Bridge  # noqa: E402


def main():
    secs = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, "tools", "capture.log")

    pid = qqnt.find_main_qq()
    if not pid:
        print("未找到 QQ 主进程（需已登录，且已加载 wrapper.node / crypto.dll）")
        return 1
    print("主进程 PID: %d" % pid)

    bridge = Bridge()
    bridge.start(pid)
    for _ in range(60):
        time.sleep(0.25)
        if bridge.channel.connected:
            break
    if not bridge.channel.connected:
        print("注入后未能连上模块：请检查权限是否与 QQ 一致")
        return 2

    print("通道: %s" % bridge.channel.status_text())
    print("挂钩: %s" % bridge.set_crypto_hook(True, False))
    print("开始抓取 %d 秒 …（期间请操作 QQ，例如发一条消息）" % secs)

    n = 0
    with open(out, "a", encoding="utf-8") as f:
        end = time.time() + secs
        while time.time() < end:
            bridge.channel.wait(200)
            for rec in bridge.channel.poll():
                line = "[%s] %s" % (rec["kind_name"], rec["text"])
                f.write(line + "\n")
                f.flush()
                if rec["kind_name"] == "签名":
                    n += 1
                    print(line)
    print("签名记录 %d 条；完整日志：%s" % (n, out))
    return 0


if __name__ == "__main__":
    sys.exit(main())