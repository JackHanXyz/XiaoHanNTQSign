# -*- coding: utf-8 -*-
"""后台抓包观察：重连已注入的模块，把 AES/TEA/签名记录落盘。

用法：
    python tools/re/watch_traffic.py [秒数] [输出文件]
默认观察 600 秒并写到 tools/re/traffic.log。

模块的通道名是固定的，所以这个脚本可以在宿主（GUI）关闭后单独运行；
两个进程同时读同一条通道会互相抢记录，所以别和 GUI 一起跑。
"""
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "host"))

from core import ipc  # noqa: E402


def main():
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 600
    out_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "traffic.log")

    ch = ipc.ShmChannel()
    ch.open(skip_history=True)   # 只看本次观察期间的新记录，历史记录在日志文件中
    print("通道状态：%s（reused=%s）" % (ch.status_text(), ch.reused))
    if not ch.connected:
        print("模块未连接：请先在 GUI 首页点「注入 QQ」，或确认 QQ 正在运行且已注入。")
        ch.close()
        return 1

    print("开始观察 %d 秒，日志写入 %s" % (seconds, out_path))
    total = 0
    last_hb = ch.heartbeat
    stalls = 0
    with open(out_path, "a", encoding="utf-8") as f:
        start = time.time()
        while time.time() - start < seconds:
            ch.wait(200)
            recs = ch.poll()
            for r in recs:
                total += 1
                line = "[%s] pid=%d %s" % (r["kind_name"], r["pid"], r["text"])
                f.write(line + "\n")
                f.flush()
                print(line)
            # 心跳每 500ms +1；连续多轮没变才认为模块失联（单轮相等属正常）
            if ch.heartbeat == last_hb:
                stalls += 1
                if stalls >= 8:
                    print("  (心跳停滞，模块可能已随目标进程退出)")
                    break
            else:
                stalls = 0
            last_hb = ch.heartbeat
    print("观察结束，共 %d 条新记录（心跳 %d）" % (total, ch.heartbeat))
    ch.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())