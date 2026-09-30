# -*- coding: utf-8 -*-
"""M4 探针工具：在 QQ 进程里挂钩/调用任意地址，用来定位签名入口。

先决条件：宿主 GUI 里完成过一次「注入 QQ」，或者本脚本自己注入（需要 DLL 已构建）。

用法：
    # 注入（若还没注入过）
    python tools/re/probe_addr.py inject

    # 在某个地址挂参数探针，观察谁调用它、参数是什么
    python tools/re/probe_addr.py hook wrapper.node+0x1a2b3c
    python tools/re/probe_addr.py watch 60

    # 卸载探针
    python tools/re/probe_addr.py unhook

    # 直接调用某个地址（0~4 个整数参数），看返回值
    python tools/re/probe_addr.py call crypto.dll+0x5cce0 0x1000 0x2000

说明：探针只能记录前 4 个整数参数（RIP/RCX/RDX/R8/R9），浮点参数与第 5 个及以后的
栈参数不会被记录，但会被原样转发、不影响目标函数本身的行为。
"""
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "host"))

from core import qqnt  # noqa: E402
from core.bridge import Bridge, DLL_NAME, DLL_PATH  # noqa: E402


def find_main_qq():
    for pid in qqnt.find_qq_pids():
        mods = dict(qqnt.module_paths(pid))
        if "crypto.dll" in mods and "wrapper.node" in mods:
            return pid
    return 0


def resolve(spec):
    """把 "模块名+0xRVA" 换算成目标进程里的绝对地址。"""
    if "+" not in spec:
        return int(spec, 16)
    mod, rva = spec.split("+", 1)
    base = qqnt.module_base(pid, mod.strip())
    if not base:
        raise SystemExit("目标进程里没有加载模块 %s" % mod)
    return base + int(rva, 16)


BRIDGE = Bridge()
pid = find_main_qq()
if not pid:
    raise SystemExit("未找到 QQ 主进程（需已登录并运行）")

cmd = sys.argv[1] if len(sys.argv) > 1 else "help"

if cmd == "inject":
    BRIDGE.start(pid)
    for _ in range(24):
        time.sleep(0.25)
        if BRIDGE.channel.connected:
            break
    print("注入结果：", BRIDGE.channel.status_text())
elif cmd == "hook":
    if len(sys.argv) < 3:
        raise SystemExit("用法：probe_addr.py hook 模块名+0xRVA")
    BRIDGE.channel.open()
    print(BRIDGE.channel.status_text())
    BRIDGE.target_pid = pid
    print(BRIDGE.hook_addr(sys.argv[2]))
elif cmd == "unhook":
    BRIDGE.channel.open()
    BRIDGE.target_pid = pid
    print(BRIDGE.unhook_addr())
elif cmd == "call":
    if len(sys.argv) < 3:
        raise SystemExit("用法：probe_addr.py call 模块名+0xRVA [a1 a2 a3 a4]")
    BRIDGE.channel.open()
    BRIDGE.target_pid = pid
    args = [int(x, 0) for x in sys.argv[3:7]]
    print("返回：", BRIDGE.call_addr(resolve(sys.argv[2]), *args))
elif cmd == "watch":
    secs = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    BRIDGE.channel.open()
    BRIDGE.target_pid = pid
    print("观察 %d 秒（注意：GUI 同时在跑会跟本脚本抢记录）..." % secs)
    start = time.time()
    while time.time() - start < secs:
        BRIDGE.channel.wait(200)
        for rec in BRIDGE.channel.poll():
            print("[%s] %s" % (rec["kind_name"], rec["text"]))
else:
    print(__doc__)