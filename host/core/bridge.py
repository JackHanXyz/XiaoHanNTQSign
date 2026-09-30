# -*- coding: utf-8 -*-
"""注入通道 + IPC 的控制层：给 UI 提供「注入 / 断开 / 收记录」这些动作。

原版工具是「注入后共享内存回传、HTTP 出签名」，这里先把通道跑通，
M3/M4 再把 HOOK 与签名逻辑挂进同一个通道。
"""
import os
import sys
import threading

from core import config, injector, ipc, qqnt

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DLL_NAME = "XHQNative_x64.dll"


def resolve_dll_path():
    """定位注入模块的磁盘路径。

    开发态用源码树里的 native/build 产物；打包态把内嵌的 DLL 释放到
    %APPDATA%\\XiaoHanQQNT\\ 下的固定路径再注入——注入后目标进程会一直映射该文件，
    若直接从 PyInstaller 的临时解包目录（_MEIxxxx）注入，会导致退出时临时目录删不掉，
    而且每次启动路径都不同。
    """
    if not getattr(sys, "frozen", False):
        return os.path.join(PROJECT_ROOT, "native", "build", DLL_NAME)

    dst = os.path.join(config.config_dir(), DLL_NAME)
    src = None
    meipass = getattr(sys, "_MEIPASS", None)
    for cand in ([os.path.join(meipass, "native", DLL_NAME)] if meipass else []) + \
                [os.path.join(os.path.dirname(sys.executable), DLL_NAME)]:
        if os.path.isfile(cand):
            src = cand
            break
    if src and (not os.path.isfile(dst) or os.path.getsize(dst) != os.path.getsize(src)):
        import shutil
        try:
            shutil.copyfile(src, dst)
        except OSError:
            return src      # 拷不动就直接用源路径，功能不受影响
    return dst


DLL_PATH = resolve_dll_path()

# 自检靶子：必须是经典 Win32 GUI 程序，而且要能在本进程外写内存。
# 注意 Win11 会陆续把 notepad / charmap 这类老工具换成应用商店打包应用
# （对它们 VirtualAllocEx 会被拒绝，错误码 5），所以这里逐个探测可用性。
TEST_TARGETS = ("dxdiag.exe", "charmap.exe")


class Bridge:
    """宿主与注入模块之间的桥。UI 只跟它打交道。"""

    def __init__(self):
        self.channel = ipc.ShmChannel()
        self.dll_path = DLL_PATH
        self.target_pid = 0
        self._on_record = None
        self._on_state = None
        self._timer = None
        self._lock = threading.Lock()
        self.last_heartbeat = 0
        self._stalled = 0
        self.paused = False       # 自检期间暂停 UI 侧轮询，避免抢走记录

    # ---------- 配置 ----------
    def set_callbacks(self, on_record, on_state):
        self._on_record = on_record
        self._on_state = on_state

    def available(self):
        """模块是否已构建。"""
        return os.path.isfile(self.dll_path)

    # ---------- 打开/关闭 ----------
    def start(self, pid):
        """打开通道并注入模块。抛异常表示失败。"""
        with self._lock:
            if not self.available():
                raise injector.InjectError(
                    "未找到注入模块，请先执行 native\\build.ps1 构建：%s" % self.dll_path)
            injector.enable_debug_privilege()
            # 模块可能已在目标进程里跑着（宿主重启后重新接管），此时跳过历史记录，
            # 免得上一次会话的记录被当成新记录重复上屏。
            self.channel.open(skip_history=True)
            self.target_pid = pid
            # 已经在目标进程里的模块不要再 LoadLibraryW：每次加载都会让引用计数 +1，
            # 累积之后即使调 FreeLibrary 也卸不掉，DLL 卸载清理逻辑就一直不会触发。
            already_loaded = qqnt.module_base(pid, DLL_NAME) != 0
            if not already_loaded:
                try:
                    injector.inject_dll(pid, self.dll_path)
                except Exception:
                    self.channel.close()
                    self.target_pid = 0
                    raise
            self.last_heartbeat = 0
            self._stalled = 0
            self._state("已%s PID %d，等待模块握手"
                        % ("接管" if already_loaded else "注入", pid))

            # 模块可能已经在目标进程里（LoadLibraryW 会直接返回已有句柄、不再执行 DllMain），
            # 例如上次「安全停用」过、或宿主刚重启。这种情况要主动唤醒它重新握手。
            import time
            deadline = time.time() + 2.0
            while time.time() < deadline and not self.channel.connected:
                time.sleep(0.1)
            if not self.channel.connected:
                try:
                    injector.call_remote_export(pid, DLL_NAME, "XHQ_Start",
                                                self.dll_path, timeout_ms=4000)
                except Exception as e:
                    self._state("唤醒已驻留模块失败：%s" % e)

    def stop(self):
        """断开：关掉宿主句柄。模块侧心跳线程会自行退出（DLL 卸载需重启目标进程）。"""
        with self._lock:
            self.channel.close()
            self.target_pid = 0
            self._state("通道已关闭")

    def shutdown(self):
        """安全停用：让模块恢复所有被改写的字节并停掉自己的线程，然后关掉通道。

        这一步不重启 QQ，也不卸载模块（模块本身无害，留着的是恢复后的原始字节）。
        """
        if self.target_pid and self.channel.connected:
            try:
                injector.call_remote_export(self.target_pid, DLL_NAME, "XHQ_Shutdown",
                                            self.dll_path)
            except Exception:
                pass        # 目标已退出时忽略
        self.stop()

    def set_crypto_hook(self, enable_aes, enable_tea):
        """开关 crypto.dll 的加密 HOOK，返回安装成功的 HOOK 数量。"""
        if not self.target_pid:
            raise injector.InjectError("尚未注入目标进程，请先在首页注入")
        import struct
        flags = struct.pack("<ii", 1 if enable_aes else 0, 1 if enable_tea else 0)
        return injector.call_remote_export(
            self.target_pid, DLL_NAME, "XHQ_SetCryptoHook", self.dll_path, arg_bytes=flags)

    def channel_rpc(self, cmd):
        """走共享内存向模块发一条命令并取回复（HTTP 接口与 UI 共用）。"""
        return self.channel.rpc_call(cmd)

    # ---------- M4 探针 ----------
    def hook_addr(self, spec):
        """在任意地址挂参数探针，spec 形如 "wrapper.node+0x1a2b3c"。"""
        return self.channel_rpc("cmd=hookaddr&spec=%s" % spec)

    def unhook_addr(self):
        return self.channel_rpc("cmd=unhookaddr")

    def call_addr(self, addr, *args, timeout_retries=1):
        """在目标进程内调用任意地址（0~4 个整数参数），返回 64 位返回值。"""
        import struct
        if not self.target_pid:
            raise injector.InjectError("尚未注入目标进程，请先在首页注入")
        if len(args) > 4:
            raise ValueError("最多支持 4 个整数参数")
        padded = tuple(args) + (0,) * (4 - len(args))
        blk = struct.pack("<QQQQQQ", int(addr), len(args), *padded)
        # XHQ_CallAddr 返回 64 位，但线程退出码只有 32 位，所以完整结果从模块回传的记录里读
        injector.call_remote_export(self.target_pid, DLL_NAME, "XHQ_CallAddr",
                                    self.dll_path, arg_bytes=blk)
        for rec in self.channel.poll():
            if rec["text"].startswith("calladdr ret="):
                return int(rec["text"].split("ret=")[1].split(" ")[0])
        return None

    @property
    def running(self):
        return self.channel.header is not None

    # ---------- 轮询 ----------
    def poll(self):
        """读一次心跳与新记录，返回新增记录列表。"""
        if not self.running:
            return []
        self.channel.wait(60)
        for rec in self.channel.poll():
            if self._on_record:
                self._on_record(rec)
        hb = self.channel.heartbeat
        if self.channel.connected and hb == self.last_heartbeat:
            self._stalled += 1
        else:
            self._stalled = 0
        self.last_heartbeat = hb
        if self._stalled == 10:      # 约 5 秒没有心跳，判定模块失联
            self._state("模块心跳中断（目标进程可能已退出或模块被卸载）")
        return []

    def status_text(self):
        if not self.running:
            return "未连接"
        return self.channel.status_text()

    # ---------- 自检 ----------
    def self_check(self):
        """在临时靶子进程里验证「注入 → 心跳 → HOOK → 记录回传」整条链路，不碰 QQ。"""
        import subprocess
        import time
        self.paused = True
        proc = None
        try:
            proc = self._spawn_target(subprocess, time)
            self.start(proc.pid)
            time.sleep(1.5)
            recs = self.channel.poll()
            connected = bool(self.channel.connected and self.channel.heartbeat > 0)

            # 宿主 → 目标：调用模块导出塞一条记录
            echo = "self-check echo from host"
            code = injector.call_remote_export(
                proc.pid, DLL_NAME, "XHQ_PushTest", self.dll_path,
                echo.encode("utf-8") + b"\x00")
            time.sleep(0.3)
            recs += self.channel.poll()

            # HOOK 引擎：挂靶子进程的 GetMessageW
            hook_ret = injector.call_remote_export(
                proc.pid, DLL_NAME, "XHQ_TestHook", self.dll_path,
                b"user32.dll!GetMessageW\x00")
            # 靶子进程此刻多半正阻塞在 GetMessage 里、不会再次进入该函数，
            # 所以直接远程调用一次 GetMessageW，确定性地打中补丁入口。
            injector.call_remote_export(proc.pid, "user32.dll", "GetMessageW",
                                        r"C:\Windows\System32\user32.dll")
            time.sleep(0.5)
            recs += self.channel.poll()

            texts = [r["text"] for r in recs]
            ok = (connected and code == 1 and hook_ret == 1
                  and any(echo in t for t in texts)
                  and any("hook hit" in t for t in texts))
            detail = "；".join(texts) if texts else "（未收到任何记录）"
            if hook_ret not in (0, 1):
                detail = "HOOK 安装失败（返回 %d）：%s" % (hook_ret, detail)
            elif not connected:
                detail = "模块未握手：%s" % detail
            self.stop()
            return ok, detail
        finally:
            if proc:
                proc.terminate()
            self.paused = False

    @staticmethod
    def _spawn_target(subprocess, time):
        """依次尝试候选靶子，返回第一个存活且允许注入的进程。"""
        tried = []
        for exe in TEST_TARGETS:
            try:
                proc = subprocess.Popen(exe)
            except OSError as e:
                tried.append("%s 启动失败(%s)" % (exe, e))
                continue
            time.sleep(1.5)
            if proc.poll() is not None:
                tried.append("%s 启动即退出" % exe)
                continue
            if not injector.can_inject(proc.pid):
                tried.append("%s 拒绝写入内存（应用商店打包应用）" % exe)
                try:
                    proc.terminate()
                except Exception:
                    pass
                continue
            return proc
        raise injector.InjectError("找不到可用的自检靶子：%s" % "；".join(tried))

    # ---------- 状态回调 ----------
    def _state(self, text):
        if self._on_state:
            self._on_state(text)


def qq_pid():
    """取 QQNT 主进程的 PID，没运行返回 0。"""
    return qqnt.find_main_qq()


def restart_qq(root, wait_s=3.0):
    """重启 QQ（对齐原版「未检测到QQ进程，是否需要重启QQ？」的行为）。

    先在后台等几秒确保旧进程完全退出，再拉起启动器。
    """
    import subprocess
    import time

    def _run():
        time.sleep(wait_s)
        exe = os.path.join(root, "QQ.exe")
        if os.path.isfile(exe):
            try:
                subprocess.Popen([exe], cwd=root)
            except OSError:
                pass

    threading.Thread(target=_run, daemon=True).start()