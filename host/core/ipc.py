# -*- coding: utf-8 -*-
"""宿主侧 IPC：共享内存 ring buffer + 命名事件，协议见 native/src/ipc_shm.h。

生命周期：
    ch = ShmChannel(); ch.open()      # 建好三个内核对象并把名字写入引导映射
    injector.inject(pid)              # 注入模块，模块自己来连
    ch.poll()                         # 读心跳与新增记录
    ch.close()                        # 关闭句柄（模块下次心跳失败后退出循环）
"""
import ctypes
import ctypes.wintypes as wt

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

XHQ_MAGIC = 0x51484E51
XHQ_ABI = 1
XHQ_BOOTSTRAP_NAME = "Local\\XiaoHanQQNT_Bootstrap"
XHQ_BOOTSTRAP_SIZE = 512
XHQ_TEXT_MAX = 4080
XHQ_CMD_MAX = 512
XHQ_OUT_MAX = 2048

KIND_NAMES = {1: "信息", 2: "签名", 3: "TEA", 4: "AES"}

PAGE_READWRITE = 0x04
FILE_MAP_ALL_ACCESS = 0x000F001F
EVENT_MODIFY_STATE = 0x0002
SYNCHRONIZE = 0x00100000


class Bootstrap(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", wt.DWORD),
        ("host_pid", wt.DWORD),
        ("shm_name", ctypes.c_wchar * 64),
        ("evt_name", ctypes.c_wchar * 64),
    ]


class Record(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("seq", wt.DWORD),
        ("kind", wt.DWORD),
        ("tick_ms", ctypes.c_ulonglong),
        ("pid", wt.DWORD),
        ("len", wt.DWORD),
        ("text", ctypes.c_char * XHQ_TEXT_MAX),
    ]


class ShmHeader(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", wt.DWORD),
        ("abi", wt.DWORD),
        ("dll_pid", wt.DWORD),
        ("dll_tid", wt.DWORD),
        ("heartbeat", ctypes.c_long),
        ("record_count", ctypes.c_long),
        ("dropped", ctypes.c_long),
        ("capacity", wt.DWORD),
        ("module_path", ctypes.c_char * 260),
    ]


class Rpc(ctypes.Structure):
    """请求/应答区，与 native/src/ipc_shm.h 的 XHQ_RPC 一一对应。"""
    _pack_ = 1
    _fields_ = [
        ("req_seq", ctypes.c_long),
        ("done_seq", ctypes.c_long),
        ("cmd_len", wt.DWORD),
        ("out_len", wt.DWORD),
        ("cmd", ctypes.c_char * XHQ_CMD_MAX),
        ("out", ctypes.c_char * XHQ_OUT_MAX),
    ]


kernel32.CreateFileMappingW.restype = wt.HANDLE
kernel32.CreateFileMappingW.argtypes = [
    wt.HANDLE, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.DWORD, wt.LPCWSTR]
kernel32.MapViewOfFile.restype = ctypes.c_void_p
kernel32.MapViewOfFile.argtypes = [wt.HANDLE, wt.DWORD, wt.DWORD, wt.DWORD, ctypes.c_size_t]
kernel32.UnmapViewOfFile.restype = wt.BOOL
kernel32.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
kernel32.CreateEventW.restype = wt.HANDLE
kernel32.CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]
kernel32.OpenEventW.restype = wt.HANDLE
kernel32.OpenEventW.argtypes = [wt.DWORD, wt.BOOL, wt.LPCWSTR]
kernel32.OpenFileMappingW.restype = wt.HANDLE
kernel32.OpenFileMappingW.argtypes = [wt.DWORD, wt.BOOL, wt.LPCWSTR]
kernel32.WaitForSingleObject.restype = wt.DWORD
kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]

INVALID_HANDLE_VALUE = wt.HANDLE(-1)


class ShmChannel:
    """宿主持有的共享内存通道。capacity 为记录槽数量。"""

    def __init__(self, capacity=256):
        self.capacity = capacity
        self.h_boot = None
        self.h_shm = None
        self.h_evt = None
        self.p_boot = None
        self.p_shm = None
        # 用固定名字而不是带 PID 的名字：这样宿主重启后可以直接重新接管已注入的模块，
        # 不需要重启 QQ（模块加载时记住的就是这两个名字）。
        self.shm_name = "Local\\XiaoHanQQNT_Shm"
        self.evt_name = "Local\\XiaoHanQQNT_Evt"
        self.header = None
        self.rpc = None
        self._read_index = 0

    # ---------- 打开/关闭 ----------
    def open(self, skip_history=False):
        """创建内核对象并写好引导信息，返回是否成功。

        skip_history=True 时（模块已在运行时重新接管），从当前写位置开始读，
        避免把上次会话的历史记录当成新记录重放。
        """
        self.close()
        h_boot = kernel32.CreateFileMappingW(
            INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0, XHQ_BOOTSTRAP_SIZE,
            XHQ_BOOTSTRAP_NAME)
        if not h_boot:
            raise OSError("创建引导映射失败: %d" % ctypes.get_last_error())
        self.h_boot = h_boot
        self.p_boot = kernel32.MapViewOfFile(h_boot, FILE_MAP_ALL_ACCESS, 0, 0, XHQ_BOOTSTRAP_SIZE)
        if not self.p_boot:
            self.close()
            raise OSError("映射引导数据失败: %d" % ctypes.get_last_error())

        size = (ctypes.sizeof(ShmHeader) + ctypes.sizeof(Rpc)
                + self.capacity * ctypes.sizeof(Record))
        # 固定名可能已被上一个宿主实例创建（句柄随模块存活），此时直接复用，
        # 这样宿主重启后能立刻接管已注入的模块。
        h_shm = kernel32.OpenFileMappingW(FILE_MAP_ALL_ACCESS, False, self.shm_name)
        reused = bool(h_shm)
        if not h_shm:
            h_shm = kernel32.CreateFileMappingW(
                INVALID_HANDLE_VALUE, None, PAGE_READWRITE,
                size >> 32, size & 0xFFFFFFFF, self.shm_name)
        if not h_shm:
            self.close()
            raise OSError("创建共享内存失败: %d" % ctypes.get_last_error())
        self.h_shm = h_shm
        self.p_shm = kernel32.MapViewOfFile(h_shm, FILE_MAP_ALL_ACCESS, 0, 0, size)
        if not self.p_shm:
            self.close()
            raise OSError("映射共享内存失败: %d" % ctypes.get_last_error())
        self.header = ctypes.cast(self.p_shm, ctypes.POINTER(ShmHeader)).contents
        self.rpc = ctypes.cast(self.p_shm + ctypes.sizeof(ShmHeader),
                               ctypes.POINTER(Rpc)).contents
        self.reused = reused
        if not reused:
            self.header.magic = XHQ_MAGIC
            self.header.abi = XHQ_ABI
            self.header.capacity = self.capacity
            self.header.dll_pid = 0
        elif int(self.header.capacity) != self.capacity:
            self.close()
            raise OSError("已有通道的容量(%d)与本进程(%d)不一致"
                          % (self.header.capacity, self.capacity))

        h_evt = kernel32.OpenEventW(
            EVENT_MODIFY_STATE | SYNCHRONIZE, False, self.evt_name)
        if not h_evt:
            h_evt = kernel32.CreateEventW(None, False, False, self.evt_name)
        self.h_evt = h_evt
        if not self.h_evt:
            self.close()
            raise OSError("创建事件对象失败: %d" % ctypes.get_last_error())

        boot = ctypes.cast(self.p_boot, ctypes.POINTER(Bootstrap)).contents
        boot.magic = XHQ_MAGIC
        boot.host_pid = ctypes.windll.kernel32.GetCurrentProcessId()
        boot.shm_name = self.shm_name
        boot.evt_name = self.evt_name
        if skip_history and reused:
            self._read_index = int(self.header.record_count)
        return True

    def close(self):
        for attr in ("p_boot", "p_shm"):
            p = getattr(self, attr)
            if p:
                kernel32.UnmapViewOfFile(ctypes.c_void_p(p))
                setattr(self, attr, None)
        for attr in ("h_boot", "h_shm", "h_evt"):
            h = getattr(self, attr)
            if h:
                kernel32.CloseHandle(h)
                setattr(self, attr, None)
        self.header = None
        self.rpc = None

    # ---------- 状态 ----------
    @property
    def heartbeat(self):
        return self.header.heartbeat if self.header else 0

    @property
    def connected(self):
        return bool(self.header and self.header.dll_pid)

    def status_text(self):
        if not self.header:
            return "通道未打开"
        if not self.header.dll_pid:
            return "已就绪，等待模块连接"
        return "已连接：PID %d，心跳 %d" % (self.header.dll_pid, self.header.heartbeat)

    def wait(self, timeout_ms=300):
        """等待模块通知（有新记录或心跳唤醒）。"""
        if not self.h_evt:
            return False
        return kernel32.WaitForSingleObject(self.h_evt, timeout_ms) == 0

    # ---------- 请求/应答 ----------
    def rpc_call(self, cmd, timeout_ms=3000):
        """发一条命令给目标进程里的模块，返回回复文本；超时抛 TimeoutError。"""
        import time
        if not self.rpc:
            raise RuntimeError("通道未打开")
        if not self.connected:
            raise RuntimeError("模块尚未连接")

        payload = cmd.encode("utf-8")[:XHQ_CMD_MAX - 1]
        cmd_addr = ctypes.addressof(self.rpc) + Rpc.cmd.offset
        ctypes.memset(cmd_addr, 0, XHQ_CMD_MAX)
        ctypes.memmove(cmd_addr, payload, len(payload))
        self.rpc.cmd_len = len(payload)

        seq = int(self.rpc.req_seq) + 1
        self.rpc.req_seq = seq

        deadline = time.time() + timeout_ms / 1000.0
        while time.time() < deadline:
            if int(self.rpc.done_seq) == seq:
                n = min(int(self.rpc.out_len), XHQ_OUT_MAX)
                return self.rpc.out[:n].decode("utf-8", "replace")
            time.sleep(0.01)
        raise TimeoutError("模块未在 %dms 内回复命令 %r" % (timeout_ms, cmd))

    # ---------- 读取记录 ----------
    def poll(self):
        """返回自上次调用后新产生的记录列表 [{'kind','kind_name','pid','tick','text'}]。"""
        if not self.header:
            return []
        base = self.p_shm + ctypes.sizeof(ShmHeader) + ctypes.sizeof(Rpc)
        slots = ctypes.cast(base, ctypes.POINTER(Record))
        count = int(self.header.record_count)
        cap = self.capacity

        # 宿主落后太多时，旧的槽位已被覆盖，直接跳到还能保证完整的区间
        if count - self._read_index > cap:
            self._read_index = count - cap

        out = []
        i = self._read_index
        while i < count:
            r = slots[i % cap]
            if int(r.seq) == (i + 1) % 0x100000000:   # seq 是「写完整」标记
                text = r.text[:min(int(r.len), XHQ_TEXT_MAX)]
                out.append({
                    "kind": int(r.kind),
                    "kind_name": KIND_NAMES.get(int(r.kind), "未知"),
                    "pid": int(r.pid),
                    "tick": int(r.tick_ms),
                    "text": text.decode("utf-8", "replace"),
                })
            i += 1
        self._read_index = count
        return out