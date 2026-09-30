# -*- coding: utf-8 -*-
"""宿主侧注入器（x64）：CreateRemoteThread + LoadLibraryW，失败时退回 RtlCreateUserThread。

只用于往目标进程里送我们自己的模块，注入前应确认目标确实是 QQ.exe。
"""
import ctypes
import ctypes.wintypes as wt
import os

from core import qqnt

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT_RESERVE = 0x3000
PAGE_READWRITE = 0x04
MEM_RELEASE = 0x8000
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0x0


kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.VirtualAllocEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, wt.DWORD]
kernel32.VirtualFreeEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD]
kernel32.WriteProcessMemory.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.GetModuleHandleW.restype = wt.HMODULE
kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
kernel32.GetProcAddress.restype = ctypes.c_void_p
kernel32.GetProcAddress.argtypes = [wt.HMODULE, ctypes.c_char_p]
kernel32.CreateRemoteThread.restype = wt.HANDLE
kernel32.CreateRemoteThread.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
    ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
kernel32.GetExitCodeThread.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
ntdll.RtlCreateUserThread.restype = ctypes.c_long
ntdll.RtlCreateUserThread.argtypes = [
    wt.HANDLE, ctypes.c_void_p, wt.BOOL, ctypes.c_ulong, ctypes.c_size_t, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wt.HANDLE), ctypes.c_void_p]


class InjectError(Exception):
    pass


def enable_debug_privilege():
    """开启 SeDebugPrivilege，便于打开更高完整性级别的进程。"""
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x0002

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wt.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    h_token = wt.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                     ctypes.byref(h_token)):
        return False
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), 0, None, None)
        return ctypes.get_last_error() == 0
    finally:
        kernel32.CloseHandle(h_token)


def _remote_load_library_addr(pid):
    """算出目标进程里 LoadLibraryW 的地址：用目标 kernel32 基址 + 本进程内偏移。"""
    target_base = qqnt.module_base(pid, "kernel32.dll")
    if not target_base:
        raise InjectError("无法获取目标进程中 kernel32.dll 基址（权限不足？）")
    local_k32 = kernel32.GetModuleHandleW("kernel32.dll")
    local_proc = kernel32.GetProcAddress(local_k32, b"LoadLibraryW")
    if not local_proc:
        raise InjectError("本进程取不到 LoadLibraryW 地址")
    # HMODULE 在 Windows 上就是模块基址
    rva = local_proc - int(ctypes.cast(local_k32, ctypes.c_void_p).value)
    return target_base + rva


def inject_dll(pid, dll_path):
    """把 dll_path 注入 pid，返回 True/False。dll_path 必须存在。"""
    dll_path = os.path.abspath(dll_path)
    if not os.path.isfile(dll_path):
        raise InjectError("模块不存在：%s" % dll_path)

    h_proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_proc:
        raise InjectError("OpenProcess 失败，错误码 %d（可能需要管理员权限）"
                          % ctypes.get_last_error())
    try:
        path_bytes = dll_path.encode("utf-16-le") + b"\x00\x00"
        size = len(path_bytes)
        addr = kernel32.VirtualAllocEx(h_proc, None, size, MEM_COMMIT_RESERVE, PAGE_READWRITE)
        if not addr:
            raise InjectError("VirtualAllocEx 失败，错误码 %d" % ctypes.get_last_error())
        try:
            written = ctypes.c_size_t(0)
            if not kernel32.WriteProcessMemory(h_proc, addr, path_bytes, size,
                                               ctypes.byref(written)) \
                    or written.value != size:
                raise InjectError("WriteProcessMemory 失败，错误码 %d" % ctypes.get_last_error())

            load_addr = _remote_load_library_addr(pid)
            h_thread = kernel32.CreateRemoteThread(
                h_proc, None, 0, ctypes.c_void_p(load_addr), addr, 0, None)
            if not h_thread:
                h_thread = _rtl_create_thread(h_proc, load_addr, addr)
            if not h_thread:
                raise InjectError("创建远程线程失败，错误码 %d" % ctypes.get_last_error())
            try:
                kernel32.WaitForSingleObject(h_thread, 15000)
                code = wt.DWORD(0)
                kernel32.GetExitCodeThread(h_thread, ctypes.byref(code))
                # LoadLibraryW 返回模块句柄，x64 下句柄值不会为 0
                if code.value in (0, 0xFFFFFFFF):
                    raise InjectError("目标进程 LoadLibraryW 返回 0（可能被安全策略拦截）")
                return True
            finally:
                kernel32.CloseHandle(h_thread)
        finally:
            kernel32.VirtualFreeEx(h_proc, addr, 0, MEM_RELEASE)
    finally:
        kernel32.CloseHandle(h_proc)


def _rtl_create_thread(h_proc, start, param):
    """RtlCreateUserThread 兜底创建线程（更底层，可绕过部分线程创建监控）。"""
    h_thread = wt.HANDLE()
    status = ntdll.RtlCreateUserThread(
        h_proc, None, False, 0, 0, 0,
        ctypes.c_void_p(start), ctypes.c_void_p(param),
        ctypes.byref(h_thread), None)
    if status != 0:
        ctypes.set_last_error(status)
        return None
    return h_thread


def export_rva(dll_path, export_name):
    """从本地 DLL 文件里取导出函数的 RVA。"""
    import pefile
    pe = pefile.PE(dll_path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir:
        for sym in export_dir.symbols:
            if sym.name and sym.name.decode("utf-8", "replace") == export_name:
                rva = sym.address
                pe.close()
                return rva
    pe.close()
    raise InjectError("模块 %s 中找不到导出 %s" % (dll_path, export_name))


def can_inject(pid):
    """探测目标进程是否允许写入内存。

    应用商店打包应用（如 Win11 新版记事本/charmap）会拒绝 VirtualAllocEx（错误码 5），
    必须在真正注入前先排除，否则会拿到一个看不懂的失败。
    """
    h_proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_proc:
        return False
    try:
        addr = kernel32.VirtualAllocEx(h_proc, None, 64, MEM_COMMIT_RESERVE, PAGE_READWRITE)
        if not addr:
            return False
        kernel32.VirtualFreeEx(h_proc, addr, 0, MEM_RELEASE)
        return True
    finally:
        kernel32.CloseHandle(h_proc)


def param_address_of(param):
    """把 ctypes 参数转成 _rtl_create_thread 需要的整数地址。"""
    if param is None:
        return 0
    if isinstance(param, int):
        return param
    return int(param.value or 0)


def call_remote_export(pid, dll_name, export_name, dll_path, arg_bytes=None,
                       param_value=None, timeout_ms=8000):
    """在目标进程里调用已注入模块的导出函数，返回函数返回值。

    arg_bytes 不为空时会写入目标进程内存，并把该地址作为唯一参数传入。
    param_value 不为空时直接把该整数作为唯一参数（用于 FreeLibrary(HMODULE) 这类按值传参）。
    需要多个参数时，模块侧应导出「取参数块指针」的形式，不要在宿主侧改寄存器
    （x64 远程线程挂起后改上下文实测会把目标线程跑崩）。
    """
    base = qqnt.module_base(pid, dll_name)
    if not base:
        raise InjectError("目标进程中未找到模块 %s（是否注入成功？）" % dll_name)
    addr = base + export_rva(dll_path, export_name)

    h_proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_proc:
        raise InjectError("OpenProcess 失败，错误码 %d" % ctypes.get_last_error())
    param_addr = None
    try:
        if arg_bytes:
            size = len(arg_bytes)
            param_addr = kernel32.VirtualAllocEx(
                h_proc, None, size, MEM_COMMIT_RESERVE, PAGE_READWRITE)
            if not param_addr:
                raise InjectError("VirtualAllocEx 失败，错误码 %d" % ctypes.get_last_error())
            written = ctypes.c_size_t(0)
            if not kernel32.WriteProcessMemory(h_proc, param_addr, arg_bytes, size,
                                               ctypes.byref(written)):
                raise InjectError("WriteProcessMemory 失败，错误码 %d" % ctypes.get_last_error())

        param = param_addr if param_addr else (
            ctypes.c_void_p(int(param_value)) if param_value is not None else None)
        h_thread = kernel32.CreateRemoteThread(
            h_proc, None, 0, ctypes.c_void_p(addr), param, 0, None)
        if not h_thread:
            h_thread = _rtl_create_thread(h_proc, addr, param_address_of(param))
        if not h_thread:
            raise InjectError("创建远程线程失败，错误码 %d" % ctypes.get_last_error())
        try:
            kernel32.WaitForSingleObject(h_thread, timeout_ms)
            code = wt.DWORD(0)
            kernel32.GetExitCodeThread(h_thread, ctypes.byref(code))
            return code.value
        finally:
            kernel32.CloseHandle(h_thread)
    finally:
        if param_addr:
            kernel32.VirtualFreeEx(h_proc, param_addr, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_proc)