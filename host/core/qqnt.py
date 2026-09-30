# -*- coding: utf-8 -*-
"""QQNT 客户端探测：进程枚举、进程路径、客户端版本目录。"""
import ctypes
import ctypes.wintypes as wt
import os
import re

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
MAX_PATH_LONG = 32768

TARGET_PROCESS = "QQ.exe"


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_wchar * wt.MAX_PATH),
    ]


def _iter_processes():
    """生成 (pid, 进程名) 序列。"""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    try:
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            yield int(entry.th32ProcessID), entry.szExeFile
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)


def find_qq_pids():
    """返回所有 QQ.exe 的 PID 列表（大小写不敏感）。"""
    want = TARGET_PROCESS.lower()
    return [pid for pid, name in _iter_processes() if name.lower() == want]


def process_path(pid):
    """查询进程完整路径，失败返回空串。"""
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(MAX_PATH_LONG)
        size = wt.DWORD(MAX_PATH_LONG)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value
        return ""
    finally:
        kernel32.CloseHandle(h)


TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * wt.MAX_PATH),
    ]


def module_entries(pid):
    """枚举目标进程已加载模块：(名字, 路径, 基址)。权限不足时返回空列表。"""
    snap = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == -1:
        return []
    entry = MODULEENTRY32W()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
    out = []
    try:
        ok = kernel32.Module32FirstW(snap, ctypes.byref(entry))
        while ok:
            out.append((entry.szModule, entry.szExePath, ctypes.cast(
                entry.modBaseAddr, ctypes.c_void_p).value or 0))
            ok = kernel32.Module32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return out


def module_paths(pid):
    """枚举目标进程已加载模块路径（失败返回空列表）。"""
    return [(name, path) for name, path, _base in module_entries(pid)]


def module_base(pid, module_name):
    """取指定模块在目标进程中的基址，找不到返回 0。"""
    want = module_name.lower()
    for name, _path, base in module_entries(pid):
        if name.lower() == want:
            return base
    return 0


def list_versions(root):
    """列出真实版本目录：必须含 QQNT.dll，借此排除热更临时目录。"""
    ver_root = os.path.join(root, "versions")
    if not os.path.isdir(ver_root):
        return []
    out = []
    for name in os.listdir(ver_root):
        p = os.path.join(ver_root, name)
        if re.match(r"^\d+(\.\d+)+-\d+$", name) and \
                os.path.isfile(os.path.join(p, "QQNT.dll")):
            out.append(name)
    # 版本号按数字段排序，最新的排最后
    out.sort(key=lambda v: [int(x) for x in re.findall(r"\d+", v)])
    return out


def launcher_cur_version(root):
    """读取 versions\\config.json 中启动器记录的当前版本。"""
    p = os.path.join(root, "versions", "config.json")
    if not os.path.isfile(p):
        return ""
    try:
        import json
        with open(p, "r", encoding="utf-8") as f:
            return (json.load(f) or {}).get("curVersion", "") or ""
    except Exception:
        return ""


def version_from_modules(pid, installed):
    """通过已加载模块路径判断进程实际运行的版本。

    QQ.exe 只是外壳，真实模块位于 versions\\<版本>\\ 下（QQNT.dll / wrapper.node）。
    """
    for _name, path in module_paths(pid):
        for ver in installed:
            if ("\\versions\\%s\\" % ver).lower() in path.lower():
                return ver
    return ""


def find_main_qq():
    """挑选 QQNT 主进程，没找到返回 0。

    不能直接取进程列表的第一个：QQ 一次会起 9 个同名 QQ.exe（Electron 主进程 +
    渲染/GPU/工具子进程）。只有主进程加载了 wrapper.node 与 crypto.dll，
    注错进程会导致 HOOK 装不上，还可能扰动子进程。多个候选时取模块最多的那个。
    """
    cands = []
    for pid in find_qq_pids():
        mods = dict(module_paths(pid))
        if "wrapper.node" in mods and "crypto.dll" in mods:
            cands.append((len(mods), pid))
    if not cands:
        return 0
    return max(cands)[1]


def running_version(root, pids=None, installed=None):
    """当前正在运行的 QQ 版本目录名；多开时取第一个能识别的。

    顺序：已加载模块 → 启动器 config.json → 已安装版本中最新。
    """
    pids = find_qq_pids() if pids is None else pids
    installed = list_versions(root) if installed is None else installed
    for pid in pids:
        ver = version_from_modules(pid, installed)
        if ver:
            return ver
    return launcher_cur_version(root)


def snapshot(root):
    """一次探测结果汇总，供 UI 展示。"""
    pids = find_qq_pids()
    installed = list_versions(root)
    paths = {pid: process_path(pid) for pid in pids}
    mods = {}
    if pids:
        mods = {n: p for n, p in module_paths(pids[0])}
    return {
        "pids": pids,
        "paths": paths,
        "modules": mods,          # 首个 QQ 进程的关键模块路径（QQNT.dll/wrapper.node）
        "version": running_version(root, pids, installed),
        "installed": installed,
        "running": bool(pids),
    }