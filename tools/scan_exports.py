# -*- coding: utf-8 -*-
"""枚举目标进程已加载模块的导出表，按关键字过滤。

用途：定位签名/加密相关入口。QQNT 的签名入口没有具名导出、且被 QVMP 保护，
但先确认其它模块（crypto.dll / ssl.dll / 各 .node）里有没有可直接用的具名函数。

用法：
    python tools/re/scan_exports.py <pid> [关键字正则]
示例：
    python tools/re/scan_exports.py 12345 "sign|tea|aes|encrypt|session"
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "host"))

import pefile  # noqa: E402
from core import qqnt  # noqa: E402

DEFAULT_PATTERN = r"sign|tea|aes|encrypt|decrypt|protocol|packet|session|crypt|hash|md5"


def exports_of(path):
    """解析文件导出表，返回 [导出名]。失败返回 None。"""
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return None
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        d = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if not d:
            return []
        return [s.name.decode("utf-8", "replace") for s in d.symbols if s.name]
    finally:
        pe.close()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    pid = int(sys.argv[1])
    pattern = re.compile(sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PATTERN, re.I)

    seen = set()
    for name, path, base in qqnt.module_entries(pid):
        if name.lower() in seen:
            continue
        seen.add(name.lower())
        exps = exports_of(path)
        if exps is None:
            print("%-22s %8s  解析失败（可能不是 PE）" % (name, "-"))
            continue
        hits = [e for e in exps if pattern.search(e)]
        print("%-22s 导出 %5d  命中 %4d  base=0x%X" % (name, len(exps), len(hits), base or 0))
        for e in hits[:20]:
            print("      %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main())