# -*- coding: utf-8 -*-
"""配置读写：对齐原版 NTQQ_Tool「签名服务」页的可配置项。"""
import json
import os

APP_NAME = "XiaoHanQQNT"

# 默认配置。字段名与原版界面一一对应，方便后续替换成真实逻辑。
DEFAULTS = {
    # 功能一：签名服务
    "call_url": "",            # 调用地址
    "offset_params": "",       # 偏移参数
    "sign_name": "",           # Sign_名称
    "extra_name": "",          # Extra_名称
    "token_name": "",          # Token_名称
    "custom_text": "",         # 自定义文本
    "port": 9377,              # 对外端口
    "path": "/sign",           # 请求路径
    "show_qq_version": True,   # 显示QQ版本

    # 运行环境
    "qqnt_root": r"D:\QQNT",   # QQNT 安装根目录（含 versions 子目录）

    # 功能二：抓包监控（M3 使用）
    "hook_tea": True,
    "hook_aes": True,
    "filter_package": "",
    "log_scroll": True,
}


def config_dir():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    d = os.path.join(base, APP_NAME)
    if not os.path.isdir(d):
        os.makedirs(d)
    return d


def config_path():
    return os.path.join(config_dir(), "config.json")


def load():
    """读取配置，缺失字段用默认值补齐。"""
    cfg = dict(DEFAULTS)
    p = config_path()
    if os.path.isfile(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                cfg.update(json.load(f) or {})
        except Exception:
            # 配置损坏时退回默认值，不阻断启动
            pass
    return cfg


def save(cfg):
    with open(config_path(), "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)