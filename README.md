# OpenPCNTQSign 

对 **PCNT（QQ NT / Electron 版 QQ）签名机制**的研究工具集 —— 既能离线加载并调用 `wrapper.node` 的原生密码学函数，也能在活客户端挂钩 `crypto.dll` 抓取真实的 AES / HMAC 调用素材。

> **XiaoHanNTQSign** 从两个方向拆解 PCNT 签名：
> 一是**离线分析**，手动映射 `wrapper.node`（不运行其 node addon 初始化），直接调用其中的 HMAC / AES 原语并与标准向量逐字节比对；
> 二是**真机抓取**，向活客户端注入模块、挂钩 `crypto.dll` 的 AES / HMAC 导出，记录真实的 `(算法, 密钥, 数据, MAC)` 作为离线复算的 ground truth。
> 两者合起来，可验证"给定密钥与数据，离线算出与客户端一致的签名"。

[![C++](https://img.shields.io/badge/C%2B%2B-17-00599C.svg)](#)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> [!WARNING]
> 本项目仅用于**个人学习、协议互操作性与安全研究**。它会**向 QQ 客户端进程注入模块并挂钩其内部函数**，可能违反服务条款并导致**账号被限制或封禁**，风险自负。抓取日志含**真实会话密钥**，切勿提交或分享。请勿用于商业用途、批量操作、外挂或干扰他人。

---

## 特性

- **零第三方依赖（离线库）**：核心仅 C++17 + Winsock，自写 HTTP 服务，全静态编译。
- **离线密码学调用**：手动映射 `wrapper.node`，直接调用其 HMAC / AES 封装，无需登录。
- **真机抓取**：注入 DLL 挂钩 `crypto.dll` 的 AES / EVP / HMAC 导出，回传真实调用素材。
- **自研 x64 inline HOOK 引擎**：不依赖任何第三方 hook 库。
- **共享内存 IPC**：宿主与被注入模块之间用 ring buffer 高效通信。
- **可复现结论**：离线调用结果与 RFC 4231、NIST SP800-38A 标准向量逐字节一致。

## 快速开始

### 离线分析库（C++）

需要 MinGW-w64 的 `g++`（如 MSYS2）。

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
.\build\xhntqsign.exe --selftest            # 映射 wrapper.node + 密码学自测
.\build\xhntqsign.exe --callers 3c13650     # 查谁直接调用了某个 RVA
.\build\xhntqsign.exe --aesdec --aes-key <32字节hex> --aes-iv <16字节hex> --aes-in <hex>
```

默认 QQNT 安装目录为 `D:\QQNT`，可用环境变量 `XHNTQSIGN_QQ_ROOT` 覆盖。

### 在客户端抓取

```powershell
# 构建注入 DLL
powershell -ExecutionPolicy Bypass -File native\build.ps1

# 依赖
pip install pefile

# 注入 + 开挂钩 + 抓 120 秒（期间请操作 QQ，例如发一条消息）
python tools\capture.py 120
```

注入后若需改动 DLL，必须先重启 QQ 释放文件占用。

## 目录结构

```
XiaoHanNTQSign/
├─ src/             离线分析库（C++17）：PE 手动映射 + 调用 wrapper.node 密码学函数
│  ├─ pe_mapper.*       PE 手动映射（分配/重定位/解析导入）
│  ├─ sign_backend.*    离线调用 HMAC / AES 原语
│  ├─ crypto.*          基于 Windows CNG 的参考实现（对照用）
│  ├─ http_server.*     QSign 兼容的 HTTP 骨架
│  └─ version_table.*   版本 → 入口 RVA 的地址库
├─ native/          在客户端抓取（C，注入 DLL）
│  ├─ src/hook*.{c,h}   自研 x64 inline HOOK 引擎
│  ├─ src/hook_crypto.c 挂钩 crypto.dll 的 AES / EVP / HMAC 导出
│  ├─ src/ipc_shm.h     共享内存 IPC 协议
│  ├─ src/pe_util.*     PE 导出解析
│  └─ build.ps1         构建脚本（MinGW-w64）
├─ host/core/       Python 宿主：注入器 + IPC + 桥
│  ├─ injector.py       远程注入
│  ├─ ipc.py            共享内存 ring buffer
│  ├─ bridge.py         注入 / 挂钩 / 收记录 的控制层
│  └─ qqnt.py           QQ 进程与模块探测
└─ tools/           抓取与逆向脚本
   ├─ capture.py        注入 + 开挂钩 + 抓取（推荐入口）
   ├─ watch_traffic.py  只观察已注入模块
   ├─ probe_addr.py     任意地址挂钩 / 调用
   └─ scan_exports.py   枚举模块导出
```

## 它解决什么问题

QSign 这类"签名服务"在安卓 QQ 上通过模拟执行 `libfekit.so` 来产出签名。PCNT 没有这样一个独立的签名函数：它的签名能力**嵌在会话对象图里**（导出的 `nt::wrapper::INTSessionShell` 会话壳），密钥来自已登录会话。本项目用离线映射与真机抓取两条路径，把"密钥与数据 → 签名"这条链路完整复现出来。

## 已复现的技术结论

均为实测、可复现：

- `wrapper.node+0x3C13650` 是 **HMAC** 封装（`HMAC_Init_ex → HMAC_Update ×2 → HMAC_Final`），`mode` 参数 `0 / 1 / 2` 分别选 `EVP_sha1 / sha256 / sha512`；离线调用结果与 RFC 4231 向量一致。
- `wrapper.node+0x3C139B0` 是 **AES-256-CBC** 封装（禁用 PKCS 填充，key 固定 32 字节）；离线调用结果与 NIST SP800-38A 向量一致。
- `crypto.dll` 会**池化复用 `EVP_CIPHER_CTX`**（`EVP_CIPHER_CTX_new` 每次返回同一指针）；在其之前先调用过 Windows CNG(bcrypt) 时，会读到陈旧的 IV —— 这是实现时必须规避的坑。
- 客户端实际的报文签名符合 **encrypt-then-MAC** 形态：`HMAC(会话MAC密钥, IV || AES-256-CBC密文 || 计数器) → MAC`。会话密钥在单次登录内恒定。

> 以上只描述结构与算法，不含任何真实密钥。

## 离线调用示例

映射指定版本的 `wrapper.node`（内部完成分配 / 重定位 / 导入解析，不运行 node addon 初始化），然后直接调用其 HMAC / AES 原语：

```cpp
xh::OfflineBackend backend;
std::string err;
backend.init("D:\\QQNT", "<QQ版本>", &err);   // 映射 wrapper.node 并定位签名/加密入口

// +0x3C13650：HMAC，mode 0/1/2 => EVP_sha1 / sha256 / sha512
std::vector<uint8_t> mac;
int ret = 0;
backend.hmac_real(/* mode */ 0, key, data1, data2, mac, &ret);

// +0x3C139B0：AES-256-CBC（无填充，key 固定 32 字节，enc 1=加密 0=解密）
std::vector<uint8_t> out;
backend.aes_real(/* enc */ 1, key32, iv16, plain, out, &ret);
```

命令行等价入口见上文 `--selftest / --callers / --aesdec`。

## 抓取示例

```python
from core.bridge import Bridge, qq_pid

bridge = Bridge()
bridge.set_callbacks(on_record=lambda rec: print(rec["text"]), on_state=print)

bridge.start(qq_pid())                       # 注入 XHQNative 到 QQ 主进程
bridge.set_crypto_hook(enable_aes=True, enable_tea=False)   # 挂钩 crypto.dll 的 AES_* / EVP_* / HMAC_* 导出

while bridge.running:                        # 心跳 + 持续收取新记录（经回调上抛）
    bridge.poll()
```

## 许可

[MIT](LICENSE) — 可自由使用与修改，见 [LICENSE](LICENSE)。
