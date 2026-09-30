/* dllmain.c —— XiaoHanQQNT 注入模块（x64）
 *
 * 职责（M2）：进入目标进程后建立共享内存通道并持续心跳，让宿主确认「已连接」。
 * 后续 M3/M4 会在这里挂 HOOK 并把数据通过 xhq_push 送出去。
 *
 * 设计要点：
 *   - 纯 C + 仅依赖 kernel32 / msvcrt，避免引入 libstdc++ 等额外 DLL；
 *   - 不在 DllMain 里做重活，创建线程后立刻返回，规避加载器锁问题；
 *   - 所有导出函数都是 C 约定，宿主可用 GetProcAddress 直接取。
 */
#include <windows.h>
#include "ipc_shm.h"
#include "hook.h"
#include "pe_util.h"
#include "xhq_log.h"
#include "hook_crypto.h"

static HANDLE        g_hShm = NULL;
static XHQ_SHM_HEADER *g_hdr = NULL;
static XHQ_RPC       *g_rpc = NULL;
static HANDLE        g_hEvt = NULL;
static volatile LONG g_inited = 0;
static volatile LONG g_shutdown = 0;   /* 置 1 后心跳/RPC 线程自行退出 */

/* ---------- 极简工具函数（不依赖 CRT） ---------- */
static unsigned int xhq_strlen(const char *s)
{
    unsigned int n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static void xhq_memcpy(void *dst, const void *src, unsigned int n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
}

static int xhq_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

/* 任意地址探针（实现见文件后半部分），命令处理里要用到，先声明 */
__declspec(dllexport) int __stdcall XHQ_HookAddr(const char *spec);
__declspec(dllexport) int __stdcall XHQ_UnhookAddr(void);

/* 追加十进制数字，返回写入长度 */
static unsigned int xhq_ui2a(unsigned long long v, char *out)
{
    char tmp[24];
    int n = 0, i;
    if (v == 0) { out[0] = '0'; return 1; }
    while (v && n < 24) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    for (i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    return (unsigned int)n;
}

/* 把 src 拼到 dst 尾部，返回新的长度（不越界） */
static unsigned int xhq_cat(char *dst, unsigned int cap, unsigned int cur, const char *src)
{
    while (*src && cur + 1 < cap) dst[cur++] = *src++;
    dst[cur] = 0;
    return cur;
}

static unsigned int xhq_cat_u(char *dst, unsigned int cap, unsigned int cur, unsigned long long v)
{
    char num[24];
    unsigned int n = xhq_ui2a(v, num);
    if (cur + n + 1 >= cap) n = (cur + 1 < cap) ? (cap - 1 - cur) : 0;
    xhq_memcpy(dst + cur, num, n);
    cur += n;
    dst[cur] = 0;
    return cur;
}

/* ---------- 共享内存 ---------- */

/* 槽位指针：header 与 RPC 区之后紧跟记录数组 */
static XHQ_RECORD *xhq_slot(unsigned int idx)
{
    XHQ_RECORD *base = (XHQ_RECORD *)((unsigned char *)g_hdr + sizeof(XHQ_SHM_HEADER)
                                      + sizeof(XHQ_RPC));
    return &base[idx % g_hdr->capacity];
}

/* 写一条记录。宿主以 seq 作为「写完整」标记，见 host/core/ipc.py */
void xhq_push(unsigned int kind, const char *text, unsigned int len)
{
    LONG n;
    unsigned int idx;
    XHQ_RECORD *r;

    if (!g_hdr) return;
    if (len > XHQ_TEXT_MAX - 1) len = XHQ_TEXT_MAX - 1;

    n = InterlockedIncrement(&g_hdr->record_count);
    idx = (unsigned int)(n - 1);
    r = xhq_slot(idx);

    r->seq = 0;                       /* 标记为写入中 */
    InterlockedExchange(&g_hdr->dropped, g_hdr->dropped);   /* 保序屏障 */
    r->kind = kind;
    r->tick_ms = GetTickCount64();
    r->pid = GetCurrentProcessId();
    r->len = len;
    if (len) xhq_memcpy(r->text, text, len);
    r->text[len] = 0;
    r->seq = idx + 1;                 /* 写入完成 */

    if (g_hEvt) SetEvent(g_hEvt);
}

/* ---------- 宿主的命令处理 ----------
 * 命令串格式与原版 URL 一致：cmd=<名称>&order=<包序>&package=<数据>
 * 支持：
 *   cmd=ping                         探活，回 "pong"
 *   cmd=status                       回模块 abi/pid/已装 HOOK 数
 *   cmd=sign&order=&package=         计算签名（M4 未完成，返回失败）
 */
static void xhq_reply(const char *text, unsigned int len)
{
    unsigned int n = len;
    if (!g_rpc) return;
    if (n > XHQ_OUT_MAX - 1) n = XHQ_OUT_MAX - 1;
    if (n) xhq_memcpy(g_rpc->out, text, n);
    g_rpc->out[n] = 0;
    g_rpc->out_len = n;
}

/* 在 s 中找子串 needle，返回首次出现位置，找不到返回空 */
static const char *xhq_find(const char *s, const char *needle)
{
    unsigned int nl = xhq_strlen(needle);
    if (!nl) return s;
    for (; *s; s++) {
        unsigned int i = 0;
        while (i < nl && s[i] == needle[i]) i++;
        if (i == nl) return s;
    }
    return NULL;
}

/* 取 "key=" 后面的值，遇 & 或结尾停止；找不到返回 0，找到返回长度 */
static unsigned int xhq_field(const char *cmd, const char *key,
                              char *out, unsigned int cap)
{
    const char *p = xhq_find(cmd, key);
    unsigned int n = 0;
    if (!p) return 0;
    p += xhq_strlen(key);
    while (*p && *p != '&' && n + 1 < cap) out[n++] = *p++;
    out[n] = 0;
    return n;
}

/* 取命令名：跳过可选的 "cmd=" 前缀，取到第一个 & 之前 */
static int xhq_cmd_name(const char *cmd, char *out, unsigned int cap)
{
    unsigned int n = 0;
    if (cmd[0] == 'c' && cmd[1] == 'm' && cmd[2] == 'd' && cmd[3] == '=') cmd += 4;
    while (*cmd && *cmd != '&' && n + 1 < cap) out[n++] = *cmd++;
    out[n] = 0;
    return (int)n;
}

static void xhq_handle_cmd(const char *cmd)
{
    char name[64];
    char buf[XHQ_OUT_MAX];

    xhq_cmd_name(cmd, name, sizeof(name));

    if (xhq_strcmp(name, "ping") == 0) {
        xhq_reply("pong", 4);
        return;
    }
    if (xhq_strcmp(name, "status") == 0) {
        unsigned int len = xhq_cat(buf, sizeof(buf), 0, "abi=");
        len = xhq_cat_u(buf, sizeof(buf), len, XHQ_ABI);
        len = xhq_cat(buf, sizeof(buf), len, " pid=");
        len = xhq_cat_u(buf, sizeof(buf), len, GetCurrentProcessId());
        len = xhq_cat(buf, sizeof(buf), len, " aes_hooks=");
        len = xhq_cat_u(buf, sizeof(buf), len, (unsigned long long)xhq_crypto_installed());
        len = xhq_cat(buf, sizeof(buf), len, " crypto=");
        len = xhq_cat_u(buf, sizeof(buf), len,
                        (unsigned long long)(unsigned long long)xhq_module_base(L"crypto.dll"));
        xhq_reply(buf, len);
        return;
    }
    if (xhq_strcmp(name, "sign") == 0) {
        char order[64], pkg[64];
        unsigned int olen = xhq_field(cmd, "order=", order, sizeof(order));
        unsigned int plen = xhq_field(cmd, "package=", pkg, sizeof(pkg));
        unsigned int len;

        (void)pkg;
        len = xhq_cat(buf, sizeof(buf), 0, "sign unavailable: wrapper.node 签名入口尚未定位(M4); order=");
        len = xhq_cat_u(buf, sizeof(buf), len, olen);
        len = xhq_cat(buf, sizeof(buf), len, "B package=");
        len = xhq_cat_u(buf, sizeof(buf), len, plen);
        len = xhq_cat(buf, sizeof(buf), len, "B");
        xhq_reply(buf, len);
        return;
    }
    /* hookaddr=模块名+0xRVA —— 在任意地址挂探针（M4 工具） */
    if (xhq_strcmp(name, "hookaddr") == 0) {
        static char spec[128];
        int rc;
        unsigned int len;
        if (!xhq_field(cmd, "spec=", spec, sizeof(spec))) {
            const char *m = "hookaddr 需要 spec=模块名+0xRVA";
            xhq_reply(m, xhq_strlen(m));
            return;
        }
        rc = XHQ_HookAddr(spec);
        len = xhq_cat(buf, sizeof(buf), 0, "hookaddr rc=");
        len = xhq_cat_u(buf, sizeof(buf), len, (unsigned long long)(unsigned int)rc);
        len = xhq_cat(buf, sizeof(buf), len, " spec=");
        len = xhq_cat(buf, sizeof(buf), len, spec);
        xhq_reply(buf, len);
        return;
    }
    if (xhq_strcmp(name, "unhookaddr") == 0) {
        unsigned int len = xhq_cat(buf, sizeof(buf), 0, "unhookaddr rc=");
        len = xhq_cat_u(buf, sizeof(buf), len,
                        (unsigned long long)(unsigned int)XHQ_UnhookAddr());
        xhq_reply(buf, len);
        return;
    }
    {
        unsigned int len = xhq_cat(buf, sizeof(buf), 0, "unknown cmd: ");
        len = xhq_cat(buf, sizeof(buf), len, name);
        xhq_reply(buf, len);
    }
}

static DWORD WINAPI xhq_rpc_loop(LPVOID param)
{
    long last = 0;
    (void)param;
    while (!g_shutdown && g_rpc) {
        long req = g_rpc->req_seq;
        if (req != last) {
            g_rpc->done_seq = 0;
            xhq_handle_cmd(g_rpc->cmd);
            last = req;
            g_rpc->done_seq = req;
        }
        Sleep(20);
    }
    return 0;
}

/* ---------- 卸载清理 ----------
 * 宿主主动停用、或本模块被 FreeLibrary 时调用：先恢复被改写的原始字节，
 * 再让线程退出。顺序很重要——先把补丁撤掉，避免在线程退出的空档里还有调用打进来
 * 命中一个即将随模块消失的蹦床。 */
void xhq_teardown(void)
{
    /* 1. 恢复所有 hook（幂等，未安装时是空操作） */
    XHQ_UnhookAddr();
    xhq_crypto_hook(0, 0);

    /* 2. 停掉心跳与 RPC 线程，并等它们真正退出 */
    InterlockedExchange(&g_shutdown, 1);
    if (g_hEvt) SetEvent(g_hEvt);
    Sleep(400);

    /* 3. 释放映射（句柄归零后线程即使被唤醒也会立刻退出） */
    g_rpc = NULL;
    g_hdr = NULL;
    if (g_hEvt) { CloseHandle(g_hEvt); g_hEvt = NULL; }
    if (g_hShm) { CloseHandle(g_hShm); g_hShm = NULL; }
}

/* ---------- 心跳线程 ---------- */
static DWORD WINAPI xhq_heartbeat(LPVOID param)
{
    (void)param;
    while (!g_shutdown && g_hdr) {
        InterlockedIncrement(&g_hdr->heartbeat);
        Sleep(500);
    }
    return 0;
}

/* 初始化：开引导映射 → 开共享内存/事件 → 打心跳与欢迎记录 */
static DWORD WINAPI xhq_setup(LPVOID param)
{
    HANDLE hBoot;
    XHQ_BOOTSTRAP boot;
    DWORD got = 0;
    char msg[256];
    unsigned int len;

    (void)param;
    if (InterlockedExchange(&g_inited, 1) != 0)
        return 0;

    /* 等待宿主把引导数据写完 */
    Sleep(50);

    hBoot = OpenFileMappingW(FILE_MAP_READ, FALSE, XHQ_BOOTSTRAP_NAME);
    if (!hBoot)
        return 0;
    {
        const void *p = MapViewOfFile(hBoot, FILE_MAP_READ, 0, 0, sizeof(XHQ_BOOTSTRAP));
        if (!p) { CloseHandle(hBoot); return 0; }
        xhq_memcpy(&boot, p, sizeof(XHQ_BOOTSTRAP));
        UnmapViewOfFile(p);
    }
    CloseHandle(hBoot);

    if (boot.magic != XHQ_MAGIC)
        return 0;

    g_hShm = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, boot.shm_name);
    if (!g_hShm)
        return 0;
    g_hdr = (XHQ_SHM_HEADER *)MapViewOfFile(g_hShm, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!g_hdr) {
        CloseHandle(g_hShm);
        g_hShm = NULL;
        return 0;
    }
    g_hEvt = OpenEventW(EVENT_MODIFY_STATE, FALSE, boot.evt_name);

    /* RPC 区紧跟在头部之后 */
    g_rpc = (XHQ_RPC *)((unsigned char *)g_hdr + sizeof(XHQ_SHM_HEADER));

    g_hdr->dll_pid = GetCurrentProcessId();
    g_hdr->dll_tid = GetCurrentThreadId();
    GetModuleFileNameA((HMODULE)0, g_hdr->module_path, (DWORD)sizeof(g_hdr->module_path));

    /* 欢迎记录：宿主收到即代表整条链路打通 */
    len = xhq_cat(msg, sizeof(msg), 0, "XHQ native module online, abi=");
    len = xhq_cat_u(msg, sizeof(msg), len, XHQ_ABI);
    len = xhq_cat(msg, sizeof(msg), len, ", pid=");
    len = xhq_cat_u(msg, sizeof(msg), len, GetCurrentProcessId());
    len = xhq_cat(msg, sizeof(msg), len, ", host=");
    len = xhq_cat_u(msg, sizeof(msg), len, boot.host_pid);
    len = xhq_cat(msg, sizeof(msg), len, ", path=");
    len = xhq_cat(msg, sizeof(msg), len, g_hdr->module_path);
    xhq_push(XHQ_KIND_INFO, msg, len);

    CreateThread(NULL, 0, xhq_heartbeat, NULL, 0, NULL);
    CreateThread(NULL, 0, xhq_rpc_loop, NULL, 0, NULL);

    SetEvent(g_hEvt);   /* 让宿主立刻拉取一次 */
    (void)got;
    return 0;
}

/* ---------- 自检 HOOK ----------
 * 由宿主调用 XHQ_TestHook("user32.dll!GetMessageW") 触发，
 * 用来在无关进程（记事本）里验证「HOOK 引擎 + IPC 回传」是否正常。
 */
static XHQ_HOOK g_test_hook;
static volatile LONG g_test_calls = 0;
static BOOL (WINAPI *g_test_orig)(void *, void *, unsigned int, unsigned int) = NULL;

static BOOL WINAPI xhq_test_detour(void *a, void *b, unsigned int c, unsigned int d)
{
    LONG n = InterlockedIncrement(&g_test_calls);
    if (n == 1 || (n % 200) == 0) {
        char buf[128];
        unsigned int len = xhq_cat(buf, sizeof(buf), 0, "hook hit: calls=");
        len = xhq_cat_u(buf, sizeof(buf), len, (unsigned long long)n);
        xhq_push(XHQ_KIND_INFO, buf, len);
    }
    return g_test_orig(a, b, c, d);
}

/* 在补丁写入前拿到蹦床地址，避免「补丁已生效但原函数指针还是空」的竞态 */
static void xhq_test_ready(void *tramp, void *ctx)
{
    (void)ctx;
    g_test_orig = (BOOL (WINAPI *)(void *, void *, unsigned int, unsigned int))tramp;
}

/* "module.dll!ExportName" → 宽字符模块名 + ANSI 导出名 */
static int xhq_parse_spec(const char *spec, wchar_t *mod, unsigned int modcap,
                          char *func, unsigned int funccap)
{
    unsigned int i = 0, j = 0;
    while (spec[i] && spec[i] != '!' && i + 1 < modcap) {
        mod[i] = (wchar_t)(unsigned char)spec[i];
        i++;
    }
    if (spec[i] != '!') return 0;
    mod[i] = 0;
    i++;
    while (spec[i] && j + 1 < funccap) {
        func[j++] = spec[i++];
    }
    func[j] = 0;
    return (mod[0] != 0 && func[0] != 0);
}

__declspec(dllexport) int __stdcall XHQ_TestHook(const char *spec)
{
    wchar_t mod[64];
    char func[64];
    void *base, *addr;
    char buf[256];
    unsigned int len;

    if (!spec) return 0;
    if (!xhq_parse_spec(spec, mod, 64, func, 64)) return 0;
    base = xhq_module_base(mod);
    if (!base) return -1;
    addr = xhq_get_export(base, func);
    if (!addr) return -2;
    /* on_ready 保证 g_test_orig 在补丁生效前就已赋值 */
    if (!xhq_hook_ex(addr, (void *)xhq_test_detour, &g_test_hook, xhq_test_ready, NULL))
        return -3;

    len = xhq_cat(buf, sizeof(buf), 0, "hook installed: ");
    len = xhq_cat(buf, sizeof(buf), len, spec);
    len = xhq_cat(buf, sizeof(buf), len, ", patch_len=");
    len = xhq_cat_u(buf, sizeof(buf), len, g_test_hook.patch_len);
    len = xhq_cat(buf, sizeof(buf), len, ", tramp=");
    len = xhq_cat_u(buf, sizeof(buf), len, (unsigned long long)g_test_hook.tramp);
    len = xhq_cat(buf, sizeof(buf), len, ", target=");
    len = xhq_cat_u(buf, sizeof(buf), len, (unsigned long long)g_test_hook.target);
    xhq_push(XHQ_KIND_INFO, buf, len);
    return 1;
}

/* ---------- 任意地址探针（M4 用） ----------
 * wrapper.node / major.node 里没有具名的签名入口，原版工具同样要求用户提供
 * “调用地址 + 偏移参数”。所以这里提供两个原语：
 *   XHQ_HookAddr —— 在任意地址挂一个“记录参数后原样转发”的探针，用来观察调用；
 *   XHQ_CallAddr —— 在目标进程内按 C 调用约定调用任意地址（0~4 个整数参数）。
 * 转发必须保持原参数与栈布局，所以探针用汇编写（push 保存 → 记日志 → pop → jmp 蹦床）。
 */
static void *g_addr_target = NULL;
/* 下面两个符号会被裸汇编写死引用，必须是非 static 的全局符号，且禁止内联 */
void *g_addr_orig = NULL;
static volatile LONG g_addr_calls = 0;
static volatile LONG g_addr_last[4];
static unsigned char g_addr_hooked = 0;
static XHQ_HOOK g_addr_hook;

static void xhq_addr_ready(void *tramp, void *ctx);
void __attribute__((noinline)) xhq_addr_log(unsigned long long a1, unsigned long long a2,
                                            unsigned long long a3, unsigned long long a4,
                                            unsigned long long ra);

/* 由汇编探针调用：记录本次调用的前四个整数参数 + 调用者返回地址。
 * 返回地址是顺着调用链往上找上层业务函数（比如签名）的关键线索。 */
void __attribute__((noinline)) xhq_addr_log(unsigned long long a1, unsigned long long a2,
                                            unsigned long long a3, unsigned long long a4,
                                            unsigned long long ra)
{
    char buf[320];
    char mod[64];
    unsigned long long rva = 0;
    unsigned int len;
    LONG n = InterlockedIncrement(&g_addr_calls);

    g_addr_last[0] = (LONG)a1;
    g_addr_last[1] = (LONG)a2;
    g_addr_last[2] = (LONG)a3;
    g_addr_last[3] = (LONG)a4;

    len = xhq_cat(buf, sizeof(buf), 0, "探针命中 #");
    len = xhq_cat_u(buf, sizeof(buf), len, (unsigned long long)n);
    len = xhq_cat(buf, sizeof(buf), len, " args=");
    len = xhq_cat_u(buf, sizeof(buf), len, a1);
    len = xhq_cat(buf, sizeof(buf), len, ",");
    len = xhq_cat_u(buf, sizeof(buf), len, a2);
    len = xhq_cat(buf, sizeof(buf), len, ",");
    len = xhq_cat_u(buf, sizeof(buf), len, a3);
    len = xhq_cat(buf, sizeof(buf), len, ",");
    len = xhq_cat_u(buf, sizeof(buf), len, a4);
    if (ra && xhq_module_of_addr((const void *)(uintptr_t)ra, mod, sizeof(mod), &rva)) {
        static const char *H = "0123456789ABCDEF";
        int shift, started = 0;
        len = xhq_cat(buf, sizeof(buf), len, " 调用者=");
        len = xhq_cat(buf, sizeof(buf), len, mod);
        len = xhq_cat(buf, sizeof(buf), len, "+0x");
        for (shift = 60; shift >= 0 && len + 1 < sizeof(buf); shift -= 4) {
            unsigned int d = (unsigned int)((rva >> shift) & 0xF);
            if (!started && d == 0 && shift > 0) continue;
            started = 1;
            buf[len++] = H[d];
        }
        buf[len] = 0;
    }
    xhq_push(XHQ_KIND_INFO, buf, len);
}

/* 探针本体：保存参数寄存器 → 调 C 记录 → 还原 → 跳到蹦床执行原前序指令。
 * 进函数时 rsp % 16 == 8；7 次 push 后为 0，再 sub 0x30 仍为 0，满足 call 的对齐要求。
 * 栈布局（相对当前 rsp）：[0..31] 影子空间，[32] 第 5 个参数，
 * [48]=r11 [56]=r10 [64]=r9 [72]=r8 [80]=rdx [88]=rcx [96]=rax [104]=返回地址。 */
__attribute__((naked)) static void xhq_addr_stub(void)
{
    __asm__ volatile(
        "pushq %rax\n\t"
        "pushq %rcx\n\t"
        "pushq %rdx\n\t"
        "pushq %r8\n\t"
        "pushq %r9\n\t"
        "pushq %r10\n\t"
        "pushq %r11\n\t"
        "subq  $0x30, %rsp\n\t"
        "movq  104(%rsp), %rax\n\t"      /* 返回地址（位于本帧之上） */
        "movq  %rax, 32(%rsp)\n\t"       /* 第 5 个参数：调用者 */
        "movq  88(%rsp), %rcx\n\t"       /* 原 rcx */
        "movq  80(%rsp), %rdx\n\t"       /* 原 rdx */
        "movq  72(%rsp), %r8\n\t"        /* 原 r8  */
        "movq  64(%rsp), %r9\n\t"        /* 原 r9  */
        "call  xhq_addr_log\n\t"
        "addq  $0x30, %rsp\n\t"
        "popq  %r11\n\t"
        "popq  %r10\n\t"
        "popq  %r9\n\t"
        "popq  %r8\n\t"
        "popq  %rdx\n\t"
        "popq  %rcx\n\t"
        "popq  %rax\n\t"
        "jmp   *g_addr_orig(%rip)\n\t");
}

/* 解析 "0x绝对地址" 或 "模块名+0xRVA"（形如 user32.dll+0x3b330） */
static void *xhq_resolve_addr(const char *spec)
{
    char mod[96];
    const char *plus;
    unsigned int n = 0;
    unsigned long long off = 0;

    if (!spec) return NULL;
    plus = spec;
    while (*plus && *plus != '+') plus++;
    if (*plus == '+') {
        wchar_t wmod[96];
        void *base;
        const char *p;
        unsigned int i;

        while (spec[n] && spec[n] != '+' && n + 1 < sizeof(mod)) {
            mod[n] = spec[n];
            n++;
        }
        mod[n] = 0;
        for (i = 0; i < n; i++) wmod[i] = (wchar_t)(unsigned char)mod[i];
        wmod[n] = 0;

        base = xhq_module_base(wmod);
        if (!base) return NULL;

        p = plus + 1;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        while (*p) {
            char c = *p++;
            unsigned int d;
            if (c >= '0' && c <= '9') d = (unsigned int)(c - '0');
            else if (c >= 'a' && c <= 'f') d = (unsigned int)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') d = (unsigned int)(c - 'A' + 10);
            else return NULL;
            off = off * 16 + d;
        }
        return (void *)((unsigned char *)base + off);
    }
    if (spec[0] == '0' && (spec[1] == 'x' || spec[1] == 'X')) spec += 2;
    while (*spec) {
        char c = *spec++;
        unsigned int d;
        if (c >= '0' && c <= '9') d = (unsigned int)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (unsigned int)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (unsigned int)(c - 'A' + 10);
        else return NULL;
        off = off * 16 + d;
    }
    return (void *)(uintptr_t)off;
}

/* spec 形如 "user32.dll+0x3b330"；返回 1 成功，负数表示各类失败 */
__declspec(dllexport) int __stdcall XHQ_HookAddr(const char *spec)
{
    void *addr;
    char buf[XHQ_OUT_MAX];
    unsigned int len;

    if (!spec || g_addr_hooked) return -1;
    addr = xhq_resolve_addr(spec);
    if (!addr) return -2;
    if (!xhq_hook_ex(addr, (void *)xhq_addr_stub, &g_addr_hook, xhq_addr_ready, NULL))
        return -3;

    g_addr_target = addr;
    g_addr_hooked = 1;
    len = xhq_cat(buf, sizeof(buf), 0, "地址探针已安装：");
    len = xhq_cat(buf, sizeof(buf), len, spec);
    len = xhq_cat(buf, sizeof(buf), len, " patch_len=");
    len = xhq_cat_u(buf, sizeof(buf), len, g_addr_hook.patch_len);
    xhq_push(XHQ_KIND_INFO, buf, len);
    return 1;
}

/* 在补丁生效前拿到蹦床，保证探针转发时 g_addr_orig 已就绪 */
static void xhq_addr_ready(void *tramp, void *ctx)
{
    (void)ctx;
    g_addr_orig = tramp;
}

__declspec(dllexport) int __stdcall XHQ_UnhookAddr(void)
{
    if (!g_addr_hooked) return 0;
    xhq_unhook(&g_addr_hook);
    g_addr_hooked = 0;
    g_addr_target = NULL;
    g_addr_orig = NULL;
    {
        const char *m = "地址探针已卸载";
        xhq_push(XHQ_KIND_INFO, m, xhq_strlen(m));
    }
    return 1;
}

/* 通用调用器：args 为参数块，nargs 取 0..4（只支持整数参数）。
 * 宿主只需把地址与参数写进目标进程内存，再用一个参数把块指针传进来。 */
__declspec(dllexport) unsigned long long __stdcall XHQ_CallAddr(const void *blk)
{
    const unsigned long long *b = (const unsigned long long *)blk;
    void *addr;
    int nargs;
    unsigned long long ret = 0;

    if (!b) return 0;
    addr = (void *)(uintptr_t)b[0];
    nargs = (int)b[1];
    if (!addr) return 0;
    switch (nargs) {
    case 0: ret = ((unsigned long long (*)(void))addr)(); break;
    case 1: ret = ((unsigned long long (*)(unsigned long long))addr)(b[2]); break;
    case 2: ret = ((unsigned long long (*)(unsigned long long, unsigned long long))addr)(
                b[2], b[3]); break;
    case 3: ret = ((unsigned long long (*)(unsigned long long, unsigned long long,
                                          unsigned long long))addr)(b[2], b[3], b[4]); break;
    case 4: ret = ((unsigned long long (*)(unsigned long long, unsigned long long,
                                          unsigned long long, unsigned long long))addr)(
                b[2], b[3], b[4], b[5]); break;
    default: return 0;
    }
    {
        char buf[256];
        unsigned int len = xhq_cat(buf, sizeof(buf), 0, "calladdr ret=");
        len = xhq_cat_u(buf, sizeof(buf), len, ret);
        len = xhq_cat(buf, sizeof(buf), len, " nargs=");
        len = xhq_cat_u(buf, sizeof(buf), len, (unsigned long long)nargs);
        xhq_push(XHQ_KIND_INFO, buf, len);
    }
    return ret;
}

/* ---------- 导出 ---------- */
__declspec(dllexport) unsigned int __stdcall XHQ_Abi(void)
{
    return XHQ_ABI;
}

__declspec(dllexport) long __stdcall XHQ_Heartbeat(void)
{
    return g_hdr ? g_hdr->heartbeat : -1;
}

__declspec(dllexport) int __stdcall XHQ_Start(void)
{
    /* 可能被「安全停用」过（g_shutdown=1、映射已关），这里重置状态重新握手。
     * 宿主重启或再次注入时会走这条路径，因此不必重启目标进程。 */
    InterlockedExchange(&g_shutdown, 0);
    InterlockedExchange(&g_inited, 0);
    xhq_setup(NULL);
    return g_hdr != NULL;
}

/* 手动塞一条记录，供宿主自检整条 IPC 链路（M3 之前的主要验证手段） */
__declspec(dllexport) int __stdcall XHQ_PushTest(const char *text)
{
    unsigned int len = xhq_strlen(text);
    if (!g_hdr) return 0;
    xhq_push(XHQ_KIND_INFO, text ? text : "", len);
    return 1;
}

__declspec(dllexport) int __stdcall XHQ_Connected(void)
{
    return g_hdr != NULL;
}

/* 开/关加密 HOOK：flags[0]=AES flags[1]=TEA，返回安装成功的数量。
 * 用参数块指针而不是多寄存器传参——宿主侧只需 CreateRemoteThread 一个参数，最稳。 */
__declspec(dllexport) int __stdcall XHQ_SetCryptoHook(const int *flags)
{
    if (!flags) return 0;
    return xhq_crypto_hook(flags[0], flags[1]);
}

__declspec(dllexport) int __stdcall XHQ_SelfTestCrypto(void)
{
    return xhq_crypto_selftest();
}

/* 宿主主动停用：恢复所有被改写的字节并停掉线程。调用后模块仍留在进程里，
 * 但已不再挂任何 hook——想彻底移除需重启目标进程。 */
__declspec(dllexport) int __stdcall XHQ_Shutdown(void)
{
    xhq_teardown();
    return 1;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        /* 不在加载器锁内做映射/建线程以外的工作 */
        CreateThread(NULL, 0, xhq_setup, NULL, 0, NULL);
    } else if (reason == DLL_PROCESS_DETACH) {
        /* reserved == NULL 表示是 FreeLibrary（而不是进程退出）。这时必须把
         * crypto.dll 里被我们改写的字节恢复回去、并让线程退出，否则本模块被卸载后
         * 目标进程里还留着指向已释放蹦床的跳转，之后一调用就会崩。 */
        if (reserved == NULL) {
            xhq_teardown();
        }
    }
    return TRUE;
}