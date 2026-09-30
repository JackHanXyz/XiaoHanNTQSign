/* hook.c —— x64 内联 HOOK。
 *
 * 思路：在目标函数入口写 14 字节绝对跳转（FF 25 disp32 + 8 字节地址），
 * 把被覆盖的前序指令搬到蹦床，蹦床末尾再绝对跳回原函数（target + patch_len）。
 *
 * 为了能挂上 OpenSSL 那些「CPU 特性分派桩」函数（开头就是
 * `mov eax,[rip+X]; test eax,0x2000000; jne ...`），蹦床必须支持重定位：
 *   1. RIP 相对寻址 —— 按新地址重算 disp32；
 *   2. rel32 分支     —— 重算 disp32；
 *   3. rel8 分支      —— 目标在覆盖区外时展开成 6 字节 rel32 形式；
 *                       目标在覆盖区内时改写成蹦床内对应位置。
 * 仍然无法安全搬迁的（如 loop/jrcxz、未知指令）直接放弃安装，宁可少 HOOK 也不写坏目标。
 * 覆盖前会挂起进程内其它线程，避免别的线程正好执行到被改写的字节。
 */
#include <windows.h>
#include <tlhelp32.h>   /* THREADENTRY32 / Thread32First */
#include "hook.h"

#define XHQ_MAX_SUSPEND   512
#define XHQ_JMP_LEN       14
#define XHQ_MAX_INSNS     12
#define XHQ_NEAR_RANGE    0x70000000ULL   /* 在目标 ±1.75GB 内找蹦床，保证 rel32 可达 */

/* 指令分类 */
#define IK_PLAIN   0
#define IK_RIP     1   /* 含 RIP 相对 disp32 */
#define IK_REL32   2   /* rel32 分支（call/jmp/jcc） */
#define IK_REL8    3   /* rel8 分支（jmp/jcc），可展开为 rel32 */

typedef struct {
    unsigned int old_off;    /* 在目标函数内的偏移 */
    unsigned int old_len;
    unsigned int new_off;    /* 在蹦床内的偏移 */
    unsigned int new_len;
    int          kind;
    int          disp_off;   /* 待重定位字段在指令内的偏移 */
    long long    abs_target; /* RIP 目标或分支目标的绝对地址 */
} XHQ_INSN;

static HANDLE g_suspended[XHQ_MAX_SUSPEND];
static int    g_susp_count = 0;

/* ---------- ModRM 解析：返回长度，*disp_off 为 disp 字段偏移（-1 表示没有），
 *            *rip_rel 置 1 表示这是 RIP 相对寻址 ---------- */
static int xhq_modrm(const unsigned char *p, int *disp_off, int *rip_rel)
{
    unsigned char m = p[0];
    int mod = m >> 6;
    int rm = m & 7;
    int len = 1;

    *disp_off = -1;
    if (mod == 3) return len;
    if (rm == 4) {                       /* 带 SIB */
        unsigned char sib = p[1];
        len++;
        if ((sib & 7) == 5 && mod == 0) { *disp_off = len; len += 4; }
    } else if (mod == 0 && rm == 5) {    /* RIP 相对 */
        *rip_rel = 1;
        *disp_off = len;
        return len + 4;
    }
    if (mod == 1) {
        if (*disp_off < 0) *disp_off = len;
        len += 1;
    } else if (mod == 2) {
        if (*disp_off < 0) *disp_off = len;
        len += 4;
    }
    return len;
}

/* ---------- 单条指令解码 ---------- */
static int xhq_decode(const unsigned char *p, int *rip_rel, XHQ_INSN *out, long long pc)
{
    int i = 0;
    int rex_w = 0;
    int imm_after_modrm = 0;   /* 0=无 1=1字节 2=4字节；0xFF 表示按 ModRM.reg 判断 */
    unsigned char op;
    int disp_off = -1;

    *rip_rel = 0;
    out->kind = IK_PLAIN;
    out->disp_off = -1;
    out->abs_target = 0;

    /* 前缀 */
    for (;;) {
        unsigned char b = p[i];
        if (b == 0x66 || b == 0x67 || b == 0xF2 || b == 0xF3 || b == 0xF0 ||
            b == 0x2E || b == 0x3E || b == 0x26 || b == 0x36 || b == 0x64 || b == 0x65) {
            i++;
            continue;
        }
        if (b >= 0x40 && b <= 0x4F) {
            rex_w = (b & 0x08) != 0;
            i++;
            continue;
        }
        break;
    }

    op = p[i++];

    /* 无操作数 / 立即数形式 */
    if ((op >= 0x50 && op <= 0x5F) || op == 0x90 || op == 0xCC || op == 0xC3 ||
        op == 0x98 || op == 0x99 || op == 0x9C || op == 0x9D || op == 0xC9) {
        out->new_len = out->old_len = (unsigned int)i;
        return i;
    }
    if (op == 0x6A) { out->new_len = out->old_len = (unsigned int)(i + 1); return i + 1; }
    if (op == 0x68) { out->new_len = out->old_len = (unsigned int)(i + 4); return i + 4; }
    if (op >= 0xB0 && op <= 0xB7) { out->new_len = out->old_len = (unsigned int)(i + 1); return i + 1; }
    if (op >= 0xB8 && op <= 0xBF) {
        int n = i + (rex_w ? 8 : 4);
        out->new_len = out->old_len = (unsigned int)n;
        return n;
    }
    /* AL/eAX 与立即数的算术逻辑运算（test eax,imm32 等），OpenSSL 的分派桩里很常见 */
    if (op == 0x04 || op == 0x0C || op == 0x14 || op == 0x1C ||
        op == 0x24 || op == 0x2C || op == 0x34 || op == 0x3C || op == 0xA8) {
        out->new_len = out->old_len = (unsigned int)(i + 1);
        return i + 1;
    }
    if (op == 0x05 || op == 0x0D || op == 0x15 || op == 0x1D ||
        op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D || op == 0xA9) {
        out->new_len = out->old_len = (unsigned int)(i + 4);
        return i + 4;
    }

    /* 分支 */
    if (op == 0xE8 || op == 0xE9 || (op >= 0x70 && op <= 0x7F) || op == 0xEB) {
        int is_rel8 = (op == 0xEB) || (op >= 0x70 && op <= 0x7F);
        int n = i + (is_rel8 ? 1 : 4);
        int disp = is_rel8 ? (signed char)p[i] : *(const int *)&p[i];
        out->kind = is_rel8 ? IK_REL8 : IK_REL32;
        out->disp_off = i;
        out->abs_target = pc + n + disp;
        out->old_len = (unsigned int)n;
        /* rel8 目标在覆盖区外时统一展开为 6 字节 rel32 形式 */
        out->new_len = (unsigned int)(is_rel8 ? 6 : n);
        return n;
    }
    if (op == 0xE0 || op == 0xE1 || op == 0xE2 || op == 0xE3) return 0;  /* loop/jrcxz 无法展开 */

    if (op == 0x0F) {
        unsigned char b2 = p[i++];
        if (b2 >= 0x80 && b2 <= 0x8F) {                 /* jcc rel32 */
            int disp = *(const int *)&p[i];
            int n = i + 4;
            out->kind = IK_REL32;
            out->disp_off = i;
            out->abs_target = pc + n + disp;
            out->new_len = out->old_len = (unsigned int)n;
            return n;
        }
        if (b2 == 0x1E) {                               /* endbr64: F3 0F 1E FA */
            if (p[i] != 0xFA) return 0;
            out->new_len = out->old_len = (unsigned int)(i + 1);
            return i + 1;
        }
        switch (b2) {
        case 0x1F:                                      /* multi-byte nop */
        case 0x10: case 0x11: case 0x28: case 0x29:     /* movups/movaps */
        case 0x6E: case 0x7E: case 0x6F: case 0x7F:     /* movd/movq/movdqa */
        case 0x57: case 0x54: case 0x55: case 0xAF:     /* xorps/andps/andnps/xorpd */
        case 0xA2: case 0xA3: case 0xB1: case 0xB6: case 0xB7:
        case 0xBE: case 0xBF:                           /* movsx/movzx */
        case 0x44: case 0x45: case 0x58: case 0x59: case 0x5C: case 0x5D:
        case 0x5E: case 0x5F: case 0xD6: case 0xEF:     /* SSE 算术/比较 */
            break;
        case 0xC6:                                      /* shufps：带 imm8 */
            imm_after_modrm = 1;
            break;
        default:
            return 0;
        }
    } else {
        switch (op) {
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x38: case 0x39: case 0x3A: case 0x3B:
        case 0x62: case 0x63: case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8D:
        case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        case 0xFE: case 0xFF: case 0x8F:                /* 无立即数 */
            break;
        case 0x69: imm_after_modrm = 2; break;
        case 0x6B: case 0x80: case 0x83: case 0xC0: case 0xC1: case 0xC6:
            imm_after_modrm = 1; break;
        case 0x81: case 0xC7:
            imm_after_modrm = 2; break;
        case 0xF6: case 0xF7:
            imm_after_modrm = 0xFF; break;              /* 仅 reg==0 时才有立即数 */
        default:
            return 0;
        }
    }

    {
        int n = i + xhq_modrm(&p[i], &disp_off, rip_rel);
        if (imm_after_modrm == 1) n += 1;
        else if (imm_after_modrm == 2) n += 4;
        else if (imm_after_modrm == 0xFF) {
            int reg = (p[i] >> 3) & 7;
            if (reg == 0) n += (op == 0xF6) ? 1 : 4;
        }
        if (n > 16) return 0;
        out->old_len = (unsigned int)n;
        out->new_len = (unsigned int)n;
        if (*rip_rel) {
            out->kind = IK_RIP;
            /* disp_off 来自 ModRM 解析，是相对 ModRM 的偏移；写入时要换算成相对指令开头 */
            out->disp_off = i + disp_off;
            out->abs_target = pc + n + *(const int *)&p[out->disp_off];
        }
        return n;
    }
}

/* ---------- 线程挂起 ---------- */
static void xhq_suspend_others(void)
{
    THREADENTRY32 te;
    HANDLE snap;
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();

    g_susp_count = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            HANDLE h;
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == tid) continue;
            if (g_susp_count >= XHQ_MAX_SUSPEND) break;
            h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!h) continue;
            if (SuspendThread(h) != (DWORD)-1) g_suspended[g_susp_count++] = h;
            else CloseHandle(h);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static void xhq_resume_others(void)
{
    int i;
    for (i = 0; i < g_susp_count; i++) {
        ResumeThread(g_suspended[i]);
        CloseHandle(g_suspended[i]);
    }
    g_susp_count = 0;
}

/* ---------- 写入绝对跳转 ---------- */
static void xhq_write_jmp(unsigned char *at, void *dest)
{
    at[0] = 0xFF;
    at[1] = 0x25;
    *(unsigned int *)(at + 2) = 0;      /* [rip+0] 即紧随其后的 8 字节 */
    *(void **)(at + 6) = dest;
}

/* ---------- 规划蹦床布局（第一遍：解码 + 计算新长度） ---------- */
static int xhq_plan(unsigned char *target, XHQ_INSN *ins, int *count, unsigned int *patch_len)
{
    unsigned int total = 0;
    int n = 0;

    while (total < XHQ_JMP_LEN) {
        XHQ_INSN cur;
        int rip = 0;
        int len;
        if (n >= XHQ_MAX_INSNS) return 0;
        len = xhq_decode(target + total, &rip, &cur, (long long)(unsigned long long)(target + total));
        if (len <= 0) return 0;
        cur.old_off = total;
        total += (unsigned int)len;
        if (total > XHQ_HOOK_MAX_PATCH) return 0;
        ins[n++] = cur;
    }

    /* rel8 分支：目标落在覆盖区内就改指蹦床（保持 2 字节），区外才展开成 rel32 */
    {
        int i, j;
        for (i = 0; i < n; i++) {
            long long rel;
            if (ins[i].kind != IK_REL8) continue;
            rel = ins[i].abs_target - (long long)(unsigned long long)target;
            for (j = 0; j < n; j++) {
                if (rel >= 0 && rel == (long long)ins[j].old_off) break;
            }
            if (j < n) ins[i].new_len = ins[i].old_len;   /* 区内 → 保持 rel8 */
        }
    }

    {
        unsigned int off = 0;
        int i;
        for (i = 0; i < n; i++) {
            ins[i].new_off = off;
            off += ins[i].new_len;
        }
    }
    *count = n;
    *patch_len = total;
    return 1;
}

/* 蹦床必须落在目标函数 ±2GB 内：搬迁后的 rel32 相对跳转/调用只能覆盖 2GB 范围，
 * 否则位移会被截断成 32 位而跳到错误地址（实测会让目标进程直接崩掉）。
 * 这里从目标地址出发按分配粒度向两侧试探，通常几 MB 内就能找到空位。 */
static void *xhq_alloc_near(void *target, unsigned int size)
{
    SYSTEM_INFO si;
    unsigned long long gran, base, delta;
    unsigned long long want = (unsigned long long)(unsigned long long)target;

    GetSystemInfo(&si);
    gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
    base = want & ~(gran - 1);

    for (delta = gran; delta < XHQ_NEAR_RANGE; delta += gran) {
        unsigned long long hi = base + delta;
        unsigned long long lo = (base > delta) ? (base - delta) : 0;
        void *p;
        if (hi < 0x7FFFFFFF0000ULL) {
            p = VirtualAlloc((void *)(uintptr_t)hi, size,
                             MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (p) return p;
        }
        if (lo) {
            p = VirtualAlloc((void *)(uintptr_t)lo, size,
                             MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (p) return p;
        }
    }
    return NULL;
}

int xhq_hook(void *target, void *detour, XHQ_HOOK *h)
{
    return xhq_hook_ex(target, detour, h, NULL, NULL);
}

int xhq_hook_ex(void *target, void *detour, XHQ_HOOK *h,
                void (*on_ready)(void *tramp, void *ctx), void *ctx)
{
    XHQ_INSN ins[XHQ_MAX_INSNS];
    unsigned int patch_len = 0;
    unsigned int tramp_len;
    DWORD old_prot = 0;
    int count = 0, i;

    if (!target || !detour || !h) return 0;
    if (h->installed) return 0;
    if (!xhq_plan((unsigned char *)target, ins, &count, &patch_len)) return 0;

    tramp_len = ins[count - 1].new_off + ins[count - 1].new_len + XHQ_JMP_LEN;
    h->tramp = (unsigned char *)xhq_alloc_near(target, tramp_len);
    if (!h->tramp) return 0;

    /* 第二遍：拷贝并重定位 */
    for (i = 0; i < count; i++) {
        unsigned char *src = (unsigned char *)target + ins[i].old_off;
        unsigned char *dst = h->tramp + ins[i].new_off;

        if (ins[i].kind == IK_REL8 && ins[i].new_len == 6) {
            /* 74 xx → 0F 84 rel32；EB xx → E9 rel32 + nop */
            long long next = (long long)(unsigned long long)(dst + 6);
            if (src[0] == 0xEB) {
                dst[0] = 0xE9;
                *(int *)(dst + 1) = (int)(ins[i].abs_target - next);
                dst[5] = 0x90;
            } else {
                dst[0] = 0x0F;
                dst[1] = (unsigned char)(0x80 + (src[0] - 0x70));
                *(int *)(dst + 2) = (int)(ins[i].abs_target - next);
            }
            continue;
        }

        memcpy(dst, src, ins[i].old_len);

        if (ins[i].kind == IK_RIP) {
            long long next_new = (long long)(unsigned long long)(dst + ins[i].new_len);
            *(int *)(dst + ins[i].disp_off) = (int)(ins[i].abs_target - next_new);
        } else if (ins[i].kind == IK_REL32) {
            long long next_new = (long long)(unsigned long long)(dst + ins[i].new_len);
            *(int *)(dst + ins[i].disp_off) = (int)(ins[i].abs_target - next_new);
        } else if (ins[i].kind == IK_REL8) {
            /* 区内分支：目标改指蹦床内对应位置 */
            long long rel = ins[i].abs_target - (long long)(unsigned long long)target;
            int j;
            for (j = 0; j < count; j++) {
                if (rel >= 0 && rel == (long long)ins[j].old_off) break;
            }
            if (j < count) {
                long long next_new = (long long)(unsigned long long)(dst + ins[i].new_len);
                long long tgt_new = (long long)(unsigned long long)(h->tramp + ins[j].new_off);
                dst[ins[i].disp_off] = (unsigned char)(tgt_new - next_new);
            }
        }
    }
    xhq_write_jmp(h->tramp + ins[count - 1].new_off + ins[count - 1].new_len,
                  (unsigned char *)target + patch_len);

    /* 挂起其它线程后改写入口（写补丁前先让调用方拿到蹦床地址） */
    xhq_suspend_others();
    if (!VirtualProtect(target, patch_len, PAGE_EXECUTE_READWRITE, &old_prot)) {
        xhq_resume_others();
        VirtualFree(h->tramp, 0, MEM_RELEASE);
        h->tramp = NULL;
        return 0;
    }
    for (i = 0; i < (int)patch_len; i++) h->orig[i] = ((unsigned char *)target)[i];
    if (on_ready) on_ready(h->tramp, ctx);
    xhq_write_jmp((unsigned char *)target, detour);
    for (i = XHQ_JMP_LEN; i < (int)patch_len; i++) ((unsigned char *)target)[i] = 0x90;
    FlushInstructionCache(GetCurrentProcess(), target, patch_len);
    VirtualProtect(target, patch_len, old_prot, &old_prot);
    xhq_resume_others();

    h->target = target;
    h->detour = detour;
    h->patch_len = patch_len;
    h->installed = 1;
    return 1;
}

void xhq_unhook(XHQ_HOOK *h)
{
    DWORD old_prot = 0;
    unsigned int i;

    if (!h || !h->installed) return;
    xhq_suspend_others();
    if (VirtualProtect(h->target, h->patch_len, PAGE_EXECUTE_READWRITE, &old_prot)) {
        for (i = 0; i < h->patch_len; i++) ((unsigned char *)h->target)[i] = h->orig[i];
        FlushInstructionCache(GetCurrentProcess(), h->target, h->patch_len);
        VirtualProtect(h->target, h->patch_len, old_prot, &old_prot);
    }
    xhq_resume_others();

    if (h->tramp) {
        VirtualFree(h->tramp, 0, MEM_RELEASE);
        h->tramp = NULL;
    }
    h->installed = 0;
}