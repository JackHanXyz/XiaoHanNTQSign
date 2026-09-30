/* pe_util.c —— PEB 模块遍历与 PE 导出表解析。
 *
 * 目标进程里我们不想依赖导入表（避免额外依赖、也便于以后换成纯 shellcode），
 * 所以模块基址从 PEB 的 InLoadOrderModuleList 走，导出地址自己解析 PE 头。
 */
#include <windows.h>
#include "pe_util.h"

static int xhq_wcsieq(const wchar_t *a, const wchar_t *b)
{
    if (!a || !b) return 0;
    while (*a && *b) {
        wchar_t ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca = (wchar_t)(ca + 32);
        if (cb >= L'A' && cb <= L'Z') cb = (wchar_t)(cb + 32);
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

static int xhq_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

/* x64 下 PEB 位于 gs:0x60 */
static void *xhq_peb(void)
{
    void *p;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(p));
    return p;
}

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} XHQ_UNICODE_STRING;

typedef struct {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    XHQ_UNICODE_STRING FullDllName;
    XHQ_UNICODE_STRING BaseDllName;
} XHQ_LDR_ENTRY;

typedef struct {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} XHQ_PEB_LDR_DATA;

typedef struct {
    BYTE  Reserved1[2];
    BYTE  BeingDebugged;
    BYTE  Reserved2[1];
    PVOID Reserved3[2];
    XHQ_PEB_LDR_DATA *Ldr;
} XHQ_PEB;

void *xhq_module_base(const wchar_t *name)
{
    XHQ_PEB *peb = (XHQ_PEB *)xhq_peb();
    XHQ_PEB_LDR_DATA *ldr;
    LIST_ENTRY *head, *cur;

    if (!peb || !peb->Ldr) return NULL;
    ldr = peb->Ldr;
    head = &ldr->InLoadOrderModuleList;
    cur = head->Flink;
    while (cur && cur != head) {
        XHQ_LDR_ENTRY *e = (XHQ_LDR_ENTRY *)cur;   /* InLoadOrderLinks 在结构体首部 */
        if (e->BaseDllName.Buffer && xhq_wcsieq(e->BaseDllName.Buffer, name))
            return e->DllBase;
        cur = cur->Flink;
    }
    return NULL;
}

unsigned int xhq_module_path(void *base, char *out, unsigned int cap)
{
    XHQ_PEB *peb = (XHQ_PEB *)xhq_peb();
    XHQ_PEB_LDR_DATA *ldr;
    LIST_ENTRY *head, *cur;
    unsigned int i = 0;

    if (!out || cap == 0) return 0;
    out[0] = 0;
    if (!peb || !peb->Ldr || !base) return 0;

    ldr = peb->Ldr;
    head = &ldr->InLoadOrderModuleList;
    cur = head->Flink;
    while (cur && cur != head) {
        XHQ_LDR_ENTRY *e = (XHQ_LDR_ENTRY *)cur;
        if (e->DllBase == base && e->FullDllName.Buffer) {
            /* 宽字符转窄：只保留低字节，够用且不依赖 CRT */
            while (e->FullDllName.Buffer[i] && i + 1 < cap) {
                out[i] = (char)(e->FullDllName.Buffer[i] & 0xFF);
                i++;
            }
            out[i] = 0;
            return i;
        }
        cur = cur->Flink;
    }
    return 0;
}

int xhq_module_of_addr(const void *addr, char *name_out, unsigned int cap,
                       unsigned long long *rva_out)
{
    XHQ_PEB *peb = (XHQ_PEB *)xhq_peb();
    XHQ_PEB_LDR_DATA *ldr;
    LIST_ENTRY *head, *cur;
    unsigned long long a = (unsigned long long)(unsigned long long)addr;
    unsigned int i;

    if (name_out && cap) name_out[0] = 0;
    if (rva_out) *rva_out = 0;
    if (!peb || !peb->Ldr || !addr) return 0;

    ldr = peb->Ldr;
    head = &ldr->InLoadOrderModuleList;
    cur = head->Flink;
    while (cur && cur != head) {
        XHQ_LDR_ENTRY *e = (XHQ_LDR_ENTRY *)cur;
        unsigned long long base = (unsigned long long)(unsigned long long)e->DllBase;
        if (base && a >= base && a < base + (unsigned long long)e->SizeOfImage) {
            if (rva_out) *rva_out = a - base;
            if (name_out && cap && e->BaseDllName.Buffer) {
                for (i = 0; e->BaseDllName.Buffer[i] && i + 1 < cap; i++)
                    name_out[i] = (char)(e->BaseDllName.Buffer[i] & 0xFF);
                name_out[i] = 0;
            }
            return 1;
        }
        cur = cur->Flink;
    }
    return 0;
}

void *xhq_get_export(void *base, const char *name)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_EXPORT_DIRECTORY *exp;
    DWORD *names;
    WORD *ords;
    DWORD *funcs;
    DWORD i;

    if (!base || !name) return NULL;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (IMAGE_NT_HEADERS *)((BYTE *)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return NULL;

    exp = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names = (DWORD *)((BYTE *)base + exp->AddressOfNames);
    ords = (WORD *)((BYTE *)base + exp->AddressOfNameOrdinals);
    funcs = (DWORD *)((BYTE *)base + exp->AddressOfFunctions);

    for (i = 0; i < exp->NumberOfNames; i++) {
        const char *sym = (const char *)((BYTE *)base + names[i]);
        if (xhq_strcmp(sym, name) == 0) {
            DWORD rva = funcs[ords[i]];
            if (rva == 0) return NULL;
            /* 转发导出（RVA 落在导出目录内）暂不支持 */
            if (rva >= nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
                rva < nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress +
                      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
                return NULL;
            return (BYTE *)base + rva;
        }
    }
    return NULL;
}