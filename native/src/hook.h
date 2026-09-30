/* hook.h —— 极简 x64 内联 HOOK 引擎（自研，无第三方依赖） */
#ifndef XHQ_HOOK_H
#define XHQ_HOOK_H

#define XHQ_HOOK_MAX_PATCH 32   /* 最多覆盖 32 字节（实际用 14 字节绝对跳转） */

typedef struct {
    void          *target;      /* 被 HOOK 的函数地址 */
    void          *detour;      /* 我们的替换函数 */
    unsigned char *tramp;       /* 蹦床：原前序指令 + 跳回原函数 */
    unsigned char  orig[XHQ_HOOK_MAX_PATCH];
    unsigned int   patch_len;
    int            installed;
} XHQ_HOOK;

/* 安装 HOOK。返回 1 成功；0 失败（前序指令无法安全搬迁，或内存不可写） */
int  xhq_hook(void *target, void *detour, XHQ_HOOK *h);

/* 同 xhq_hook，但在写入跳转之前先回调 on_ready(tramp, ctx)。
 * 调用方用这个回调把「原函数指针」赋值好，避免补丁生效后、指针还没赋值的竞态。 */
int  xhq_hook_ex(void *target, void *detour, XHQ_HOOK *h,
                 void (*on_ready)(void *tramp, void *ctx), void *ctx);

/* 卸载 HOOK（还原原始字节，释放蹦床） */
void xhq_unhook(XHQ_HOOK *h);

#endif /* XHQ_HOOK_H */