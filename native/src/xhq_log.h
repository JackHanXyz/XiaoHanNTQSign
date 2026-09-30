/* xhq_log.h —— 记录回传接口（实现见 dllmain.c），供各 HOOK 模块使用 */
#ifndef XHQ_LOG_H
#define XHQ_LOG_H

#include "ipc_shm.h"

/* 往共享内存 ring buffer 追加一条记录（kind 取 XHQ_KIND_*） */
void xhq_push(unsigned int kind, const char *text, unsigned int len);

#endif /* XHQ_LOG_H */