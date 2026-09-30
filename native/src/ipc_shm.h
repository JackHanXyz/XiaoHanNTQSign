/* ipc_shm.h —— 宿主(Python) 与注入模块(C) 之间的共享内存协议。
 *
 * 约定：
 *   1. 宿主先创建「引导映射」Local\XiaoHanQQNT_Bootstrap，写入 host_pid 与后续两个对象名；
 *   2. 宿主注入本模块；
 *   3. 模块在独立线程里打开引导映射，再打开真正的共享内存与事件对象，
 *      周期性递增 heartbeat，并通过事件通知宿主有新记录。
 * 全部结构 1 字节对齐，禁止改动字段顺序/类型，宿主的 ctypes 结构体与之一一对应。
 */
#ifndef XHQ_IPC_SHM_H
#define XHQ_IPC_SHM_H

#define XHQ_MAGIC        0x51484E51u   /* 'QNHQ' */
#define XHQ_ABI          1u            /* 协议版本，宿主不匹配则拒绝连接 */

#define XHQ_BOOTSTRAP_NAME  L"Local\\XiaoHanQQNT_Bootstrap"
#define XHQ_BOOTSTRAP_SIZE  512

/* 记录类型 */
#define XHQ_KIND_INFO    1u   /* 普通信息 */
#define XHQ_KIND_SIGN    2u   /* 签名计算 */
#define XHQ_KIND_TEA     3u   /* TEA 加解密 */
#define XHQ_KIND_AES     4u   /* AES 加解密 */

#define XHQ_TEXT_MAX     4080
#define XHQ_CMD_MAX      512
#define XHQ_OUT_MAX      2048

#pragma pack(push, 1)

/* 引导映射内容 */
typedef struct {
    unsigned int  magic;
    unsigned int  host_pid;
    wchar_t       shm_name[64];   /* 共享内存对象名，例如 Local\XiaoHanQQNT_Shm_1234 */
    wchar_t       evt_name[64];   /* 事件对象名 */
} XHQ_BOOTSTRAP;

/* 单条抓包/日志记录，定长，方便 ring buffer 下标计算 */
typedef struct {
    unsigned int        seq;
    unsigned int        kind;          /* XHQ_KIND_* */
    unsigned long long  tick_ms;       /* GetTickCount64 */
    unsigned int        pid;           /* 产生记录的进程 */
    unsigned int        len;           /* text 有效长度（不含结尾 0） */
    char                text[XHQ_TEXT_MAX];
} XHQ_RECORD;

/* 共享内存头部，后面紧跟一个 XHQ_RPC，再紧跟 capacity 个 XHQ_RECORD */
typedef struct {
    unsigned int   magic;
    unsigned int   abi;
    unsigned int   dll_pid;
    unsigned int   dll_tid;            /* 心跳线程 id */
    volatile long  heartbeat;          /* 每 500ms +1，宿主据此判断存活 */
    volatile long  record_count;       /* 累计写入记录数 */
    volatile long  dropped;            /* 因覆盖而丢弃的记录数 */
    unsigned int   capacity;           /* 记录槽数量 */
    char           module_path[260];   /* 模块自身路径，便于宿主确认版本 */
} XHQ_SHM_HEADER;

/* 宿主 → 模块 的请求 / 模块 → 宿主 的应答。
 * 宿主写 cmd 后把 req_seq 加一；模块处理完写 out 并把 done_seq 设为该 req_seq。 */
typedef struct {
    volatile long req_seq;
    volatile long done_seq;
    unsigned int  cmd_len;
    unsigned int  out_len;
    char          cmd[XHQ_CMD_MAX];
    char          out[XHQ_OUT_MAX];
} XHQ_RPC;

#pragma pack(pop)

#endif /* XHQ_IPC_SHM_H */