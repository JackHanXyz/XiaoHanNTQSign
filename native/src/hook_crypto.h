/* hook_crypto.h —— crypto.dll 具名导出的 HOOK（AES 系列） */
#ifndef XHQ_HOOK_CRYPTO_H
#define XHQ_HOOK_CRYPTO_H

/* 安装/卸载 crypto.dll 的 HOOK。返回本次成功安装的 HOOK 数量 */
int xhq_crypto_hook(int enable_aes, int enable_tea);

/* 当前已安装数量 */
int xhq_crypto_installed(void);

/* 进程内自测：用标准测试向量走一遍被 HOOK 的 AES 导出，验证 HOOK 是否真的生效 */
int xhq_crypto_selftest(void);

#endif /* XHQ_HOOK_CRYPTO_H */