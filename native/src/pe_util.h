/* pe_util.h —— 不依赖导入表的模块/导出解析（PEB 遍历 + 导出表解析） */
#ifndef XHQ_PE_UTIL_H
#define XHQ_PE_UTIL_H

/* 按模块名取基址（大小写不敏感），如 L"crypto.dll"；找不到返回 0 */
void *xhq_module_base(const wchar_t *name);

/* 取模块自身路径（ANSI），返回写入长度 */
unsigned int xhq_module_path(void *base, char *out, unsigned int cap);

/* 按导出名取函数地址，找不到返回 0 */
void *xhq_get_export(void *base, const char *name);

/* 找一个地址落在哪个模块里，写出模块名(ANSI)与模块内偏移；找不到返回 0。
 * 用于记录「谁调用了被挂钩的函数」——把返回地址翻译成 模块名+0xRVA。 */
int xhq_module_of_addr(const void *addr, char *name_out, unsigned int cap,
                       unsigned long long *rva_out);

#endif /* XHQ_PE_UTIL_H */