/* hook_crypto.c —— HOOK crypto.dll（OpenSSL 衍生的加密模块）。
 *
 * 目标函数全部是具名导出，先解析导出表拿到地址再挂 HOOK，因此不依赖固定偏移，
 * QQ 小版本更新一般也不会失效（对比 TEA：没有具名导出，只能走特征码，见 M4）。
 *
 * 关键字段对齐原版 NTQQ_Tool 的抓包展示：
 *   密钥内容(Key)、计算偏移(IV)、填充内容(TAG)、加密前包体
 */
#include <windows.h>
#include <string.h>
#include "ipc_shm.h"
#include "hook.h"
#include "pe_util.h"
#include "hook_crypto.h"
#include "xhq_log.h"

#define XHQ_AES_HOOKS 10
#define XHQ_EVP_HOOKS 6
#define XHQ_TEXT_CAP  4000

/* ---------- 简易字符串拼接 ---------- */
typedef struct {
    char         buf[XHQ_TEXT_CAP];
    unsigned int len;
} XHQ_SB;

static void sb_raw(XHQ_SB *s, const char *t)
{
    while (*t && s->len + 1 < XHQ_TEXT_CAP) s->buf[s->len++] = *t++;
    s->buf[s->len] = 0;
}

static void sb_num(XHQ_SB *s, unsigned long long v)
{
    char tmp[24];
    int n = 0, i;
    if (v == 0) { sb_raw(s, "0"); return; }
    while (v && n < 24) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    for (i = n - 1; i >= 0; i--) {
        if (s->len + 1 < XHQ_TEXT_CAP) s->buf[s->len++] = tmp[i];
    }
    s->buf[s->len] = 0;
}

static void sb_hex(XHQ_SB *s, const unsigned char *d, unsigned int n)
{
    static const char *H = "0123456789ABCDEF";
    unsigned int i;
    for (i = 0; i < n; i++) {
        if (s->len + 3 >= XHQ_TEXT_CAP) break;
        s->buf[s->len++] = H[(d[i] >> 4) & 0xF];
        s->buf[s->len++] = H[d[i] & 0xF];
    }
    s->buf[s->len] = 0;
}

static void sb_ptr(XHQ_SB *s, unsigned long long v)
{
    static const char *H = "0123456789ABCDEF";
    int shift;
    sb_raw(s, "0x");
    for (shift = 60; shift >= 0; shift -= 4) {
        if (s->len + 1 < XHQ_TEXT_CAP) s->buf[s->len++] = H[(v >> shift) & 0xF];
    }
    s->buf[s->len] = 0;
}

/* 零填充的十六进制（不带 0x），用于 RVA */
static void sb_hexval(XHQ_SB *s, unsigned long long v)
{
    static const char *H = "0123456789ABCDEF";
    int shift, started = 0;
    for (shift = 60; shift >= 0; shift -= 4) {
        unsigned int d = (unsigned int)((v >> shift) & 0xF);
        if (!started && d == 0 && shift > 0) continue;
        started = 1;
        if (s->len + 1 < XHQ_TEXT_CAP) s->buf[s->len++] = H[d];
    }
    s->buf[s->len] = 0;
}

/* 调用来源：把返回地址翻译成「模块名+0xRVA」。
 * 这是定位上层业务逻辑的关键——被挂钩的加密函数是谁调的，一目了然。 */
static void sb_caller(XHQ_SB *s, void *ra)
{
    char mod[64];
    unsigned long long rva = 0;

    if (!ra) return;
    if (!xhq_module_of_addr(ra, mod, sizeof(mod), &rva)) return;
    sb_raw(s, " | 调用来源：");
    sb_raw(s, mod);
    sb_raw(s, "+0x");
    sb_hexval(s, rva);
}

/* ---------- 抓到的上下文（原版同款字段） ---------- */
static unsigned char g_key[32];
static unsigned int  g_key_len = 0;
static unsigned char g_iv[16];
static unsigned int  g_iv_len = 0;
static unsigned char g_tag[16];
static unsigned int  g_tag_len = 0;

/* 限速：每秒最多回传若干条，避免刷爆 ring buffer */
static int allow(void)
{
    static volatile LONG bucket = 0;
    static volatile LONG last = 0;
    LONG now = (LONG)GetTickCount64();
    if (now - last >= 200) { last = now; bucket = 0; }
    if (bucket >= 5) return 0;
    bucket++;
    return 1;
}

static void emit(const char *title, const unsigned char *data, unsigned int datalen,
                 int with_ctx, void *caller)
{
    XHQ_SB s;
    s.len = 0;
    s.buf[0] = 0;
    sb_raw(&s, title);
    if (with_ctx) {
        if (g_key_len) { sb_raw(&s, " | 密钥内容(Key)："); sb_hex(&s, g_key, g_key_len); }
        if (g_iv_len)  { sb_raw(&s, " | 计算偏移(IV)：");  sb_hex(&s, g_iv, g_iv_len); }
        if (g_tag_len) { sb_raw(&s, " | 填充内容(TAG)："); sb_hex(&s, g_tag, g_tag_len); }
    }
    if (data && datalen) {
        sb_raw(&s, " | 加密前包体：");
        sb_hex(&s, data, datalen > 32 ? 32 : datalen);
        if (datalen > 32) sb_raw(&s, "...");
    }
    sb_caller(&s, caller);
    xhq_push(XHQ_KIND_AES, s.buf, s.len);
}

/* ---------- 原始函数指针 ---------- */
typedef int  (*fn_set_key)(const unsigned char *, int, void *);
typedef void (*fn_block)(const unsigned char *, unsigned char *, const void *);
typedef void (*fn_cbc)(const unsigned char *, unsigned char *, size_t,
                       const void *, unsigned char *, int);
typedef int  (*fn_gcm_init)(void *, const void *, void *, int);
typedef int  (*fn_gcm_iv)(void *, const unsigned char *, size_t);
typedef int  (*fn_gcm_tag)(void *, unsigned char *, size_t);
typedef int  (*fn_gcm_crypt)(void *, const unsigned char *, unsigned char *, size_t);

static fn_set_key   o_set_enc;
static fn_set_key   o_set_dec;
static fn_block     o_enc;
static fn_block     o_dec;
static fn_cbc       o_cbc;
static fn_gcm_init  o_gcm_init;
static fn_gcm_iv    o_gcm_setiv;
static fn_gcm_tag   o_gcm_tag;
static fn_gcm_crypt o_gcm_enc;
static fn_gcm_crypt o_gcm_dec;

/* ---------- 替换函数 ---------- */
static int det_set_enc(const unsigned char *userKey, int bits, void *key)
{
    unsigned int n = (bits > 0) ? (unsigned int)(bits / 8) : 16;
    if (n > sizeof(g_key)) n = sizeof(g_key);
    if (userKey) {
        unsigned int i;
        for (i = 0; i < n; i++) g_key[i] = userKey[i];
        g_key_len = n;
    }
    return o_set_enc(userKey, bits, key);
}

static int det_set_dec(const unsigned char *userKey, int bits, void *key)
{
    return o_set_dec(userKey, bits, key);
}

static void det_enc(const unsigned char *in, unsigned char *out, const void *key)
{
    if (allow()) emit("AES - 加密(单块)", in, 16, 1, __builtin_return_address(0));
    o_enc(in, out, key);
}

static void det_dec(const unsigned char *in, unsigned char *out, const void *key)
{
    if (allow()) emit("AES - 解密(单块)", in, 16, 1, __builtin_return_address(0));
    o_dec(in, out, key);
}

static void det_cbc(const unsigned char *in, unsigned char *out, size_t len,
                    const void *key, unsigned char *ivec, int enc)
{
    if (ivec) {
        unsigned int i;
        for (i = 0; i < sizeof(g_iv); i++) g_iv[i] = ivec[i];
        g_iv_len = sizeof(g_iv);
    }
    if (allow()) {
        XHQ_SB s;
        s.len = 0; s.buf[0] = 0;
        sb_raw(&s, enc ? "AES-CBC - 加密" : "AES-CBC - 解密");
        sb_raw(&s, " | 长度："); sb_num(&s, (unsigned long long)len);
        if (g_key_len) { sb_raw(&s, " | 密钥内容(Key)："); sb_hex(&s, g_key, g_key_len); }
        if (g_iv_len)  { sb_raw(&s, " | 计算偏移(IV)：");  sb_hex(&s, g_iv, g_iv_len); }
        if (in && len) { sb_raw(&s, " | 加密前包体："); sb_hex(&s, in, len > 32 ? 32 : (unsigned int)len); }
        xhq_push(XHQ_KIND_AES, s.buf, s.len);
    }
    o_cbc(in, out, len, key, ivec, enc);
}

static int det_gcm_init(void *ctx, const void *key, void *block, int enc)
{
    if (key) {
        unsigned int i;
        for (i = 0; i < 16; i++) g_key[i] = ((const unsigned char *)key)[i];
        g_key_len = 16;
    }
    return o_gcm_init(ctx, key, block, enc);
}

static int det_gcm_setiv(void *ctx, const unsigned char *iv, size_t len)
{
    unsigned int n = (len > sizeof(g_iv)) ? (unsigned int)sizeof(g_iv) : (unsigned int)len;
    if (iv && n) {
        unsigned int i;
        for (i = 0; i < n; i++) g_iv[i] = iv[i];
        g_iv_len = n;
    }
    return o_gcm_setiv(ctx, iv, len);
}

static int det_gcm_tag(void *ctx, unsigned char *tag, size_t len)
{
    int rc = o_gcm_tag(ctx, tag, len);
    unsigned int n = (len > sizeof(g_tag)) ? (unsigned int)sizeof(g_tag) : (unsigned int)len;
    if (tag && n) {
        unsigned int i;
        for (i = 0; i < n; i++) g_tag[i] = tag[i];
        g_tag_len = n;
    }
    return rc;
}

static int det_gcm_enc(void *ctx, const unsigned char *in, unsigned char *out, size_t len)
{
    if (allow()) emit("AES-GCM - 加密", in, (unsigned int)len, 1, __builtin_return_address(0));
    return o_gcm_enc(ctx, in, out, len);
}

static int det_gcm_dec(void *ctx, const unsigned char *in, unsigned char *out, size_t len)
{
    if (allow()) emit("AES-GCM - 解密", in, (unsigned int)len, 1, __builtin_return_address(0));
    return o_gcm_dec(ctx, in, out, len);
}

/* ---------- crypto.dll 运行时解析的辅助接口 ---------- */
typedef int  (*fn_nid_cipher)(const void *);
typedef int  (*fn_nid_ctx)(const void *);
typedef const char *(*fn_nid2sn)(int);
typedef int  (*fn_ctx_len)(const void *);

static fn_nid_cipher  o_cipher_nid;
static fn_nid_ctx     o_ctx_nid;
static fn_nid2sn      o_nid2sn;
static fn_ctx_len     o_ctx_keylen;
static fn_ctx_len     o_ctx_ivlen;

/* ---------- 上下文表：把 Init 阶段拿到的 key/iv 与后续 Update 关联起来 ----------
 * 一个 ctx 对应一路加密；QQ 通常同一时刻只有一两路在用，24 个槽足够。
 * 只在初始化/更新时访问，简单轮转覆盖即可，不做加锁。 */
#define XHQ_CTX_MAX 24
typedef struct {
    const void   *ctx;
    int           nid;
    unsigned char key[32];
    unsigned int  klen;
    unsigned char iv[16];
    unsigned int  ivlen;
} XHQ_CTXINFO;

static XHQ_CTXINFO   g_ctx[XHQ_CTX_MAX];
static volatile LONG g_ctx_rr = 0;

static void ctx_put(const void *ctx, int nid, const unsigned char *key, unsigned int klen,
                    const unsigned char *iv, unsigned int ivlen)
{
    LONG i;
    XHQ_CTXINFO *e = NULL;

    if (!ctx) return;
    for (i = 0; i < XHQ_CTX_MAX; i++) {
        if (g_ctx[i].ctx == ctx) { e = &g_ctx[i]; break; }
    }
    if (!e) {
        LONG idx = InterlockedIncrement(&g_ctx_rr) - 1;
        e = &g_ctx[idx % XHQ_CTX_MAX];
    }
    e->ctx = ctx;
    e->nid = nid;
    e->klen = (klen > sizeof(e->key)) ? (unsigned int)sizeof(e->key) : klen;
    e->ivlen = (ivlen > sizeof(e->iv)) ? (unsigned int)sizeof(e->iv) : ivlen;
    if (key && e->klen) {
        unsigned int k;
        for (k = 0; k < e->klen; k++) e->key[k] = key[k];
    }
    if (iv && e->ivlen) {
        unsigned int k;
        for (k = 0; k < e->ivlen; k++) e->iv[k] = iv[k];
    }
}

static XHQ_CTXINFO *ctx_get(const void *ctx)
{
    LONG i;
    if (!ctx) return NULL;
    for (i = 0; i < XHQ_CTX_MAX; i++) {
        if (g_ctx[i].ctx == ctx) return &g_ctx[i];
    }
    return NULL;
}

/* 算法名：NID → "AES-128-CBC" 这类短名，拿不到就退化成 nid 数值 */
static void sb_cipher_name(XHQ_SB *s, int nid)
{
    const char *sn = NULL;
    if (nid && o_nid2sn) sn = o_nid2sn(nid);
    if (sn && sn[0]) {
        sb_raw(s, sn);
    } else if (nid) {
        sb_raw(s, "NID#");
        sb_num(s, (unsigned long long)(unsigned int)nid);
    } else {
        sb_raw(s, "未知算法");
    }
}

/* ---------- EVP 层抓包 ----------
 * wrapper.node 导入的是 EVP_EncryptInit_ex / EVP_EncryptUpdate，
 * 也就是 QQ 实际走的高层入口。挂钩这些才能稳定拿到「算法 + Key + IV + 明文」，
 * 而底下具体调 AES_encrypt 还是 aesni 汇编实现都不影响。 */
typedef int (*fn_evp_init5)(void *, const void *, void *, const unsigned char *,
                            const unsigned char *);
typedef int (*fn_evp_init6)(void *, const void *, void *, const unsigned char *,
                            const unsigned char *, int);
typedef int (*fn_evp_update)(void *, unsigned char *, int *, const unsigned char *, int);

static fn_evp_init5  o_einit;
static fn_evp_init5  o_dinit;
static fn_evp_init6  o_cinit;
static fn_evp_update o_eupdate;
static fn_evp_update o_dupdate;
static fn_evp_update o_cupdate;

/* Init 阶段：记录 ctx 对应的算法与 key/iv */
static void evp_capture_init(void *ctx, const void *type, const unsigned char *key,
                             const unsigned char *iv)
{
    int nid = 0;
    unsigned int klen = 0, ivlen = 0;

    if (type && o_cipher_nid) nid = o_cipher_nid(type);
    if (!nid && ctx && o_ctx_nid) nid = o_ctx_nid(ctx);
    if (key && ctx && o_ctx_keylen) {
        int n = o_ctx_keylen(ctx);
        klen = (n > 0) ? (unsigned int)n : 16;
    }
    if (iv && ctx && o_ctx_ivlen) {
        int n = o_ctx_ivlen(ctx);
        ivlen = (n > 0) ? (unsigned int)n : 16;
    }
    ctx_put(ctx, nid, key, klen, iv, ivlen);
}

static int det_einit(void *ctx, const void *type, void *impl, const unsigned char *key,
                     const unsigned char *iv)
{
    int rc = o_einit(ctx, type, impl, key, iv);
    evp_capture_init(ctx, type, key, iv);
    return rc;
}

static int det_dinit(void *ctx, const void *type, void *impl, const unsigned char *key,
                     const unsigned char *iv)
{
    int rc = o_dinit(ctx, type, impl, key, iv);
    evp_capture_init(ctx, type, key, iv);
    return rc;
}

static int det_cinit(void *ctx, const void *type, void *impl, const unsigned char *key,
                     const unsigned char *iv, int enc)
{
    int rc = o_cinit(ctx, type, impl, key, iv, enc);
    evp_capture_init(ctx, type, key, iv);
    return rc;
}

/* Update 阶段：把明文/密文抓出来 */
static void evp_emit(const char *title, void *ctx, const unsigned char *in, int inl,
                     void *caller)
{
    XHQ_CTXINFO *ci;
    XHQ_SB s;

    if (!in || inl <= 0) return;
    ci = ctx_get(ctx);

    s.len = 0;
    s.buf[0] = 0;
    if (ci) {
        sb_cipher_name(&s, ci->nid);
        sb_raw(&s, " - ");
    }
    sb_raw(&s, title);
    if (ci && ci->klen) { sb_raw(&s, " | 密钥内容(Key)："); sb_hex(&s, ci->key, ci->klen); }
    if (ci && ci->ivlen) { sb_raw(&s, " | 计算偏移(IV)："); sb_hex(&s, ci->iv, ci->ivlen); }
    sb_raw(&s, " | 数据长度：");
    sb_num(&s, (unsigned long long)(unsigned int)inl);
    sb_caller(&s, caller);
    sb_raw(&s, " | 加密前包体：");
    sb_hex(&s, in, (inl > 48) ? 48u : (unsigned int)inl);
    if (inl > 48) sb_raw(&s, "...");
    xhq_push(XHQ_KIND_AES, s.buf, s.len);
}

static int det_eupdate(void *ctx, unsigned char *out, int *outl, const unsigned char *in,
                       int inl)
{
    void *ra = __builtin_return_address(0);
    if (allow()) evp_emit("加密", ctx, in, inl, ra);
    return o_eupdate(ctx, out, outl, in, inl);
}

static int det_dupdate(void *ctx, unsigned char *out, int *outl, const unsigned char *in,
                       int inl)
{
    void *ra = __builtin_return_address(0);
    if (allow()) evp_emit("解密", ctx, in, inl, ra);
    return o_dupdate(ctx, out, outl, in, inl);
}

static int det_cupdate(void *ctx, unsigned char *out, int *outl, const unsigned char *in,
                       int inl)
{
    void *ra = __builtin_return_address(0);
    if (allow()) evp_emit("加/解密", ctx, in, inl, ra);
    return o_cupdate(ctx, out, outl, in, inl);
}

/* ---------- HMAC 抓取（签名素材） ----------
 * 目标同样是 crypto.dll 的具名导出。捕获 (key, 算法, 数据×2) → mac。
 * PCNT 上层的签名/完整性校验就是走这条 HMAC 路径（实测 wrapper.node+0x3C13650
 * 封装的就是它），因此这里抓到的是最接近“签名”的原始素材。 */
#define XHQ_HMAC_HOOKS     3
#define XHQ_HMAC_CTX_MAX   24
#define XHQ_HMAC_KEY_MAX   96
#define XHQ_HMAC_DATA_MAX  4096

typedef int  (*fn_hmac_init)(void *, const void *, int, const void *, void *);
typedef int  (*fn_hmac_update)(void *, const unsigned char *, size_t);
typedef int  (*fn_hmac_final)(void *, unsigned char *, unsigned int *);
typedef int  (*fn_md_type)(const void *);
typedef const char *(*fn_nid2sn)(int);

static fn_hmac_init   o_hmac_init;
static fn_hmac_update o_hmac_update;
static fn_hmac_final  o_hmac_final;
static fn_md_type     o_md_type;
static fn_nid2sn      o_hmac_nid2sn;

typedef struct {
    const void   *ctx;
    unsigned char key[XHQ_HMAC_KEY_MAX];
    unsigned int  keylen;
    int           md_nid;
    int           nupdate;
    unsigned char d1[XHQ_HMAC_DATA_MAX]; unsigned int d1len;
    unsigned char d2[XHQ_HMAC_DATA_MAX]; unsigned int d2len;
} XHQ_HMAC_INFO;

static XHQ_HMAC_INFO g_hmac[XHQ_HMAC_CTX_MAX];
static volatile LONG g_hmac_rr = 0;

static XHQ_HMAC_INFO *hmac_slot(const void *ctx)
{
    LONG i;
    XHQ_HMAC_INFO *e;
    if (!ctx) return NULL;
    for (i = 0; i < XHQ_HMAC_CTX_MAX; i++)
        if (g_hmac[i].ctx == ctx) return &g_hmac[i];
    i = InterlockedIncrement(&g_hmac_rr) - 1;
    e = &g_hmac[i % XHQ_HMAC_CTX_MAX];
    memset(e, 0, sizeof(*e));
    e->ctx = ctx;
    return e;
}

static XHQ_HMAC_INFO *hmac_get(const void *ctx)
{
    LONG i;
    if (!ctx) return NULL;
    for (i = 0; i < XHQ_HMAC_CTX_MAX; i++)
        if (g_hmac[i].ctx == ctx) return &g_hmac[i];
    return NULL;
}

/* nid → 算法短名（sha256 之类），拿不到就退化成 nid#数值 */
static void hmac_alg(char *out, unsigned int cap, int nid)
{
    const char *sn = (nid && o_hmac_nid2sn) ? o_hmac_nid2sn(nid) : NULL;
    unsigned int i = 0;
    if (sn && sn[0]) {
        while (sn[i] && i + 1 < cap) { out[i] = sn[i]; i++; }
    } else {
        const char *p = "nid#";
        char t[12]; int n = 0, j;
        unsigned int v = (unsigned int)nid;
        while (*p && i + 1 < cap) out[i++] = *p++;
        if (!v) t[n++] = '0';
        while (v && n < 12) { t[n++] = (char)('0' + v % 10); v /= 10; }
        for (j = n - 1; j >= 0 && i + 1 < cap; j--) out[i++] = t[j];
    }
    out[i] = 0;
}

static void hmac_store(const void *ctx, const unsigned char *d, size_t len)
{
    XHQ_HMAC_INFO *e = hmac_get(ctx);
    unsigned int n;
    if (!e || !d || len == 0) return;
    n = (len > XHQ_HMAC_DATA_MAX) ? (unsigned int)XHQ_HMAC_DATA_MAX : (unsigned int)len;
    if (e->nupdate == 0) {
        memcpy(e->d1, d, n); e->d1len = n;
    } else if (e->nupdate == 1) {
        memcpy(e->d2, d, n); e->d2len = n;
    }
    e->nupdate++;
}

static int det_hmac_init(void *ctx, const void *key, int keylen,
                         const void *md, void *impl)
{
    int rc = o_hmac_init(ctx, key, keylen, md, impl);
    XHQ_HMAC_INFO *e = hmac_slot(ctx);
    if (e) {
        unsigned int n = (keylen > 0) ? (unsigned int)keylen : 0;
        if (n > XHQ_HMAC_KEY_MAX) n = XHQ_HMAC_KEY_MAX;
        if (key && n) { memcpy(e->key, key, n); e->keylen = n; }
        e->md_nid = (md && o_md_type) ? o_md_type(md) : 0;
        e->nupdate = 0;
    }
    return rc;
}

static int det_hmac_update(void *ctx, const unsigned char *data, size_t len)
{
    if (allow()) hmac_store(ctx, data, len);
    return o_hmac_update(ctx, data, len);
}

static int det_hmac_final(void *ctx, unsigned char *md, unsigned int *len)
{
    unsigned int want = (len) ? *len : 0;
    int rc = o_hmac_final(ctx, md, len);
    XHQ_HMAC_INFO *e = hmac_get(ctx);
    if (e && allow() && md) {
        unsigned int maclen = (len) ? *len : want;
        char alg[24];
        XHQ_SB s;
        s.len = 0; s.buf[0] = 0;
        hmac_alg(alg, sizeof(alg), e->md_nid);
        sb_raw(&s, "HMAC");
        sb_raw(&s, " | 算法："); sb_raw(&s, alg);
        if (e->keylen) { sb_raw(&s, " | 密钥(Key)："); sb_hex(&s, e->key, e->keylen); }
        if (e->d1len) {
            sb_raw(&s, " | 数据1("); sb_num(&s, e->d1len); sb_raw(&s, "字节)：");
            sb_hex(&s, e->d1, e->d1len > 200 ? 200 : e->d1len);
        }
        if (e->d2len) {
            sb_raw(&s, " | 数据2("); sb_num(&s, e->d2len); sb_raw(&s, "字节)：");
            sb_hex(&s, e->d2, e->d2len > 32 ? 32 : e->d2len);
        }
        if (maclen)    { sb_raw(&s, " | MAC("); sb_num(&s, maclen); sb_raw(&s, "字节)："); sb_hex(&s, md, maclen); }
        xhq_push(XHQ_KIND_SIGN, s.buf, s.len);
    }
    return rc;
}

/* ---------- 安装 ---------- */
typedef struct {
    const char *name;
    void       *detour;
    void      **orig;
} XHQ_TARGET;

static XHQ_HOOK g_hooks[XHQ_AES_HOOKS];
static XHQ_HOOK g_evp_hooks[XHQ_EVP_HOOKS];
static XHQ_HOOK g_hmac_hooks[XHQ_HMAC_HOOKS];
static int      g_hook_count = 0;
static int      g_evp_count = 0;
static int      g_hmac_count = 0;

static const XHQ_TARGET g_targets[XHQ_AES_HOOKS] = {
    { "AES_set_encrypt_key",    (void *)det_set_enc,   (void **)&o_set_enc },
    { "AES_set_decrypt_key",    (void *)det_set_dec,   (void **)&o_set_dec },
    { "AES_encrypt",            (void *)det_enc,       (void **)&o_enc },
    { "AES_decrypt",            (void *)det_dec,       (void **)&o_dec },
    { "AES_cbc_encrypt",        (void *)det_cbc,       (void **)&o_cbc },
    { "CRYPTO_gcm128_init_key", (void *)det_gcm_init,  (void **)&o_gcm_init },
    { "CRYPTO_gcm128_setiv",    (void *)det_gcm_setiv, (void **)&o_gcm_setiv },
    { "CRYPTO_gcm128_tag",      (void *)det_gcm_tag,   (void **)&o_gcm_tag },
    { "CRYPTO_gcm128_encrypt",  (void *)det_gcm_enc,   (void **)&o_gcm_enc },
    { "CRYPTO_gcm128_decrypt",  (void *)det_gcm_dec,   (void **)&o_gcm_dec },
};

static const XHQ_TARGET g_evp_targets[XHQ_EVP_HOOKS] = {
    { "EVP_EncryptInit_ex", (void *)det_einit,    (void **)&o_einit },
    { "EVP_DecryptInit_ex", (void *)det_dinit,    (void **)&o_dinit },
    { "EVP_CipherInit_ex",  (void *)det_cinit,    (void **)&o_cinit },
    { "EVP_EncryptUpdate",  (void *)det_eupdate,  (void **)&o_eupdate },
    { "EVP_DecryptUpdate",  (void *)det_dupdate,  (void **)&o_dupdate },
    { "EVP_CipherUpdate",   (void *)det_cupdate,  (void **)&o_cupdate },
};

static const XHQ_TARGET g_hmac_targets[XHQ_HMAC_HOOKS] = {
    { "HMAC_Init_ex", (void *)det_hmac_init,   (void **)&o_hmac_init },
    { "HMAC_Update",  (void *)det_hmac_update, (void **)&o_hmac_update },
    { "HMAC_Final",   (void *)det_hmac_final,  (void **)&o_hmac_final },
};

/* 解析抓算法名所需的辅助导出 */
static void resolve_helpers(void *base)
{
    o_cipher_nid = (fn_nid_cipher)xhq_get_export(base, "EVP_CIPHER_nid");
    o_ctx_nid = (fn_nid_ctx)xhq_get_export(base, "EVP_CIPHER_CTX_nid");
    o_nid2sn = (fn_nid2sn)xhq_get_export(base, "OBJ_nid2sn");
    o_ctx_keylen = (fn_ctx_len)xhq_get_export(base, "EVP_CIPHER_CTX_key_length");
    o_ctx_ivlen = (fn_ctx_len)xhq_get_export(base, "EVP_CIPHER_CTX_iv_length");
    o_md_type = (fn_md_type)xhq_get_export(base, "EVP_MD_type");
    o_hmac_nid2sn = (fn_nid2sn)xhq_get_export(base, "OBJ_nid2sn");
}

int xhq_crypto_installed(void)
{
    return g_hook_count + g_evp_count + g_hmac_count;
}

/* 在补丁写入前把蹦床地址交给调用方，避免「跳转已生效、原函数指针还是空」的竞态 */
static void xhq_set_orig(void *tramp, void *ctx)
{
    if (ctx) *(void **)ctx = tramp;
}

int xhq_crypto_hook(int enable_aes, int enable_tea)
{
    void *base;
    XHQ_SB s;
    char failed[XHQ_AES_HOOKS][2];
    char evpfailed[XHQ_EVP_HOOKS][2];
    char hmacfailed[XHQ_HMAC_HOOKS][2];
    int i;
    int ok = 0;
    int evpok = 0;
    int hmacok = 0;

    (void)enable_tea;   /* TEA 在别的模块里（crypto.dll 无 TEA 导出），见探针方案 */

    for (i = 0; i < XHQ_AES_HOOKS; i++) failed[i][0] = '-';
    for (i = 0; i < XHQ_EVP_HOOKS; i++) evpfailed[i][0] = '-';
    for (i = 0; i < XHQ_HMAC_HOOKS; i++) hmacfailed[i][0] = '-';

    if (!enable_aes) {
        for (i = 0; i < XHQ_AES_HOOKS; i++) {
            if (g_hooks[i].installed) xhq_unhook(&g_hooks[i]);
        }
        for (i = 0; i < XHQ_EVP_HOOKS; i++) {
            if (g_evp_hooks[i].installed) xhq_unhook(&g_evp_hooks[i]);
        }
        for (i = 0; i < XHQ_HMAC_HOOKS; i++) {
            if (g_hmac_hooks[i].installed) xhq_unhook(&g_hmac_hooks[i]);
        }
        g_hook_count = 0;
        g_evp_count = 0;
        g_hmac_count = 0;
        return 0;
    }
    if (g_hook_count > 0 || g_evp_count > 0 || g_hmac_count > 0)
        return g_hook_count + g_evp_count + g_hmac_count;

    base = xhq_module_base(L"crypto.dll");
    s.len = 0; s.buf[0] = 0;
    if (!base) {
        sb_raw(&s, "crypto.dll 未加载，加密 HOOK 跳过");
        xhq_push(XHQ_KIND_INFO, s.buf, s.len);
        return 0;
    }

    resolve_helpers(base);

    for (i = 0; i < XHQ_AES_HOOKS; i++) {
        void *addr = xhq_get_export(base, g_targets[i].name);
        if (!addr) {
            failed[i][0] = 'E';   /* 导出表里没有 */
            continue;
        }
        if (!xhq_hook_ex(addr, g_targets[i].detour, &g_hooks[i],
                         xhq_set_orig, g_targets[i].orig)) {
            failed[i][0] = 'H';   /* 前序指令无法安全搬迁 */
            continue;
        }
        failed[i][0] = 'O';
        ok++;
    }
    g_hook_count = ok;

    /* EVP 层才是 QQ 实际调用的入口（wrapper.node 导入的就是它） */
    for (i = 0; i < XHQ_EVP_HOOKS; i++) {
        void *addr = xhq_get_export(base, g_evp_targets[i].name);
        if (!addr) {
            evpfailed[i][0] = 'E';
            continue;
        }
        if (!xhq_hook_ex(addr, g_evp_targets[i].detour, &g_evp_hooks[i],
                         xhq_set_orig, g_evp_targets[i].orig)) {
            evpfailed[i][0] = 'H';
            continue;
        }
        evpfailed[i][0] = 'O';
        evpok++;
    }
    g_evp_count = evpok;

    /* HMAC 抓取：PCNT 的签名/完整性校验素材 */
    for (i = 0; i < XHQ_HMAC_HOOKS; i++) {
        void *addr = xhq_get_export(base, g_hmac_targets[i].name);
        if (!addr) {
            hmacfailed[i][0] = 'E';
            continue;
        }
        if (!xhq_hook_ex(addr, g_hmac_targets[i].detour, &g_hmac_hooks[i],
                         xhq_set_orig, g_hmac_targets[i].orig)) {
            hmacfailed[i][0] = 'H';
            continue;
        }
        hmacfailed[i][0] = 'O';
        hmacok++;
    }
    g_hmac_count = hmacok;

    sb_raw(&s, "加密 HOOK 已安装：底层 ");
    sb_num(&s, (unsigned long long)ok);
    sb_raw(&s, "/");
    sb_num(&s, (unsigned long long)XHQ_AES_HOOKS);
    sb_raw(&s, "，EVP 层 ");
    sb_num(&s, (unsigned long long)evpok);
    sb_raw(&s, "/");
    sb_num(&s, (unsigned long long)XHQ_EVP_HOOKS);
    sb_raw(&s, "，HMAC 层 ");
    sb_num(&s, (unsigned long long)hmacok);
    sb_raw(&s, "/");
    sb_num(&s, (unsigned long long)XHQ_HMAC_HOOKS);
    sb_raw(&s, "，crypto.dll 基址=");
    sb_ptr(&s, (unsigned long long)base);
    xhq_push(XHQ_KIND_INFO, s.buf, s.len);

    /* 明细：O=已挂钩 E=无此导出 H=前序指令不安全 */
    for (i = 0; i < XHQ_AES_HOOKS; i++) {
        s.len = 0; s.buf[0] = 0;
        sb_raw(&s, "  ");
        if (failed[i][0] == 'O') sb_raw(&s, "[O] ");
        else if (failed[i][0] == 'E') sb_raw(&s, "[E] ");
        else sb_raw(&s, "[H] ");
        sb_raw(&s, g_targets[i].name);
        xhq_push(XHQ_KIND_INFO, s.buf, s.len);
    }
    for (i = 0; i < XHQ_EVP_HOOKS; i++) {
        s.len = 0; s.buf[0] = 0;
        sb_raw(&s, "  ");
        if (evpfailed[i][0] == 'O') sb_raw(&s, "[O] ");
        else if (evpfailed[i][0] == 'E') sb_raw(&s, "[E] ");
        else sb_raw(&s, "[H] ");
        sb_raw(&s, g_evp_targets[i].name);
        xhq_push(XHQ_KIND_INFO, s.buf, s.len);
    }
    for (i = 0; i < XHQ_HMAC_HOOKS; i++) {
        s.len = 0; s.buf[0] = 0;
        sb_raw(&s, "  ");
        if (hmacfailed[i][0] == 'O') sb_raw(&s, "[O] ");
        else if (hmacfailed[i][0] == 'E') sb_raw(&s, "[E] ");
        else sb_raw(&s, "[H] ");
        sb_raw(&s, g_hmac_targets[i].name);
        xhq_push(XHQ_KIND_INFO, s.buf, s.len);
    }
    return ok + evpok + hmacok;
}

/* 进程内自测：用标准测试向量依次调用（已被 HOOK 的）导出函数，
 * 用来在不依赖 QQ 网络流量、也不依赖宿主多参数调用的前提下验证 HOOK 是否真的生效。
 * 目标函数地址取自导出表，因此调用一定会经过我们的 detour。
 * 每推进一步都先写一条记录，即使某步把进程打崩也能看出崩在哪一步。 */
int xhq_crypto_selftest(void)
{
    void *base = xhq_module_base(L"crypto.dll");
    void *p_setkey, *p_enc;
    unsigned char key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    unsigned char in[16]  = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                              0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    unsigned char out[16];
    unsigned char aes_key[244];
    XHQ_SB s;
    int rc;

    if (!base) return -1;
    p_setkey = xhq_get_export(base, "AES_set_encrypt_key");
    p_enc = xhq_get_export(base, "AES_encrypt");
    if (!p_setkey || !p_enc) return -2;

    /* 取证：把被替换处与被搬迁的蹦床字节都记下来，进程若崩溃也留得下证据 */
    {
        static const char *dbg_names[2] = { "AES_set_encrypt_key", "AES_encrypt" };
        void *dbg_addr[2];
        int d;
        dbg_addr[0] = p_setkey;
        dbg_addr[1] = p_enc;
        for (d = 0; d < 2; d++) {
            int k;
            for (k = 0; k < XHQ_AES_HOOKS; k++) {
                if (!g_hooks[k].installed || g_hooks[k].target != dbg_addr[d]) continue;
                s.len = 0; s.buf[0] = 0;
                sb_raw(&s, "取证 ");
                sb_raw(&s, dbg_names[d]);
                sb_raw(&s, " patch_len=");
                sb_num(&s, g_hooks[k].patch_len);
                sb_raw(&s, " 原始：");
                sb_hex(&s, g_hooks[k].orig, g_hooks[k].patch_len);
                sb_raw(&s, " 蹦床：");
                sb_hex(&s, g_hooks[k].tramp, 40);   /* 覆盖前序指令 + 末尾绝对跳转 */
                xhq_push(XHQ_KIND_INFO, s.buf, s.len);
                break;
            }
        }
    }

    xhq_push(XHQ_KIND_INFO, "自测[1/2] AES_set_encrypt_key", 31);
    rc = ((int (*)(const unsigned char *, int, void *))p_setkey)(key, 128, aes_key);
    {
        s.len = 0; s.buf[0] = 0;
        sb_raw(&s, "自测 set_encrypt_key 返回：");
        sb_num(&s, (unsigned long long)(unsigned int)rc);
        xhq_push(XHQ_KIND_INFO, s.buf, s.len);
    }
    if (rc != 0) return -3;

    xhq_push(XHQ_KIND_INFO, "自测[2/2] AES_encrypt(单块)", 29);
    ((void (*)(const unsigned char *, unsigned char *, const void *))p_enc)(in, out, aes_key);

    s.len = 0; s.buf[0] = 0;
    sb_raw(&s, "自测[2/2] 完成，AES-128 输出应为 69C4E0D86A7B0430D8CDB78070B4C55A，实际：");
    sb_hex(&s, out, 16);
    if (out[0] == 0x69 && out[1] == 0xC4 && out[15] == 0x5A) {
        sb_raw(&s, " → 一致，HOOK 与蹦床重定位正确");
    } else {
        sb_raw(&s, " → 不一致！");
    }
    xhq_push(XHQ_KIND_AES, s.buf, s.len);
    return 1;
}
/* 说明：CRYPTO_gcm128_* 这几个 HOOK 不在这里自测——GCM 的上下文/回调约定较绕，
 * 自测里用错参数会把宿主进程打崩，而自测必须能在 QQ 里安全运行。
 * 这几个 HOOK 是否真的被 QQ 用到，靠抓包页的真实流量记录来判断。 */