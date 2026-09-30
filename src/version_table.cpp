// version_table.cpp —— 入口库数据与查询。
#include "version_table.h"

#include <cstdlib>

namespace xh {

// ---------------------------------------------------------------------------
// 数据来源：XiaoHanQQNT 的实测逆向（见其 host/core/offsets.py）。
// 定位方法可复现：
//   1. scan_exports.py 确认目标函数无具名导出；
//   2. HOOK crypto.dll 的加解密/哈希导出，记录调用者返回地址 → 模块名+RVA；
//   3. 拿该 RVA 在 wrapper.node 里反汇编，确认调用序列。
// ---------------------------------------------------------------------------
static const VersionEntry kTable[] = {
    {
        "9.9.35-52892",
        {
            {
                "签名（HMAC，SHA1/256/512 可选）",
                0x3C13650ULL,
                "HMAC_CTX_new → 按模式选 EVP_sha1/sha256/sha512 → "
                "HMAC_Init_ex(key,keylen) → HMAC_Update ×2 → HMAC_Final。"
                "反汇编还原的 ABI（x64/MS）："
                "int fn(void*占位, int mode, const void* key, int keylen,"
                " const void* in1, int len1, const void* in2, int len2, void* out)",
            },
            {
                "报文加密（AES-256-CBC）",
                0x3C139B0ULL,
                "EVP_CIPHER_CTX_new → EVP_aes_256_cbc → "
                "EVP_CipherInit_ex(key,iv,enc) → EVP_CIPHER_CTX_set_padding(0) → "
                "EVP_CipherUpdate → EVP_CipherFinal_ex；由 0x327B350 调用。"
                "反汇编还原的 ABI（x64/MS）："
                "int fn(void*占位, int enc, const void* key32, void*占位,"
                " const void* iv16, const void* in, int inlen, void* out)；"
                "key 固定 32 字节、无 PKCS 填充（inlen 须为 16 倍数）",
            },
            {
                "上层报文组装",
                0x327B350ULL,
                "调用报文加密函数（实测 46 次/14 秒）",
            },
        },
    },
};

const VersionEntry *find_version(const std::string &version)
{
    for (const auto &v : kTable) {
        if (v.version == version) return &v;
    }
    return nullptr;
}

uint64_t sign_rva(const std::string &version)
{
    const VersionEntry *v = find_version(version);
    if (!v) return 0;
    for (const auto &e : v->entries) {
        if (e.name.find("签名") != std::string::npos) return e.rva;
    }
    return 0;
}

uint64_t aes_rva(const std::string &version)
{
    const VersionEntry *v = find_version(version);
    if (!v) return 0;
    for (const auto &e : v->entries) {
        if (e.name.find("加密") != std::string::npos) return e.rva;
    }
    return 0;
}

std::vector<std::string> known_versions()
{
    std::vector<std::string> out;
    for (const auto &v : kTable) out.push_back(v.version);
    return out;
}

std::string default_qq_root()
{
    // 优先用环境变量覆盖，其次是本机已确认的安装位置。
    const char *env = std::getenv("XHNTQSIGN_QQ_ROOT");
    if (env && *env) return env;
    return "D:\\QQNT";
}

}  // namespace xh