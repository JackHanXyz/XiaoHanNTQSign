// crypto.cpp —— bcrypt(CNG) 封装实现。
#include "crypto.h"

#include <windows.h>
#include <bcrypt.h>

#include "log.h"

// 链接由构建脚本的 -lbcrypt 负责（MinGW 不支持 MSVC 的 #pragma comment）。

namespace xh {

namespace {

LPCWSTR alg_id(HashAlg a)
{
    switch (a) {
        case HashAlg::Sha1:   return BCRYPT_SHA1_ALGORITHM;
        case HashAlg::Sha256: return BCRYPT_SHA256_ALGORITHM;
        default:              return BCRYPT_SHA512_ALGORITHM;
    }
}

struct AlgHandle {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~AlgHandle() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};

// 读取一个 ULONG 型算法属性（OBJECT_LENGTH / HASH_LENGTH）。
bool get_ulong(BCRYPT_ALG_HANDLE alg, LPCWSTR prop, ULONG &out)
{
    ULONG cb = 0;
    if (BCryptGetProperty(alg, prop, reinterpret_cast<PUCHAR>(&out),
                          sizeof(out), &cb, 0) < 0)
        return false;
    return true;
}

}  // namespace

bool hmac(HashAlg a, const uint8_t *key, size_t key_len,
          const uint8_t *data, size_t data_len, std::vector<uint8_t> &out)
{
    AlgHandle alg;
    if (BCryptOpenAlgorithmProvider(&alg.h, alg_id(a), nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0) {
        LOGE("BCryptOpenAlgorithmProvider(HMAC) 失败");
        return false;
    }

    ULONG obj_len = 0, hash_len = 0;
    if (!get_ulong(alg.h, BCRYPT_OBJECT_LENGTH, obj_len) ||
        !get_ulong(alg.h, BCRYPT_HASH_LENGTH, hash_len))
        return false;

    std::vector<uint8_t> obj(obj_len);
    BCRYPT_HASH_HANDLE h = nullptr;
    if (BCryptCreateHash(alg.h, &h, obj.data(), obj_len,
                         const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0) < 0) {
        LOGE("BCryptCreateHash(HMAC) 失败");
        return false;
    }

    out.resize(hash_len);
    bool ok = BCryptHashData(h, const_cast<PUCHAR>(data),
                             static_cast<ULONG>(data_len), 0) >= 0 &&
              BCryptFinishHash(h, out.data(), hash_len, 0) >= 0;
    BCryptDestroyHash(h);
    return ok;
}

bool digest(HashAlg a, const uint8_t *data, size_t data_len, std::vector<uint8_t> &out)
{
    AlgHandle alg;
    if (BCryptOpenAlgorithmProvider(&alg.h, alg_id(a), nullptr, 0) < 0)
        return false;

    ULONG obj_len = 0, hash_len = 0;
    if (!get_ulong(alg.h, BCRYPT_OBJECT_LENGTH, obj_len) ||
        !get_ulong(alg.h, BCRYPT_HASH_LENGTH, hash_len))
        return false;

    std::vector<uint8_t> obj(obj_len);
    BCRYPT_HASH_HANDLE h = nullptr;
    if (BCryptCreateHash(alg.h, &h, obj.data(), obj_len, nullptr, 0, 0) < 0)
        return false;

    out.resize(hash_len);
    bool ok = BCryptHashData(h, const_cast<PUCHAR>(data),
                             static_cast<ULONG>(data_len), 0) >= 0 &&
              BCryptFinishHash(h, out.data(), hash_len, 0) >= 0;
    BCryptDestroyHash(h);
    return ok;
}

namespace {

// AES-256-CBC 加解密公共实现。key_len 允许 16/24/32。
bool aes_cbc(bool enc, const uint8_t *key, size_t key_len, const uint8_t *iv,
             const uint8_t *data, size_t data_len, bool padding,
             std::vector<uint8_t> &out)
{
    AlgHandle alg;
    if (BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0) {
        LOGE("BCryptOpenAlgorithmProvider(AES) 失败");
        return false;
    }
    if (BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_CBC)),
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0) < 0) {
        LOGE("BCryptSetProperty(CBC) 失败");
        return false;
    }

    ULONG obj_len = 0;
    if (!get_ulong(alg.h, BCRYPT_OBJECT_LENGTH, obj_len))
        return false;

    std::vector<uint8_t> obj(obj_len);
    BCRYPT_KEY_HANDLE kh = nullptr;
    if (BCryptGenerateSymmetricKey(alg.h, &kh, obj.data(), obj_len,
                                   const_cast<PUCHAR>(key),
                                   static_cast<ULONG>(key_len), 0) < 0) {
        LOGE("BCryptGenerateSymmetricKey 失败");
        return false;
    }

    ULONG flags = padding ? BCRYPT_BLOCK_PADDING : 0;
    out.resize(data_len + 16);
    ULONG produced = 0;
    NTSTATUS st = enc
        ? BCryptEncrypt(kh, const_cast<PUCHAR>(data), static_cast<ULONG>(data_len),
                        nullptr, const_cast<PUCHAR>(iv), 16,
                        out.data(), static_cast<ULONG>(out.size()), &produced, flags)
        : BCryptDecrypt(kh, const_cast<PUCHAR>(data), static_cast<ULONG>(data_len),
                        nullptr, const_cast<PUCHAR>(iv), 16,
                        out.data(), static_cast<ULONG>(out.size()), &produced, flags);

    BCryptDestroyKey(kh);
    if (st < 0) {
        LOGE("BCrypt%s 失败 status=0x%08lX", enc ? "Encrypt" : "Decrypt",
             static_cast<unsigned long>(st));
        return false;
    }
    out.resize(produced);
    return true;
}

}  // namespace

bool aes256_cbc_encrypt(const uint8_t *key, size_t key_len, const uint8_t *iv,
                        const uint8_t *data, size_t data_len, bool padding,
                        std::vector<uint8_t> &out)
{
    return aes_cbc(true, key, key_len, iv, data, data_len, padding, out);
}

bool aes256_cbc_decrypt(const uint8_t *key, size_t key_len, const uint8_t *iv,
                        const uint8_t *data, size_t data_len, bool padding,
                        std::vector<uint8_t> &out)
{
    return aes_cbc(false, key, key_len, iv, data, data_len, padding, out);
}

}  // namespace xh