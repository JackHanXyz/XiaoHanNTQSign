// crypto.h —— 基于 Windows CNG(bcrypt) 的密码学原语封装。
//
// 这是「路线 B（净室复刻）」的种子工具箱：PCNT 报文加密用的 AES-256-CBC，
// 签名用的 HMAC(SHA1/256/512)，全部走系统自带实现，不引入第三方库。
// 现阶段先用它验证「离线算出来的字节」能否与真机抓到的字节对上。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace xh {

enum class HashAlg { Sha1, Sha256, Sha512 };

// HMAC-<alg>(key, data) -> out（out 长度 = 摘要长度）
bool hmac(HashAlg alg, const uint8_t *key, size_t key_len,
          const uint8_t *data, size_t data_len, std::vector<uint8_t> &out);

// 明文 SHA-<alg>(data)
bool digest(HashAlg alg, const uint8_t *data, size_t data_len, std::vector<uint8_t> &out);

// AES-256-CBC，PKCS7 填充由调用方决定；这里显式控制 padding：
//   padding == false  → 数据长度必须是 16 的整数倍（QQ 报文常见做法）
bool aes256_cbc_encrypt(const uint8_t *key, size_t key_len, const uint8_t *iv,
                        const uint8_t *data, size_t data_len, bool padding,
                        std::vector<uint8_t> &out);

bool aes256_cbc_decrypt(const uint8_t *key, size_t key_len, const uint8_t *iv,
                        const uint8_t *data, size_t data_len, bool padding,
                        std::vector<uint8_t> &out);

}  // namespace xh