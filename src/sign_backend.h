// sign_backend.h —— 签名后端抽象。
//
// 服务层只依赖这个接口；后端负责「怎么把 sign/token/extra 算出来」。
// 当前实现 OfflineBackend 走路线 A：离线映射 wrapper.node 并定位签名入口。
// 后续可替换/叠加路线 B（净室复刻）实现，而服务层与协议不变。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "pe_mapper.h"

namespace xh {

// 对齐 QSign 协议的请求字段。
struct SignRequest {
    std::string uin;         // QQ 号
    std::string qua;         // 客户端标识
    std::string cmd;         // 指令名，如 "wtlogin.login"
    std::string version;     // 协议版本
    std::string buffer_hex;  // 待签名报文（十六进制）
    int         seq = 1;
};

struct SignResult {
    int         code = 0;          // 0 = 成功
    std::string msg = "success";
    std::string sign_hex;          // 十六进制
    std::string token_hex;         // 十六进制
    std::string extra_hex;         // 十六进制
};

class SignBackend {
public:
    virtual ~SignBackend() = default;

    // 初始化。失败返回 false 并写 err。
    virtual bool init(const std::string &qq_root, const std::string &version,
                      std::string *err) = 0;

    virtual SignResult sign(const SignRequest &req) = 0;

    // 人类可读的自述（状态、基址、入口等）。
    virtual std::string describe() const = 0;
};

// 路线 A 后端：离线手动映射 wrapper.node，定位签名/加密入口。
class OfflineBackend : public SignBackend {
public:
    ~OfflineBackend() override;

    bool init(const std::string &qq_root, const std::string &version,
              std::string *err) override;
    SignResult sign(const SignRequest &req) override;
    std::string describe() const override;

    // 校验映射结果：基址、重定位、入口 RVA 与入口前若干字节。
    std::string selftest() const;

    // 扫描整个映像，找出所有「直接 call 目标 RVA」的调用点，返回调用点 RVA。
    // 用于追踪调用链：谁调用了签名/加密函数。
    std::vector<uint64_t> find_callers(uint64_t target_rva) const;

    // 离线调用 wrapper.node 的 HMAC 签名原语（+0x3C13650）。
    // 反汇编还原出的 ABI：
    //   int fn(void *unused, int mode, const void *key, int keylen,
    //          const void *in1, int len1, const void *in2, int len2, void *out);
    // mode 0/1/2 分别选取 sha1/sha256/sha512；in2 可为空（只做一次 Update）。
    // 成功写入 out（定长 64 字节缓冲）并返回 true；ret 回传原函数返回值。
    bool hmac_real(int mode, const std::vector<uint8_t> &key,
                   const std::vector<uint8_t> &in1, const std::vector<uint8_t> &in2,
                   std::vector<uint8_t> &out, int *ret) const;

    // 离线调用 wrapper.node 的 AES-256-CBC 报文加密原语（+0x3C139B0）。
    // 反汇编还原出的 ABI：
    //   int fn(void *unused, int enc, const void *key32, void *unused,
    //          const void *iv16, const void *in, int inlen, void *out);
    // enc: 1=加密 0=解密。key 固定 32 字节；函数禁用了 PKCS 填充，
    // 因此 inlen 必须是 16 的整数倍。
    bool aes_real(int enc, const std::vector<uint8_t> &key,
                  const std::vector<uint8_t> &iv, const std::vector<uint8_t> &in,
                  std::vector<uint8_t> &out, int *ret) const;

    uint64_t sign_rva() const { return sign_rva_; }
    uint64_t aes_rva() const { return aes_rva_; }
    uintptr_t sign_va() const { return sign_va_; }

private:
    PeImage    *image_ = nullptr;
    std::string version_;
    std::string wrapper_path_;
    uint64_t    sign_rva_ = 0;
    uint64_t    aes_rva_ = 0;
    uintptr_t   sign_va_ = 0;
    uintptr_t   aes_va_ = 0;
    std::vector<uint8_t> sign_head_;   // 入口前 32 字节
    bool        wired_ = false;        // 签名入口是否已接通（M1 尚未）
};

}  // namespace xh