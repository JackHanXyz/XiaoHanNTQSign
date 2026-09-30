// sign_backend.cpp —— 路线 A 后端实现。
#include "sign_backend.h"

#include <cstdio>
#include <cstring>
#include <sstream>

#include "crypto.h"
#include "log.h"
#include "util.h"
#include "version_table.h"

namespace xh {

OfflineBackend::~OfflineBackend()
{
    delete image_;
}

bool OfflineBackend::init(const std::string &qq_root, const std::string &version,
                          std::string *err)
{
    version_ = version;

    // 目录结构：<qq_root>\versions\<version>\resources\app\wrapper.node
    std::string ver_dir = qq_root + "\\versions\\" + version;
    std::string app_dir = ver_dir + "\\resources\\app";
    wrapper_path_ = app_dir + "\\wrapper.node";

    // 让依赖解析能找到同目录的 crypto.dll / libvips-42.dll（app 目录）
    // 以及 QQNT.dll（版本根目录）。
    PeImage::add_search_dir(app_dir);
    PeImage::add_search_dir(ver_dir);

    std::wstring wpath(wrapper_path_.begin(), wrapper_path_.end());
    std::string lerr;
    image_ = PeImage::load(wpath, /*resolve_imports=*/true, &lerr);
    if (!image_) {
        if (err) *err = "映射 wrapper.node 失败：" + lerr + "（路径：" + wrapper_path_ + "）";
        return false;
    }

    // 显式限定命名空间，避免与同名成员函数冲突。
    sign_rva_ = xh::sign_rva(version_);
    aes_rva_  = xh::aes_rva(version_);
    if (sign_rva_) {
        sign_va_ = image_->rva_to_va(sign_rva_);
        sign_head_ = image_->read_bytes(sign_rva_, 32);
    } else {
        LOGW("版本 %s 未登记签名入口 RVA，需先逆向补充 version_table",
             version_.c_str());
    }
    if (aes_rva_) aes_va_ = image_->rva_to_va(aes_rva_);

    // M1 里程碑：映射与入口解析完成；实际调用签名函数留待 M2（需构造入参/上下文）。
    wired_ = false;

    LOGI("wrapper.node 已离线映射：base=%p size=0x%zX relocated=%d",
         image_->base(), image_->image_size(), image_->relocated() ? 1 : 0);
    LOGI("签名入口 wrapper.node+0x%llX → %p；报文加密入口 +0x%llX",
         static_cast<unsigned long long>(sign_rva_), reinterpret_cast<void *>(sign_va_),
         static_cast<unsigned long long>(aes_rva_));
    return true;
}

SignResult OfflineBackend::sign(const SignRequest &req)
{
    SignResult r;

    // 记录请求概要，便于与真机抓包比对。
    std::vector<uint8_t> buf;
    bool buf_ok = from_hex(req.buffer_hex, buf);
    LOGI("签名请求：uin=%s cmd=%s version=%s seq=%d buffer=%s(%zu字节)",
         req.uin.c_str(), req.cmd.c_str(), req.version.c_str(), req.seq,
         buf_ok ? "hex" : "非法hex", buf.size());

    if (!wired_) {
        r.code = -1;
        r.msg = "签名入口尚未接通（M1：wrapper.node 映射与入口解析已完成）";
        LOGW("%s；入口 VA=%p", r.msg.c_str(), reinterpret_cast<void *>(sign_va_));
        return r;
    }
    return r;
}

std::string OfflineBackend::describe() const
{
    std::ostringstream os;
    os << "后端=offline(路线A) 版本=" << version_ << "\n";
    os << "wrapper.node=" << wrapper_path_ << "\n";
    if (image_) {
        os << "映像基址=0x" << std::hex << reinterpret_cast<uintptr_t>(image_->base())
           << " 大小=0x" << image_->image_size()
           << " 重定位=" << (image_->relocated() ? "是" : "否")
           << " 未解析导入=" << std::dec << image_->unresolved_imports().size() << "\n";
    }
    os << "签名入口 RVA=0x" << std::hex << sign_rva_
       << " VA=0x" << sign_va_ << "\n";
    os << "报文加密 RVA=0x" << std::hex << aes_rva_ << std::dec << "\n";
    os << "离线原语=HMAC(sha1/256/512)+AES-256-CBC 已可调用"
       << "（见 --selftest；协议级 sign/token/extra 待接通）\n";
    os << "接通状态=" << (wired_ ? "已接通" : "未接通(M1)");
    return os.str();
}

std::vector<uint64_t> OfflineBackend::find_callers(uint64_t target_rva) const
{
    std::vector<uint64_t> out;
    if (!image_) return out;

    const uint8_t *mem = image_->base();
    const size_t   n = image_->image_size();
    const uintptr_t base = reinterpret_cast<uintptr_t>(mem);
    const uintptr_t target = base + target_rva;

    // 直接调用编码为 E8 <rel32>；目标 = 指令地址 + 5 + rel32。
    for (size_t i = 0; i + 5 <= n; i++) {
        if (mem[i] != 0xE8) continue;
        int32_t rel;
        std::memcpy(&rel, mem + i + 1, sizeof(rel));
        if (base + i + 5 + static_cast<intptr_t>(rel) == target)
            out.push_back(static_cast<uint64_t>(i));
    }
    return out;
}

namespace {

// AMD64 函数序言判读：涵盖 push 序言与 /GS 栈保护 cookie 两类特征。
bool has_stack_cookie(const std::vector<uint8_t> &b)
{
    for (size_t i = 0; i + 2 < b.size(); i++) {
        if (b[i] == 0x48 && b[i + 1] == 0x31 && b[i + 2] == 0xE0) return true;  // xor rax, rsp
    }
    return false;
}

bool is_typical_prologue(const std::vector<uint8_t> &b)
{
    if (b.empty()) return false;
    size_t i = 0;
    if ((b[i] & 0xF0) == 0x40) i++;          // 跳过 REX 前缀
    if (i >= b.size()) return false;
    uint8_t op = b[i];
    if (op == 0x55) return true;             // push rbp
    if (op >= 0x50 && op <= 0x57) return true;  // push r64
    if (op == 0x48 && i + 1 < b.size()) {    // REX.W sub/mov/lea
        uint8_t op2 = b[i + 1];
        if (op2 == 0x83 || op2 == 0x81 || op2 == 0x89 || op2 == 0x8B) return true;
    }
    return false;
}

}  // namespace

bool OfflineBackend::hmac_real(int mode, const std::vector<uint8_t> &key,
                               const std::vector<uint8_t> &in1,
                               const std::vector<uint8_t> &in2,
                               std::vector<uint8_t> &out, int *ret) const
{
    if (!sign_va_) return false;

    // 反汇编还原的 ABI（Windows x64 / MS ABI，MinGW 在 x64 上即为此约定）。
    typedef int (*fn_hmac_sign)(void *, int, const void *, int,
                                const void *, int, const void *, int, void *);
    auto fn = reinterpret_cast<fn_hmac_sign>(sign_va_);

    // 该函数首先检查 arg5（in1 指针）非空，为空直接返回错误；in2 允许为空。
    static const uint8_t zero = 0;
    const void *p1 = in1.empty() ? static_cast<const void *>(&zero) : in1.data();
    const void *p2 = in2.empty() ? nullptr : in2.data();

    unsigned char buf[64] = {0};
    int rc = fn(nullptr, mode,
                key.empty() ? nullptr : key.data(), static_cast<int>(key.size()),
                p1, static_cast<int>(in1.size()),
                p2, static_cast<int>(in2.size()),
                buf);
    if (ret) *ret = rc;
    out.assign(buf, buf + sizeof(buf));
    return true;
}

bool OfflineBackend::aes_real(int enc, const std::vector<uint8_t> &key,
                              const std::vector<uint8_t> &iv,
                              const std::vector<uint8_t> &in,
                              std::vector<uint8_t> &out, int *ret) const
{
    if (!aes_va_) return false;

    // 反汇编还原的 ABI：arg4(r9) 未被使用，与 HMAC 一样存在一个占位参数。
    typedef int (*fn_aes)(void *, int, const void *, void *,
                          const void *, const void *, int, void *);
    auto fn = reinterpret_cast<fn_aes>(aes_va_);

    static const uint8_t zero = 0;
    const void *piv = iv.empty() ? static_cast<const void *>(&zero) : iv.data();
    const void *pin = in.empty() ? static_cast<const void *>(&zero) : in.data();

    out.assign(in.size() + 16, 0);
    int rc = fn(nullptr, enc, key.data(), nullptr,
                piv, pin, static_cast<int>(in.size()), out.data());
    if (ret) *ret = rc;
    // 无填充时输出长度等于输入长度。
    out.resize(in.size());
    return true;
}

std::string OfflineBackend::selftest() const
{
    std::ostringstream os;
    if (!image_) {
        os << "未映射映像";
        return os.str();
    }
    os << "基底=0x" << std::hex << reinterpret_cast<uintptr_t>(image_->base())
       << " 首选基址=0x" << image_->preferred_base()
       << " 重定位=" << (image_->relocated() ? "是" : "否") << "\n";

    // ---- AES-256-CBC 原语验证 ----
    // 这里刻意放在 selftest 最前面：crypto.dll 会池化复用 EVP_CIPHER_CTX，
    // 实测“本进程内第一次 AES 调用”结果稳定正确，之后与其它 crypto.dll 调用
    // 混跑时可能取到陈旧 IV（详见 README 的已知问题）。
    if (aes_va_) {
        os << "\n真机 AES-256-CBC 对比（wrapper.node+0x" << std::hex << aes_rva_
           << " vs 系统 CNG）：\n" << std::dec;

        std::vector<uint8_t> key, iv, pt;
        from_hex("603deb1015ca71be2b73aef0857d7781"
                 "1f352c073b6108d72d9810a30914dff4", key);
        from_hex("000102030405060708090a0b0c0d0e0f", iv);
        from_hex("6bc1bee22e409f96e93d7e117393172a"
                 "ae2d8a571e03ac9c9eb76fac45af8e51", pt);

        // 参考密文用 NIST 向量硬编码，避免在 wrapper 调用前先跑 bcrypt
        //（实测：先跑 CNG 会使 crypto.dll 池化的 EVP ctx 带上陈旧 IV）。
        std::vector<uint8_t> ref_ct;
        from_hex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                 "9cfc4e967edb808d679f777bc6702c7d", ref_ct);

        int rc = 0;
        std::vector<uint8_t> dec;
        aes_real(0, key, iv, ref_ct, dec, &rc);
        os << "  解密 真实返回=" << rc << " 还原=" << to_hex(dec)
           << "  → " << (dec == pt ? "正确" : "错误") << "\n";

        std::vector<uint8_t> real_ct;
        aes_real(1, key, iv, pt, real_ct, &rc);
        os << "  加密 真实返回=" << rc << " 真机=" << to_hex(real_ct) << "\n";
        os << "            参考=" << to_hex(ref_ct)
           << "  → " << (real_ct == ref_ct ? "一致" : "不一致") << "\n";
    }

    if (sign_rva_ && !sign_head_.empty()) {
        os << "签名入口 0x" << std::hex << sign_rva_ << " 前 " << std::dec
           << sign_head_.size() << " 字节：" << to_hex(sign_head_) << "\n";
        // AMD64 常见序言：48 89 5C 24 (mov [rsp+x],rbx) / 48 83 EC (sub rsp) 等。
        os << "序言判读：";
        bool prolog = is_typical_prologue(sign_head_);
        bool cookie = has_stack_cookie(sign_head_);
        if (prolog || cookie) {
            os << "标准函数序言";
            if (cookie) os << "（含 /GS 栈保护 cookie：xor rax,rsp）";
            os << "，与该函数入口相符";
        } else {
            os << "非典型序言，需反汇编确认（可能落在跳转桩/数据）";
        }
        os << "\n";
    } else {
        os << "无签名入口（版本未登记或 RVA 越界）\n";
    }

    // 反查两个函数内部关键 call 指向的导入符号，消除对算法名的猜测。
    {
        struct Slot { uint64_t rva; const char *what; };
        static const Slot slots[] = {
            {0x4a4d2f0, "AES: CTX_new"},     {0x4a4d4d0, "AES: cipher"},
            {0x4a4d330, "AES: CipherInit"},  {0x4a4d300, "AES: set_padding"},
            {0x4a4d338, "AES: CipherUpdate"},{0x4a4d328, "AES: CipherFinal"},
            {0x4a4d2e0, "AES: CTX_free"},
            {0x4a4d520, "HMAC: CTX_new"},    {0x4a4d4f0, "HMAC: mode0"},
            {0x4a4d4f8, "HMAC: mode1"},      {0x4a4d500, "HMAC: mode2"},
            {0x4a4d530, "HMAC: Init_ex"},    {0x4a4d538, "HMAC: Update"},
            {0x4a4d528, "HMAC: Final"},      {0x4a4d518, "HMAC: CTX_free"},
        };
        os << "\n关键调用的导入符号：\n";
        for (const auto &s : slots) {
            uintptr_t va = reinterpret_cast<uintptr_t>(image_->base()) + s.rva;
            os << "  " << s.what << " = " << image_->symbol_for_iat(va) << "\n";
        }
    }

    // ---- HMAC 原语验证（真机 vs 系统 CNG）----
    if (sign_va_) {
        os << "\n真机 HMAC 原语对比（wrapper.node+0x" << std::hex << sign_rva_
           << " vs 系统 CNG）：\n" << std::dec;

        std::vector<uint8_t> key(20, 0x0b);
        const char *msg = "Hi There";
        std::vector<uint8_t> in1(msg, msg + std::strlen(msg));

        struct Case { int mode; HashAlg alg; const char *name; size_t dlen; };
        const Case cases[] = {
            {0, HashAlg::Sha1,   "SHA1",   20},
            {1, HashAlg::Sha256, "SHA256", 32},
            {2, HashAlg::Sha512, "SHA512", 64},
        };
        for (const auto &c : cases) {
            std::vector<uint8_t> real;
            int rc = 0;
            bool called = hmac_real(c.mode, key, in1, {}, real, &rc);
            real.resize(c.dlen);

            std::vector<uint8_t> ref;
            bool refok = hmac(c.alg, key.data(), key.size(),
                              in1.data(), in1.size(), ref);
            bool match = called && refok && real == ref;

            os << "  mode=" << c.mode << "(" << c.name << ") 真实返回=" << rc
               << "  真机=" << to_hex(real) << "\n";
            os << "            参考=" << (refok ? to_hex(ref) : std::string("n/a"))
               << "  → " << (match ? "一致" : "不一致") << "\n";
        }
    }

    if (!image_->unresolved_imports().empty()) {
        os << "未解析导入（前 10 条）：\n";
        size_t n = image_->unresolved_imports().size() < 10
                       ? image_->unresolved_imports().size() : 10;
        for (size_t i = 0; i < n; i++)
            os << "  " << image_->unresolved_imports()[i] << "\n";
    }
    return os.str();
}

}  // namespace xh