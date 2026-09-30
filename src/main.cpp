// main.cpp —— XiaoHanNTQSign 入口。
//
// 用法：
//   xhntqsign --selftest                 映射 wrapper.node + 密码学自测
//   xhntqsign --serve [--port 9377]       启动 QSign 兼容签名服务
//   xhntqsign --sign --buffer <hex> ...   一次性离线签名（打印结果）
//   xhntqsign --versions                 列出已登记版本
//   通用参数：--root <QQNT目录>  --version <版本号>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <windows.h>

#include "crypto.h"
#include "http_server.h"
#include "log.h"
#include "sign_backend.h"
#include "util.h"
#include "version_table.h"

namespace {

struct Options {
    std::string mode = "help";
    std::string root = xh::default_qq_root();
    std::string version;
    std::string uin, qua, cmd, buffer_hex;
    std::string aes_key, aes_iv, aes_in;   // AES 原语调试用
    std::string callers_rva;               // --callers 目标 RVA
    int port = 9377;
    int seq = 1;
};

// 从版本目录里挑一个：未指定则取已安装的最新版本。
std::string pick_version(const std::string &root, const std::string &want)
{
    (void)root;  // 目前只用内存中的版本表；后续可改为扫描磁盘已安装版本
    if (!want.empty()) return want;
    auto known = xh::known_versions();
    if (!known.empty()) return known.back();  // 表内最新
    return "";
}

std::string json_escape(const std::string &s)
{
    std::string o;
    for (char c : s) {
        if (c == '"' || c == '\\') { o.push_back('\\'); o.push_back(c); }
        else if (c == '\n') o += "\\n";
        else o.push_back(c);
    }
    return o;
}

std::string build_json(const xh::SignResult &r)
{
    char head[64];
    std::snprintf(head, sizeof(head), "{\"code\":%d,\"msg\":\"", r.code);
    std::string out = head;
    out += json_escape(r.msg);
    out += "\",\"data\":{";
    if (r.code == 0) {
        out += "\"sign\":\"" + r.sign_hex + "\",";
        out += "\"token\":\"" + r.token_hex + "\",";
        out += "\"extra\":\"" + r.extra_hex + "\"";
    }
    out += "}}";
    return out;
}

// 密码学自测：用标准测试向量验证 bcrypt 封装是否正确。
int crypto_selftest()
{
    int fails = 0;

    // RFC 4231 Test Case 1：HMAC-SHA256
    {
        std::vector<uint8_t> key(20, 0x0b);
        const char *msg = "Hi There";
        std::vector<uint8_t> mac;
        bool ok = xh::hmac(xh::HashAlg::Sha256, key.data(), key.size(),
                           reinterpret_cast<const uint8_t *>(msg), std::strlen(msg), mac);
        std::string want =
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        std::string got = xh::to_hex(mac);
        bool pass = ok && got == want;
        std::printf("[HMAC-SHA256] %s\n  期望=%s\n  实际=%s\n",
                    pass ? "通过" : "失败", want.c_str(), got.c_str());
        if (!pass) fails++;
    }

    // NIST SP800-38A F.2.5：AES-256-CBC 单块（无填充）
    {
        std::vector<uint8_t> key, iv, pt;
        xh::from_hex("603deb1015ca71be2b73aef0857d7781"
                     "1f352c073b6108d72d9810a30914dff4", key);
        xh::from_hex("000102030405060708090a0b0c0d0e0f", iv);
        xh::from_hex("6bc1bee22e409f96e93d7e117393172a", pt);
        std::vector<uint8_t> ct;
        bool ok = xh::aes256_cbc_encrypt(key.data(), key.size(), iv.data(),
                                         pt.data(), pt.size(), false, ct);
        std::string want = "f58c4c04d6e5f1ba779eabfb5f7bfbd6";
        std::string got = xh::to_hex(ct);
        bool pass = ok && got == want;
        std::printf("[AES-256-CBC] %s\n  期望=%s\n  实际=%s\n",
                    pass ? "通过" : "失败", want.c_str(), got.c_str());
        if (!pass) fails++;
    }
    return fails;
}

void print_help()
{
    std::printf(
        "XiaoHanNTQSign —— 离线 PCNT 签名服务（路线A）\n\n"
        "用法：\n"
        "  xhntqsign --selftest                 映射 wrapper.node + 密码学自测\n"
        "  xhntqsign --serve [--port 9377]       启动 QSign 兼容签名服务\n"
        "  xhntqsign --sign --buffer <hex>       一次性离线签名\n"
        "  xhntqsign --aesenc/--aesdec           离线调用真机 AES-256-CBC\n"
        "        --aes-key <hex32> --aes-iv <hex16> --aes-in <hex>\n"
        "  xhntqsign --evpdiag                  观测 crypto.dll 的 EVP ctx 池化\n"
        "  xhntqsign --versions                 列出已登记版本\n"
        "通用：--root <QQNT目录>  --version <版本号>  --uin/--qua/--cmd/--seq\n");
}

Options parse_args(int argc, char **argv)
{
    Options o;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&](std::string &dst) { if (i + 1 < argc) dst = argv[++i]; };
        if (a == "--selftest") o.mode = "selftest";
        else if (a == "--serve") o.mode = "serve";
        else if (a == "--sign") o.mode = "sign";
        else if (a == "--versions") o.mode = "versions";
        else if (a == "--aesenc") o.mode = "aesenc";
        else if (a == "--aesdec") o.mode = "aesdec";
        else if (a == "--aes-key") next(o.aes_key);
        else if (a == "--aes-iv") next(o.aes_iv);
        else if (a == "--aes-in") next(o.aes_in);
        else if (a == "--evpdiag") o.mode = "evpdiag";
        else if (a == "--callers") { o.mode = "callers"; next(o.callers_rva); }
        else if (a == "--help" || a == "-h") o.mode = "help";
        else if (a == "--root") next(o.root);
        else if (a == "--version") next(o.version);
        else if (a == "--port") { std::string s; next(s); o.port = std::atoi(s.c_str()); }
        else if (a == "--uin") next(o.uin);
        else if (a == "--qua") next(o.qua);
        else if (a == "--cmd") next(o.cmd);
        else if (a == "--seq") { std::string s; next(s); o.seq = std::atoi(s.c_str()); }
        else if (a == "--buffer") next(o.buffer_hex);
        else LOGW("忽略未知参数：%s", a.c_str());
    }
    return o;
}

}  // namespace

int main(int argc, char **argv)
{
    Options opt = parse_args(argc, argv);

    if (opt.mode == "help") { print_help(); return 0; }

    if (opt.mode == "versions") {
        for (const auto &v : xh::known_versions()) std::printf("%s\n", v.c_str());
        std::printf("默认 QQNT 目录：%s\n", xh::default_qq_root().c_str());
        return 0;
    }

    std::string version = pick_version(opt.root, opt.version);
    if (version.empty()) {
        LOGE("未确定 QQ 版本，请用 --version 指定");
        return 2;
    }

    xh::OfflineBackend backend;
    std::string err;
    if (!backend.init(opt.root, version, &err)) {
        LOGE("后端初始化失败：%s", err.c_str());
        // 自测模式下即使失败也继续跑密码学自测，便于定位是映射问题还是工具链问题。
        if (opt.mode != "selftest") return 3;
    } else {
        LOGI("后端就绪：\n%s", backend.describe().c_str());
    }

    if (opt.mode == "selftest") {
        std::printf("\n===== 映像自测 =====\n%s\n", backend.selftest().c_str());
        std::printf("\n===== 密码学自测 =====\n");
        int fails = crypto_selftest();
        std::printf("\n%s\n", fails ? "存在失败项，请检查工具链/依赖" : "全部通过");
        return fails ? 1 : 0;
    }

    if (opt.mode == "aesenc" || opt.mode == "aesdec") {
        std::vector<uint8_t> key, iv, in;
        if (!xh::from_hex(opt.aes_key, key) || !xh::from_hex(opt.aes_iv, iv) ||
            !xh::from_hex(opt.aes_in, in)) {
            LOGE("hex 参数非法");
            return 2;
        }
        std::vector<uint8_t> out;
        int rc = 0;
        bool ok = backend.aes_real(opt.mode == "aesenc" ? 1 : 0, key, iv, in, out, &rc);
        std::printf("ok=%d rc=%d out=%s\n", ok ? 1 : 0, rc, xh::to_hex(out).c_str());
        return ok ? 0 : 1;
    }

    // 扫描调用点：谁直接 call 了目标函数（用于追调用链）。
    if (opt.mode == "callers") {
        uint64_t rva = std::strtoull(opt.callers_rva.c_str(), nullptr, 16);
        auto cs = backend.find_callers(rva);
        std::printf("目标 RVA 0x%llX 的直接调用点：%zu 个\n",
                    static_cast<unsigned long long>(rva), cs.size());
        for (uint64_t c : cs) std::printf("  caller 0x%llX\n",
                                          static_cast<unsigned long long>(c));
        return 0;
    }

    // 直接驱动 crypto.dll 的 EVP（绕过 wrapper.node），用于观测其 EVP_CIPHER_CTX
    // 是否被池化复用。实测每次都会返回同一指针，据此可解释 AES 的状态敏感性。
    if (opt.mode == "evpdiag") {
        HMODULE c = GetModuleHandleW(L"crypto.dll");
        if (!c) { LOGE("crypto.dll 未加载"); return 3; }

        typedef void *(*f_new)(void);
        typedef void *(*f_cbc)(void);
        typedef int (*f_init)(void *, const void *, void *, const unsigned char *,
                              const unsigned char *, int);
        typedef int (*f_pad)(void *, int);
        typedef int (*f_upd)(void *, unsigned char *, int *, const unsigned char *, int);
        typedef int (*f_fin)(void *, unsigned char *, int *);
        typedef void (*f_free)(void *);

        auto p_new  = (f_new)GetProcAddress(c, "EVP_CIPHER_CTX_new");
        auto p_cbc  = (f_cbc)GetProcAddress(c, "EVP_aes_256_cbc");
        auto p_init = (f_init)GetProcAddress(c, "EVP_CipherInit_ex");
        auto p_pad  = (f_pad)GetProcAddress(c, "EVP_CIPHER_CTX_set_padding");
        auto p_upd  = (f_upd)GetProcAddress(c, "EVP_CipherUpdate");
        auto p_fin  = (f_fin)GetProcAddress(c, "EVP_CipherFinal_ex");
        auto p_free = (f_free)GetProcAddress(c, "EVP_CIPHER_CTX_free");
        if (!p_new || !p_cbc || !p_init || !p_pad || !p_upd || !p_fin || !p_free) {
            LOGE("crypto.dll 缺少所需 EVP 导出");
            return 3;
        }

        std::vector<uint8_t> kv, ivv, pv;
        xh::from_hex("603deb1015ca71be2b73aef0857d7781"
                     "1f352c073b6108d72d9810a30914dff4", kv);
        xh::from_hex("000102030405060708090a0b0c0d0e0f", ivv);
        xh::from_hex("6bc1bee22e409f96e93d7e117393172a", pv);

        std::printf("期望密文=f58c4c04d6e5f1ba779eabfb5f7bfbd6\n");

        for (int round = 0; round < 3; round++) {
            void *ctx = p_new();
            p_init(ctx, p_cbc(), nullptr, nullptr, nullptr, 1);
            p_pad(ctx, 0);
            p_init(ctx, nullptr, nullptr, kv.data(), ivv.data(), 1);
            unsigned char out[64] = {0};
            int l1 = 0, l2 = 0;
            p_upd(ctx, out, &l1, pv.data(), static_cast<int>(pv.size()));
            p_fin(ctx, out + l1, &l2);
            std::printf("round %d ctx=%p out=%s\n", round, ctx,
                        xh::to_hex(out, l1 + l2).c_str());
            p_free(ctx);
        }
        return 0;
    }

    if (opt.mode == "sign") {
        xh::SignRequest req;
        req.uin = opt.uin;
        req.qua = opt.qua;
        req.cmd = opt.cmd;
        req.version = version;
        req.seq = opt.seq;
        req.buffer_hex = opt.buffer_hex;
        xh::SignResult r = backend.sign(req);
        std::printf("%s\n", build_json(r).c_str());
        return r.code == 0 ? 0 : 1;
    }

    if (opt.mode == "serve") {
        xh::HttpServer server(opt.port, [&backend](const xh::HttpRequest &req) {
            xh::HttpResponse resp;
            if (req.path == "/sign") {
                xh::SignRequest sr;
                auto get = [&](const char *k) -> std::string {
                    auto it = req.query.find(k);
                    return it == req.query.end() ? "" : it->second;
                };
                sr.uin = get("uin");
                sr.qua = get("qua");
                sr.cmd = get("cmd");
                sr.version = get("version");
                sr.buffer_hex = get("buffer");
                try { sr.seq = std::stoi(get("seq")); } catch (...) { sr.seq = 1; }
                resp.body = build_json(backend.sign(sr));
            } else if (req.path == "/" || req.path == "/health") {
                resp.body = "{\"code\":0,\"msg\":\"XiaoHanNTQSign online\"}";
            } else {
                resp.status = 404;
                resp.body = "{\"code\":404,\"msg\":\"not found\"}";
            }
            return resp;
        });

        std::string serr;
        if (!server.start(&serr)) {
            LOGE("启动失败：%s", serr.c_str());
            return 4;
        }
        LOGI("就绪，等待请求。示例：curl \"http://127.0.0.1:%d/sign?uin=10000&cmd=wtlogin.login\"",
             opt.port);
        server.run();
        return 0;
    }

    print_help();
    return 0;
}