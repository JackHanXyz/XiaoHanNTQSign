// pe_mapper.h —— PE 手动映射器。
//
// 路线 A 的核心基座：把 wrapper.node 这类 .node（本质是 DLL）在**不运行其
// 初始化例程**的前提下映射进本进程，从而离线调用其中的真签名函数。
//
// 直接 LoadLibrary 会触发 node addon 的注册逻辑（依赖 napi 环境而崩溃），
// 因此这里手工完成：分配映像 → 拷贝节区 → 应用重定位 → 解析导入表。
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace xh {

class PeImage {
public:
    ~PeImage();

    PeImage(const PeImage &) = delete;
    PeImage &operator=(const PeImage &) = delete;

    // 映射文件。失败返回 nullptr 并写入 err。
    // resolve_imports 为 true 时解析导入表（需要能加载依赖 DLL）。
    static PeImage *load(const std::wstring &path, bool resolve_imports, std::string *err);

    uint8_t *base() const { return base_; }
    size_t   image_size() const { return image_size_; }
    uint64_t preferred_base() const { return preferred_base_; }
    bool     relocated() const { return actual_base_ != preferred_base_; }

    // RVA → 本进程内绝对地址；越界返回 nullptr。
    uintptr_t rva_to_va(uint64_t rva) const;
    bool      valid_rva(uint64_t rva) const;

    // 从映像读取若干字节（用于反汇编核对入口前几字节）。
    std::vector<uint8_t> read_bytes(uint64_t rva, size_t n) const;

    // 导入解析失败的依赖，便于排查。
    const std::vector<std::string> &unresolved_imports() const { return unresolved_; }

    // 查询某个 IAT 槽（本进程绝对地址）对应的 "dll!函数名"。
    // 用于反查某条 call [rip+…] 究竟调的是哪个导入函数。
    std::string symbol_for_iat(uintptr_t va) const;

    // 依赖 DLL 的搜索目录（默认追加到进程搜索路径，用于找到 crypto.dll 等）。
    static void add_search_dir(const std::string &dir);

private:
    PeImage() = default;

    bool map_sections(const std::vector<uint8_t> &file, std::string *err);
    bool apply_relocations(const std::vector<uint8_t> &file, std::string *err);
    bool resolve_imports(const std::vector<uint8_t> &file);

    uint8_t *base_ = nullptr;
    size_t   image_size_ = 0;
    uint64_t preferred_base_ = 0;
    uint64_t actual_base_ = 0;
    std::vector<std::string> unresolved_;
    std::unordered_map<uintptr_t, std::string> iat_symbols_;
};

}  // namespace xh