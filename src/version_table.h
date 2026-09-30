// version_table.h —— 版本化的关键函数入口库。
//
// 沿用并扩展 XiaoHanQQNT\host\core\offsets.py 的逆向成果：
// 每条记录都是实测反汇编确认过的「模块 + RVA」，换 QQ 版本后地址会变，
// 所以按版本登记，并保留取证说明。离线签名服务据此在 wrapper.node 里定位入口。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace xh {

struct Entry {
    std::string name;      // 中文功能名
    uint64_t    rva;       // wrapper.node 内偏移（不含映像基址）
    std::string evidence;  // 取证：反汇编依据
};

struct VersionEntry {
    std::string        version;   // 版本目录名，如 "9.9.35-52892"
    std::vector<Entry> entries;
};

// 取指定版本的入口表；未知版本返回 nullptr。
const VersionEntry *find_version(const std::string &version);

// 便捷取用：找不到返回 0。
uint64_t sign_rva(const std::string &version);
uint64_t aes_rva(const std::string &version);

// 列出所有已登记版本名。
std::vector<std::string> known_versions();

// 默认 QQNT 安装根目录（含 versions 子目录）。
std::string default_qq_root();

}  // namespace xh