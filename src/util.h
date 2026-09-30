// util.h —— 通用小工具：十六进制、URL 解码、字符串切分。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace xh {

// ---------- 十六进制 ----------
inline std::string to_hex(const uint8_t *data, size_t len)
{
    static const char *H = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        s.push_back(H[(data[i] >> 4) & 0xF]);
        s.push_back(H[data[i] & 0xF]);
    }
    return s;
}

inline std::string to_hex(const std::vector<uint8_t> &v)
{
    return to_hex(v.data(), v.size());
}

inline int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// 返回是否成功；奇数长度或非法字符返回 false。
inline bool from_hex(const std::string &s, std::vector<uint8_t> &out)
{
    out.clear();
    if (s.size() % 2 != 0) return false;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = hex_val(s[i]);
        int lo = hex_val(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

// ---------- URL 编码解码 ----------
inline std::string url_decode(const std::string &s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i + 2 < s.size()) {
            int hi = hex_val(s[i + 1]);
            int lo = hex_val(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        if (s[i] == '+') {
            out.push_back(' ');
            continue;
        }
        out.push_back(s[i]);
    }
    return out;
}

// ---------- 字符串切分 ----------
inline std::vector<std::string> split(const std::string &s, char delim)
{
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == delim) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

}  // namespace xh