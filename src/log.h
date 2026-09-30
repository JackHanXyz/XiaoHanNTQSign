// log.h —— 极简线程安全日志。输出到 stderr，带时间戳与级别。
#pragma once

#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>

namespace xh {

enum class LogLevel { Debug, Info, Warn, Error };

inline void log(LogLevel lv, const char *fmt, ...)
{
    static std::mutex m;
    std::lock_guard<std::mutex> lk(m);

    const char *tag = lv == LogLevel::Debug ? "DEBUG"
                    : lv == LogLevel::Info  ? "INFO "
                    : lv == LogLevel::Warn  ? "WARN "
                                            : "ERROR";

    std::time_t t = std::time(nullptr);
    std::tm tmv {};
    localtime_s(&tmv, &t);
    char ts[16] = "??:??:??";
    std::strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);

    std::fprintf(stderr, "[%s][%s] ", ts, tag);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
}

}  // namespace xh

#define LOGD(...) ::xh::log(::xh::LogLevel::Debug, __VA_ARGS__)
#define LOGI(...) ::xh::log(::xh::LogLevel::Info, __VA_ARGS__)
#define LOGW(...) ::xh::log(::xh::LogLevel::Warn, __VA_ARGS__)
#define LOGE(...) ::xh::log(::xh::LogLevel::Error, __VA_ARGS__)