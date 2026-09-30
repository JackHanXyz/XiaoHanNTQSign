// http_server.cpp —— 极简 HTTP 服务实现。
#include "http_server.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstring>
#include <sstream>
#include <thread>

#include "log.h"
#include "util.h"

namespace xh {

namespace {

// winsock 需要一次性初始化，用局部静态保证只做一次。
bool ensure_wsa()
{
    static bool inited = [] {
        WSADATA d;
        return WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }();
    return inited;
}

int parse_content_length(const std::string &headers)
{
    // 大小写不敏感地找 Content-Length
    std::istringstream is(headers);
    std::string line;
    while (std::getline(is, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = line.substr(0, colon);
        for (auto &c : key) c = static_cast<char>(::tolower(c));
        if (key == "content-length") {
            try { return std::stoi(line.substr(colon + 1)); } catch (...) { return 0; }
        }
    }
    return 0;
}

void parse_query(const std::string &qs, std::map<std::string, std::string> &out)
{
    for (const auto &kv : split(qs, '&')) {
        if (kv.empty()) continue;
        auto eq = kv.find('=');
        if (eq == std::string::npos) {
            out[url_decode(kv)] = "";
        } else {
            out[url_decode(kv.substr(0, eq))] = url_decode(kv.substr(eq + 1));
        }
    }
}

const char *status_text(int code)
{
    switch (code) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        default:  return "OK";
    }
}

}  // namespace

HttpServer::HttpServer(int port, Handler handler)
    : port_(port), handler_(std::move(handler)) {}

HttpServer::~HttpServer()
{
    stop();
}

bool HttpServer::start(std::string *err)
{
    if (!ensure_wsa()) {
        if (err) *err = "WSAStartup 失败";
        return false;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        if (err) *err = "socket 创建失败";
        return false;
    }

    BOOL yes = TRUE;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char *>(&yes), sizeof(yes));

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(static_cast<u_short>(port_));

    if (bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        if (err) *err = "bind 失败（端口可能被占用）：" + std::to_string(port_);
        closesocket(s);
        return false;
    }
    if (listen(s, 16) == SOCKET_ERROR) {
        if (err) *err = "listen 失败";
        closesocket(s);
        return false;
    }

    listen_sock_ = static_cast<uintptr_t>(s);
    running_ = true;
    LOGI("HTTP 服务已监听 0.0.0.0:%d", port_);
    return true;
}

void HttpServer::run()
{
    while (running_) {
        SOCKET c = accept(static_cast<SOCKET>(listen_sock_), nullptr, nullptr);
        if (c == INVALID_SOCKET) {
            if (!running_) break;
            continue;
        }
        std::thread(&HttpServer::handle_client, this,
                    static_cast<uintptr_t>(c)).detach();
    }
}

void HttpServer::stop()
{
    if (!running_) return;
    running_ = false;
    if (listen_sock_ != ~uintptr_t(0)) {
        closesocket(static_cast<SOCKET>(listen_sock_));
        listen_sock_ = ~uintptr_t(0);
    }
}

void HttpServer::handle_client(uintptr_t sp)
{
    SOCKET s = static_cast<SOCKET>(sp);
    std::string raw;
    char buf[4096];

    // 读到请求头结束（\r\n\r\n）
    size_t hdr_end = std::string::npos;
    while (hdr_end == std::string::npos) {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) { closesocket(s); return; }
        raw.append(buf, n);
        hdr_end = raw.find("\r\n\r\n");
        if (raw.size() > 1 << 20) { closesocket(s); return; }  // 头过大，丢弃
    }

    std::string head = raw.substr(0, hdr_end);
    std::string body = raw.substr(hdr_end + 4);

    // 补齐 Content-Length 声明的体
    int clen = parse_content_length(head);
    while (static_cast<int>(body.size()) < clen) {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        body.append(buf, n);
    }
    if (static_cast<int>(body.size()) > clen) body.resize(clen);

    // 请求行
    HttpRequest req;
    {
        std::istringstream is(head);
        std::string reqline;
        std::getline(is, reqline);
        if (!reqline.empty() && reqline.back() == '\r') reqline.pop_back();
        auto parts = split(reqline, ' ');
        if (parts.size() >= 2) {
            req.method = parts[0];
            std::string target = parts[1];
            auto q = target.find('?');
            if (q == std::string::npos) {
                req.path = target;
            } else {
                req.path = target.substr(0, q);
                parse_query(target.substr(q + 1), req.query);
            }
        }
    }

    sockaddr_in peer {};
    int plen = sizeof(peer);
    getpeername(s, reinterpret_cast<sockaddr *>(&peer), &plen);
    char ip[64] = "";
    inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
    req.client = std::string(ip) + ":" + std::to_string(ntohs(peer.sin_port));

    // 表单体参数合并进 query（application/x-www-form-urlencoded）
    if (req.method == "POST" && !body.empty()) {
        req.body = body;
        parse_query(body, req.query);
    }

    HttpResponse resp = handler_(req);

    std::ostringstream out;
    out << "HTTP/1.1 " << resp.status << " " << status_text(resp.status) << "\r\n"
        << "Content-Type: " << resp.content_type << "\r\n"
        << "Content-Length: " << resp.body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << resp.body;
    std::string out_str = out.str();

    size_t sent = 0;
    while (sent < out_str.size()) {
        int n = send(s, out_str.data() + sent,
                     static_cast<int>(out_str.size() - sent), 0);
        if (n <= 0) break;
        sent += static_cast<size_t>(n);
    }
    closesocket(s);
}

}  // namespace xh