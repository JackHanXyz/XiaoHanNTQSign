// http_server.h —— 极简 HTTP/1.1 服务（Winsock），零第三方依赖。
//
// 只服务于签名接口：解析请求行/查询串/表单体，交给 Handler，写回响应。
// 每连接一线程；QSign 类签名服务的 QPS 很低，这样足够且实现简单。
#pragma once

#include <functional>
#include <map>
#include <string>

namespace xh {

struct HttpRequest {
    std::string method;   // GET / POST
    std::string path;     // 去掉查询串的路径，如 "/sign"
    std::map<std::string, std::string> query;  // 查询串 + 表单体合并
    std::string body;     // 原始请求体
    std::string client;   // 对端 ip:port
};

struct HttpResponse {
    int         status = 200;
    std::string content_type = "application/json; charset=utf-8";
    std::string body;
};

class HttpServer {
public:
    using Handler = std::function<HttpResponse(const HttpRequest &)>;

    HttpServer(int port, Handler handler);
    ~HttpServer();

    HttpServer(const HttpServer &) = delete;
    HttpServer &operator=(const HttpServer &) = delete;

    // 绑定并开始监听。失败返回 false 并写 err。
    bool start(std::string *err);

    // 阻塞式接受连接，直到 stop()。
    void run();

    void stop();

    int port() const { return port_; }

private:
    void handle_client(uintptr_t sock);

    int      port_;
    Handler  handler_;
    uintptr_t listen_sock_ = ~uintptr_t(0);  // INVALID_SOCKET
    volatile bool running_ = false;
};

}  // namespace xh