#pragma once

#include "tls.h"

namespace crypto {

/*
 * some info:
 * tls packet size limit = 32K
 * http header size limit = 8K
 */
struct http_client {
    using socket_type = boost::asio::ip::tcp::socket;
    template <typename T>
    using awaitable = boost::asio::awaitable<T>;

    boost::asio::io_context ctx;
    std::string url_internal;
    socket_type s{ctx};
    tls13_<socket_type, awaitable> tls_layer{&s};
    bool follow_location{true}; // for now
    bool redirected{};
    bool tls{true};

    struct http_message {
        static inline constexpr auto line_delim = "\r\n"sv;
        static inline constexpr auto body_delim = "\r\n\r\n"sv;

        std::string response;
        string_view code;
        std::map<string_view, string_view> headers;
        string_view body;
        std::vector<string_view> chunked_body;

        http_message() {
            response.reserve(10'000'000);
        }
        awaitable<void> receive(auto &&s, auto &&transport) {
            auto append = [&]() -> awaitable<size_t> {
                auto dec = co_await transport.receive_some();
                response.append((char *)dec.data(), dec.size());
                co_return dec.size();
            };

            while (!response.contains(body_delim)) {
                co_await append();
            }

            // read headers
            auto p = response.find(body_delim);
            headers.clear();
            auto header = string_view{response.data(), p};
            auto hdrs = header | std::views::split(line_delim);
            auto cod = *std::begin(hdrs);
            code = std::string_view{cod.begin(), cod.end()};
            for (auto &&h : hdrs | std::views::drop(1)) {
                std::string_view s{h.begin(), h.end()};
                auto p = s.find(':');
                if (p == -1) {
                    throw std::runtime_error{format("bad header: {}", s)};
                }
                auto v = s.substr(p + 1);
                if (v[0] == ' ') {
                    v = v.substr(1);
                }
                headers[s.substr(0, p)] = v;
            }

            // read body
            if (auto it = headers.find("Content-Length"sv); it != headers.end()) {
                auto sz = std::stoull(it->second.data());
                while (response.size() != p + body_delim.size() + sz) {
                    co_await append();
                }
                string_view sv{response.begin(), response.end()};
                auto start = p + body_delim.size();
                body = sv.substr(start, sz);
            } else if (auto it = headers.find("Transfer-Encoding"sv); it != headers.end()) {
                if (it->second != "chunked"sv) {
                    throw std::logic_error{"not impl"};
                }
                while (1) {
                    string_view sv{response.begin(), response.end()};
                    body = sv.substr(p + body_delim.size());
                    if (body.contains(line_delim)) {
                        break;
                    }
                    co_await append();
                }
                while (1) {
                    while (!body.contains(line_delim)) {
                        auto pos = body.data() - response.data();
                        co_await append();
                        string_view sv{response.begin(), response.end()};
                        body = sv.substr(pos);
                    }
                    size_t sz_read;
                    auto needs_more = std::stoll(body.data(), &sz_read, 16);
                    if (needs_more == 0 && sz_read == 1) {
                        break;
                    }
                    body = body.substr(sz_read);
                    if (!body.starts_with(line_delim)) {
                        throw std::runtime_error{"bad http body data"};
                    }
                    body = body.substr(line_delim.size());
                    auto begin = body.data() - response.data();
                    auto end = begin + needs_more;
                    auto jump = end + line_delim.size();
                    needs_more -= body.size();
                    while (needs_more > 0) {
                        needs_more -= co_await append();
                    }
                    chunked_body.push_back(string_view{response.begin() + begin, response.begin() + end});
                    body = string_view{response.begin(), response.end()};
                    body = body.substr(jump);
                }
            } else {
                // complete message
                string_view sv{response.begin(), response.end()};
                body = sv.substr(p + body_delim.size());
            }
        }
    };
    http_message m;

    // http_client(auto &&ctx, auto &&url) : url_internal{url}, s{ctx} {}
    // http_client(auto &&url) : http_client{default_io_context(), url} {}
    http_client(const std::string &url) : url_internal{url} {
    }
    void run() {
        // run(default_io_context());
        // run(ctx);
        //}
        // void run(auto &&ctx) {
        boost::asio::co_spawn(ctx, run_coro(), [](auto eptr) {
            if (eptr) {
                std::rethrow_exception(eptr);
            }
        });
        ctx.run();
        // ctx.restart();
    }
    awaitable<void> run_coro() {
        m = co_await open_url(url_internal);
        while (m.headers.contains("Location") && follow_location) {
            redirected = true;
            m = co_await open_url(m.headers["Location"]);
        }
    }
    awaitable<http_message> open_url(std::string_view url) {
        using boost::asio::use_awaitable;
        auto ex = co_await boost::asio::this_coro::executor;

        string host{url_internal};
        string port = "443";
        if (host.starts_with("http://")) {
            host = host.substr(7);
            port = "80";
            tls = false;
        }
        if (host.starts_with("https://")) {
            host = host.substr(8);
        }
        auto p_slash = host.find('/');
        auto path = p_slash == -1 ? "/" : host.substr(p_slash);
        host = host.substr(0, p_slash);
        if (host.empty()) {
            throw std::runtime_error{"bad host"};
        }
        while (host.back() == '.') {
            host.pop_back();
        }
        if (host.empty()) {
            throw std::runtime_error{"bad host"};
        }
        if (auto p = host.rfind('.', host.rfind('.') - 1); p != -1) {
            // host = host.substr(p + 1);
        }

        if (auto p = host.rfind(':'); p != -1) {
            port = host.substr(p + 1);
            host = host.substr(0, p);
        }

        boost::asio::ip::tcp::resolver r{ex};
        auto result = co_await r.async_resolve(host, port, use_awaitable);
        if (result.empty()) {
            throw std::runtime_error{"cannot resolve"};
        }
        s.close();
        co_await s.async_connect(result.begin()->endpoint(), use_awaitable);
        /*for (int i = 0; auto &&e : result) {
            try {
                co_await s.async_connect(e.endpoint(), use_awaitable);
            } catch (std::exception &) {
                if (i == result.size() - 1) {
                    throw;
                }
            }
            ++i;
        }*/

        auto remote_ep = s.remote_endpoint();
        auto remote_ad = remote_ep.address();
        std::string ss = remote_ad.to_string();
        // std::cout << ss << "\n";

        tls_layer = decltype(tls_layer){
            .s = &s,
            .servername = host,
            .ignore_server_hostname_check = tls_layer.ignore_server_hostname_check,
            .ignore_server_certificate_check = tls_layer.ignore_server_certificate_check,
            .force_suite = tls_layer.force_suite,
            .force_kex = tls_layer.force_kex,
        };

        // http layer
        string req = std::format("GET {} HTTP/1.1\r\n", path);
        req += "Host: "s + host + "\r\n";
        // req += "Transfer-Encoding: chunked\r\n";
        req += "\r\n";
        auto resp = co_await http_query(req);
        co_return resp;
    }
    // http layer
    awaitable<http_message> http_query(auto &&q) {
        co_await send_message(q);
        co_return co_await receive_http_message();
    }
    awaitable<http_message> receive_http_message() {
        http_message m;
        co_await m.receive(s, *this);
        co_return m;
    }

    awaitable<std::string> receive_some() {
        if (!tls) {
            char buf[8192];
            auto n = co_await s.async_read_some(boost::asio::mutable_buffer(buf, sizeof(buf)), boost::asio::use_awaitable);
            co_return std::string{buf, n};
        } else {
            co_return co_await tls_layer.receive_tls_message();
        }
    }
    awaitable<void> send_message(bytes_concept data) {
        if (!tls) {
            co_await s.async_send(boost::asio::const_buffer(data.data(), data.size()), boost::asio::use_awaitable);
            co_return;
        }
        if (!tls_layer.initialized) {
            co_await tls_layer.init_ssl();
        }
        co_await tls_layer.send_message(data);
    }
};


}
