// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "dns.h"
#include "tls.h"

namespace crypto {

/*
 * some info:
 * tls packet size limit = 32K
 * http header size limit = 8K
 */
struct http_client {
    using socket_type = win32::tcp_socket; // boost::asio::ip::tcp::socket;
    template <typename T>
    using awaitable = awaitable<T>;

    std::string url_internal;
    //boost::asio::io_context ctx;
    //socket_type s{default_io_context()};
    //tls13_<socket_type, awaitable> tls_layer{&s};
    bool follow_location{true}; // for now
    bool redirected{};
    bool ignore_server_certificate_check{};
    std::string query_type{"GET"s};
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;

    struct http_message {
        static inline constexpr auto line_delim = "\r\n"sv;
        static inline constexpr auto body_delim = "\r\n\r\n"sv;

        std::string header, body;
        string_view code_raw;
        int code{};
        std::map<string_view, string_view> headers;

        http_message() {
            header.reserve(10'000'000);
        }
        explicit operator bool() const {
            return code >= 200 && code < 300;
        }
        awaitable<void> receive(auto &&s, auto &&transport) {
            auto receive = [&]() -> awaitable<std::string> {
                co_return co_await transport.receive_some(s);
            };

            size_t pos{SIZE_MAX};
            for (; pos == -1;) {
                if (header.size() > 100*1024) {
                    throw std::runtime_error{"too long header"s};
                }
                header += co_await receive();
                pos = header.find(body_delim);
            }
            body = header.substr(pos + body_delim.size());
            header.resize(pos);

            // read headers
            auto hdrs = header | std::views::split(line_delim);
            auto cod = *std::begin(hdrs);
            code_raw = std::string_view{cod.begin(), cod.end()};
            if (auto p = code_raw.find(' '); p != -1) {
                auto c = code_raw.substr(p + 1);
                if (c.size() >= 3) {
                    std::from_chars(&c[0], &c[3], code);
                }
            }
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
                while (body.size() < sz) {
                    body += co_await receive();
                }
            } else if (auto it = headers.find("Transfer-Encoding"sv); it != headers.end()) {
                if (it->second != "chunked"sv) {
                    throw std::logic_error{"not impl"s};
                }
                auto part = std::move(body);
                while (1) {
                    for (pos = part.find(line_delim); pos == -1; pos = part.find(line_delim)) {
                        part += co_await receive();
                    }
                    if (part.starts_with("0\r\n"sv)) {
                        break;
                    }
                    size_t sz_read;
                    auto more = std::stoll(part, &sz_read, 16);
                    if (more == 0 && sz_read == 1) {
                        break;
                    }
                    auto b = pos + line_delim.size();
                    while (part.size() - b < more + line_delim.size()) {
                        part += co_await receive();
                    }
                    body += part.substr(b, more);
                    if (part.compare(b + more, line_delim.size(), line_delim) != 0) {
                        throw std::logic_error{"bad data"s};
                    }
                    part.erase(0, b + more + line_delim.size());
                }
            } else {
                // complete message, nothing to do
            }
        }
    };
    http_message m;

    // http_client(auto &&ctx, auto &&url) : url_internal{url}, s{ctx} {}
    // http_client(auto &&url) : http_client{default_io_context(), url} {}
    http_client(const std::string &url) : url_internal{url} {
    }
    void set_browser_agent() {
        headers.emplace_back("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36");
    }
    void run() {
        run(crypto::default_io_context());
    }
    void run(auto &ctx) {
        std::exception_ptr eptr;
        ctx.co_spawn(run_coro(), [&](auto &&e) {
            eptr = e;
        });
        ctx.run();
        if (eptr) {
            std::rethrow_exception(eptr);
        }
    }
    awaitable<void> run_coro() {
        m = co_await open_url(url_internal);
        while (m.headers.contains("Location") && follow_location) {
            redirected = true;
            m = co_await open_url(m.headers["Location"]);
        }
    }
    awaitable<http_message> open_url(std::string_view url) {
        //auto ex = co_await boost::asio::this_coro::executor;

        string host{url_internal};
        uint16_t port = 443;
        bool tls{ true };
        if (host.starts_with("http://")) {
            host = host.substr(7);
            port = 80;
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
            port = std::stoi(host.substr(p + 1));
            host = host.substr(0, p);
        }

        auto &r = get_default_dns();
        auto &&result = co_await r.query_async<dns_packet::a>(default_io_context(), host);
        if (result.empty()) {
            throw std::runtime_error{"cannot resolve"};
        }
        socket_type s{default_io_context()};
        co_await s.async_connect(endpoint{result.begin()->address,port});
        //for (int i = 0; auto &&e : result) {
        //    try {
        //        co_await s.async_connect(e.endpoint(), use_awaitable);
        //    } catch (std::exception &) {
        //        if (i == result.size() - 1) {
        //            throw;
        //        }
        //    }
        //    ++i;
        //}

        //auto remote_ep = s.remote_endpoint();
        //auto remote_ad = remote_ep.address();
        //std::string ss = remote_ad.to_string();
        // std::cout << ss << "\n";

        tls13_<socket_type> tls_layer{
            .s = &s,
                .servername = host,
                //.ignore_server_hostname_check = tls_layer.ignore_server_hostname_check,
                //.ignore_server_certificate_check = tls_layer.ignore_server_certificate_check,
                //.force_suite = tls_layer.force_suite,
                //.force_kex = tls_layer.force_kex,
        };
        co_await tls_layer.init_ssl();

        // http layer
        string req = std::format("{} {} HTTP/1.1\r\n", query_type, path);
        req += "Host: "s + host + "\r\n";
        // req += "Transfer-Encoding: chunked\r\n";
        for (auto &&[k, v] : headers) {
            req += k + ": "s + v + "\r\n";
        }
        req += "\r\n";
        if (!body.empty()) {
            req += body;
        }
        //auto resp = co_await http_query(s, req);
        auto resp = co_await http_query(tls_layer, req);
        co_await s.async_close();
        co_return resp;
    }
    // http layer
    awaitable<http_message> http_query(auto &s, auto &&q) {
        co_await send_message(s, q);
        co_return co_await receive_http_message(s);
    }
    awaitable<http_message> receive_http_message(auto &s) {
        http_message m;
        co_await m.receive(s, *this);
        co_return m;
    }

    awaitable<std::string> receive_some(auto &s) {
        co_return co_await s.async_read_some();
    }
    awaitable<void> send_message(auto &s, bytes_concept data) {
        co_await s.async_send(data);
    }
};

}
