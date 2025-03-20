#pragma once

#include "dns.h"
#include "sha2.h"

namespace crypto {

struct input_email {
    struct header {
        std::string_view name;
        std::string_view value;

        header(std::string_view v) {
            name = v.substr(v.find(':'));
        }
    };
    std::vector<std::string_view> headers;
    std::string_view body;

    input_email(std::string_view text) {
        constexpr auto delim = "\r\n"sv;
        constexpr auto body_delim = "\r\n\r\n"sv;
        auto p = text.find(body_delim);
        auto h = text.substr(0, p);
        body = text.substr(h.size() + body_delim.size());
        for (auto &&v : std::views::split(h, delim)) {
            if (!headers.empty() && !v.empty() && (v[0] == ' ' || v[0] == '\t')) {
                auto &prev = headers.back();
                prev = std::string_view{prev.data(), prev.size() + delim.size() + v.size()};
            } else {
                headers.emplace_back(v);
            }
        }
    }
    std::optional<std::string_view> find(std::string_view header) const {
        auto it = std::ranges::find_if(headers, [&](auto &&v){return v.starts_with(header);});
        return it == headers.end() ? std::optional<std::string_view>{} : std::optional<std::string_view>{*it};
    }
    auto dkim() const {
        struct dkim {
            std::string_view header;

            void hash() const {
            }
        };
        if (auto sig = find("DKIM-Signature"sv)) {
            return std::optional<dkim>{*sig};
        }
        return std::optional<dkim>{};
    }
    bool verify_dkim() {
    }
};

struct email {
    using socket_type = boost::asio::ip::tcp::socket;
    template <typename T>
    using awaitable = boost::asio::awaitable<T>;

    std::string from;
    std::string to;
    std::vector<std::string> cc;
    std::vector<std::string> bcc;
    std::string title;
    std::string text;

    boost::asio::io_context ctx;
    socket_type s{ctx};

    void send() {
        auto p = to.rfind('@');
        if (p == -1) {
            throw std::runtime_error{"no server for recepient"};
        }
        auto host = to.substr(p + 1);

        boost::asio::co_spawn(ctx, run_coro(host), [](auto eptr) {
            if (eptr) {
                std::rethrow_exception(eptr);
            }
        });
        ctx.run();
    }
    awaitable<void> run_coro(auto host) {
        using boost::asio::use_awaitable;
        auto ex = co_await boost::asio::this_coro::executor;

        //dns_resolver serv{"8.8.8.8", "8.8.4.4", "1.1.1.1"};
        //auto res = serv.resolve(host);

        uint16_t relay_port = 25;
        uint16_t legacy_port = 465; // ssl
        uint16_t secure_port = 587; // tls
        uint16_t secondary_port = 588;
        uint16_t alternative_port = 2525;
        auto port = std::to_string(relay_port);

        boost::asio::ip::tcp::resolver r{ex};
        auto result = co_await r.async_resolve("gmail-smtp-in.l.google.com"sv, port, use_awaitable);
        //auto result = co_await r.async_resolve("smtp-relay.gmail.com"sv, port, use_awaitable);
        //auto result = co_await r.async_resolve("smtp.gmail.com"sv, port, use_awaitable);
        if (result.empty()) {
            throw std::runtime_error{"cannot resolve"};
        }
        co_await s.async_connect(result.begin()->endpoint(), use_awaitable);
        //ip::tcp::endpoint e{ip::make_address_v4("108.177.14.27"s), secure_port};
        //co_await s.async_connect(e, use_awaitable);
        auto msg = co_await wait_for_message();
        msg = co_await command("EHLO home\r\n"sv);
        //msg = co_await command("STARTTLS\r\n"s);
        msg = co_await command(std::format("MAIL FROM:<{}>\r\n", from));
        msg = co_await command(std::format("RCPT TO:<{}>\r\n", to));
        msg = co_await command("DATA\r\n"sv);

        auto t = time(0);
        auto msg_id = std::format("{}@{}", t, from.substr(from.rfind('@')+1));

        // supports rsa-sha256
        // supports ed25519-sha256
        auto priv = R"(
   -----BEGIN RSA PRIVATE KEY-----
   MIICXwIBAAKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFC
   jxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gb
   to/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
   AoGBALmn+XwWk7akvkUlqb+dOxyLB9i5VBVfje89Teolwc9YJT36BGN/l4e0l6QX
   /1//6DWUTB3KI6wFcm7TWJcxbS0tcKZX7FsJvUz1SbQnkS54DJck1EZO/BLa5ckJ
   gAYIaqlA9C0ZwM6i58lLlPadX/rtHb7pWzeNcZHjKrjM461ZAkEA+itss2nRlmyO
   n1/5yDyCluST4dQfO8kAB3toSEVc7DeFeDhnC1mZdjASZNvdHS4gbLIA1hUGEF9m
   3hKsGUMMPwJBAPW5v/U+AWTADFCS22t72NUurgzeAbzb1HWMqO4y4+9Hpjk5wvL/
   eVYizyuce3/fGke7aRYw/ADKygMJdW8H/OcCQQDz5OQb4j2QDpPZc0Nc4QlbvMsj
   7p7otWRO5xRa6SzXqqV3+F0VpqvDmshEBkoCydaYwc2o6WQ5EBmExeV8124XAkEA
   qZzGsIxVP+sEVRWZmW6KNFSdVUpk3qzK0Tz/WjQMe5z0UunY9Ax9/4PVhp/j61bf
   eAYXunajbBSOLlx4D+TunwJBANkPI5S9iylsbLs6NkaMHV6k5ioHBBmgCak95JGX
   GMot/L2x0IYyMLAz6oLWh2hm7zwtb0CgOrPo1ke44hFYnfc=
   -----END RSA PRIVATE KEY-----
)"sv;
        std::string bh, b;
        auto dkim = std::format("v=1; a=rsa-sha256; s=pc; d=egorpugin.ru; c=simple/simple;"
     "h=Received : From : To : Subject : Date : Message-ID;"
     "bh={}; b={};", bh, b);

        msg = co_await command(std::format(
            "DKIM-Signature: {}\r\n"
            "From: <{}>\r\n"
            "To: <{}>\r\n"
            "Message-ID: <{}>\r\n\r\n"
            "{}\r\n.\r\n"
            , dkim, from, to, msg_id, text));
        msg = co_await command("QUIT\r\n"sv);

        int a = 5;
        a++;
    }
    awaitable<std::string> wait_for_message() {
        using boost::asio::use_awaitable;

        char buf[8192];
        auto n = co_await s.async_read_some(boost::asio::mutable_buffer(buf, sizeof(buf)), boost::asio::use_awaitable);
        co_return std::string{buf, n};
    }
    awaitable<std::string> command(auto &&cmd) {
        co_await s.async_send(boost::asio::const_buffer(cmd.data(), cmd.size()), boost::asio::use_awaitable);
        co_return co_await wait_for_message();
    }
};

struct smtp {
};

}
