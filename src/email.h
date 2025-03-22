// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "base64.h"
#include "dns.h"
#include "rsa.h"
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
    static auto extract_fields(auto &&data, auto &&delim) {
        std::vector<std::string_view> fields;
        for (auto &&v : std::views::split(data, delim)) {
            auto &f = fields.emplace_back(v);
            while (!f.empty() && (f[0] == ' ' || f[0] == '\t' || f[0] == '\r' || f[0] == '\n')) {
                f.remove_prefix(1);
            }
        }
        return fields;
    }
    static std::string_view get_field(auto &&fields, std::string_view f) {
        for (auto &&s : fields) {
            if (s.starts_with(f)) {
                return s.substr(f.size());
            }
        }
        return {};
    }
    auto dkim() const {
        struct dkim {
            std::string_view header;
            std::string_view body;
            std::vector<std::string_view> fields;

            dkim(std::string_view d) : header{d} {
                body = header.substr(header.find(':') + 1);
                fields = extract_fields(body, ";"sv);
            }
            std::string_view get_field(std::string_view f) {
                return input_email::get_field(fields, f);
            }
        };
        if (auto sig = find("DKIM-Signature"sv)) {
            return std::optional<dkim>{*sig};
        }
        return std::optional<dkim>{};
    }
    bool verify_dkim() const {
        auto dko = dkim();
        if (!dko) {
            return false;
        }
        auto &dk = *dko;
        auto v = dk.get_field("v="sv);
        auto a = dk.get_field("a="sv);
        auto d = dk.get_field("d="sv);
        auto s = dk.get_field("s="sv);
        auto c = dk.get_field("c="sv);
        auto bh = dk.get_field("bh="sv);
        auto h = dk.get_field("h="sv);
        auto b = dk.get_field("b="sv);

        if (v != "1"sv) {
            return false;
        }
        if (a != "rsa-sha256"sv) {
            return false;
        }

        auto c_headers_simple = c.empty() || c.starts_with("simple");
        auto c_body_simple = c.empty() || c == "simple" || c.contains("/simple");

        auto &dns = get_default_dns();
        auto txt = dns.query_one<dns_packet::txt>(std::format("{}._domainkey.{}", s, d));
        auto txt_fields = extract_fields(txt.data, ";"sv);
        auto tv = get_field(txt_fields, "v="sv);
        auto tk = get_field(txt_fields, "k="sv);
        auto tp = get_field(txt_fields, "p="sv);

        if (tv != "DKIM1"sv) {
            return false;
        }
        if (tk != "rsa"sv) {
            return false;
        }

        auto pubk = rsa::public_key::load_pkcs8(base64::decode(tp));
        if (bytes_concept{base64::decode(bh)} != sha256::digest(body)) {
            if (c_body_simple) {
                throw std::runtime_error{"not impl or bad hash"};
            } else {
                throw std::runtime_error{"not impl or bad hash"};
            }
            return false;
        }
        sha256 h_headers;
        auto add_to_hash = [&](auto &&what) {
            //std::print("{}", what);
            h_headers.update(what);
        };
        auto add_to_hash_byte = [&](auto &&what) {
            //std::print("{}", what);
            h_headers.update(bytes_concept{&what, 1});
        };
        if (c_headers_simple) {
            throw std::runtime_error{"not impl"};
        } else {
            auto process_header = [&](std::string_view s) {
                auto p = s.find(':') + 1;
                std::string name(s.substr(0, p));
                for (auto &&c : name) {
                    c = tolower(c);
                }
                add_to_hash(name);
                bool skip_spaces{true};
                auto is_space = [](auto &&c){return c == ' ' || c == '\t' || c == '\r' || c == '\n';};
                while (!s.empty() && is_space(s.back())) {
                    s.remove_suffix(1);
                }
                for (auto it = s.begin() + p; it != s.end(); ++it) {
                    if (is_space(*it)) {
                        if (skip_spaces) {
                            continue;
                        } else {
                            add_to_hash(" "sv);
                            skip_spaces = true;
                        }
                    } else {
                        add_to_hash_byte(*it);
                        skip_spaces = false;
                    }
                }
            };
            for (auto &&v : std::views::split(h, ":"sv)) {
                if (auto f = find(std::string_view{v})) {
                    process_header(*f);
                    add_to_hash("\r\n"sv);
                }
            }
            process_header(dk.header.substr(0, b.data() - dk.header.data()));
        }
        return pubk.verify_pkcs1_digest<256>(h_headers.digest(), base64::decode<true>(b));
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
