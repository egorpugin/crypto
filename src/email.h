// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "base64.h"
#include "dns.h"
#include "rsa.h"
#include "sha2.h"
#include "ed25519.h"

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
    auto find(auto &&begin, auto &&end, std::string_view header) const {
        auto it = std::ranges::find_if(begin, end, [&](auto &&v){
            return v.size() >= header.size() && std::ranges::equal(
                header.begin(), header.end(),
                v.begin(), v.begin() + header.size(),
                {}, ::tolower, ::tolower
            );
            return v.starts_with(header);
        });
        return it;
    }
    std::optional<std::string_view> find(std::string_view header) const {
        auto it = find(headers.begin(), headers.end(), header);
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
        auto it = std::ranges::find_if(fields, [&](auto &&v){return v.starts_with(f);});
        return it == fields.end() ? std::string_view{} : it->substr(f.size());
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

        if (v != "1"sv) {
            return false;
        }
        if (a != "rsa-sha256"sv && a != "ed25519-sha256"sv) {
            return false;
        }
        if (d.empty() || s.empty()) {
            return false;
        }

        auto &dns = get_default_dns();
        auto txt = dns.query_one<dns_packet::txt>(std::format("{}._domainkey.{}", s, d));
        auto txt_fields = extract_fields(txt.data, ";"sv);
        auto tv = get_field(txt_fields, "v="sv);
        auto tk = get_field(txt_fields, "k="sv);
        auto tp = get_field(txt_fields, "p="sv);

        if (tv != "DKIM1"sv) {
            return false;
        }
        if (tk == "rsa"sv) {
            auto pubk = rsa::public_key::load_pkcs8(base64::decode(tp));
            return verify_dkim_rsa(pubk);
        }
        if (tk == "ed25519"sv) {
            return verify_dkim_ed25519(base64::decode(tp));
        }
        return false;
    }
    bool verify_dkim_rsa(auto &&pubk) const {
        return verify_dkim([&](auto &&digest, auto &&sig){
            return pubk.template verify_pkcs1_digest<256>(digest, sig);
        });
    }
    bool verify_dkim_ed25519(auto &&pubk) const {
        return verify_dkim([&](auto &&digest, auto &&sig){
            return ed25519::verify(pubk, digest, sig);
        });
    }
    bool verify_dkim(auto &&f) const {
        auto dko = dkim();
        if (!dko) {
            return false;
        }
        auto &dk = *dko;
        auto v = dk.get_field("v="sv);
        auto a = dk.get_field("a="sv);
        auto c = dk.get_field("c="sv);
        auto bh = dk.get_field("bh="sv);
        auto h = dk.get_field("h="sv);
        auto b = dk.get_field("b="sv);

        auto c_headers_simple = c.empty() || c.starts_with("simple");
        auto c_body_simple = c.empty() || c == "simple" || c.contains("/simple");

        auto add_to_hash = [&](auto &&h, auto &&what) {
            //std::print("{}", what);
            h.update(what);
        };
        auto add_to_hash_byte = [&](auto &&h, auto &&what) {
            //std::print("{}", what);
            h.update(bytes_concept{&what, 1});
        };

        // normalization is not 100% correct
        if (c_body_simple) {
            sha256 body_h;
            body_h.update(body);
            if (!body.ends_with("\r\n"sv)) {
                body_h.update("\r\n"sv);
            }
            if (bytes_concept{base64::decode(bh)} != body_h.digest()) {
                return false;
            }
        } else {
            constexpr auto delim = "\r\n"sv;
            auto is_space = [](auto &&c){return c == ' ' || c == '\t';};
            std::vector<std::string_view> lines;
            for (auto &&line : std::views::split(body, delim)) {
                auto &l = lines.emplace_back(line);
                while (!l.empty() && is_space(l.back())) {
                    l.remove_suffix(1);
                }
            }
            while (!lines.empty() && lines.back().empty()) {
                lines.pop_back();
            }
            sha256 h;
            bool skip_spaces{false};
            for (auto &&line : lines) {
                for (auto &&c : line) {
                    if (is_space(c)) {
                        if (!skip_spaces) {
                            add_to_hash_byte(h, ' ');
                            skip_spaces = true;
                        }
                    } else {
                        add_to_hash_byte(h, c);
                        skip_spaces = false;
                    }
                }
                add_to_hash(h, delim);
            }
            if (bytes_concept{base64::decode(bh)} != h.digest()) {
                return false;
            }
        }
        sha256 h_headers;
        bool has_from{};
        std::map<std::string_view, decltype(headers)::const_reverse_iterator> next_iters;
        if (c_headers_simple) {
            auto is_space = [](auto &&c){return c == ' ' || c == '\t';};
            for (auto &&v : std::views::split(h, ":"sv)) {
                std::string_view sv{v};
                while (!sv.empty() && is_space(sv.front())) {
                    sv.remove_prefix(1);
                }
                while (!sv.empty() && is_space(sv.back())) {
                    sv.remove_suffix(1);
                }
                has_from |= std::ranges::equal(sv, "from"sv, {}, ::tolower);
                auto h_it = headers.rbegin();
                auto it = next_iters.find(sv);
                if (it != next_iters.end()) {
                    h_it = it->second;
                }
                if (h_it = find(h_it, headers.rend(), sv); h_it != headers.rend()) {
                    add_to_hash(h_headers, *h_it);
                    add_to_hash(h_headers, "\r\n"sv);
                    next_iters[sv] = std::next(h_it);
                }
            }
            add_to_hash(h_headers, dk.header.substr(0, b.data() - dk.header.data()));
            if (!dk.fields.empty() && dk.fields.back().empty()) {
                add_to_hash_byte(h_headers, ';'); // respect last ';'
            }
        } else {
            auto is_space = [](auto &&c){return c == ' ' || c == '\t' || c == '\r' || c == '\n';};
            auto process_header = [&](std::string_view s) {
                auto p = s.find(':') + 1;
                std::string name(s.substr(0, p));
                for (auto &&c : name) {
                    c = tolower(c);
                }
                add_to_hash(h_headers, name);
                bool skip_spaces{true};
                while (!s.empty() && is_space(s.back())) {
                    s.remove_suffix(1);
                }
                for (auto it = s.begin() + p; it != s.end(); ++it) {
                    if (is_space(*it)) {
                        if (!skip_spaces) {
                            add_to_hash(h_headers, " "sv);
                            skip_spaces = true;
                        }
                    } else {
                        add_to_hash_byte(h_headers, *it);
                        skip_spaces = false;
                    }
                }
            };
            for (auto &&v : std::views::split(h, ":"sv)) {
                std::string_view sv{v};
                while (!sv.empty() && is_space(sv.front())) {
                    sv.remove_prefix(1);
                }
                while (!sv.empty() && is_space(sv.back())) {
                    sv.remove_suffix(1);
                }
                has_from |= std::ranges::equal(sv, "from"sv, {}, ::tolower);
                auto h_it = headers.rbegin();
                auto it = next_iters.find(sv);
                if (it != next_iters.end()) {
                    h_it = it->second;
                }
                if (h_it = find(h_it, headers.rend(), sv); h_it != headers.rend()) {
                    process_header(*h_it);
                    add_to_hash(h_headers, "\r\n"sv);
                    next_iters[sv] = std::next(h_it);
                }
            }
            process_header(dk.header.substr(0, b.data() - dk.header.data()));
        }
        if (!has_from) {
            return false;
        }
        return f(h_headers.digest(), base64::decode<true>(b));
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

        uint16_t relay_port = 25;
        uint16_t legacy_port = 465; // ssl
        uint16_t secure_port = 587; // tls
        uint16_t secondary_port = 588;
        uint16_t alternative_port = 2525;
        auto port = std::to_string(relay_port);

        boost::asio::ip::tcp::resolver r{ex};
        auto hostname = "gmail-smtp-in.l.google.com"s;
        //auto hostname = "smtp-relay.gmail.com"s;
        //auto hostname = "smtp.gmail.com"s;
        //auto hostname = "smtp.yandex.ru"s;
        auto result = co_await r.async_resolve(hostname, port, use_awaitable);
        if (result.empty()) {
            throw std::runtime_error{"cannot resolve"};
        }
        co_await s.async_connect(result.begin()->endpoint(), use_awaitable);
        //ip::tcp::endpoint e{ip::make_address_v4("108.177.14.27"s), secure_port};
        //co_await s.async_connect(e, use_awaitable);
        auto msg = co_await wait_for_message();
        msg = co_await command("EHLO home\r\n"sv);
        msg = co_await command("STARTTLS\r\n"s); // rfc3207
        tls13_<decltype(s), awaitable> tls{
            .s = &s,
            .servername = hostname,
        };
        co_await tls.init_ssl();
        auto tls_command = [&](auto &&cmd) -> awaitable<std::string> {
            co_await tls.send_message(cmd);
            co_return co_await tls.receive_tls_message();
        };
        msg = co_await tls_command("EHLO home\r\n"sv);
        msg = co_await tls_command(std::format("MAIL FROM:<{}>\r\n", from));
        msg = co_await tls_command(std::format("RCPT TO:<{}>\r\n", to));
        msg = co_await tls_command("DATA\r\n"sv);
        auto data = make_message();
        msg = co_await command(msg + ".\r\n"s);
        msg = co_await command("QUIT\r\n"sv);
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
    std::string sign_message(auto &&signer) const {
        auto msg = make_message();
        input_email ie{msg};

        auto body_h = sha256::digest(ie.body);

        sha256 h;
        std::string dkim_h;
        std::map<std::string_view, decltype(ie.headers)::reverse_iterator> next_iters;
        auto append_header = [&](auto &&name) mutable {
            dkim_h += std::format("{}:", name);

            auto h_it = ie.headers.rbegin();
            auto it = next_iters.find(name);
            if (it != next_iters.end()) {
                h_it = it->second;
            }
            if (h_it = ie.find(h_it, ie.headers.rend(), name); h_it != ie.headers.rend()) {
                h.update(*h_it);
                h.update("\r\n"sv);
                next_iters[name] = std::next(h_it);
            }
        };
        append_header("Subject"sv);
        append_header("From"sv);
        append_header("To"sv);
        append_header("Message-ID"sv);
        dkim_h.pop_back();

        auto dkim = std::format("DKIM-Signature: v=1; a={}-sha256; s={}; d={}; c=simple/simple; h={}; bh={}; b=",
            signer.get_type(), signer.selector, from.substr(from.rfind('@') + 1), dkim_h, base64::encode(body_h));
        h.update(dkim);
        dkim += base64::encode(signer.sign(h.digest()));
        dkim += "\r\n"sv;

        msg = std::format("{}{}", dkim, msg);
        return msg;
    }
    // input arg id?
    std::string make_message() const {
        std::string_view sv{text};
        while (!sv.empty() && isspace(sv.back())) {
            sv.remove_suffix(1);
        }

        auto t = time(0);
        auto msg_id = std::format("{}@{}", t, from.substr(from.rfind('@')+1));

        auto msg = std::format(
            "Subject: {}\r\n"
            "From: {}\r\n"
            "To: {}\r\n"
            "Message-ID: {}\r\n\r\n"
            "{}\r\n"
            , title, from, to, msg_id, sv);
        return msg;
    }
};

struct smtp {
};

struct dkim_ed25519_signer {
    std::string selector;
    ed25519 ed;

    static auto get_type() {
        return "ed25519"sv;
    }
    auto sign(auto &&text) {
        return ed.sign(text);
    }
};

}
