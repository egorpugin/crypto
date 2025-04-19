// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "dns.h"

namespace crypto {

struct ssh2 {
    enum class message_id {
         SSH_MSG_DISCONNECT                    =   1,
         SSH_MSG_IGNORE                        =   2,
         SSH_MSG_UNIMPLEMENTED                 =   3,
         SSH_MSG_DEBUG                         =   4,
         SSH_MSG_SERVICE_REQUEST               =   5,
         SSH_MSG_SERVICE_ACCEPT                =   6,
         SSH_MSG_KEXINIT                       =  20,
         SSH_MSG_NEWKEYS                       =  21,
         SSH_MSG_USERAUTH_REQUEST              =  50,
         SSH_MSG_USERAUTH_FAILURE              =  51,
         SSH_MSG_USERAUTH_SUCCESS              =  52,
         SSH_MSG_USERAUTH_BANNER               =  53,
         SSH_MSG_GLOBAL_REQUEST                =  80,
         SSH_MSG_REQUEST_SUCCESS               =  81,
         SSH_MSG_REQUEST_FAILURE               =  82,
         SSH_MSG_CHANNEL_OPEN                  =  90,
         SSH_MSG_CHANNEL_OPEN_CONFIRMATION     =  91,
         SSH_MSG_CHANNEL_OPEN_FAILURE          =  92,
         SSH_MSG_CHANNEL_WINDOW_ADJUST         =  93,
         SSH_MSG_CHANNEL_DATA                  =  94,
         SSH_MSG_CHANNEL_EXTENDED_DATA         =  95,
         SSH_MSG_CHANNEL_EOF                   =  96,
         SSH_MSG_CHANNEL_CLOSE                 =  97,
         SSH_MSG_CHANNEL_REQUEST               =  98,
         SSH_MSG_CHANNEL_SUCCESS               =  99,
         SSH_MSG_CHANNEL_FAILURE               = 100,
    };

    using length_type = bigendian_unsigned<4>;

    std::string_view address;
    std::string_view user;
    dns_packet::a ip;
    uint16_t port{22};

    void connect(std::string_view addr) {
        auto p = addr.rfind('@');
        user = addr.substr(0, p);
        address = addr.substr(p+1);

        auto &dns = get_default_dns();
        //ip = dns.query_one<dns_packet::a>(address);

        boost::asio::io_context ctx;
        boost::asio::co_spawn(ctx, run(), [](auto eptr) {
            if (eptr) {
                std::rethrow_exception(eptr);
            }
        });
        ctx.run();
    }

    template <typename T = void> using awaitable = boost::asio::awaitable<T>;

    awaitable<> run() {
        using socket_type = boost::asio::ip::tcp::socket;
        using boost::asio::use_awaitable;
        auto ex = co_await boost::asio::this_coro::executor;
        socket_type s{ex};
        co_await s.async_connect(boost::asio::ip::tcp::endpoint{boost::asio::ip::make_address_v4(
            "178.208.90.175"sv
            //ip.address
        ), port}, use_awaitable);

        auto client_id = "SSH-2.0-sw_0.0.1\r\n"sv;
        co_await s.async_send(boost::asio::buffer(client_id), use_awaitable);
        auto server_id = co_await receive_some(s);

        struct packet {
            length_type length;
            u8 padding_length;
            u8 data[0];
        };



        co_return;
    }
    awaitable<std::string> receive_some(auto &s) {
        char buf[8192];
        auto n = co_await s.async_read_some(boost::asio::mutable_buffer(buf, sizeof(buf)), boost::asio::use_awaitable);
        co_return std::string{buf, n};
    }
};

}
