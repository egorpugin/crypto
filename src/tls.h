#pragma once

#include "tls13.h"

#include <boost/asio.hpp>
#include <iostream>

namespace crypto {

struct tls {
    std::string url;
    boost::asio::io_context ctx;

    tls(auto &&url) : url{url} {
    }

    void run() {
        boost::asio::co_spawn(ctx, run1(), [](auto eptr) {
            try {
                std::rethrow_exception(eptr);
            } catch (std::exception &e) {
                std::cerr << e.what() << "\n";
            }
        });
        ctx.run();
    }
    boost::asio::awaitable<void> run1() {
        using namespace tls13;
        using boost::asio::use_awaitable;

        auto ex = co_await boost::asio::this_coro::executor;

        boost::asio::ip::tcp::resolver r{ex};
        auto result = co_await r.async_resolve({url,"443"}, use_awaitable);
        if (result.empty()) {
            throw std::runtime_error{"cannot resolve"};
        }
        boost::asio::ip::tcp::socket s{ex};
        co_await s.async_connect(result.begin()->endpoint(), use_awaitable);

        TLSPlaintext msg;
        //msg.type = tls13::ContentType::handshake;
        //msg.fragment =

        Handshake client_hello;
        client_hello.msg_type = tls13::HandshakeType::client_hello;
        client_hello.length[0] = 0;
        client_hello.length[1] = 0;
        client_hello.length[2] = 0;
        co_await s.async_send(boost::asio::buffer(&client_hello, sizeof(client_hello)), use_awaitable);

        char buf[8192]{};
        co_await s.async_read_some(boost::asio::buffer(&buf, sizeof(buf)), use_awaitable);

        //ServerHello server_hello;
        //co_await s.async_receive(boost::asio::buffer(&server_hello, sizeof(server_hello)), use_awaitable);

        int a = 5;
        a++;
        co_return;
    }
};

} // namespace crypto
