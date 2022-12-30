#pragma once

#include "helpers.h"
#include "tls13.h"

#include <boost/asio.hpp>
#include <nameof.hpp>
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

        std::vector<boost::asio::const_buffer> buffers;
        buffers.reserve(20);

        TLSPlaintext<client, Handshake<ClientHello<1>>> msg;
        auto &client_hello = msg.fragment;
        client_hello.message.cipher_suites_[0] = CipherSuite::TLS_AES_256_GCM_SHA384;

        Extension<server_name> sn;
        sn.e.server_name_ = url;
        client_hello.message.extensions.add(sn);
        client_hello.message.extensions.add<supported_versions>();
        client_hello.message.extensions.add<signature_algorithms>();
        client_hello.message.extensions.add<supported_groups>();
        client_hello.message.extensions.add<key_share>();
        client_hello.message.extensions.add<psk_key_exchange_modes>();
        Extension<padding> p;
        client_hello.message.extensions.add(p);

        auto sz = msg.make_buffers(buffers);

        co_await s.async_send(buffers, use_awaitable);

        TLSPlaintext<server> smsg;
        co_await s.async_read_some(boost::asio::buffer(&smsg, smsg.recv_size()), use_awaitable);

        switch (smsg.type) {
        case tls13::ContentType::alert:
        {
            Alert a;
            co_await s.async_read_some(boost::asio::buffer(&a, sizeof(a)), use_awaitable);
            smsg.fragment = a;
        }
            break;
        default:
            throw std::logic_error{format("content is not implemented: {}", (string)NAMEOF_ENUM(smsg.type))};
        }

        visit(smsg.fragment, [](Alert &a) {
            if (a.level == tls13::Alert::Level::fatal) {
                throw std::runtime_error{format("fatal tls error: {} ({})",
                    (string)NAMEOF_ENUM(a.description),
                    std::to_underlying(a.description))};
            }
        });



        //ServerHello server_hello;
        //co_await s.async_receive(boost::asio::buffer(&server_hello, sizeof(server_hello)), use_awaitable);

        int a = 5;
        a++;
        co_return;
    }
};

} // namespace crypto
