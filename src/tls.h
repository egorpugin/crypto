#pragma once

#include "helpers.h"
#include "tls13.h"
#include "random.h"
#include "ec25519.h"
#include "aes.h"
#include "hmac.h"

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
        get_random_secure_bytes(client_hello.message.legacy_session_id.data);
        get_random_secure_bytes(client_hello.message.random);
        client_hello.message.cipher_suites_[0] = CipherSuite::TLS_AES_256_GCM_SHA384;

        Extension<server_name> sn;
        sn.e.server_name_ = url;
        client_hello.message.extensions.add(sn);
        client_hello.message.extensions.add<supported_versions>();
        client_hello.message.extensions.add<signature_algorithms>();
        client_hello.message.extensions.add<supported_groups>();
        auto &k = client_hello.message.extensions.add<key_share>();
        uint8_t priv[32], peer[32], shared[32];
        get_random_secure_bytes(priv);
        curve25519(priv, k.e.key);
        client_hello.message.extensions.add<psk_key_exchange_modes>();
        Extension<padding> p;
        client_hello.message.extensions.add(p);

        auto sz = msg.make_buffers(buffers);

        co_await s.async_send(buffers, use_awaitable);



        co_await handle_server_message(s, peer);
        curve25519(priv, peer, shared);
        co_await handle_server_message(s, shared);
        co_await handle_server_message(s, shared);
        co_await handle_server_message(s, shared);
        co_await handle_server_message(s, shared);
        co_await handle_server_message(s, shared);


        //ServerHello server_hello;
        //co_await s.async_receive(boost::asio::buffer(&server_hello, sizeof(server_hello)), use_awaitable);

        int a = 5;
        a++;
        co_return;
    }
    boost::asio::awaitable<void> handle_server_message(auto &s, uint8_t key[32]) {
        using namespace tls13;
        using boost::asio::use_awaitable;

        uint8_t buf[8192];

        TLSPlaintext<server> smsg;
        co_await s.async_read_some(boost::asio::buffer(&smsg, smsg.recv_size()), use_awaitable);
        if ((int)smsg.length > sizeof(buf)) {
            throw std::logic_error{"unhandled lentth"};
        }
        co_await s.async_read_some(boost::asio::buffer(&buf, smsg.length), use_awaitable);

        auto p = buf;

        switch (smsg.type) {
        case tls13::ContentType::alert: {
            auto &a = *(Alert*)p;
            if (a.level == tls13::Alert::Level::fatal) {
                throw std::runtime_error{format("fatal tls error: {} ({})", (string)NAMEOF_ENUM(a.description),
                                                std::to_underlying(a.description))};
            } else if (a.level == tls13::Alert::Level::warning) {
                throw std::runtime_error{format("tls warning: {} ({})", (string)NAMEOF_ENUM(a.description),
                                                std::to_underlying(a.description))};
            }
        } break;
        case tls13::ContentType::change_cipher_spec: {
            break;
        }
        case tls13::ContentType::application_data: {
            auto hkdf_extract = [&](auto &&salt, auto &&input_keying_material) {
                return hmac<sha2<256>>(salt, input_keying_material);
            };
            auto hkdf_expand = [&](auto &&pseudorandom_key, auto &&info) {
                return "";
            };
            auto hkdf_expand_label = [&](auto &&pseudorandom_key, auto &&label) {
                return hkdf_expand(pseudorandom_key, "tls13 "s + label);
            };

            uint8_t salt0[32]{};
            auto early_secret = hkdf_extract(salt0, key);

            //auto k = hkdf(key, "key", "");
            //auto iv = hkdf(key, "iv", "");

            int len = smsg.length;
            // we need:
            // 1. HKDF to get 'key' and 'iv' (initialization vector)
            // https://github.com/randombit/botan/blob/master/src/lib/kdf/hkdf/hkdf.h#L113
            // https://www.oryx-embedded.com/doc/tls13__key__material_8c_source.html
            // key = HKDF-Expand-Label(Secret, "key", "", key_length)
            // write_iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
            // https://github.com/chromium/chromium/blob/b75d8e421243371fa43f83b72ff68aa37342b84a/crypto/hkdf.cc
            // simple HKDF based on hmac_256 or hmac_384?
            // https://www.rfc-editor.org/rfc/rfc5869 has tests
            // 2. aes gcm or chacha20/poly or ...
            throw std::logic_error{"unimpl"};
            //aes_gcm<256> aes{key};
            //uint8_t dec[8192];
            //aes.decrypt(buf, dec);
            int a = 5;
            a++;
            break;
        }
        case tls13::ContentType::handshake: {
            auto &h = *(Handshake<ServerHello> *)p;
            p += h.recv_size();
            switch (h.msg_type) {
            case HandshakeType::server_hello: {
                auto &sh = *(ServerHello *)p;
                p += sh.recv_size();
                auto ext = (ExtensionType)std::byteswap(*(std::underlying_type_t<ExtensionType>*)p);
                p += sizeof(ExtensionType);
                switch (ext) {
                case ExtensionType::key_share:
                {
                    p += sizeof(Extension<key_share>::length);
                    auto &ksh = *(key_share::entry*)p;
                    memcpy(key, ksh.key, 32);
                    int a = 5;
                    a++;
                } break;
                default:
                    throw std::logic_error{"no key_share as first ext"};
                }

                int a = 5;
                a++;
            } break;
            default:
                throw std::logic_error{format("msg_type is not implemented: {}", (string)NAMEOF_ENUM(h.msg_type))};
            }
        } break;
        default:
            throw std::logic_error{format("content is not implemented: {}", (string)NAMEOF_ENUM(smsg.type))};
        }
    }
};

} // namespace crypto
