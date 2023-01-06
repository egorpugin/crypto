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
    using hash = sha2<256>;
    using aes = aes_gcm<128>;

    std::string url;
    boost::asio::io_context ctx;
    hash h;
    bool auth_ok{};

    template <auto Peer, auto Type>
    struct peer_data {
        using sequence_number = uint64_t;
        array<hash::digest_size_bytes> secret;
        sequence_number record_id{-1ULL};
        array<aes::key_size_bytes> key;
        array<aes::iv_size_bytes> iv;

        auto bump_nonce() {
            auto v = ++record_id;
            v = std::byteswap(v);
            auto iv = this->iv;
            (*(uint64_t *)&iv[aes::iv_size_bytes - sizeof(sequence_number)]) ^= v;
            return iv;
        }
        array<aes::iv_size_bytes> next_nonce() {
            return bump_nonce();
        }
        void make_keys(auto &&input_secret, auto &&h) {
            string s;
            s += Peer;
            s += " ";
            s += Type;
            s += " ";
            s += "traffic";
            secret = derive_secret<hash>(input_secret, s, h);
            key = hkdf_expand_label<hash, aes::key_size_bytes>(secret, "key");
            iv = hkdf_expand_label<hash, aes::iv_size_bytes>(secret, "iv");
        }
    };
    template <auto Type>
    struct server_peer_data : peer_data<"s"_s, Type> {
        auto decrypt(auto &&ciphered_text, auto &&auth_data) {
            aes a{this->key, this->next_nonce()};
            return a.decrypt(ciphered_text, auth_data);
        }
    };
    template <auto Type>
    struct client_peer_data : peer_data<"c"_s, Type> {
    };
    template <auto Type>
    struct peer_pair {
        server_peer_data<Type> server;
        client_peer_data<Type> client;

        void make_keys(auto &&input_secret, auto &&h) {
            server.make_keys(input_secret, h);
            client.make_keys(input_secret, h);
        }
    };
    peer_pair<"hs"_s> handshake;
    peer_pair<"ap"_s> traffic;

    tls(auto &&url) : url{url} {
    }

    void run() {
        boost::asio::co_spawn(ctx, run1(), [](auto eptr) {
            if (!eptr) {
                return;
            }
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
        auto result = co_await r.async_resolve({url,url=="localhost"s?"11111":"443"}, use_awaitable);
        if (result.empty()) {
            throw std::runtime_error{"cannot resolve"};
        }
        boost::asio::ip::tcp::socket s{ex};
        co_await s.async_connect(result.begin()->endpoint(), use_awaitable);

        std::vector<boost::asio::const_buffer> buffers;
        buffers.reserve(20);

        TLSPlaintext<client_tag, Handshake<ClientHello<1>>> msg;
        auto &client_hello = msg.fragment;
        get_random_secure_bytes(client_hello.message.legacy_session_id.data);
        get_random_secure_bytes(client_hello.message.random);
        client_hello.message.cipher_suites_[0] = CipherSuite::TLS_AES_128_GCM_SHA256;

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
        Extension<padding> p;
        client_hello.message.extensions.add(p);

        auto sz = msg.make_buffers(buffers);
        for (auto &&b : buffers | std::views::drop(1)) {
            h.update(b);
        }
        co_await s.async_send(buffers, use_awaitable);



        co_await handle_server_message(s, peer);
        curve25519(priv, peer, shared);
        co_await handle_server_message(s, shared);
        // actual traffic
        co_await handle_server_message(s, shared);
    }
    boost::asio::awaitable<void> handle_server_message(auto &s, uint8_t key[32]) {
        using namespace tls13;
        using boost::asio::use_awaitable;

        uint8_t buf[8192];

        TLSPlaintext<server_tag> smsg;
        co_await s.async_read_some(boost::asio::buffer(&smsg, smsg.recv_size()), use_awaitable);
        if ((int)smsg.length > sizeof(buf)) {
            throw std::logic_error{"unhandled length"};
        }
        co_await s.async_read_some(boost::asio::buffer(&buf, smsg.length), use_awaitable);

        auto p = buf;

        if (auth_ok) {
            auto dec = traffic.server.decrypt(std::span<uint8_t>(buf, smsg.length),
                                                std::span<uint8_t>((uint8_t *)&smsg, smsg.recv_size()));
            if (dec.size() == 0) {
                co_return;
            }
        }

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
            auto key2 = std::span<uint8_t>{key, 32}; // ecdhe?
            auto ecdhe = key2;
            std::array<uint8_t, 32> zero_bytes{};
            auto salt0 = zero_bytes;
            auto psk = salt0; // zero psk

            auto early_secret = hkdf_extract<hash>(salt0, psk);
            //auto binder_key = derive_secret(early_secret, "ext binder"|"res binder"s, ""s);
            //auto client_early_traffic_secret = derive_secret(early_secret, "c e traffic"s, ""s);
            auto derived1 = derive_secret<hash>(early_secret, "derived"s); // handshake_secret?
            auto handshake_secret = hkdf_extract<hash>(derived1, ecdhe); // pre master key?
            handshake.make_keys(handshake_secret, h);
            auto derived2 = derive_secret<hash>(handshake_secret, "derived"s);
            auto master_secret = hkdf_extract<hash>(derived2, zero_bytes);

            auto dec = handshake.server.decrypt(std::span<uint8_t>(buf, smsg.length),std::span<uint8_t>((uint8_t*)&smsg, smsg.recv_size()));
            if (dec.size() == 0) {
                co_return;
            }
            h.update(dec);
            auto &e = *(Handshake<extensions_type>*)dec.data();
            switch (e.msg_type) {
            case tls13::HandshakeType::encrypted_extensions:
            {
                uint16 t1 = *(uint16*)&e.message.extensions;
                auto type = (ExtensionType)std::byteswap(t1);
                int len = *(length<2>*)(((uint8_t*)&e.message.extensions) + sizeof(type));
                auto p = (NamedGroup*)(((uint8_t*)&e.message.extensions) + sizeof(type) + sizeof(length<2>) + sizeof(length<2>));
                auto grps = std::span<NamedGroup>(p, p + len / sizeof(NamedGroup));
                switch (type) {
                case ExtensionType::supported_groups:
                    break;
                default:
                    break;
                }
            }
                break;
            default:
                throw std::logic_error{"unimpl"};
            }

            auto f = [&]() -> boost::asio::awaitable<void> {
                co_await s.async_read_some(boost::asio::buffer(&smsg, smsg.recv_size()), use_awaitable);
                if ((int)smsg.length > sizeof(buf)) {
                    throw std::logic_error{"unhandled length"};
                }
                if (smsg.type != tls13::ContentType::application_data) {
                    throw std::logic_error{"unimpl"};
                }
                co_await s.async_read_some(boost::asio::buffer(&buf, smsg.length), use_awaitable);

                auto dec = handshake.server.decrypt(std::span<uint8_t>(buf, smsg.length),
                                          std::span<uint8_t>((uint8_t *)&smsg, smsg.recv_size()));
                if (dec.size() == 0) {
                    co_return;
                }
                h.update(dec);
                auto &e = *(Handshake<extensions_type> *)dec.data();
                switch (e.msg_type) {
                case tls13::HandshakeType::certificate:
                {
                }
                    break;
                case tls13::HandshakeType::finished:
                    auth_ok = true;
                    traffic.make_keys(master_secret, h);
                    break;
                default:
                    break;
                }
            };
            while (!auth_ok) {
                co_await f();
            }

            // 2. aes gcm or chacha20/poly or ...
            //aes_gcm<256> aes{key};
            //uint8_t dec[8192];
            //aes.decrypt(buf, dec);
            int a = 5;
            a++;
            break;
        }
        case tls13::ContentType::handshake: {
            h.update(buf, smsg.length);

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
