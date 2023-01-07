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
    template <typename Cipher, typename Hash, auto Suite>
    struct suite_ {
        using cipher_type = Cipher;
        using hash_type = Hash;
        static constexpr tls13::CipherSuite suite() { return Suite; }
    };

    template <typename DefaultSuite, typename ... Suites>
    struct suites {
        using default_suite = DefaultSuite;
        static constexpr auto size() { return sizeof...(Suites) + 1; }

        static void for_each(auto &&f) {
            f(DefaultSuite{});
            (f(Suites{}),...);
        }
    };

    using all_suites = suites<
        suite_<aes_gcm<128>,sha2<256>,tls13::CipherSuite::TLS_AES_128_GCM_SHA256>
        //suite_<aes_gcm<256>,sha2<384>,tls13::CipherSuite::TLS_AES_256_GCM_SHA384>
    >;
    using suite_type = all_suites::default_suite;
    using cipher = suite_type::cipher_type;
    using hash = suite_type::hash_type;

    struct status_ {
        struct empty{};
        struct handshake{};
        struct auth_ok{};
    };
    //using status_type = std::variant<status_::empty,status_::handshake>;

    std::string url;
    boost::asio::io_context ctx;
    bool auth_ok{};
    hash h;
    //ec25519
    uint8_t priv[32], peer[32], shared[32];
    array<hash::digest_size_bytes> master_secret;

    struct buf_type {
        using header_type = tls13::TLSPlaintext;

        std::vector<uint8_t> data;
        bool crypted_exchange{};

        buf_type() {
            data.resize(10000);
        }
        boost::asio::awaitable<void> receive(auto &s) {
            using boost::asio::use_awaitable;

            auto &h = header();
            co_await s.async_read_some(boost::asio::buffer(&h, sizeof(header_type)), use_awaitable);
            std::cout << h.size() << "\n";
            data.resize(sizeof(header_type) + h.size());
            co_await s.async_read_some(boost::asio::buffer((uint8_t*)&h + sizeof(header_type), h.size()), use_awaitable);

            switch (h.type) {
            case parameters::content_type::alert:
                handle_alert();
                break;
            case parameters::content_type::change_cipher_spec:
                co_await receive(s);
                break;
            }
            if (crypted_exchange && h.type != parameters::content_type::application_data) {
                throw std::runtime_error{"bad tls message"};
            }
            switch (h.type) {
            case parameters::content_type::handshake:
                crypted_exchange = true;
                break;
            case parameters::content_type::application_data:
                break;
            default:
                throw std::logic_error{format("content is not implemented: {}", (string)NAMEOF_ENUM(h.type))};
            }
        }
        header_type &header() {
            return *(header_type *)data.data();
        }
        auto header_raw() {
            return std::span<uint8_t>(data.data(), sizeof(header_type));
        }
        template <typename T>
        T &content() {
            return *(T *)(data.data() + sizeof(header_type));
        }
        auto content_raw() {
            return std::span<uint8_t>(data.data() + sizeof(header_type), header().size());
        }
        void handle_alert() {
            using namespace tls13;
            auto &a = content<Alert>();
            if (a.level == tls13::Alert::level_type::fatal) {
                throw std::runtime_error{format("fatal tls error: {} ({})", (string)NAMEOF_ENUM(a.description),
                                                std::to_underlying(a.description))};
            } else if (a.level == tls13::Alert::level_type::warning) {
                throw std::runtime_error{format("tls warning: {} ({})", (string)NAMEOF_ENUM(a.description),
                                                std::to_underlying(a.description))};
            }
        }
    };
    buf_type buf;

    template <auto Peer, auto Type>
    struct peer_data {
        using sequence_number = uint64_t;
        array<hash::digest_size_bytes> secret;
        sequence_number record_id{-1ULL};
        array<cipher::key_size_bytes> key;
        array<cipher::iv_size_bytes> iv;
        cipher c;

        auto bump_nonce() {
            auto v = ++record_id;
            v = std::byteswap(v);
            auto iv = this->iv;
            (*(uint64_t *)&iv[cipher::iv_size_bytes - sizeof(sequence_number)]) ^= v;
            return iv;
        }
        array<cipher::iv_size_bytes> next_nonce() {
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
            key = hkdf_expand_label<hash, cipher::key_size_bytes>(secret, "key");
            iv = hkdf_expand_label<hash, cipher::iv_size_bytes>(secret, "iv");
            c = cipher{key};
        }
    };
    template <auto Type>
    struct server_peer_data : peer_data<"s"_s, Type> {
        auto decrypt(auto &&ciphered_text, auto &&auth_data) {
            this->c.set_iv(this->next_nonce());
            return this->c.decrypt(ciphered_text, auth_data);
        }
    };
    template <auto Type>
    struct client_peer_data : peer_data<"c"_s, Type> {
    };
    template <auto Type>
    struct peer_pair {
        array<hash::digest_size_bytes> secret;
        server_peer_data<Type> server;
        client_peer_data<Type> client;

        void make_keys(auto &&input_secret, auto &&h) {
            secret = input_secret;
            server.make_keys(input_secret, h);
            client.make_keys(input_secret, h);
        }
        auto make_master_keys(auto &&h) {
            auto derived2 = derive_secret<hash>(secret, "derived"s);
            std::array<uint8_t, hash::digest_size_bytes> zero_bytes{};
            auto master_secret = hkdf_extract<hash>(derived2, zero_bytes);
            peer_pair<"ap"_s> traffic;
            traffic.make_keys(master_secret, h);
            return traffic;
        }
    };
    peer_pair<"hs"_s> handshake;
    peer_pair<"ap"_s> traffic;

    tls(auto &&url) : url{url} {
        get_random_secure_bytes(priv);
    }
    void run() {
        boost::asio::co_spawn(ctx, run1(), [](auto eptr) {
            if (eptr) {
                std::rethrow_exception(eptr);
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

        auto remote_ep = s.remote_endpoint();
        auto remote_ad = remote_ep.address();
        std::string ss = remote_ad.to_string();
        std::cout << ss << "\n";

        std::vector<boost::asio::const_buffer> buffers;
        buffers.reserve(20);

        ClientHello<all_suites::size()> message;
        get_random_secure_bytes(message.legacy_session_id.data);
        get_random_secure_bytes(message.random);
        int csid{};
        all_suites::for_each([&](auto &&s) {
            message.cipher_suites_[csid++] = s.suite();
        });
        //message.cipher_suites_[0] = CipherSuite::TLS_CHACHA20_POLY1305_SHA256;

        Extension<server_name> sn;
        sn.e.server_name_ = url;
        message.extensions.add(sn);
        message.extensions.add<supported_versions>();
        message.extensions.add<signature_algorithms>();
        //message.extensions.add<signature_algorithms_cert>();
        message.extensions.add<supported_groups>();
        auto &k = message.extensions.add<key_share>();
        curve25519(priv, k.e.key);
        Extension<padding> p;
        message.extensions.add(p);

        TLSPlaintext msg;
        msg.type = parameters::content_type::handshake;
        buffers.emplace_back(&msg, sizeof(msg));

        Handshake client_hello;
        client_hello.msg_type = parameters::handshake_type::client_hello;
        buffers.emplace_back(&client_hello, sizeof(client_hello));
        auto sz = message.make_buffers(buffers);
        client_hello.length = sz;
        msg.length = sz + sizeof(client_hello);
        for (auto &&b : buffers | std::views::drop(1)) {
            h.update(b);
        }
        co_await s.async_send(buffers, use_awaitable);

        co_await buf.receive(s);
        handle_handshake();
        curve25519(priv, peer, shared);
        co_await buf.receive(s);
        co_await handle_handshake_application_data(s);

        int a = 5;
        a++;

        //co_await handle_server_message(s, shared);
        // actual traffic
        //co_await handle_server_message(s, shared);



        /*if (auth_ok) {
            auto dec = traffic.server.decrypt(std::span<uint8_t>(buf, smsg.length),
                                                std::span<uint8_t>((uint8_t *)&smsg, smsg.recv_size()));
            if (dec.size() == 0) {
                co_return;
            }
        }*/
    }
    auto decrypt_handshake() {
        auto dec = handshake.server.decrypt(buf.content_raw(), buf.header_raw());
        h.update(dec);
        return dec;
    }
    void read_extensions(auto &&in) {
        using namespace tls13;

        uint16_t len = in.read();
        auto s = in.substream(len);
        while (s) {
            ExtensionType type = s.read();
            uint16_t len2 = s.read();
            switch (type) {
            case tls13::ExtensionType::supported_groups: {
                //uint16_t len = s.read();
                auto n = len2 / sizeof(tls13::ExtensionType);
                while (n--) {
                    parameters::supported_groups g = s.read();
                    std::cout << "group: " << std::hex << (string)NAMEOF_ENUM(g) << "\n";
                }
                break;
            }
            case ExtensionType::key_share: {
                key_share::entry &ksh = s.read();
                memcpy(peer, ksh.key, 32);
                break;
            }
            case ExtensionType::supported_versions: {
                tls_version ver = s.read();
                if (ver != tls13::tls_version::tls13) {
                    throw std::runtime_error{"bad tls version"s};
                }
                break;
            }
            default:
                s.step(len2);
                std::cout << "unhandled ext: " << (string)NAMEOF_ENUM(type) << "\n";
            }
        }
    }
    void read_handshake(be_stream s) {
        using namespace tls13;

        while (s) {
            Handshake &h = s.read();
            switch (h.msg_type) {
            case parameters::handshake_type::server_hello: {
                ServerHello &sh = s.read();
                read_extensions(s);
                break;
            }
            case parameters::handshake_type::encrypted_extensions: {
                read_extensions(s);
                break;
            }
            case parameters::handshake_type::certificate: {
                auto s2 = s.substream((uint32_t)h.length);
                uint8_t certificate_request_context = s2.read();
                s2.step(certificate_request_context);
                length<3> len = s2.read();
                while (s2) {
                    // read one cert
                    length<3> len = s2.read();
                    // If the corresponding certificate type extension
                    // ("server_certificate_type" or "client_certificate_type") was not negotiated in EncryptedExtensions,
                    // or the X .509 certificate type was negotiated,
                    // then each CertificateEntry contains a DER - encoded X .509 certificate.
                    CertificateType type = tls13::CertificateType::X509; //s2.read();
                    switch (type) {
                    case tls13::CertificateType::X509: {
                        uint32_t len2 = len;
                        s2.step(len2);
                        read_extensions(s2);
                        break;
                    }
                    default:
                        throw std::logic_error{
                            format("cert type is not implemented: {}", (string)NAMEOF_ENUM(type))};
                    }
                }
                break;
            }
            case parameters::handshake_type::certificate_verify: {
                parameters::signature_scheme scheme = s.read();
                uint16_t len = s.read();
                s.skip(len);
                break;
            }
            case parameters::handshake_type::finished: {
                // verify_data
                s.skip(hash::digest_size_bytes);
                auth_ok = true;
                traffic = handshake.make_master_keys(this->h);
                break;
            }
            default:
                throw std::logic_error{format("msg_type is not implemented: {}", std::to_string((int)h.msg_type))};
            }
        }
    }
    boost::asio::awaitable<void> handle_handshake_application_data(auto &s) {
        using namespace tls13;

        std::array<uint8_t, hash::digest_size_bytes> zero_bytes{};
        auto early_secret = hkdf_extract<hash>(zero_bytes, zero_bytes);
        auto derived1 = derive_secret<hash>(early_secret, "derived"s);
        auto handshake_secret = hkdf_extract<hash>(derived1, shared);
        handshake.make_keys(handshake_secret, h);

        auto dec = decrypt_handshake();
        if (dec.empty()) {
            co_return;
        }
        read_handshake(dec);

        auto f = [&]() -> boost::asio::awaitable<void> {
            co_await buf.receive(s);
            auto dec = decrypt_handshake();
            if (dec.empty()) {
                co_return;
            }
            read_handshake(dec);
        };
        while (!auth_ok) {
            co_await f();
        }
    }
    void handle_handshake() {
        using namespace tls13;

        this->h.update(buf.content_raw());
        read_handshake(buf.content_raw());
    }
};

} // namespace crypto
