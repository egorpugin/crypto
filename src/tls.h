#pragma once

#include "helpers.h"
#include "tls13.h"
#include "random.h"
#include "ec25519.h"
#include "aes.h"
#include "hmac.h"
#include "ec.h"
#include "gcm.h"
#include "asn1.h"
#include "grasshopper.h"
#include "magma.h"
#include "streebog.h"
#include "mgm.h"
#include "sm4.h"
#include "sm3.h"
#include "chacha20_poly1305.h"

#include <boost/asio.hpp>
#include <nameof.hpp>

#include <fstream>
#include <iostream>
#include <map>

/*
* security notes
* - we must check incoming keys for special values, etc.
* - check that points lie on the curves
* - timing attacks? use sleep for?
*/

namespace crypto {

template <typename RawSocket, template <typename> typename Awaitable> // tcp or udp
struct tls13_ {
    template <typename Cipher, typename Hash, auto SuiteId, typename suite_type = void>
    struct suite_ {
        using cipher_type = Cipher;
        using hash_type = Hash;
        static constexpr auto suite() {
            return SuiteId;
        }

        Hash h;

        using hash = hash_type;
        using cipher = cipher_type;

        template <auto Peer, auto Type>
        struct peer_data {
            // FIXME: gost uses 128 bits sequence number
            using sequence_number = uint64_t;
            array<hash::digest_size_bytes> secret;
            sequence_number record_id{};
            array<cipher::key_size_bytes> base_key, key;
            array<cipher::iv_size_bytes> iv;
            cipher c;

            auto bump_nonce() {
                auto v = record_id++;
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
                if constexpr (requires { suite_type::init_keys(*this); }) {
                    suite_type::init_keys(*this);
                } else {
                    c = cipher{key};
                }
            }
            void update_keys() {
                record_id = 0;
                secret = hkdf_expand_label<hash, hash::digest_size_bytes>(secret, "traffic upd");
                key = hkdf_expand_label<hash, cipher::key_size_bytes>(secret, "key");
                iv = hkdf_expand_label<hash, cipher::iv_size_bytes>(secret, "iv");
                if constexpr (requires { suite_type::init_keys(*this); }) {
                    suite_type::init_keys(*this);
                } else {
                    c = cipher{key};
                }
            }
        };
        template <auto Type>
        struct server_peer_data : peer_data<"s"_s, Type> {
            auto decrypt(auto &&ciphered_text, auto &&auth_data) {
                if constexpr (requires { suite_type::make_keys(*this); }) {
                    suite_type::make_keys(*this);
                }
                return this->c.decrypt_with_tag(this->next_nonce(), ciphered_text, auth_data);
            }
        };
        template <auto Type>
        struct client_peer_data : peer_data<"c"_s, Type> {
            auto encrypt(auto &&plain_text, auto &&auth_data) {
                if constexpr (requires { suite_type::make_keys(*this); }) {
                    suite_type::make_keys(*this);
                }
                return this->c.encrypt_and_tag(this->next_nonce(), plain_text, auth_data);
            }
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
            auto make_handshake_keys(auto &&shared, auto &&h) {
                std::array<uint8_t, hash::digest_size_bytes> zero_bytes{};
                auto early_secret = hkdf_extract<hash>(zero_bytes, zero_bytes);
                auto derived1 = derive_secret<hash>(early_secret, "derived"s);
                auto handshake_secret = hkdf_extract<hash>(derived1, shared);
                make_keys(handshake_secret, h);
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
    };
    template <typename Cipher, typename Hash, auto SuiteId, typename suite_type>
    struct gost_suite : suite_<Cipher, Hash, SuiteId, suite_type> {
        using base = suite_<Cipher, Hash, SuiteId, suite_type>;
        using hash = base::hash;
        using cipher = base::cipher;

        static void init_keys(auto &&obj) {
            obj.base_key = obj.key;
            obj.iv[0] &= 0x7f;
        }
        static void make_keys(auto &&obj) {
            if (gost::tlstree_needs_new_key<suite_type>(obj.record_id)) {
                obj.key = gost::tlstree<hash, suite_type>(obj.base_key, obj.record_id);
                obj.c = cipher{obj.key};
            }
        }
    };
    struct TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S
        : gost_suite<mgm<grasshopper>, streebog<256>,
                     parameters::cipher_suites::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S,
                     TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S> {
        static inline constexpr uint64_t C[] = {0xffffffffe0000000ULL, 0xffffffffffff0000ULL, 0xfffffffffffffff8ULL};
        // static inline constexpr uint64_t SNMAX = (1ULL << 42) - 1;
    };
    struct TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L
        : gost_suite<mgm<grasshopper>, streebog<256>,
                     parameters::cipher_suites::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L,
                     TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L> {
        static inline constexpr uint64_t C[] = {0xf800000000000000ULL, 0xfffffff000000000ULL, 0xffffffffffffe000ULL};
        // static inline constexpr uint64_t SNMAX = std::numeric_limits<unsigned long long>::max();
    };
    struct TLS_GOSTR341112_256_WITH_MAGMA_MGM_S
        : gost_suite<mgm<magma>, streebog<256>,
                     parameters::cipher_suites::TLS_GOSTR341112_256_WITH_MAGMA_MGM_S,
                     TLS_GOSTR341112_256_WITH_MAGMA_MGM_S> {
        static inline constexpr uint64_t C[] = {0xfffffffffc000000ULL, 0xffffffffffffe000ULL, 0xffffffffffffffffULL};
        // static inline constexpr uint64_t SNMAX = (1ULL << 39) - 1;
    };
    struct TLS_GOSTR341112_256_WITH_MAGMA_MGM_L
        : gost_suite<mgm<magma>, streebog<256>,
                     parameters::cipher_suites::TLS_GOSTR341112_256_WITH_MAGMA_MGM_L,
                     TLS_GOSTR341112_256_WITH_MAGMA_MGM_L> {
        static inline constexpr uint64_t C[] = {0xffe0000000000000ULL, 0xffffffffc0000000ULL, 0xffffffffffffff80ULL};
        // static inline constexpr uint64_t SNMAX = std::numeric_limits<unsigned long long>::max();
    };

    template <typename T, auto Value>
    struct key_exchange {
        using type = T;
        static inline constexpr auto group_name = Value;

        type private_key;
        type::public_key_type peer_public_key;
    };
    template <typename KeyExchange, typename... KeyExchanges>
    struct key_exchanges : types<KeyExchange, KeyExchanges...> {
        static constexpr auto size() {
            return sizeof...(KeyExchange) + 1;
        }

        static void for_each(auto &&f) {
            f(KeyExchange{});
            (f(KeyExchanges{}), ...);
        }
    };

    template <typename DefaultSuite, typename... Suites>
    struct suites : types<DefaultSuite, Suites...> {
        static constexpr auto size() {
            return sizeof...(Suites) + 1;
        }

        static void for_each(auto &&f) {
            f(DefaultSuite{});
            (f(Suites{}), ...);
        }
    };

    using all_suites = suites<
        suite_<gcm<aes_ecb<128>>, sha2<256>, tls13::CipherSuite::TLS_AES_128_GCM_SHA256>, // mandatory
        suite_<gcm<aes_ecb<256>>, sha2<384>, tls13::CipherSuite::TLS_AES_256_GCM_SHA384>, // nice to have
        suite_<chacha20_poly1305_aead, sha2<256>, tls13::CipherSuite::TLS_CHACHA20_POLY1305_SHA256>, // nice to have
        //
        TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S,
        TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L,
        TLS_GOSTR341112_256_WITH_MAGMA_MGM_S,
        TLS_GOSTR341112_256_WITH_MAGMA_MGM_L,
        //
        suite_<gcm<sm4_encrypt>, sm3, tls13::CipherSuite::TLS_SM4_GCM_SM3>
        >;
    using all_key_exchanges = key_exchanges<
        key_exchange<curve25519, parameters::supported_groups::x25519>,
        key_exchange<ec::secp256r1, parameters::supported_groups::secp256r1>,
        key_exchange<ec::secp384r1, parameters::supported_groups::secp384r1>,
        //
        key_exchange<ec::gost::r34102012::ec256a, parameters::supported_groups::GC256A>,
        key_exchange<ec::gost::r34102012::ec256b, parameters::supported_groups::GC256B>,
        key_exchange<ec::gost::r34102012::ec256c, parameters::supported_groups::GC256C>,
        key_exchange<ec::gost::r34102012::ec256d, parameters::supported_groups::GC256D>,
        key_exchange<ec::gost::r34102012::ec512a, parameters::supported_groups::GC512A>,
        key_exchange<ec::gost::r34102012::ec512b, parameters::supported_groups::GC512B>,
        key_exchange<ec::gost::r34102012::ec512c, parameters::supported_groups::GC512C>,
        //
        key_exchange<ec::sm2, parameters::supported_groups::curveSM2>
    >;
    static inline constexpr parameters::signature_scheme all_signature_algorithms[] = {
        parameters::signature_scheme::ecdsa_secp256r1_sha256, // mandatory
        parameters::signature_scheme::rsa_pkcs1_sha256,       // mandatory
        parameters::signature_scheme::rsa_pss_rsae_sha256,    // mandatory
        //
        parameters::signature_scheme::ecdsa_secp384r1_sha384,
        parameters::signature_scheme::ed25519,
        parameters::signature_scheme::ecdsa_sha1, // remove? some sha1 certs may have long time period
        parameters::signature_scheme::rsa_pss_pss_sha256,
        //
        parameters::signature_scheme::gostr34102012_256a,
        parameters::signature_scheme::gostr34102012_256b,
        parameters::signature_scheme::gostr34102012_256c,
        parameters::signature_scheme::gostr34102012_256d,
        parameters::signature_scheme::gostr34102012_512a,
        parameters::signature_scheme::gostr34102012_512b,
        parameters::signature_scheme::gostr34102012_512c,
        //
        parameters::signature_scheme::sm2sig_sm3,
    };

    static inline constexpr auto max_tls_package = 40'000;

    RawSocket *s{nullptr};
    std::string servername;
    bool auth_ok{};
    bool initialized{};
    bool hello_retry_request{};
    bytes_concept client_hello1;
    bool ignore_server_certificate_check{};
    uint8_t legacy_session_id[32];
    tls13::Random random;

    all_suites::variant_type suite;
    all_key_exchanges::variant_type kex;

    //
    struct buf_type {
        using header_type = tls13::TLSPlaintext;

        std::vector<uint8_t> data;
        bool crypted_exchange{};

        buf_type() {
            data.resize(400000);
        }
        Awaitable<void> receive(auto &s) {
            using boost::asio::use_awaitable;

            co_await async_read(s, boost::asio::buffer(&header(), sizeof(header_type)), use_awaitable);
            if (header().size() > 40'000) {
                throw std::runtime_error{"too big tls packet"};
            }
            data.resize(sizeof(header_type) + header().size());
            auto n = co_await async_read(s, boost::asio::buffer(data.data() + sizeof(header_type), header().size()),
                                         use_awaitable);

            // after we get stable memory
            auto &h = header();
            switch (h.type) {
            case parameters::content_type::alert:
                handle_alert();
                break;
            case parameters::content_type::change_cipher_spec:
                co_await receive(s);
                break;
            }
            /*if (crypted_exchange && h.type != parameters::content_type::application_data) {
                throw std::runtime_error{"bad tls message"};
            }*/
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
        std::span<uint8_t> header_raw() {
            return std::span<uint8_t>(data.data(), sizeof(header_type));
        }
        template <typename T>
        T &content() {
            return *(T *)(data.data() + sizeof(header_type));
        }
        std::span<uint8_t> content_raw() {
            return std::span<uint8_t>(data.data() + sizeof(header_type), header().size());
        }
        void handle_alert() {
            handle_alert(content<tls13::alert>());
        }
        void handle_alert(tls13::alert &a) {
            if (a.level == tls13::alert::level_type::fatal) {
                throw std::runtime_error{format("fatal tls error: {} ({})", (string)NAMEOF_ENUM(a.description),
                                                std::to_underlying(a.description))};
            } else if (a.level == tls13::alert::level_type::warning) {
                throw std::runtime_error{format("tls warning: {} ({})", (string)NAMEOF_ENUM(a.description),
                                                std::to_underlying(a.description))};
            }
        }
    };
    buf_type buf;

    struct packet_writer {
        uint8_t buf[2048]{};
        uint8_t *p = buf;

        template <typename T, auto N>
        T *next() {
            auto r = (T *)p;
            for (int i = 0; i < N; ++i) {
                r[i] = T{};
            }
            p += sizeof(T) * N;
            return r;
        }
        template <typename T>
        T &next() {
            auto &r = *(T *)p;
            r = T{};
            p += sizeof(T);
            return r;
        }
        template <typename T>
        operator T&() {
            return next<T>();
        }
        void operator+=(auto &&v) {
            memcpy(p, v.data(), v.size());
            p += v.size();
        }
    };

    auto encrypt(auto &&what, auto &&buf, auto &&auth_data) {
        auto dec = what.client.encrypt(buf, auth_data);
        return dec;
    }
    auto decrypt(auto &&what) {
        auto dec = what.server.decrypt(buf.content_raw(), buf.header_raw());
        if (dec.empty()) {
            throw std::runtime_error{"empty message"};
        }
        return dec;
    }

    RawSocket &socket() { return *s; }

    Awaitable<std::string> receive_tls_message() {
        co_await buf.receive(socket());
        auto dec = visit(suite, [&](auto &&s){return decrypt(s.traffic);});
        while (dec.back() == 0) {
            dec.resize(dec.size() - 1);
        }
        if (dec.back() != (!auth_ok ? (uint8_t)parameters::content_type::handshake
                                    : (uint8_t)parameters::content_type::application_data)) {
            if (dec.back() == (uint8_t)parameters::content_type::alert) {
                buf.handle_alert(*(tls13::alert *)dec.data());
            }
            if (dec.back() == (uint8_t)parameters::content_type::handshake) {
                dec.resize(dec.size() - 1);
                read_handshake(dec);
                co_return co_await receive_tls_message();
            } else {
                throw std::runtime_error{"bad content type"};
            }
        }
        dec.resize(dec.size() - 1);
        co_return dec;
    }
    Awaitable<void> send_message(bytes_concept in) {
        using namespace tls13;
        using boost::asio::use_awaitable;

        std::string buf;
        buf.append(in.begin(), in.end());
        buf += (char)parameters::content_type::application_data;

        TLSPlaintext msg;
        msg.type = parameters::content_type::application_data;
        msg.length = buf.size() + visit(suite, [](auto &&s){return std::decay_t<decltype(s)>::cipher::tag_size_bytes;});

        auto out = visit(suite, [&](auto &&s){return encrypt(s.traffic, buf, std::span<uint8_t>((uint8_t *)&msg, sizeof(msg)));});

        std::vector<boost::asio::const_buffer> buffers;
        buffers.emplace_back(&msg, sizeof(msg));
        buffers.emplace_back(out.data(), out.size());
        co_await socket().async_send(buffers, use_awaitable);
    }
    Awaitable<void> init_ssl() {
        using namespace tls13;
        using boost::asio::use_awaitable;

        buf = buf_type{};

        {
            packet_writer w;
            TLSPlaintext &msg = w;
            msg.type = parameters::content_type::handshake;

            Handshake &client_hello = w;
            client_hello.msg_type = parameters::handshake_type::client_hello;

            ClientHello &hello = w;
            if (!hello_retry_request) {
                get_random_secure_bytes(legacy_session_id);
                get_random_secure_bytes(random);
            }
            memcpy(hello.legacy_session_id, legacy_session_id, 32);
            hello.random = random;

            ube16 &ciphers_len = w;
            ciphers_len = sizeof(ube16) * all_suites::size();
            auto client_suites = w.next<ube16, all_suites::size()>();
            all_suites::for_each([&, i = 0](auto &&s) mutable {
                client_suites[i++] = s.suite();
            });

            uint8_t &legacy_compression_methods_len = w;
            legacy_compression_methods_len = 1;
            uint8_t &legacy_compression_methods = w;

            ube16 &extensions_len = w;
            auto exts_start = w.p;

            auto &url = servername;
            if (!url.empty()) {
                server_name &sn = w;
                w += url;
                sn.server_name_length += url.size();
                sn.server_name_list_length += url.size();
                sn.len += url.size();
            }

            supported_versions &sv = w;
            ProtocolVersion &supported_version1 = w;
            supported_version1 = tls_version::tls13;
            sv.length += sizeof(supported_version1);
            sv.len += sizeof(supported_version1);

            supported_groups &sg = w;
            all_key_exchanges::for_each([&, i = 0](auto &&s) mutable {
                ube16 &v = w;
                v = s.group_name;
                sg.length += sizeof(v);
                sg.len += sizeof(v);
            });

            signature_algorithms &sa = w;
            for (auto &&a : all_signature_algorithms) {
                ube16 &v = w;
                v = a;
                sa.length += sizeof(v);
                sa.len += sizeof(v);
            }

            key_share &k = w;
            {
                visit(kex, [&](auto &&ke) {
                    using key_exchange = std::decay_t<decltype(ke)>::type;

                    ube16 &len = w;
                    k.length += sizeof(len);

                    auto e_start = w.p;
                    ube16 &scheme = w;
                    scheme = ke.group_name;
                    ube16 &length = w;
                    length = key_exchange::key_size;
                    array<key_exchange::key_size> &key = w;
                    ke.private_key.private_key();
                    ke.private_key.public_key(key);

                    len += w.p - e_start;
                    k.length += w.p - e_start;
                });
            }

            padding &p = w;
            auto msg_size = (w.p - w.buf + 511) / 512 * 512;
            auto plen = msg_size - (w.p - (uint8_t *)&client_hello);
            w.p += plen;
            p.length = plen;
            extensions_len = w.p - exts_start;

            client_hello.length = msg_size - 4;
            msg.length = msg_size;

            client_hello1 = bytes_concept{(uint8_t *)&client_hello, msg.length};
            visit(suite, [&](auto &&s){s.h.update((uint8_t *)&client_hello, msg.length);});

            co_await socket().async_send(boost::asio::buffer(w.buf, msg_size + sizeof(msg)), use_awaitable);

            if (hello_retry_request) {
                hello_retry_request = false;
            }

            co_await buf.receive(socket());
            read_handshake(buf.content_raw());

            if (hello_retry_request) {
                co_return co_await init_ssl();
            }

            co_await buf.receive(socket());
            std::visit([&](auto &&s, auto &&k) {
                auto shared = k.private_key.shared_secret(k.peer_public_key);
                s.handshake.make_handshake_keys(shared, s.h);
            }, suite, kex);
            co_await handle_handshake_application_data();
            visit(suite, [&](auto &&s) { s.traffic = s.handshake.make_master_keys(s.h); });
        }

        // send client Finished
        {
            std::vector<boost::asio::const_buffer> buffers;
            buffers.reserve(20);

            TLSPlaintext msg;
            msg.type = parameters::content_type::application_data;
            buffers.emplace_back(&msg, sizeof(msg));

            auto hash_size = visit(suite, [&](auto &&s){return std::decay_t<decltype(s)>::hash::digest_size_bytes;});

            std::string hma;
            hma.resize(sizeof(Handshake) + hash_size + 1);
            hma[sizeof(Handshake) + hash_size] = (uint8_t)parameters::content_type::handshake;
            msg.length = hma.size() + visit(suite, [](auto &&s){return std::decay_t<decltype(s)>::cipher::tag_size_bytes;});

            Handshake &client_hello = *(Handshake *)hma.data();
            client_hello.msg_type = parameters::handshake_type::finished;
            client_hello.length = hash_size;
            visit(suite, [&](auto &&s){
                using hash = std::decay_t<decltype(s)>::hash;
                auto hm = hmac<hash>(hkdf_expand_label<hash>(s.handshake.client.secret, "finished"), hash{s.h}.digest());
                memcpy(hma.data() + sizeof(Handshake), hm.data(), hm.size());
            });
            auto out = visit(suite, [&](auto &&s){
                return encrypt(s.handshake, hma, std::span<uint8_t>((uint8_t *)&msg, sizeof(msg)));
            });
            buffers.emplace_back(out.data(), out.size());
            co_await socket().async_send(buffers, use_awaitable);
        }
    }
    void read_extensions(auto &&in) {
        uint16_t len = in.read();
        auto s = in.substream(len);
        while (s) {
            tls13::ExtensionType type = s.read();
            uint16_t len2 = s.read();
            if (len2 == 0) {
                break;
            }
            switch (type) {
            case tls13::ExtensionType::supported_groups: {
                auto n = len2 / sizeof(tls13::ExtensionType);
                while (n--) {
                    parameters::supported_groups g = s.read();
                    std::cout << "group: " << std::hex << (string)NAMEOF_ENUM(g) << "\n";
                }
                break;
            }
            case tls13::ExtensionType::key_share: {
                parameters::supported_groups group = s.read();
                bool changed_key{};
                visit(kex, [&](auto &&k) {
                    if (group != k.group_name) {
                        all_key_exchanges::for_each([&](auto &&k) {
                            if (group == k.group_name) {
                                kex = k;
                                changed_key = true;
                            }
                        });
                        if (!changed_key) {
                            throw std::runtime_error{"unknown group"};
                        }
                    }
                });
                visit(kex, [&](auto &&k) {
                    uint16_t len = s.read();
                    if (len != 0 && !hello_retry_request) {
                        if (len != k.peer_public_key.size()) {
                            throw std::runtime_error{"key size mismatch"};
                        }
                        memcpy(k.peer_public_key.data(), s.p, len);
                    }
                    s.step(len);
                });
                break;
            }
            case tls13::ExtensionType::supported_versions: {
                tls13::tls_version ver = s.read();
                if (ver != tls13::tls_version::tls13) {
                    throw std::runtime_error{"bad tls version"s};
                }
                break;
            }
            default:
                s.step(len2);
                std::cout << "unhandled ext: " << (uint16_t)type << "\n";
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
                static array<32> hello_retry_request_data = bytes_concept{"CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C"_sb};
                if (sh.random == hello_retry_request_data) {
                    hello_retry_request = true;
                }

                if ((uint16_t)sh.legacy_version != (uint16_t)tls_version::tls12) {
                    throw std::runtime_error{"not a tls13"};
                }

                visit(suite, [&](auto &&s) {
                    if ((uint16_t)sh.cipher_suite != (uint16_t)s.suite()) {
                        bool changed_suite{};
                        all_suites::for_each([&](auto &&s2) {
                            if ((uint16_t)sh.cipher_suite == (uint16_t)s2.suite()) {
                                s2.h.update(client_hello1);
                                if (hello_retry_request) {
                                    std::string str(1 + 2 + 1 + std::decay_t<decltype(s2)>::hash::digest_size_bytes, 0);
                                    str[0] = (uint8_t)tls13::ExtensionType::message_hash;
                                    str[3] = std::decay_t<decltype(s2)>::hash::digest_size_bytes;
                                    auto h = s2.h.digest();
                                    memcpy(str.data() + 4, h.data(), h.size());

                                    s2.h = decltype(s2.h){};
                                    s2.h.update(str);
                                }

                                suite = s2;
                                changed_suite = true;
                            }
                        });
                        if (!changed_suite) {
                            throw std::runtime_error{"suite mismatch, server does not want our suite"};
                        }
                    } else if (hello_retry_request) {
                        std::string str(1 + 2 + 1 + std::decay_t<decltype(s)>::hash::digest_size_bytes, 0);
                        str[0] = (uint8_t)tls13::ExtensionType::message_hash;
                        str[3] = std::decay_t<decltype(s)>::hash::digest_size_bytes;
                        auto h = s.h.digest();
                        memcpy(str.data() + 4, h.data(), h.size());

                        s.h = decltype(s.h){};
                        s.h.update(str);
                    }
                });
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
                static int d = -1;
                ++d;
                int cert_number = 0;
                while (s2) {
                    // read one cert
                    length<3> len = s2.read();
                    // If the corresponding certificate type extension
                    // ("server_certificate_type" or "client_certificate_type") was not negotiated in
                    // EncryptedExtensions, or the X .509 certificate type was negotiated, then each CertificateEntry
                    // contains a DER - encoded X .509 certificate.
                    CertificateType type = tls13::CertificateType::X509; // s2.read();
                    switch (type) {
                    case tls13::CertificateType::X509: {
                        uint32_t len2 = len;

                        auto data = s2.span(len2);
                        asn1 a{data};

                        // https://www.rfc-editor.org/rfc/rfc8017 pkcs #1
                        //  1.2.840.113549.1.1.11 sha256WithRSAEncryption
                        //  1.2.840.113549.1.1.12 sha384WithRSAEncryption
                        //  1.3.101.112 curveEd25519 (EdDSA 25519 signature algorithm)
                        // 1.3.6.1.5.5.7.3.1 serverAuth

                        // rsaEncryption (PKCS #1)
                        constexpr auto rsaEncryption = make_oid<1, 2, 840, 113549, 1, 1, 1>();
                        constexpr auto ecPublicKey = make_oid<1,2,840,10045,2,1>();
                        constexpr auto Ed25519 = make_oid<1,3,101,112>();
                        constexpr auto GOST_R3410_12_256 = make_oid<1,2,643,7,1,1,1,1>();
                        constexpr auto GOST_R3410_12_512 = make_oid<1,2,643,7,1,1,1,2>();

                        auto pka = a.get<asn1_oid>(x509::main, x509::certificate, x509::subject_public_key_info,
                                                    x509::public_key_algorithm, 0);

                        int i = 0;
                        path fn = format("d:/dev/crypto/.sw/cert/{}/{}.der", d, i++);
                        auto write_cert = [&]() {
                            fs::create_directories(fn.parent_path());
                            std::ofstream of{fn, std::ios::binary};
                            of.write((const char *)data.data(), data.size());
                        };

                        if (pka == ecPublicKey) {
                            auto curve = a.get<asn1_oid>(x509::main, x509::certificate, x509::subject_public_key_info,
                                                            x509::public_key_algorithm, 1);
                            constexpr auto prime256v1 = make_oid<1,2,840,10045,3,1,7>();
                            constexpr auto secp384r1 = make_oid<1,3,132,0,34>();
                            if (curve == prime256v1) {
                            } else if (curve == secp384r1) {
                            } else {
                                string s = curve;
                                std::cerr << "unknown x509::public_key_algorithm::curve: " << s << "\n";

                                write_cert();
                                throw std::runtime_error{"unknown x509::public_key_algorithm::curve"};
                            }
                        } else if (pka == rsaEncryption) {
                        } else if (pka == Ed25519) {
                        } else if (pka == GOST_R3410_12_256) {
                        } else if (pka == GOST_R3410_12_512) {
                        } else {
                            string s = pka;
                            std::cerr << "unknown x509::public_key_algorithm: " << s << "\n";

                            write_cert();
                            throw std::runtime_error{"unknown x509::public_key_algorithm"};
                        }

                        if (cert_number++ == 0) {
                            bool servername_ok{};
                            auto compare_servername = [&](bytes_concept certname) {
                                if (certname == servername) {
                                    return true;
                                }
                                if (!certname.contains('*')) {
                                    return false;
                                }
                                int npoints{};
                                for (int
                                    i = certname.size() - 1,
                                    j = servername.size() - 1; i >= 0 && j >= 0;
                                        --i, --j) {
                                    if (certname[i] == '*' && npoints >= 2) {
                                        return true;
                                    }
                                    if (certname[i] != servername[j]) {
                                        return false;
                                    }
                                    npoints += certname[i] == '.';
                                }
                                return false;
                            };
                            auto check_name = [&](auto &&name) {
                                if (name.is<asn1_printable_string>()) {
                                    auto s = name.get<asn1_printable_string>();
                                    servername_ok |= compare_servername(s);
                                } else if (name.is<asn1_utf8_string>()) {
                                    auto s = name.get<asn1_utf8_string>();
                                    servername_ok |= compare_servername(s);
                                }
                            };
                            for (auto &&seq : a.get<asn1_set>(x509::main, x509::certificate, x509::subject_name, 0)) {
                                auto s = seq.get<asn1_sequence>();
                                auto string_name = s.get<asn1_oid>(0);
                                constexpr auto commonName = make_oid<2, 5, 4, 3>();
                                if (string_name == commonName) {
                                    check_name(s.subsequence(1));
                                }
                            }
                            if (!servername_ok) {
                                for (auto &&seq : a.get<asn1_sequence>(x509::main, x509::certificate)) {
                                    if (seq.data[0] != 0xA3) { // exts
                                        continue;
                                    }
                                    for (auto &&seq2 : seq.get<asn1_bit_string>().get<asn1_sequence>(0)) {
                                        auto s = seq2.get<asn1_sequence>();
                                        auto string_name = s.get<asn1_oid>(0);
                                        constexpr auto subjectAltName = make_oid<2,5,29,17>();
                                        if (string_name != subjectAltName) {
                                            continue;
                                        }
                                        auto names = s.get<asn1_sequence>(1,0);
                                        for (auto &&name : names.data_as_strings()) {
                                            servername_ok |= compare_servername(name);
                                        }
                                    }
                                }
                            }
                            // still check for server_name even if ignore_server_certificate_check set?
                            if (!servername_ok && !ignore_server_certificate_check) {
                                write_cert();
                                throw std::runtime_error{format("cannot match servername")};
                            }

                            // verify cert here? or in certificate_verify
                            int a = 5;
                            a++;
                        }

                        read_extensions(s2);
                        break;
                    }
                    default:
                        throw std::logic_error{format("cert type is not implemented: {}", (string)NAMEOF_ENUM(type))};
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
                visit(suite, [&](auto &&suit) {
                    using hash = std::decay_t<decltype(suit)>::hash;
                    auto l = hmac<hash>(hkdf_expand_label<hash>(suit.handshake.server.secret, "finished"), hash{suit.h}.digest());
                    auto r = s.span(hash::digest_size_bytes);
                    if (l != r) {
                        throw std::runtime_error{"finished verification failed"};
                    }
                });
                auth_ok = true;
                break;
            }
            case parameters::handshake_type::new_session_ticket: {
                uint32_t ticket_lifetime = s.read();
                uint32_t ticket_age_add = s.read();
                uint8_t len = s.read();
                auto ticket_nonce = s.span(len);
                uint16_t len2 = s.read();
                auto ticket = s.span(len2);
                read_extensions(s);
                break;
            }
            case parameters::handshake_type::key_update: {
                KeyUpdateRequest kupdate = s.read();
                if (kupdate == tls13::KeyUpdateRequest::update_requested) {
                    // If the request_update field is set to "update_requested", then the
                    // receiver MUST send a KeyUpdate of its own with request_update set to
                    // "update_not_requested" prior to sending its next Application Data record.
                    throw std::logic_error{"not impl"};
                } else {
                    visit(suite, [](auto &&s) {
                        s.traffic.server.update_keys();
                    });
                }
                break;
            }
            default:
                throw std::logic_error{format("msg_type is not implemented: {}", std::to_string((int)h.msg_type))};
            }
            visit(suite, [&](auto &&s) {
                s.h.update((uint8_t *)&h, (uint32_t)h.length + sizeof(h));
            });
        }
    }
    Awaitable<void> handle_handshake_application_data() {
        auto d = [&]() {
            auto dec = visit(suite, [&](auto &&s) { return decrypt(s.handshake); });
            while (dec.back() == 0) {
                dec.resize(dec.size() - 1);
            }
            if (dec.back() != (uint8_t)parameters::content_type::handshake) {
                throw std::runtime_error{"bad content type"};
            }
            dec.resize(dec.size() - 1);
            return dec;
        };
        auto dec = d();
        read_handshake(dec);
        while (!auth_ok) {
            co_await buf.receive(socket());
            dec = d();
            read_handshake(dec);
        }
    }
};

/*
 * some info:
 * tls packet size limit = 32K
 * http header size limit = 8K
 */
struct http_client {
    using socket_type = boost::asio::ip::tcp::socket;
    template <typename T>
    using awaitable = boost::asio::awaitable<T>;

    std::string url_internal;
    boost::asio::io_context ctx;
    socket_type s{ctx};
    tls13_<socket_type, awaitable> tls_layer{&s};

    struct http_message {
        static inline constexpr auto line_delim = "\r\n"sv;
        static inline constexpr auto body_delim = "\r\n\r\n"sv;

        std::string response;
        string_view code;
        std::map<string_view, string_view> headers;
        string_view body;
        std::vector<string_view> chunked_body;

        http_message() {
            response.reserve(1'000'000);
        }
        awaitable<void> receive(auto &&s, auto &&transport) {
            auto app = [&]() -> awaitable<size_t> {
                auto dec = co_await transport.receive_some();
                response.append((char *)dec.data(), dec.size());
                co_return dec.size();
            };

            while (!response.contains(body_delim)) {
                co_await app();
            }

            // read headers
            auto p = response.find(body_delim);
            headers.clear();
            auto header = string_view{response.data(), p};
            auto hdrs = header | std::views::split(line_delim);
            auto cod = *std::begin(hdrs);
            code = std::string_view{cod.begin(), cod.end()};
            for (auto &&h : hdrs | std::views::drop(1)) {
                std::string_view s{h.begin(), h.end()};
                auto p = s.find(':');
                if (p == -1) {
                    throw std::runtime_error{format("bad header: {}"s, s)};
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
                while (response.size() != p + body_delim.size() + sz) {
                    co_await app();
                }
                string_view sv{response.begin(), response.end()};
                auto start = p + body_delim.size();
                body = sv.substr(start, sz);
            } else if (auto it = headers.find("Transfer-Encoding"sv); it != headers.end()) {
                if (it->second != "chunked"sv) {
                    throw std::logic_error{"not impl"};
                }
                while (1) {
                    string_view sv{response.begin(), response.end()};
                    body = sv.substr(p + body_delim.size());
                    if (body.contains(line_delim)) {
                        break;
                    }
                    co_await app();
                }
                while (1) {
                    while (!body.contains(line_delim)) {
                        auto pos = body.data() - response.data();
                        co_await app();
                        string_view sv{response.begin(), response.end()};
                        body = sv.substr(pos);
                    }
                    size_t sz_read;
                    auto needs_more = std::stoll(body.data(), &sz_read, 16);
                    if (needs_more == 0 && sz_read == 1) {
                        break;
                    }
                    body = body.substr(sz_read);
                    if (!body.starts_with(line_delim)) {
                        throw std::runtime_error{"bad http body data"};
                    }
                    body = body.substr(line_delim.size());
                    auto begin = body.data() - response.data();
                    auto end = begin + needs_more;
                    auto jump = end + line_delim.size();
                    needs_more -= body.size();
                    while (needs_more > 0) {
                        needs_more -= co_await app();
                    }
                    chunked_body.push_back(string_view{response.begin() + begin, response.begin() + end});
                    body = string_view{response.begin(), response.end()};
                    body = body.substr(jump);
                }
            } else {
                // complete message
                string_view sv{response.begin(), response.end()};
                body = sv.substr(p + body_delim.size());
            }
        }
    };

    http_client(auto &&url) : url_internal{url} {
    }
    void run() {
        boost::asio::co_spawn(ctx, run1(), [](auto eptr) {
            if (eptr) {
                std::rethrow_exception(eptr);
            }
        });
        ctx.run();
    }
    awaitable<void> run1() {
        auto make_fn_url = [](auto &&u) {
            return u.substr(0, u.find(':'));
        };

        auto m = co_await open_url(url_internal);
        std::ofstream{"d:/dev/crypto/.sw/" + make_fn_url(url_internal) + ".txt", std::ios::binary} << m.response;
        std::ofstream{"d:/dev/crypto/.sw/" + make_fn_url(url_internal) + ".jpg", std::ios::binary} << m.body;
        int i = 0;
        while (!m.headers["Location"].empty()) {
            string url{m.headers["Location"].begin(), m.headers["Location"].end()};
            m = co_await open_url(url);
            std::ofstream{"d:/dev/crypto/.sw/" + make_fn_url(url_internal) + "." + std::to_string(++i) + ".txt", std::ios::binary} << m.response;
        }
    }
    awaitable<http_message> open_url(auto &&url) {
        using boost::asio::use_awaitable;
        auto ex = co_await boost::asio::this_coro::executor;

        string host = url;
        if (host.starts_with("http://")) {
            host = host.substr(7);
        }
        if (host.starts_with("https://")) {
            host = host.substr(8);
        }
        host = host.substr(0, host.find('/'));
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
            //host = host.substr(p + 1);
        }

        string port = "443";
        if (auto p = host.rfind(':'); p != -1) {
            port = host.substr(p+1);
            host = host.substr(0,p);
        }

        boost::asio::ip::tcp::resolver r{ex};
        auto result = co_await r.async_resolve(host, port, use_awaitable);
        if (result.empty()) {
            throw std::runtime_error{"cannot resolve"};
        }
        s.close();
        co_await s.async_connect(result.begin()->endpoint(), use_awaitable);
        /*for (int i = 0; auto &&e : result) {
            try {
                co_await s.async_connect(e.endpoint(), use_awaitable);
            } catch (std::exception &) {
                if (i == result.size() - 1) {
                    throw;
                }
            }
            ++i;
        }*/

        auto remote_ep = s.remote_endpoint();
        auto remote_ad = remote_ep.address();
        std::string ss = remote_ad.to_string();
        // std::cout << ss << "\n";

        if (host == "91.244.183.22") {
            host = "test-gost.infotecs.ru";
        }
        if (host == "127.0.0.1") {
            //host = "localhost";
            //host = "www.wolfssl.com";
        }
        tls_layer = decltype(tls_layer){&s, host};
        if (host == "127.0.0.1") {
            tls_layer.ignore_server_certificate_check = true;
        }

        // http layer
        //string req = "GET /image.jpg HTTP/1.1\r\n";
        string req = "GET / HTTP/1.1\r\n";
        req += "Host: "s + url + "\r\n";
        // req += "Transfer-Encoding: chunked\r\n";
        req += "\r\n";
        auto resp = co_await http_query(req);
        co_return resp;
    }
    // http layer
    awaitable<http_message> http_query(auto &&q) {
        co_await send_message(q);
        co_return co_await receive_http_message();
    }
    awaitable<http_message> receive_http_message() {
        http_message m;
        co_await m.receive(s, *this);
        co_return m;
    }

    awaitable<std::string> receive_some() {
        co_return co_await tls_layer.receive_tls_message();
    }
    awaitable<void> send_message(bytes_concept data) {
        if (!tls_layer.initialized) {
            co_await tls_layer.init_ssl();
        }
        co_await tls_layer.send_message(data);
    }
};

} // namespace crypto
