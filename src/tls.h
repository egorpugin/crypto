// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "aes.h"
#include "asn1.h"
#include "chacha20_poly1305.h"
#include "ec.h"
#include "ec25519.h"
#include "gcm.h"
#include "grasshopper.h"
#include "helpers.h"
#include "hmac.h"
#include "magma.h"
#include "mgm.h"
#include "mlkem.h"
#include "random.h"
#include "sm3.h"
#include "sm4.h"
#include "streebog.h"
#include "tls13.h"
#include "x509.h"

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

        using hash = hash_type;
        using cipher = cipher_type;

        template <auto Peer, auto Type>
        struct peer_data {
            // FIXME: gost uses 128 bits sequence number
            using sequence_number = u64;
            array<hash::digest_size_bytes> secret;
            sequence_number record_id{};
            array<cipher::key_size_bytes> base_key, key;
            array<cipher::iv_size_bytes> iv;
            cipher c;

            auto bump_nonce() {
                auto v = record_id++;
                v = std::byteswap(v);
                auto iv = this->iv;
                (*(u64 *)&iv[cipher::iv_size_bytes - sizeof(sequence_number)]) ^= v;
                return iv;
            }
            array<cipher::iv_size_bytes> next_nonce() {
                return bump_nonce();
            }
            void make_keys(auto &&input_secret, auto &&h) {
                using namespace tls13;

                auto s = std::format("{} {} traffic", (string_view)Peer, (string_view)Type);
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
                using namespace tls13;

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
            auto encrypt(auto &&plain_text, auto &&auth_data) {
                if constexpr (requires { suite_type::make_keys(*this); }) {
                    suite_type::make_keys(*this);
                }
                return this->c.encrypt_and_tag(this->next_nonce(), plain_text, auth_data);
            }
            auto decrypt(auto &&ciphered_text, auto &&auth_data) {
                if constexpr (requires { suite_type::make_keys(*this); }) {
                    suite_type::make_keys(*this);
                }
                return this->c.decrypt_with_tag(this->next_nonce(), ciphered_text, auth_data);
            }
        };
        template <auto Type>
        struct peer_pair {
            array<hash::digest_size_bytes> secret;
            peer_data<"s"_s, Type> server;
            peer_data<"c"_s, Type> client;

            void make_keys(auto &&input_secret, auto &&h) {
                secret = input_secret;
                server.make_keys(input_secret, h);
                client.make_keys(input_secret, h);
            }
        };

        Hash h;
        peer_pair<"hs"_s> handshake;
        peer_pair<"ap"_s> traffic;

        auto make_handshake_keys(auto &&shared) {
            using namespace tls13;

            std::array<u8, hash::digest_size_bytes> zero_bytes{};
            auto early_secret = hkdf_extract<hash>(zero_bytes, zero_bytes);
            auto derived = derive_secret<hash>(early_secret, "derived"s);
            auto handshake_secret = hkdf_extract<hash>(derived, shared);
            handshake.make_keys(handshake_secret, h);
        }
        auto make_master_keys() {
            using namespace tls13;

            std::array<u8, hash::digest_size_bytes> zero_bytes{};
            auto derived = derive_secret<hash>(handshake.secret, "derived"s);
            auto master_secret = hkdf_extract<hash>(derived, zero_bytes);
            traffic.make_keys(master_secret, h);
        }
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
        : gost_suite<mgm<grasshopper>, streebog<256>, tls13::CipherSuite::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S,
                     TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S> {
        static inline constexpr u64 C[] = {0xffffffffe0000000ULL, 0xffffffffffff0000ULL, 0xfffffffffffffff8ULL};
        // static inline constexpr u64 SNMAX = (1ULL << 42) - 1;
    };
    struct TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L
        : gost_suite<mgm<grasshopper>, streebog<256>, tls13::CipherSuite::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L,
                     TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L> {
        static inline constexpr u64 C[] = {0xf800000000000000ULL, 0xfffffff000000000ULL, 0xffffffffffffe000ULL};
        // static inline constexpr u64 SNMAX = std::numeric_limits<unsigned long long>::max();
    };
    struct TLS_GOSTR341112_256_WITH_MAGMA_MGM_S
        : gost_suite<mgm<magma>, streebog<256>, tls13::CipherSuite::TLS_GOSTR341112_256_WITH_MAGMA_MGM_S, TLS_GOSTR341112_256_WITH_MAGMA_MGM_S> {
        static inline constexpr u64 C[] = {0xfffffffffc000000ULL, 0xffffffffffffe000ULL, 0xffffffffffffffffULL};
        // static inline constexpr u64 SNMAX = (1ULL << 39) - 1;
    };
    struct TLS_GOSTR341112_256_WITH_MAGMA_MGM_L
        : gost_suite<mgm<magma>, streebog<256>, tls13::CipherSuite::TLS_GOSTR341112_256_WITH_MAGMA_MGM_L, TLS_GOSTR341112_256_WITH_MAGMA_MGM_L> {
        static inline constexpr u64 C[] = {0xffe0000000000000ULL, 0xffffffffc0000000ULL, 0xffffffffffffff80ULL};
        // static inline constexpr u64 SNMAX = std::numeric_limits<unsigned long long>::max();
    };

    template <typename T, auto Value>
    struct key_exchange {
        using type = T;
        static inline constexpr auto group_name = Value;

        template <typename U>
        struct type_v {
            using type = U;
        };
        static consteval auto pkt() {
            if constexpr (requires { typename type::peer_key_type; }) {
                return type_v<typename type::peer_key_type>{};
            } else {
                return type_v<typename type::public_key_type>{};
            }
        }
        using peer_key_type = decltype(pkt())::type;

        type private_key;
        peer_key_type peer_public_key;

        auto shared_secret() {
            return private_key.shared_secret(peer_public_key);
        }
    };
    struct X25519MLKEM768 {
        using mlkem_type = mlkem<768>;
        static inline constexpr auto key_size = sizeof(curve25519::public_key_type) + sizeof(mlkem_type::public_key_type);
        using public_key_type = array<key_size>;
        static inline constexpr auto peer_key_size = sizeof(curve25519::public_key_type) + mlkem_type::kem_cipher_text_len;
        using peer_key_type = array<peer_key_size>;

        mlkem_type m;
        curve25519 ec;

        void private_key() {
            m.private_key();
            ec.private_key();
        }
        void public_key(auto &&key) {
            memcpy(key.data(), m.public_key_.data(), m.public_key_.size());
            ec.public_key(bytes_concept{key.data() + m.public_key_.size(), sizeof(curve25519::public_key_type)});
        }
        auto shared_secret(const peer_key_type &peer_public_key) {
            array<32 + 32> shared_secret;
            array<mlkem_type::shared_secret_byte_len> ss;
            m.decapsulate(std::span{peer_public_key}.first<mlkem_type::kem_cipher_text_len>(), ss);
            auto ss2 = ec.shared_secret(bytes_concept{peer_public_key.data() + mlkem_type::kem_cipher_text_len, sizeof(curve25519::public_key_type)});
            memcpy(shared_secret.data(), ss.data(), 32);
            memcpy(shared_secret.data() + 32, ss2.data(), 32);
            return shared_secret;
        }
    };
    template <typename KeyExchange, typename... KeyExchanges>
    struct key_exchanges : types<KeyExchange, KeyExchanges...> {
        static constexpr auto size() {
            return sizeof...(KeyExchanges) + 1;
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
    using all_suites = suites<suite_<gcm<aes_ecb<128>>, sha2<256>, tls13::CipherSuite::TLS_AES_128_GCM_SHA256>,            // mandatory
                              suite_<gcm<aes_ecb<256>>, sha2<384>, tls13::CipherSuite::TLS_AES_256_GCM_SHA384>,            // nice to have
                              suite_<chacha20_poly1305_aead, sha2<256>, tls13::CipherSuite::TLS_CHACHA20_POLY1305_SHA256>, // nice to have
                              // ru
                              TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S, TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L, TLS_GOSTR341112_256_WITH_MAGMA_MGM_S,
                              TLS_GOSTR341112_256_WITH_MAGMA_MGM_L,
                              // cn
                              suite_<gcm<sm4_encrypt>, sm3, tls13::CipherSuite::TLS_SM4_GCM_SM3>>;
    using all_key_exchanges =
        key_exchanges<key_exchange<curve25519, parameters::supported_groups::x25519>, key_exchange<ec::secp256r1, parameters::supported_groups::secp256r1>,
                      key_exchange<ec::secp384r1, parameters::supported_groups::secp384r1>,
                      // ru
                      key_exchange<ec::gost::r34102012::ec256a, parameters::supported_groups::GC256A>,
                      key_exchange<ec::gost::r34102012::ec256b, parameters::supported_groups::GC256B>,
                      key_exchange<ec::gost::r34102012::ec256c, parameters::supported_groups::GC256C>,
                      key_exchange<ec::gost::r34102012::ec256d, parameters::supported_groups::GC256D>,
                      key_exchange<ec::gost::r34102012::ec512a, parameters::supported_groups::GC512A>,
                      key_exchange<ec::gost::r34102012::ec512b, parameters::supported_groups::GC512B>,
                      key_exchange<ec::gost::r34102012::ec512c, parameters::supported_groups::GC512C>,
                      // cn
                      key_exchange<ec::sm2, parameters::supported_groups::curveSM2>,
                      // ml-kem
                      key_exchange<X25519MLKEM768, parameters::supported_groups::X25519MLKEM768>>;
    static inline constexpr parameters::signature_scheme all_signature_algorithms[] = {
        parameters::signature_scheme::ecdsa_secp256r1_sha256, // mandatory
        parameters::signature_scheme::rsa_pkcs1_sha256,       // mandatory
        parameters::signature_scheme::rsa_pss_rsae_sha256,    // mandatory
        //
        parameters::signature_scheme::ecdsa_secp384r1_sha384,
        parameters::signature_scheme::ed25519,
        parameters::signature_scheme::ecdsa_sha1, // remove? some sha1 certs may have long time period. ca only?
        parameters::signature_scheme::rsa_pss_pss_sha256,
        // ru
        parameters::signature_scheme::gostr34102012_256a,
        parameters::signature_scheme::gostr34102012_256b,
        parameters::signature_scheme::gostr34102012_256c,
        parameters::signature_scheme::gostr34102012_256d,
        parameters::signature_scheme::gostr34102012_512a,
        parameters::signature_scheme::gostr34102012_512b,
        parameters::signature_scheme::gostr34102012_512c,
        // cn
        parameters::signature_scheme::sm2sig_sm3,
    };

    static inline constexpr auto max_tls_package = 40'000;

    RawSocket *s{nullptr};
    std::string servername;
    bool auth_ok{};
    bool initialized{};
    bool hello_retry_request{};
    bytes_concept client_hello1;
    bool ignore_server_hostname_check{};
    bool ignore_server_certificate_check{};
    u8 legacy_session_id[32];
    tls13::Random random;
    std::string cookie;
    std::string server_certificate;

    all_suites::variant_type suite;
    all_key_exchanges::variant_type kex;
    tls13::CipherSuite force_suite{};
    parameters::supported_groups force_kex{};

    //
    struct buf_type {
        using header_type = tls13::TLSPlaintext;

        std::vector<u8> data;
        bool crypted_exchange{};

        buf_type() {
            data.resize(41'000);
        }
        Awaitable<void> receive(auto &s) {
            using boost::asio::use_awaitable;

            co_await async_read(s, boost::asio::buffer(&header(), sizeof(header_type)), use_awaitable);
            if (header().size() > 40'000) {
                throw std::runtime_error{"too big tls packet"};
            }
            data.resize(sizeof(header_type) + header().size());
            auto n = co_await async_read(s, boost::asio::buffer(data.data() + sizeof(header_type), header().size()), use_awaitable);

            // after we get stable memory
            auto &h = header();
            switch (h.type) {
            case parameters::content_type::alert:
                handle_alert();
                break;
            case parameters::content_type::change_cipher_spec:
                co_await receive(s);
                break;
            default:
                break;
            }
            switch (h.type) {
            case parameters::content_type::handshake:
                crypted_exchange = true;
                break;
            case parameters::content_type::application_data:
                break;
            default:
                throw std::logic_error{format("content is not implemented: {}", (int)h.type)};
            }
        }
        header_type &header() {
            return *(header_type *)data.data();
        }
        auto header_raw() {
            return std::span<u8>(data.data(), sizeof(header_type));
        }
        template <typename T>
        T &content() {
            return *(T *)(data.data() + sizeof(header_type));
        }
        auto content_raw() {
            return std::span<u8>(data.data() + sizeof(header_type), header().size());
        }
        void handle_alert() {
            handle_alert(content<tls13::alert>());
        }
        void handle_alert(tls13::alert &a) {
            if (a.level == tls13::alert::level_type::fatal) {
                throw std::runtime_error{format("fatal tls error: {}", std::to_underlying(a.description))};
            } else if (a.level == tls13::alert::level_type::warning) {
                throw std::runtime_error{format("tls warning: {}", std::to_underlying(a.description))};
            }
        }
    };
    buf_type buf;

    struct packet_writer {
        u8 buf[2048]{};
        u8 *p = buf;

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
        operator T &() {
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

    RawSocket &socket() {
        return *s;
    }

    Awaitable<std::string> receive_tls_message() {
        co_await buf.receive(socket());
        auto dec = visit(suite, [&](auto &&s) {
            return decrypt(s.traffic);
        });
        while (dec.back() == 0) {
            dec.resize(dec.size() - 1);
        }
        if (dec.back() != (!auth_ok ? (u8)parameters::content_type::handshake : (u8)parameters::content_type::application_data)) {
            if (dec.back() == (u8)parameters::content_type::alert) {
                buf.handle_alert(*(tls13::alert *)dec.data());
            }
            if (dec.back() == (u8)parameters::content_type::handshake) {
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
        msg.length = buf.size() + visit(suite, [](auto &&s) {
                         return std::decay_t<decltype(s)>::cipher::tag_size_bytes;
                     });

        auto out = visit(suite, [&](auto &&s) {
            return encrypt(s.traffic, buf, std::span<u8>((u8 *)&msg, sizeof(msg)));
        });

        std::vector<boost::asio::const_buffer> buffers;
        buffers.emplace_back(&msg, sizeof(msg));
        buffers.emplace_back(out.data(), out.size());
        co_await socket().async_send(buffers, use_awaitable);
    }
    Awaitable<void> init_ssl() {
        using namespace tls13;
        using boost::asio::use_awaitable;

        buf = buf_type{};

        // client hello
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
            int n_suites{};
            all_suites::for_each([&](auto &&s) {
                if (!(int)force_suite || force_suite == s.suite()) {
                    ube16 &su = w;
                    su = s.suite();
                    ++n_suites;
                    if (!hello_retry_request && visit(suite, [&](auto &&s) {
                                                    return s.suite();
                                                }) != force_suite) {
                        suite = s;
                    }
                }
            });
            ciphers_len = sizeof(ube16) * n_suites;

            u8 &legacy_compression_methods_len = w;
            legacy_compression_methods_len = 1;
            u8 &legacy_compression_methods = w;

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
                if (!(int)force_kex || force_kex == (decltype(force_kex))s.group_name) {
                    ube16 &v = w;
                    v = s.group_name;
                    sg.length += sizeof(v);
                    sg.len += sizeof(v);
                    if ((int)force_kex) {
                        kex = s;
                    }
                }
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
                    using key_exchange_type = std::decay_t<decltype(ke)>::type;

                    ube16 &len = w;
                    k.length += sizeof(len);

                    auto e_start = w.p;
                    ube16 &scheme = w;
                    scheme = ke.group_name;
                    ube16 &length = w;
                    length = key_exchange_type::key_size;
                    array<key_exchange_type::key_size> &key = w;
                    ke.private_key.private_key();
                    ke.private_key.public_key(key);

                    len += w.p - e_start;
                    k.length += w.p - e_start;
                });
            }

            if (!cookie.empty()) {
                cookie_extension_type &c = w;
                c.len += cookie.size();
                c.length = cookie.size();
                w += cookie;
                cookie.clear();
            }

            /*renegotiation_info &reneg = w;
            reneg.length += 1;
            u8 &_ = w;*/

            padding &p = w;
            auto msg_size = (w.p - w.buf + 511) / 512 * 512;
            auto plen = msg_size - (w.p - (u8 *)&client_hello);
            w.p += plen;
            p.length = plen;
            extensions_len = w.p - exts_start;

            client_hello.length = msg_size - 4;
            msg.length = msg_size;

            client_hello1 = bytes_concept{(u8 *)&client_hello, msg.length};
            visit(suite, [&](auto &&s) {
                s.h.update((u8 *)&client_hello, msg.length);
            });

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
            std::visit(
                [&](auto &&s, auto &&k) {
                    s.make_handshake_keys(k.shared_secret());
                },
                suite, kex);
            co_await handle_handshake_application_data();
            visit(suite, [&](auto &&s) {
                s.make_master_keys();
            });
        }

        // send client Finished
        {
            std::vector<boost::asio::const_buffer> buffers;
            buffers.reserve(20);

            TLSPlaintext msg;
            msg.type = parameters::content_type::application_data;
            buffers.emplace_back(&msg, sizeof(msg));

            auto hash_size = visit(suite, [&](auto &&s) {
                return std::decay_t<decltype(s)>::hash::digest_size_bytes;
            });

            std::string hma;
            hma.resize(sizeof(Handshake) + hash_size + 1);
            hma[sizeof(Handshake) + hash_size] = (u8)parameters::content_type::handshake;
            msg.length = hma.size() + visit(suite, [](auto &&s) {
                             return std::decay_t<decltype(s)>::cipher::tag_size_bytes;
                         });

            Handshake &client_hello = *(Handshake *)hma.data();
            client_hello.msg_type = parameters::handshake_type::finished;
            client_hello.length = hash_size;
            visit(suite, [&](auto &&s) {
                using hash = std::decay_t<decltype(s)>::hash;
                auto hm = hmac<hash>(hkdf_expand_label<hash>(s.handshake.client.secret, "finished"), hash{s.h}.digest());
                memcpy(hma.data() + sizeof(Handshake), hm.data(), hm.size());
            });
            auto out = visit(suite, [&](auto &&s) {
                return encrypt(s.handshake, hma, std::span<u8>((u8 *)&msg, sizeof(msg)));
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
                    std::println("group: {:X}", (int)g);
                }
                break;
            }
            case tls13::ExtensionType::key_share: {
                parameters::supported_groups group = s.read();
                len2 -= sizeof(group);
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
                if (len2) {
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
                }
                break;
            }
            case tls13::ExtensionType::supported_versions: {
                tls13::tls_version ver = s.read();
                if (ver != tls13::tls_version::tls13) {
                    throw std::runtime_error{"bad tls version"s};
                }
                break;
            }
            case tls13::ExtensionType::cookie: {
                uint16_t len = s.read();
                cookie = s.span(len);
                break;
            }
            default:
                s.step(len2);
                std::println("unhandled ext: {} ({:X})", (uint16_t)type, (uint16_t)type);
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
                static array<32> hello_retry_request_data =
                    bytes_concept{"CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C"_sb};
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
                                    str[0] = (u8)tls13::ExtensionType::message_hash;
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
                        str[0] = (u8)tls13::ExtensionType::message_hash;
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
                auto s2 = s.substream(h.length);
                u8 certificate_request_context = s2.read();
                s2.step(certificate_request_context);
                length_type<3> len = s2.read();
                int cert_number = 0;
                x509_storage certs;

                while (s2) {
                    // read one cert
                    length_type<3> len = s2.read();
                    // If the corresponding certificate type extension
                    // ("server_certificate_type" or "client_certificate_type") was not negotiated in
                    // EncryptedExtensions, or the X .509 certificate type was negotiated, then each CertificateEntry
                    // contains a DER - encoded X .509 certificate.
                    CertificateType type = tls13::CertificateType::X509; // s2.read();
                    switch (type) {
                    case tls13::CertificateType::X509: {
                        u32 len2 = len;

                        auto data = s2.span(len2);
                        asn1 a{data};

                        /*auto write_cert = [&]() {
                            static int d = 0;
                            path fn = format("d:/dev/crypto/.sw/cert/{}.der", ++d);
                            fs::create_directories(fn.parent_path());
                            std::ofstream of{fn, std::ios::binary};
                            of.write((const char *)data.data(), data.size());
                        };
                        write_cert();*/

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
                                for (int i = certname.size() - 1, j = servername.size() - 1; i >= 0 && j >= 0; --i, --j) {
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
                                if (name.template is<asn1_printable_string>()) {
                                    auto s = name.template get<asn1_printable_string>();
                                    servername_ok |= compare_servername(s);
                                } else if (name.template is<asn1_utf8_string>()) {
                                    auto s = name.template get<asn1_utf8_string>();
                                    servername_ok |= compare_servername(s);
                                }
                            };
                            for (auto &&seq : x509{a.data}.get_tbs_field<asn1_sequence>(x509::subject_name)) {
                                auto s = seq.get<asn1_set>();
                                auto s2 = s.get<asn1_sequence>();
                                auto string_name = s2.get<asn1_oid>(0);
                                constexpr auto commonName = make_oid<2, 5, 4, 3>();
                                if (string_name == commonName) {
                                    check_name(s2.subsequence(1));
                                }
                            }
                            if (!servername_ok) {
                                auto cert = a.get<asn1_sequence>(x509::main, x509::tbs_certificate);
                                if (auto exts = cert.get_next<asn1_x509_extensions>()) {
                                    constexpr auto subjectAltName = make_oid<2, 5, 29, 17>();
                                    if (auto sk = exts->get_extension(subjectAltName)) {
                                        auto names = sk->get<asn1_sequence>(0, 1, 0);
                                        for (auto &&name : names.data_as_strings()) {
                                            servername_ok |= compare_servername(name);
                                        }
                                    }
                                }
                            }
                            if (!servername_ok && !ignore_server_hostname_check) {
                                throw std::runtime_error{format("cannot match servername")};
                            }
                        }
                        certs.add(data);
                        if (server_certificate.empty()) {
                            //server_certificate.assign_range(data); // gcc15 only
                            server_certificate.assign(data.begin(), data.end());
                        }
                        read_extensions(s2);
                        break;
                    }
                    default:
                        throw std::logic_error{format("cert type is not implemented: {}", (int)type)};
                    }
                }
                if (!certs.verify(server_certificate) && !ignore_server_certificate_check) {
                    throw std::runtime_error{"certificate verification failed"};
                }
                break;
            }
            case parameters::handshake_type::certificate_verify: {
                parameters::signature_scheme scheme = s.read();
                uint16_t len = s.read();
                auto data = s.span(len);

                x509 cert{server_certificate};
                auto pubk_info = cert.get_tbs_field<asn1_sequence>(x509::subject_public_key_info);
                auto pubkey = pubk_info.get<asn1_bit_string>(x509::subject_public_key);
                auto pubkey_data = pubkey.data.subspan(1);

                asn1 a{data};
                auto hs = visit(suite, [&](auto &&s) {
                    const auto context_string = "TLS 1.3, server CertificateVerify"s;
                    // constexpr auto context_string = "TLS 1.3, client CertificateVerify"s;
                    auto h = s.h;
                    auto d = h.digest();
                    std::string hs(64 + context_string.size() + 1 + d.size(), ' ');
                    memcpy(hs.data() + 64, context_string.data(), context_string.size() + 1);
                    memcpy(hs.data() + 64 + context_string.size() + 1, d.data(), d.size());
                    return hs;
                });

                auto rsa_sha2 = [&]<auto Bits>() {
                    sha2<Bits> h;
                    h.update(hs);
                    auto pubk = rsa::public_key::load_raw(pubkey_data);
                    if (!pubk.verify_pss_mgf1<Bits>(hs, data)) {
                        throw std::runtime_error{"bad signature"};
                    }
                };
                auto rsa_pkcs1_sha2 = [&]<auto Bits>() {
                    sha2<Bits> h;
                    h.update(hs);
                    auto pubk = rsa::public_key::load_raw(pubkey_data);
                    if (!pubk.verify_pkcs1<Bits>(hs, data)) {
                        throw std::runtime_error{"bad signature"};
                    }
                };
                auto ecdsa_check = [&](auto &&c, auto &&h) {
                    auto r = a.get<asn1_integer>(0, 0);
                    auto s = a.get<asn1_integer>(0, 1);
                    h.update(hs);
                    if (!c.verify(h.digest(), pubkey_data, r.data, s.data)) {
                        throw std::runtime_error{"bad signature"};
                    }
                };
                auto gost_check = [&](auto &&c, auto &&h) {
                    h.update(hs);

                    auto r = data | std::views::reverse;
                    std::vector<u8> sig2(std::begin(r), std::end(r));
                    //std::vector<u8> sig2{std::from_range, data | std::views::reverse};//gcc-15

                    auto r2 = h.digest() | std::views::reverse;
                    std::vector<u8> h2(std::begin(r2), std::end(r2));
                    //std::vector<u8> h2{std::from_range, h.digest() | std::views::reverse};//gcc-15

                    if (!c.verify(h2, asn1{pubkey_data}.get<asn1_octet_string>().data, sig2)) {
                        throw std::runtime_error{"bad signature"};
                    }
                };
                auto sm2sm3_check = [&]() {
                    auto r = a.get<asn1_integer>(0, 0).data;
                    auto s = a.get<asn1_integer>(0, 1).data;
                    if (!ec::sm2::verify<sm3>("TLSv1.3+GM+Cipher+Suite"sv, hs, pubkey_data, r, s)) {
                        throw std::runtime_error{"bad signature"};
                    }
                };

                switch (scheme) {
                case parameters::signature_scheme::ecdsa_secp256r1_sha256:
                    ecdsa_check(ec::secp256r1{}, sha2<256>{});
                    break;
                case parameters::signature_scheme::ecdsa_secp384r1_sha384:
                    ecdsa_check(ec::secp384r1{}, sha2<384>{});
                    break;
                case parameters::signature_scheme::ecdsa_secp521r1_sha512:
                    ecdsa_check(ec::secp521r1{}, sha2<512>{});
                    break;
                case parameters::signature_scheme::gostr34102012_256a:
                    gost_check(ec::gost::r34102012::ec256a{}, streebog<256>{});
                    break;
                case parameters::signature_scheme::gostr34102012_256b:
                    gost_check(ec::gost::r34102012::ec256b{}, streebog<256>{});
                    break;
                case parameters::signature_scheme::gostr34102012_256c:
                    gost_check(ec::gost::r34102012::ec256c{}, streebog<256>{});
                    break;
                case parameters::signature_scheme::gostr34102012_256d:
                    gost_check(ec::gost::r34102012::ec256d{}, streebog<256>{});
                    break;
                case parameters::signature_scheme::gostr34102012_512a:
                    gost_check(ec::gost::r34102012::ec512a{}, streebog<512>{});
                    break;
                case parameters::signature_scheme::gostr34102012_512b:
                    gost_check(ec::gost::r34102012::ec512b{}, streebog<512>{});
                    break;
                case parameters::signature_scheme::gostr34102012_512c:
                    gost_check(ec::gost::r34102012::ec512c{}, streebog<512>{});
                    break;
                // case parameters::signature_scheme::rsa_pkcs1_sha256: rsa_pkcs1_sha2.template operator()<256>(); break; // not tested
                case parameters::signature_scheme::rsa_pss_rsae_sha256:
                    rsa_sha2.template operator()<256>();
                    break;
                case parameters::signature_scheme::rsa_pss_rsae_sha384:
                    rsa_sha2.template operator()<384>();
                    break;
                case parameters::signature_scheme::rsa_pss_rsae_sha512:
                    rsa_sha2.template operator()<512>();
                    break;
                case parameters::signature_scheme::sm2sig_sm3:
                    sm2sm3_check();
                    break;
                default:
                    throw std::runtime_error{"not impl: parameters::signature_scheme certificate verify"};
                }
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
                u32 ticket_lifetime = s.read();
                u32 ticket_age_add = s.read();
                u8 len = s.read();
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
                s.h.update((u8 *)&h, (u32)h.length + sizeof(h));
            });
        }
    }
    Awaitable<void> handle_handshake_application_data() {
        auto d = [&]() {
            auto dec = visit(suite, [&](auto &&s) {
                return decrypt(s.handshake);
            });
            while (dec.back() == 0) {
                dec.resize(dec.size() - 1);
            }
            if (dec.back() != (u8)parameters::content_type::handshake) {
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

auto &default_io_context() {
    static boost::asio::io_context ctx;
    return ctx;
}

} // namespace crypto
