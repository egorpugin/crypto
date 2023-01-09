#pragma once

#include "helpers.h"
#include "tls13.h"
#include "random.h"
#include "ec25519.h"
#include "aes.h"
#include "hmac.h"
#include "ec.h"

#include <boost/asio.hpp>
#include <nameof.hpp>

#include <fstream>
#include <iostream>
#include <map>

/*
* security notes
* - we must check incoming keys for special values, etc.
* - check that points lie on the curves
* - timing attacks?
*/

namespace crypto {

//<typename RawSocket> // tcp or udp
struct tls_socket {
};

/*
 * some info:
 * tls packet size limit = 32K
 * http header size limit = 8K
 */
struct tls {
    template <typename Cipher, typename Hash, auto SuiteId>
    struct suite_ {
        using cipher_type = Cipher;
        using hash_type = Hash;
        static constexpr auto suite() { return SuiteId; }
    };

    template <typename T, auto Value>
    struct pair {
        using type = T;
        static inline constexpr auto value = Value;
    };
    template <typename KeyExchange, typename ... KeyExchanges>
    struct key_exchanges {
        using default_key_exchange = KeyExchange;
        static constexpr auto size() { return sizeof...(KeyExchange) + 1; }

        static void for_each(auto &&f) {
            f(KeyExchange{});
            (f(KeyExchanges{}),...);
        }
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
        suite_<aes_gcm<128>,sha2<256>,tls13::CipherSuite::TLS_AES_128_GCM_SHA256> // ok
        //suite_<aes_gcm<256>,sha2<384>,tls13::CipherSuite::TLS_AES_256_GCM_SHA384> // ok
    >;
    using suite_type = all_suites::default_suite;
    using cipher = suite_type::cipher_type;

    using all_key_exchanges = key_exchanges<
        pair<curve25519,parameters::supported_groups::x25519>,
        pair<ec::secp256r1,parameters::supported_groups::secp256r1>
    >;

    using hash = suite_type::hash_type;
    using key_exchange = ec::secp256r1;
    static inline constexpr auto group_name = parameters::supported_groups::secp256r1;

    std::string url_internal;
    boost::asio::io_context ctx;
    boost::asio::ip::tcp::socket s{ctx};

    bool auth_ok{};
    hash h;
    key_exchange private_key;
    key_exchange::public_key_type peer_public_key;

    struct buf_type {
        using header_type = tls13::TLSPlaintext;

        std::vector<uint8_t> data;
        bool crypted_exchange{};

        buf_type() {
            data.resize(400000);
        }
        boost::asio::awaitable<void> receive(auto &s) {
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

    struct tls_data {
    };

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
        void update_keys() {
            record_id = -1ULL;
            secret = hkdf_expand_label<hash, hash::digest_size_bytes>(secret, "traffic upd");
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
        auto encrypt(auto &&plain_text, auto &&auth_data) {
            this->c.set_iv(this->next_nonce());
            return this->c.encrypt(plain_text, auth_data);
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
        boost::asio::awaitable<void> receive(auto &&s, auto &&transport) {
            auto app = [&]() -> boost::asio::awaitable<size_t> {
                auto dec = co_await transport.receive_tls_message();
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
                body = sv.substr(p + body_delim.size());
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

    tls(auto &&url) : url_internal{url} {
    }
    void run() {
        boost::asio::co_spawn(ctx, run1(), [](auto eptr) {
            if (eptr) {
                std::rethrow_exception(eptr);
            }
        });
        ctx.run();
    }
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
    boost::asio::awaitable<void> run1() {
        auto m = co_await open_url(url_internal);
        std::ofstream{"d:/dev/crypto/.sw/" + url_internal + ".txt"} << m.response;
        int i = 0;
        while (!m.headers["Location"].empty()) {
            string url{m.headers["Location"].begin(),m.headers["Location"].end()};
            m = co_await open_url(url);
            std::ofstream{"d:/dev/crypto/.sw/" + url_internal + "." + std::to_string(++i) + ".txt"} << m.response;
        }
    }
    boost::asio::awaitable<http_message> open_url(auto &&url) {
        using namespace tls13;
        using boost::asio::use_awaitable;
        auto ex = co_await boost::asio::this_coro::executor;

        buf.crypted_exchange = false;
        auth_ok = false;
        s.close();
        h = hash{};
        handshake = decltype(handshake){};
        traffic = decltype(traffic){};

        string host = url;
        if (host.starts_with("http://")) {
            host = host.substr(7);
        }
        if (host.starts_with("https://")) {
            host = host.substr(8);
        }
        host = host.substr(0, host.find('/'));

        boost::asio::ip::tcp::resolver r{ex};
        auto result = co_await r.async_resolve({host, host == "localhost"sv ? "11111" : "443"}, use_awaitable);
        if (result.empty()) {
            throw std::runtime_error{"cannot resolve"};
        }
        co_await s.async_connect(result.begin()->endpoint(), use_awaitable);

        auto remote_ep = s.remote_endpoint();
        auto remote_ad = remote_ep.address();
        std::string ss = remote_ad.to_string();
        // std::cout << ss << "\n";

        co_await init_ssl(host);

        // http layer
        string req = "GET / HTTP/1.1\r\n";
        req += "Host: "s + url + "\r\n";
        // req += "Transfer-Encoding: chunked\r\n";
        req += "\r\n";
        co_return co_await http_query(req);
    }
    // http layer
    boost::asio::awaitable<http_message> http_query(auto &&q) {
        co_await send_message(q);
        co_return co_await receive_http_message();
    }
    boost::asio::awaitable<http_message> receive_http_message() {
        http_message m;
        co_await m.receive(s, *this);
        co_return m;
    }

    // tls layer
    boost::asio::awaitable<std::string> receive_tls_message() {
        co_await buf.receive(s);
        auto dec = decrypt(traffic);
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
    boost::asio::awaitable<void> send_message(std::string buf) {
        using namespace tls13;
        using boost::asio::use_awaitable;

        buf += (char)parameters::content_type::application_data;

        TLSPlaintext msg;
        msg.type = parameters::content_type::application_data;
        msg.length = buf.size() + cipher::tag_size_bytes;

        auto out = encrypt(traffic, buf, std::span<uint8_t>((uint8_t *)&msg, sizeof(msg)));

        std::vector<boost::asio::const_buffer> buffers;
        buffers.emplace_back(&msg, sizeof(msg));
        buffers.emplace_back(out.data(), out.size());
        co_await s.async_send(buffers, use_awaitable);
    }
    boost::asio::awaitable<void> init_ssl(const string &url) {
        using namespace tls13;
        using boost::asio::use_awaitable;

        {
            packet_writer w;
            TLSPlaintext &msg = w;
            msg.type = parameters::content_type::handshake;

            Handshake &client_hello = w;
            client_hello.msg_type = parameters::handshake_type::client_hello;

            ClientHello &hello = w;
            get_random_secure_bytes(hello.legacy_session_id);
            get_random_secure_bytes(hello.random);

            ube16 &ciphers_len = w;
            ciphers_len = sizeof(ube16) * all_suites::size();
            auto client_suites = w.next<ube16, all_suites::size()>();
            all_suites::for_each([&, i = 0](auto &&s) mutable {
                client_suites[i++] = s.suite();
            });
            // message.cipher_suites_[0] = CipherSuite::TLS_CHACHA20_POLY1305_SHA256;

            uint8_t &legacy_compression_methods_len = w;
            legacy_compression_methods_len = 1;
            uint8_t &legacy_compression_methods = w;

            ube16 &extensions_len = w;
            auto exts_start = w.p;

            if (!url.empty()) {
                server_name &sn = w;
                w += url;
                sn.server_name_length += url.size();
                sn.server_name_list_length += url.size();
                sn.len += url.size();
            }

            supported_versions &sv = w;
            signature_algorithms &sa = w;
            supported_groups &sg = w;
            ube16 &g = w;
            g = group_name;
            sg.length = sizeof(g);
            sg.len += sizeof(g);

            key_share<key_exchange::key_size> &k = w;
            k.e.scheme = group_name;
            get_random_secure_bytes(private_key.private_key);
            private_key.public_key(k.e.key);

            padding &p = w;
            auto plen = 512 - (w.p - (uint8_t*)&client_hello);
            w.p += plen;
            p.len = plen;
            extensions_len = w.p - exts_start;

            client_hello.length = 508;
            msg.length = 512;

            h.update((uint8_t*)&client_hello, 512);

            co_await s.async_send(boost::asio::buffer(w.buf, 512+sizeof(msg)), use_awaitable);

            co_await buf.receive(s);
            read_handshake(buf.content_raw());
            auto shared = private_key.shared_secret(peer_public_key);
            co_await buf.receive(s);
            handshake.make_handshake_keys(shared, h);
            co_await handle_handshake_application_data();
            traffic = handshake.make_master_keys(h);
        }

        // send client Finished
        {
            std::vector<boost::asio::const_buffer> buffers;
            buffers.reserve(20);

            TLSPlaintext msg;
            msg.type = parameters::content_type::application_data;
            buffers.emplace_back(&msg, sizeof(msg));

            std::string hma;
            hma.resize(sizeof(Handshake) + hash::digest_size_bytes + 1);
            hma[sizeof(Handshake) + hash::digest_size_bytes] = (uint8_t)parameters::content_type::handshake;
            msg.length = hma.size() + cipher::tag_size_bytes;

            Handshake &client_hello = *(Handshake *)hma.data();
            client_hello.msg_type = parameters::handshake_type::finished;
            client_hello.length = hash::digest_size_bytes;
            auto hm = hmac<hash>(hkdf_expand_label<hash>(handshake.client.secret, "finished"), hash{h}.digest());
            memcpy(hma.data() + sizeof(Handshake), hm.data(), hm.size());
            auto out = encrypt(handshake, hma, std::span<uint8_t>((uint8_t *)&msg, sizeof(msg)));
            buffers.emplace_back(out.data(), out.size());
            co_await s.async_send(buffers, use_awaitable);
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
                if (group != group_name) {
                    throw std::runtime_error{"unknown group"};
                }
                uint16_t len = s.read();
                if (len != peer_public_key.size()) {
                    throw std::runtime_error{"key size mismatch"};
                }
                memcpy(peer_public_key.data(), s.p, len);
                s.step(len);
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
                auto l = hmac<hash>(hkdf_expand_label<hash>(handshake.server.secret, "finished"), hash{this->h}.digest());
                auto r = s.span(hash::digest_size_bytes);
                if (l != r) {
                    throw std::runtime_error{"finished verification failed"};
                }
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
                    traffic.server.update_keys();
                }
                break;
            }
            default:
                throw std::logic_error{format("msg_type is not implemented: {}", std::to_string((int)h.msg_type))};
            }
            this->h.update((uint8_t *)&h, (uint32_t)h.length + sizeof(h));
        }
    }
    boost::asio::awaitable<void> handle_handshake_application_data() {
        auto d = [&]() {
            auto dec = decrypt(handshake);
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
            co_await buf.receive(s);
            dec = d();
            read_handshake(dec);
        }
    }
};

} // namespace crypto
