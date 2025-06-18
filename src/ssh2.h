// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "dns.h"
#include "ec25519.h"
#include "ed25519.h"
#include "chacha20_poly1305.h"

namespace crypto {

struct ssh2 {
    template <typename T = void> using awaitable = boost::asio::awaitable<T>;
    static inline constexpr auto use_awaitable = boost::asio::use_awaitable;

    enum class message_id : u8 {
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

         SSH_MSG_KEX_ECDH_INIT                 = 30,
         SSH_MSG_KEX_ECDH_REPLY                = 31,
    };

    using length_type = bigendian_unsigned<4>;

    struct packet {
        length_type length;
        u8 padding_length;
        //u8 data[0];

        void set_length(size_t sz) {
            int multiple_of = 8;
            constexpr auto min_padding = 4;
            padding_length = divceil(sz + min_padding, multiple_of) * multiple_of - sz;
            length = sz - sizeof(length) + padding_length;
        }
        // for chacha
        void set_length(size_t sz, int multiple_of) {
            constexpr auto min_padding = 4;
            auto sz_minus_len = sz - sizeof(length);
            padding_length = divceil(sz_minus_len + min_padding, multiple_of) * multiple_of - sz_minus_len;
            length = sz - sizeof(length) + padding_length;
        }
        auto payload_full() {
            return bytes_concept{&padding_length + 1,(uint32_t)length - padding_length - sizeof(padding_length)};
        }
        auto payload() {
            struct pl {
                message_id packet_type;
            };
            return (pl*)payload_full().data();
        }
    };
    struct string_list {
        length_type length;
        std::string value;

        void operator+=(auto &&s) {
            if (!value.empty()) {
                value += ","s;
            }
            value += s;
        }
        auto size() const {return value.size();}
    };
    template <typename T>
    struct pair {
        T client_to_server;
        T server_to_client;
    };
    struct string_list_pair : pair<string_list> {
        void operator+=(auto &&s) {
            client_to_server += s;
            server_to_client += s;
        }
    };
    struct send_buffers {
        packet p;
        message_id packet_type;
        u8 padding[16]{};
        std::vector<boost::asio::const_buffer> buffers;

        send_buffers(message_id m) {
            packet_type = m;
            get_random_secure_bytes(padding);
            buffers.emplace_back((u8 *)&p, sizeof(p));
            buffers.emplace_back(&packet_type, sizeof(packet_type));
        }
        void emplace_back(auto *p, size_t sz) {
            buffers.emplace_back((const u8*)p, sz);
        }
        void emplace_back(bytes_concept b) {
            emplace_back(b.data(), b.size());
        }
        void emplace_back(string_list &sl) {
            sl.length = sl.size();
            buffers.emplace_back(sl.length.data, sizeof(sl.length.data));
            buffers.emplace_back(sl.value.data(), sl.value.size());
        }
        void emplace_back(string_list_pair &p) {
            emplace_back(p.client_to_server);
            emplace_back(p.server_to_client);
        }
        auto size() const {
            size_t sz{};
            for (auto &&b : buffers) {
                sz += b.size();
            }
            return sz;
        }
        awaitable<void> send(auto &&s) {
            p.set_length(size());
            emplace_back(padding, p.padding_length);
            co_await s.async_send(buffers, use_awaitable);
        }
        // chacha
        awaitable<void> send_chacha20_poly1305(auto &&s, auto &&length_cipher, auto &&cipher) {
            constexpr auto tag_size_bytes = 16;

            p.set_length(size(), tag_size_bytes);
            emplace_back(padding, p.padding_length);

            auto sz = size();
            std::string data(sz, 0);
            auto ptr = data.data();
            for (auto &&b : buffers) {
                memcpy(ptr, b.data(), b.size());
                ptr += b.size();
            }
            length_cipher.cipher((u8*)data.data(), (u8*)data.data(), sizeof(p.length));
            array<32> otk;
            memcpy(otk.data(), cipher.block, 32);
            cipher.cipher((u8*)data.data() + sizeof(p.length), (u8*)data.data() + sizeof(p.length), data.size() - sizeof(p.length));
            data.resize(data.size() + tag_size_bytes);
            poly1305_auth((u8*)data.data() + data.size() - tag_size_bytes, (u8*)data.data(), data.size() - tag_size_bytes, otk.data());

            std::vector<boost::asio::const_buffer> buffers;
            buffers.emplace_back(data.data(), data.size());
            co_await s.async_send(buffers, use_awaitable);
        }
        void payload_hash(auto &&h) {
            auto e = buffers.size() - 1;
            length_type sz{};
            for (int i = 1; i < e; ++i) {
                sz += buffers[i].size();
            }
            h.update((u8 *)&sz, sizeof(sz));
            for (int i = 1; i < e; ++i) {
                h.update((u8*)buffers[i].data(), buffers[i].size());
            }
        }
    };
    struct stream {
        u8 *p;

        stream(auto &&s) {
            p = (u8*)s.data();
        }
        template <typename T> operator T&() {
            auto t = (T*)p;
            p += sizeof(T);
            return *t;
        }
        operator std::string_view() {
            length_type &l = *this;
            auto b = p;
            p += (uint32_t)l;
            return std::string_view{(const char *)b,(const char *)p};
        }
    };

    std::string_view address;
    std::string_view user;
    dns_packet::a ip;
    uint16_t port{ 22 };
    u8 recvbuf[40000];
    size_t recvbuf_bytes{};
    pair<u64> sequence{};

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

    awaitable<> run() {
        using socket_type = boost::asio::ip::tcp::socket;
        auto ex = co_await boost::asio::this_coro::executor;

        auto addr = "178.208.90.175"sv;
        //auto addr = "127.0.0.1"sv;
        //port = 10000;

        socket_type s{ex};
        co_await s.async_connect(boost::asio::ip::tcp::endpoint{boost::asio::ip::make_address_v4(
            addr
            //ip.address
        ), port}, use_awaitable);

        auto client_id = "SSH-2.0-sw_0.0.1\r\n"sv;
        co_await s.async_send(boost::asio::buffer(client_id), use_awaitable);
        auto server_id = co_await receive_hello(s);

        using hash_type = sha256;

        hash_type h;
        auto add_string = [&](auto &&data) {
            length_type sz = data.size();
            h.update((u8 *)&sz, sizeof(sz));
            h.update(data);
        };
        add_string(client_id.substr(0, client_id.size() - 2));
        add_string(server_id.substr(0, server_id.size() - 2));

        send_buffers kex_buffers{ message_id::SSH_MSG_KEXINIT };
        {
            u8 cookie[16];
            get_random_secure_bytes(cookie);
            string_list kex_algorithms;
            kex_algorithms += "curve25519-sha256"sv;
            //kex_algorithms += "curve448-sha512"sv; // we dont have curve448 yet
            string_list server_host_key_algorithms;
            server_host_key_algorithms += "ssh-ed25519"sv;
            server_host_key_algorithms += "rsa-sha2-512"sv;
            server_host_key_algorithms += "rsa-sha2-256"sv;
            server_host_key_algorithms += "ecdsa-sha2-nistp256"sv;
            string_list_pair encryption_algorithms;
            encryption_algorithms += "chacha20-poly1305@openssh.com"sv;
            //encryption_algorithms += "aes256-ctr"sv;
            //encryption_algorithms += "aes256-cbc"sv; // 128, 192
            //encryption_algorithms += "aes128-gcm@openssh.com"sv;
            //encryption_algorithms += "aes256-gcm@openssh.com"sv;
            string_list_pair mac_algorithms;
            //mac_algorithms += "hmac-sha2-256"sv;
            //mac_algorithms += "hmac-sha2-512"sv;
            string_list_pair compression_algorithms;
            compression_algorithms += "none"sv;
            string_list_pair languages;
            u8 first_kex_packet_follows{0};
            u32 reserved{};

            auto &buffers = kex_buffers;
            buffers.emplace_back(cookie, sizeof(cookie));
            buffers.emplace_back(kex_algorithms);
            buffers.emplace_back(server_host_key_algorithms);
            buffers.emplace_back(encryption_algorithms);
            buffers.emplace_back(mac_algorithms);
            buffers.emplace_back(compression_algorithms);
            buffers.emplace_back(languages);
            buffers.emplace_back(&first_kex_packet_follows, sizeof(first_kex_packet_follows));
            buffers.emplace_back(&reserved, sizeof(reserved));
            co_await buffers.send(s);
            kex_buffers.payload_hash(h); // I_C
            ++sequence.client_to_server;
        }

        auto server_kex = co_await receive_packet(s);
        stream sk{ server_kex };
        packet &skp = sk;

        {
            curve25519 ec;
            ec.private_key();
            auto pubk = ec.public_key();
            length_type pubk_length = pubk.size();

            send_buffers buffers{message_id::SSH_MSG_KEX_ECDH_INIT};
            buffers.emplace_back(&pubk_length, sizeof(pubk_length));
            buffers.emplace_back(pubk);
            co_await buffers.send(s);
            ++sequence.client_to_server;

            auto server_kex_reply = co_await expect_packet(s, message_id::SSH_MSG_KEX_ECDH_REPLY);
            stream skr{server_kex_reply};
            packet &p = skr;
            message_id &type = skr;
            length_type &host_key_length = skr;
            std::string_view host_key_type = skr;
            std::string_view host_pubk = skr;
            std::string_view dh_pubk = skr;
            length_type &host_sig_length = skr;
            std::string_view host_sig_type = skr;
            std::string_view host_sig = skr;

            auto K = ec.shared_secret(dh_pubk);
            {
                send_buffers buffers{ message_id::SSH_MSG_NEWKEYS };
                co_await buffers.send(s);
                ++sequence.client_to_server;
            }
            co_await expect_packet(s, message_id::SSH_MSG_NEWKEYS);

            auto I_S = skp.payload_full();
            add_string(I_S);
            h.update(((u8 *)&host_key_length), host_key_length + sizeof(host_key_length));
            auto add_mpint = [&](auto &&data) {
                auto bi = bytes_to_bigint(data);
                auto s = bi.to_ssh_mpint_string();
                h.update(s);
            };
            add_string(pubk);
            add_string(dh_pubk);
            add_mpint(K);
            auto H = h.digest();
            auto session_id = H;
            //print_buffer("kexhash", H);

            if (!ed25519::verify(host_pubk, H, host_sig)) {
                throw std::runtime_error{ "bad server signature" };
            }

            auto letter = "A"s;
            auto next_hash = [&]() {
                auto h = hash_type::digest(bytes_to_bigint(K).to_ssh_mpint_string(), H, letter, session_id);
                ++letter[0];
                return h;
            };
            auto next_pair = [&]() {
                return pair<decltype(hash_type::digest(letter))>{next_hash(), next_hash()};
            };
            auto initial_iv = next_pair();
            auto encryption_key = next_pair();
            auto integrity_key = next_pair();

            struct chacha20_data {
                chacha20 length_cipher;
                chacha20 payload_cipher;
            };
            //pair<chacha20_data>
            auto make_chacha20_ciphers = [&](auto &&key, auto &&seq) {
                auto next_key = hash_type::digest(bytes_to_bigint(K).to_ssh_mpint_string(), H, key);

                u32 n[3]{};
                *(u64 *)&n[1] = std::byteswap(seq);
                chacha20 length_cipher{ next_key.data(), (u8*)&n };
                chacha20 payload_cipher{ key.data(), (u8 *)&n };
                payload_cipher.set_counter(1);
                return std::tuple{length_cipher, payload_cipher};
            };

            auto [cs_len, cs] = make_chacha20_ciphers(encryption_key.client_to_server, sequence.client_to_server);
            auto [sc_len, sc] = make_chacha20_ciphers(encryption_key.server_to_client, sequence.server_to_client);

            {
                send_buffers buffers{ message_id::SSH_MSG_SERVICE_REQUEST };
                string_list sl;
                sl += "ssh-userauth"sv;
                buffers.emplace_back(sl);
                co_await buffers.send_chacha20_poly1305(s, cs_len, cs);
                ++sequence.client_to_server;
            }

            auto lensz = sizeof(packet::length);
            co_await s.async_receive(boost::asio::mutable_buffer(recvbuf, lensz), boost::asio::use_awaitable);
            ++sequence.server_to_client;
            length_type l;
            sc_len.cipher(recvbuf, (u8*)&l, sizeof(p.length));
            size_t to_recv = l;
            if (to_recv > 35000) {
                throw std::runtime_error{ "too big packet" };
            }
            co_await s.async_receive(boost::asio::mutable_buffer(recvbuf + sizeof(p.length), to_recv + 16), boost::asio::use_awaitable);
            array<32> otk;
            memcpy(otk.data(), sc.block, 32);
            u8 tag[16];
            poly1305_auth(tag, recvbuf, to_recv + sizeof(p.length), otk.data());
            if (memcmp(tag, recvbuf + to_recv + sizeof(p.length), 16) != 0) {
                throw std::runtime_error{ "bad auth tag" };
            }
            sc.cipher(recvbuf + sizeof(p.length), recvbuf + sizeof(p.length), to_recv);

            //auto pkt = co_await receive_packet(s);

            int a = 5;
            a++;
        }

        int a = 5;
        a++;
    }
    awaitable<std::string> receive_hello(auto &s) {
        recvbuf_bytes = co_await s.async_read_some(boost::asio::mutable_buffer(recvbuf, sizeof(recvbuf)), boost::asio::use_awaitable);
        if (recvbuf_bytes > 35000) {
            throw std::runtime_error{ "too big packet" };
        }
        std::string str{ (char*)recvbuf, recvbuf_bytes };
        auto rn = "\r\n"sv;
        auto pos = str.find(rn);
        if (pos == -1) {
            throw std::runtime_error{ "continuation not implemented" };
        }
        auto off = pos + rn.size();
        str.resize(off);
        memmove(recvbuf, recvbuf + off, recvbuf_bytes -= off);
        co_return str;
    }
    awaitable<std::string> receive_packet(auto &s) {
        auto lensz = sizeof(packet::length);
        if (recvbuf_bytes == 0) {
            co_await s.async_receive(boost::asio::mutable_buffer(recvbuf, lensz), boost::asio::use_awaitable);
        }
        auto &p = *(packet *)recvbuf;
        size_t to_recv = p.length;
        if (to_recv > 35000) {
            throw std::runtime_error{ "too big packet" };
        }
        if (recvbuf_bytes) {
            lensz = recvbuf_bytes;
            to_recv -= recvbuf_bytes - sizeof(packet::length);
            recvbuf_bytes = 0;
        }
        co_await s.async_receive(boost::asio::mutable_buffer(recvbuf + lensz, to_recv), boost::asio::use_awaitable);
        ++sequence.server_to_client;
        co_return std::string{ (char*)recvbuf, p.length };
    }
    awaitable<std::string> expect_packet(auto &s, auto type) {
        auto pkt = co_await receive_packet(s);
        auto &p = *(packet *)pkt.data();
        if (p.payload()->packet_type != type) {
            throw std::runtime_error{std::format("unexpected packet: got {}, expected {}", (u8)p.payload()->packet_type, (u8)type)};
        }
        co_return pkt;
    }
};

}
