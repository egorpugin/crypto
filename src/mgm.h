#pragma once

#include "helpers.h"

#include <array>
#include <algorithm>
#include <cstring>
#include <span>
#include <stdexcept>

// no need to implement ccm

namespace crypto {

// see
// https://meganorm.ru/Data2/1/4293727/4293727270.pdf
// https://www.rfc-editor.org/rfc/rfc9058.html
template <typename Cipher>
struct mgm {
    static inline constexpr auto block_size_bytes = Cipher::block_size_bytes;
    static inline constexpr auto iv_size_bytes = 12; // 8 + 4
    static inline constexpr auto tag_size_bytes = 16;
    static inline constexpr auto key_size_bytes = Cipher::key_size_bytes;

    Cipher c;

    mgm() = default;
    mgm(bytes_concept k) {
        c.expand_key(k);
    }
    void inc_counter(auto &&what, int sz = block_size_bytes) {
        for (int i = sz; i >= 0; --i) {
            if (++what[i - 1] != 0)
                break;
        }
    }
    auto encrypt(auto &&nonce, auto &&data, auto &&auth_data) {
        array<block_size_bytes> T{}, Z, Y, L;
        memcpy(Z.data(), nonce.data(), nonce.size());
        memcpy(Y.data(), nonce.data(), nonce.size());

        Z[0] |= 0x80;
        Z = c.encrypt(Z);
        auto h = (auth_data.size() + block_size_bytes - 1) / block_size_bytes;
        std::string auth = auth_data;
        auth.resize(h * block_size_bytes, 0);
        for (int i = 0; i < h; ++i) {
            auto H = c.encrypt(Z);
            inc_counter(Z, block_size_bytes / 2);
            gmult(H, (uint8_t *)(auth.data() + i * block_size_bytes));
            for (int j = 0; j < block_size_bytes; ++j) {
                T[j] ^= H[j];
            }
        }
        auth.resize(auth_data.size());

        Y[0] &= 0x7f;
        Y = c.encrypt(Y);
        auto q = (data.size() + block_size_bytes - 1) / block_size_bytes;
        std::string out = data;
        out.resize(q * block_size_bytes, 0);
        for (int i = 0; i < q; ++i) {
            auto Ek = c.encrypt(Y);
            inc_counter(Y);
            for (int j = 0; j < block_size_bytes; ++j) {
                out[j + i * block_size_bytes] ^= Ek[j];
            }

            auto H = c.encrypt(Z);
            inc_counter(Z, block_size_bytes / 2);
            gmult(H, (uint8_t *)(out.data() + i * block_size_bytes));
            for (int j = 0; j < block_size_bytes; ++j) {
                T[j] ^= H[j];
            }
        }
        out.resize(data.size());

        auto H = c.encrypt(Z);
        print_buffer("H", H);

        *(uint64_t*)L.data() = std::byteswap(auth.size() * 8);
        *(((uint64_t *)L.data()) + 1) = std::byteswap(out.size() * 8);
        //L = c.encrypt(L);
        gmult(H, (uint8_t *)L.data());
        for (int j = 0; j < block_size_bytes; ++j) {
            T[j] ^= H[j];
        }

        T = c.encrypt(T);
        print_buffer("T", T);
        return out;
    }


    void set_iv(auto &&iv) {
    }
    auto encrypt(auto &&data, auto &&auth_data) {
        std::string out(data.size(), 0);
        //encrypt1(std::span<uint8_t>((uint8_t*)data.data(), data.size()), std::span<uint8_t>((uint8_t*)out.data(), out.size()));
        //auto auth_tag = make_tag(auth_data, out);
        out.resize(out.size() + tag_size_bytes);
        //memcpy(out.data() + data.size(), auth_tag.data(), tag_size_bytes);
        return out;
    }
    auto decrypt(auto &&data, auto &&auth_data) {
        std::string out(data.size() - tag_size_bytes, 0);
        return out;
    }

    void gmult(auto &&buf, uint8_t *buf2) {
        // for now
        *(uint64_t *)(buf.data() + 0) = std::byteswap(*(uint64_t *)(buf.data() + 0));
        *(uint64_t *)(buf.data() + 8) = std::byteswap(*(uint64_t *)(buf.data() + 8));
        *(uint64_t *)(buf2 + 0) = std::byteswap(*(uint64_t *)(buf2 + 0));
        *(uint64_t *)(buf2 + 8) = std::byteswap(*(uint64_t *)(buf2 + 8));

        gmult2((uint64_t *)buf.data(), (uint64_t *)buf2);

        *(uint64_t *)(buf.data() + 0) = std::byteswap(*(uint64_t *)(buf.data() + 0));
        *(uint64_t *)(buf.data() + 8) = std::byteswap(*(uint64_t *)(buf.data() + 8));
        *(uint64_t *)(buf2 + 0) = std::byteswap(*(uint64_t *)(buf2 + 0));
        *(uint64_t *)(buf2 + 8) = std::byteswap(*(uint64_t *)(buf2 + 8));
    }
    void gmult2(uint64_t *X, uint64_t *Y) {
        uint64_t Z[2] = {0, 0};
        uint64_t V[2];
        int i, j;
        V[0] = X[0];
        V[1] = X[1];
        for (i = 0; i < 2; i++) {
            auto y = Y[i];
            for (j = 0; j < 64; j++) {
                uint64_t mask = 0 - (y >> 63);
                Z[0] ^= V[0] & mask;
                Z[1] ^= V[1] & mask;
                auto v1 = (0 - (V[1] & 1)) & 0xE100000000000000ULL;
                V[1] >>= 1;
                V[1] |= V[0] << 63;
                V[0] >>= 1;
                V[0] ^= v1;
                y <<= 1;
            }
        }
        X[0] = Z[0];
        X[1] = Z[1];
    }
};

} // namespace crypto
