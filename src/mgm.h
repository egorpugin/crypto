// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "helpers.h"

#include <array>
#include <algorithm>
#include <cstring>
#include <span>
#include <stdexcept>

namespace crypto {

// see
// https://meganorm.ru/Data2/1/4293727/4293727270.pdf
// https://www.rfc-editor.org/rfc/rfc9058.html
template <typename Cipher>
struct mgm {
    static inline constexpr auto block_size_bytes = Cipher::block_size_bytes;
    static inline constexpr auto iv_size_bytes = block_size_bytes;
    static inline constexpr auto tag_size_bytes = block_size_bytes;
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
    auto encrypt(auto &&nonce, auto &&data, bytes_concept auth_data, bool decode = false) {
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
            mul(H, (uint8_t *)(auth.data() + i * block_size_bytes));
            for (int j = 0; j < block_size_bytes; ++j) {
                T[j] ^= H[j];
            }
        }
        auth.resize(auth_data.size());

        Y[0] &= 0x7f;
        Y = c.encrypt(Y);
        auto q = (data.size() + block_size_bytes - 1) / block_size_bytes;
        std::string out;
        out.resize(data.size());
        memcpy(out.data(), data.data(), data.size());

        auto calc_auth = [&]() {
            // ciphered text must be nulled up to q * block_size_bytes
            // so we calculate T in separate loop
            out.resize(q * block_size_bytes, 0);
            for (int i = 0; i < q; ++i) {
                auto H = c.encrypt(Z);
                inc_counter(Z, block_size_bytes / 2);
                mul(H, (uint8_t *)(out.data() + i * block_size_bytes));
                for (int j = 0; j < block_size_bytes; ++j) {
                    T[j] ^= H[j];
                }
            }
            out.resize(data.size());
        };

        if (decode) {
            calc_auth();
        }
        out.resize(q * block_size_bytes, 0);
        for (int i = 0; i < q; ++i) {
            auto Ek = c.encrypt(Y);
            inc_counter(Y);
            for (int j = 0; j < block_size_bytes; ++j) {
                out[j + i * block_size_bytes] ^= Ek[j];
            }
        }
        out.resize(data.size());
        if (!decode) {
            calc_auth();
        }

        auto H = c.encrypt(Z);
        using lentype = std::conditional_t<block_size_bytes == 8, uint32_t, uint64_t>;
        lentype sz = auth.size() * 8;
        *(lentype*)L.data() = std::byteswap(sz);
        sz = out.size() * 8;
        *(((lentype *)L.data()) + 1) = std::byteswap(sz);
        mul(H, (uint8_t *)L.data());
        for (int j = 0; j < block_size_bytes; ++j) {
            T[j] ^= H[j];
        }

        T = c.encrypt(T);
        return std::tuple{out,T};
    }
    auto decrypt(auto &&nonce, auto &&data, auto &&auth_data, auto &&auth_tag) {
        auto [dec,tag] = encrypt(nonce,data,auth_data,true);
        if (tag != auth_tag) {
            throw std::runtime_error{"auth tag is incorrect"};
        }
        return dec;
    }

    auto encrypt_and_tag(auto &&nonce, auto &&data, bytes_concept auth_data) {
        auto [out, tag] = encrypt(nonce, data, auth_data);
        auto sz = out.size();
        out.resize(out.size() + tag.size());
        memcpy(out.data() + sz, tag.data(), tag.size());
        return out;
    }
    auto decrypt_with_tag(auto &&nonce, auto &&data, auto &&auth_data) {
        bytes_concept enc{data};
        if (enc.size() < tag_size_bytes) {
            throw std::runtime_error{"data error"};
        }
        enc.sz -= tag_size_bytes;
        bytes_concept tag{data};
        tag = tag.subspan(enc.size());
        auto out = decrypt(nonce, enc, auth_data, tag);
        return out;
    }

    void mul(array<block_size_bytes> &buf, uint8_t *buf2) {
        if constexpr (block_size_bytes == 8) {
            mul64(buf, buf2);
        } else {
            gf128(buf, buf2);
        }
    }
    // [gogost.git] / mgm / mul64.go
    void mul64(array<block_size_bytes> &buf, uint8_t *buf2) {
        auto x = std::byteswap(*(uint64_t *)(buf.data() + 0));
        auto y = std::byteswap(*(uint64_t *)(buf2 + 0));
        uint64_t z = 0;
        while (y) {
            if (y & 1) {
                z ^= x;
            }
            if (x >> 63) {
                x <<= 1;
                x ^= 0x1b;
            } else {
                x <<= 1;
            }
            y >>= 1;
        }
        auto len = [](uint8_t *buf) {
            int xlen = 0;
            int i = 0;
            for (int i = 0; i < 8; ++i) {
                if (buf[i++]) {
                    break;
                }
                ++xlen;
            }
            return xlen;
        };
        *(uint64_t *)(buf.data() + 0) = std::byteswap(z);
    }
    // [gogost.git] / mgm / mul128.go
    void gf128(array<block_size_bytes> &buf, uint8_t *buf2) {
        auto x0 = std::byteswap(*(uint64_t *)(buf.data() + 8));
        auto x1 = std::byteswap(*(uint64_t *)(buf.data() + 0));
        auto y0 = std::byteswap(*(uint64_t *)(buf2 + 8));
        auto y1 = std::byteswap(*(uint64_t *)(buf2 + 0));

        uint64_t t,z0{},z1{};
        std::tie(t,x0,x1,z0,z1) = gf128half(64,y0,x0,x1,0,0);
        std::tie(t,x0,x1,z0,z1) = gf128half(63,y1,x0,x1,z0,z1);
        if (t & 1) {
            z0 ^= x0;
            z1 ^= x1;
        }

        *(uint64_t *)(buf.data() + 8) = std::byteswap(z0);
        *(uint64_t *)(buf.data() + 0) = std::byteswap(z1);
    }
    auto gf128half(int n, auto t, uint64_t x0, uint64_t x1, uint64_t z0, uint64_t z1) {
        for (int i = 0; i < n; ++i) {
            if (t & 1) {
                z0 ^= x0;
                z1 ^= x1;
            }
            t >>= 1;
            auto sign = x1 >> 63;
            x1 = (x1 << 1) ^ (x0 >> 63);
            x0 <<= 1;
            if (sign) {
                x0 ^= 0x87;
            }
        }
        return std::tuple{t, x0, x1, z0, z1};
    }
};

} // namespace crypto
