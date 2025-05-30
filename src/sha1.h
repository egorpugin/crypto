// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "helpers.h"

namespace crypto {

struct sha1 : hash_traits<sha1> {
    using hash_traits_type = hash_traits<sha1>;
    using hash_traits_type::digest;
    using hash_traits_type::update;

    static inline constexpr auto state_size = 5;
    static inline constexpr auto digest_size_bytes = state_size * sizeof(u32);

    u32 state[state_size] = {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
    };
    u8 buffer[64]{};
    int blockpos{};
    u64 n_bytes{};

    void update(const u8 *data, size_t length) noexcept {
        n_bytes += length;
        hash_traits_type::update_fast_post(data, length, buffer, sizeof(buffer), blockpos, [&]() {
            transform();
        });
    }
    auto digest() {
        // pad
        buffer[blockpos++] = 0x80;
        auto orig_size = blockpos;
        while (blockpos < sizeof(buffer)) {
            buffer[blockpos++] = 0;
        }
        if (orig_size > sizeof(buffer) - 8) {
            transform();
            for (size_t i = 0; i < sizeof(buffer) - 8; i++) {
                buffer[i] = 0;
            }
        }

        u64 total_bits = n_bytes * 8;
        *(u64 *)(buffer + sizeof(buffer) - 8) = std::byteswap(total_bits);
        transform();

        array<digest_size_bytes> res;
        for (int i = 0; auto &&d : state) {
            ((u32 *)res.data())[i++] = std::byteswap(d);
        }
        return res;
    }

private:
    void transform() {
        auto block = (u32 *)buffer;
        for (int i = 0; i < 16; ++i) {
            block[i] = std::byteswap(block[i]);
        }

        auto blk = [&](size_t i) {
            block[i] = std::rotl(block[(i + 13) & 15] ^ block[(i + 8) & 15] ^ block[(i + 2) & 15] ^ block[i], 1);
        };
        auto tail = [&](u32 v, u32 &w, u32 &z, size_t i, u32 const_) {
            z += block[i] + const_ + std::rotl(v, 5);
            w = std::rotl(w, 30);
        };
        auto R0 = [&](u32 v, u32 &w, u32 x, u32 y, u32 &z, size_t i) {
            z += (w & (x ^ y)) ^ y;
            tail(v, w, z, i, 0x5a827999);
        };
        auto R1 = [&](u32 v, u32 &w, u32 x, u32 y, u32 &z, size_t i) {
            blk(i);
            R0(v,w,x,y,z,i);
        };
        auto R2_0 = [&](u32 v, u32 &w, u32 x, u32 y, u32 &z, size_t i, u32 const_) {
            blk(i);
            z += w ^ x ^ y;
            tail(v, w, z, i, const_);
        };
        auto R2 = [&](auto &&...args) {
            R2_0(args..., 0x6ed9eba1);
        };
        auto R3 = [&](u32 v, u32 &w, u32 x, u32 y, u32 &z, size_t i) {
            blk(i);
            z += ((w | x) & y) | (w & x);
            tail(v, w, z, i, 0x8f1bbcdc);
        };
        auto R4 = [&](auto &&...args) {
            R2_0(args..., 0xca62c1d6);
        };

        auto a = state[0];
        auto b = state[1];
        auto c = state[2];
        auto d = state[3];
        auto e = state[4];

        R0(a, b, c, d, e, 0);
        R0(e, a, b, c, d, 1);
        R0(d, e, a, b, c, 2);
        R0(c, d, e, a, b, 3);
        R0(b, c, d, e, a, 4);
        R0(a, b, c, d, e, 5);
        R0(e, a, b, c, d, 6);
        R0(d, e, a, b, c, 7);
        R0(c, d, e, a, b, 8);
        R0(b, c, d, e, a, 9);
        R0(a, b, c, d, e, 10);
        R0(e, a, b, c, d, 11);
        R0(d, e, a, b, c, 12);
        R0(c, d, e, a, b, 13);
        R0(b, c, d, e, a, 14);
        R0(a, b, c, d, e, 15);
        R1(e, a, b, c, d, 0);
        R1(d, e, a, b, c, 1);
        R1(c, d, e, a, b, 2);
        R1(b, c, d, e, a, 3);
        R2(a, b, c, d, e, 4);
        R2(e, a, b, c, d, 5);
        R2(d, e, a, b, c, 6);
        R2(c, d, e, a, b, 7);
        R2(b, c, d, e, a, 8);
        R2(a, b, c, d, e, 9);
        R2(e, a, b, c, d, 10);
        R2(d, e, a, b, c, 11);
        R2(c, d, e, a, b, 12);
        R2(b, c, d, e, a, 13);
        R2(a, b, c, d, e, 14);
        R2(e, a, b, c, d, 15);
        R2(d, e, a, b, c, 0);
        R2(c, d, e, a, b, 1);
        R2(b, c, d, e, a, 2);
        R2(a, b, c, d, e, 3);
        R2(e, a, b, c, d, 4);
        R2(d, e, a, b, c, 5);
        R2(c, d, e, a, b, 6);
        R2(b, c, d, e, a, 7);
        R3(a, b, c, d, e, 8);
        R3(e, a, b, c, d, 9);
        R3(d, e, a, b, c, 10);
        R3(c, d, e, a, b, 11);
        R3(b, c, d, e, a, 12);
        R3(a, b, c, d, e, 13);
        R3(e, a, b, c, d, 14);
        R3(d, e, a, b, c, 15);
        R3(c, d, e, a, b, 0);
        R3(b, c, d, e, a, 1);
        R3(a, b, c, d, e, 2);
        R3(e, a, b, c, d, 3);
        R3(d, e, a, b, c, 4);
        R3(c, d, e, a, b, 5);
        R3(b, c, d, e, a, 6);
        R3(a, b, c, d, e, 7);
        R3(e, a, b, c, d, 8);
        R3(d, e, a, b, c, 9);
        R3(c, d, e, a, b, 10);
        R3(b, c, d, e, a, 11);
        R4(a, b, c, d, e, 12);
        R4(e, a, b, c, d, 13);
        R4(d, e, a, b, c, 14);
        R4(c, d, e, a, b, 15);
        R4(b, c, d, e, a, 0);
        R4(a, b, c, d, e, 1);
        R4(e, a, b, c, d, 2);
        R4(d, e, a, b, c, 3);
        R4(c, d, e, a, b, 4);
        R4(b, c, d, e, a, 5);
        R4(a, b, c, d, e, 6);
        R4(e, a, b, c, d, 7);
        R4(d, e, a, b, c, 8);
        R4(c, d, e, a, b, 9);
        R4(b, c, d, e, a, 10);
        R4(a, b, c, d, e, 11);
        R4(e, a, b, c, d, 12);
        R4(d, e, a, b, c, 13);
        R4(c, d, e, a, b, 14);
        R4(b, c, d, e, a, 15);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }
};

} // namespace crypto
