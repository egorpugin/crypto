// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "helpers.h"
#include "sha2.h"

namespace crypto {

template <auto DigestSizeBits, auto Width>
struct blake2_base {
    static_assert(Width == 64 || Width == 32);
    static_assert(DigestSizeBits / 8 >= 1 && DigestSizeBits / 8 <= Width);

    static inline constexpr auto rounds = Width == 64 ? 12 : 10;
    static inline constexpr auto bb = Width * 2;
    static inline constexpr int rot_constants32[] = {16,12,8,7};
    static inline constexpr int rot_constants64[] = {32,24,16,63};
    static inline constexpr auto R = Width == 64 ? rot_constants64 : rot_constants32;
    static inline constexpr auto iv = sha2_data::h<Width * 8, Width * 8>();
    static inline constexpr auto block_bytes = Width * 2;
    using message_length_type = std::conditional_t<Width == 64, uint128_t, uint64_t>;
    using state_type = std::conditional_t<Width == 64, uint64_t, uint32_t>;
    static inline constexpr int sigma[12][16] = {
        {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, },
        { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3, },
        { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4, },
        {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8, },
        {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13, },
        {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9, },
        { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11, },
        { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10, },
        {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5, },
        { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0, },

        {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, },
        { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3, },
    };

    blake2_base(bytes_concept key = bytes_concept{}, uint8_t output_bytes = DigestSizeBits / 8) : output_bytes{output_bytes} {
        if (output_bytes < 1 || output_bytes > Width) {
            throw std::runtime_error{"invalid output_bytes size"};
        }
        if (key.size() > Width) {
            throw std::runtime_error{"invalid key size"};
        }
        h = iv;
        h[0] = h[0] ^ 0x01010000 ^ (key.size() << 8) ^ output_bytes;
        if (key.size()) {
            memcpy(m, key.data(), key.size());
            bytelen += block_bytes;
            transform(false);
        }
    }
    void update(bytes_concept b) noexcept {
        update(b.data(), b.size());
    }
    void update(const uint8_t *data, size_t length) noexcept {
        return update_slow(data, length);
    }
    auto digest() noexcept {
        pad();
        std::vector<uint8_t> hash(output_bytes);
        memcpy(hash.data(), h.data(), output_bytes);
        return hash;
    }
    static auto digest(auto &&v) noexcept {
        blake2_base h;
        h.update(v);
        return h.digest();
    }

private:
    std::remove_const_t<decltype(iv)> h;
    state_type m[16]{};
    message_length_type bytelen{};
    int blockpos{};
    // parameters
    // make templated?
    uint8_t output_bytes;

    constexpr void pad() noexcept {
        auto padding_size = block_bytes - blockpos;
        memset(((uint8_t*)m) + blockpos, 0, padding_size);
        bytelen += blockpos;
        transform(true);
    }
    void update_slow(const uint8_t *data, size_t length) noexcept {
        for (size_t i = 0; i < length; ++i) {
            if (blockpos == block_bytes) {
                bytelen += block_bytes;
                transform(false);
                blockpos = 0;
            }
            ((uint8_t*)m)[blockpos++] = data[i];
        }
    }

    static void G(auto &&v, int a, int b, int c, int d, auto x, auto y) {
        v[a] = v[a] + v[b] + x;
        v[d] = std::rotr(v[d] ^ v[a], R[0]);
        v[c] = v[c] + v[d];
        v[b] = std::rotr(v[b] ^ v[c], R[1]);
        v[a] = v[a] + v[b] + y;
        v[d] = std::rotr(v[d] ^ v[a], R[2]);
        v[c] = v[c] + v[d];
        v[b] = std::rotr(v[b] ^ v[c], R[3]);
    }
    // F or Compress
    void transform(bool final) {
        state_type v[16];
        memcpy(&v[0], h.data(), h.size() * sizeof(state_type));
        memcpy(&v[8], iv.data(), iv.size() * sizeof(state_type));
        v[12] ^= bytelen;
        v[13] ^= bytelen >> Width;
        if (final) {
            v[14] = ~v[14];
        }
        for (int i = 0; i < rounds; ++i) {
            auto &s = sigma[i];

            G(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
            G(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
            G(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
            G(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);

            G(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
            G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            G(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
            G(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
        }
        for (int i = 0; i < 8; ++i) {
            h[i] ^= v[i] ^ v[i+8];
        }
    }
};

template <auto Bits> struct blake2s; // short
template <auto Bits> struct blake2b; // big

template <> struct blake2s<224> : blake2_base<224, 32> {using base = blake2_base<224, 32>; using base::base;};
template <> struct blake2s<256> : blake2_base<256, 32> {using base = blake2_base<256, 32>; using base::base;};
template <> struct blake2b<384> : blake2_base<384, 64> {using base = blake2_base<384, 64>; using base::base;};
template <> struct blake2b<512> : blake2_base<512, 64> {using base = blake2_base<512, 64>; using base::base;};

} // namespace crypto
