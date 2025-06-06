// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "helpers.h"

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>

namespace crypto {

struct sha2_data {
    static inline constexpr u32 K256[] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
            0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
            0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
            0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
            0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
            0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
            0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
            0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
            0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    };
    static inline constexpr u64 K512[] = {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
            0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
            0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
            0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
            0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
            0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    };
    static inline constexpr std::array<u32, 8> h224 = {
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
    };
    static inline constexpr std::array<u32, 8> h256 = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    static inline constexpr std::array<u64, 8> h384 = {
            0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
            0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
    };
    static inline constexpr std::array<u64, 8> h512 = {
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    };
    static inline constexpr std::array<u64, 8> h512_224 = {
            0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
            0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
    };
    static inline constexpr std::array<u64, 8> h512_256 = {
            0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
            0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
    };

    template <auto ShaType, auto Bits> static consteval auto h() {
        if (0) {
        } else if constexpr (ShaType == 256 && Bits == 224) {
            return h224;
        } else if constexpr (ShaType == 256 && Bits == 256) {
            return h256;
        } else if constexpr (ShaType == 512 && Bits == 384) {
            return h384;
        } else if constexpr (ShaType == 512 && Bits == 512) {
            return h512;
        } else if constexpr (ShaType == 512 && Bits == 224) {
            return h512_224;
        } else if constexpr (ShaType == 512 && Bits == 256) {
            return h512_256;
        }
    }
    template <auto small> static consteval auto K() {
        if constexpr (small) {
            return K256;
        } else {
            return K512;
        }
    }
    template <auto small> static consteval auto sigma() {
        struct sigma_t {
            int r1,r2,sh;
        };
        return small ? std::array<sigma_t,2>{sigma_t{7,18,3},sigma_t{17,19,10}} : std::array<sigma_t,2>{sigma_t{1,8,7},sigma_t{19,61,6}};
    }
    template <auto small> static consteval auto sum() {
        struct sum_t {
            int r1,r2,r3;
        };
        return small ? std::array<sum_t,2>{sum_t{2,13,22},sum_t{6,11,25}} : std::array<sum_t,2>{sum_t{28,34,39},sum_t{14,18,41}};
    }
};

template <auto ShaType, auto DigestSizeBits = ShaType>
struct sha2_base : hash_traits<sha2_base<ShaType, DigestSizeBits>> {
    using hash_traits_type = hash_traits<sha2_base<ShaType, DigestSizeBits>>;
    using hash_traits_type::digest;
    using hash_traits_type::update;

    static_assert(ShaType == 256 || ShaType == 512);
    static inline constexpr auto small_sha = ShaType == 256;
    static inline constexpr auto rounds = small_sha ? 64 : 80;
    static inline constexpr auto chunk_size_bits = small_sha ? 512 : 1024;
    static inline constexpr auto chunk_size_bytes = chunk_size_bits / 8;
    static inline constexpr auto digest_size_bytes = DigestSizeBits / 8;
    using state_type = std::conditional_t<small_sha, u32, u64>;
    static inline constexpr auto state_size = 8;
    using message_length_type = std::conditional_t<small_sha, u64, uint128_t>;
    static inline constexpr auto K = sha2_data::K<small_sha>();
    static inline constexpr auto s = sha2_data::sigma<small_sha>();
    static inline constexpr auto S = sha2_data::sum<small_sha>();

    void update(const u8 *data, size_t length) noexcept {
        bitlen += length * 8;
        hash_traits_type::update_fast_post(data, length, m_data, sizeof(m_data), blockpos, [&]() {
            transform();
        });
    }
    auto digest() noexcept {
        pad();
        if constexpr (ShaType == 512 && DigestSizeBits < ShaType) {
            decltype(h) swapped;
            for (u8 i = 0; i < 8; i++) {
                swapped[i] = std::byteswap(h[i]);
            }
            array<DigestSizeBits / 8> hash;
            memcpy(hash.data(), swapped.data(), DigestSizeBits / 8);
            return hash;
        } else {
            array<DigestSizeBits / 8> hash;
            for (u8 i = 0; i < DigestSizeBits / 8 / sizeof(state_type); i++) {
                *(state_type *)(hash.data() + i * sizeof(state_type)) = std::byteswap(h[i]);
            }
            return hash;
        }
    }

private:
    u8 m_data[chunk_size_bytes];
    std::array<state_type, state_size> h{sha2_data::h<ShaType, DigestSizeBits>()};
    message_length_type bitlen{};
    int blockpos{};

    static constexpr auto choose(auto e, auto f, auto g) noexcept {
        return (e & f) ^ (~e & g);
    }
    static constexpr auto majority(auto a, auto b, auto c) noexcept {
        return (a & (b | c)) | (b & c);
    }
    template <auto P> static constexpr auto sigma(auto x) noexcept {
        using std::rotr;
        return rotr(x, P.r1) ^ rotr(x, P.r2) ^ (x >> P.sh);
    }
    template <auto P> static constexpr auto sum(auto x) noexcept {
        using std::rotr;
        return rotr(x, P.r1) ^ rotr(x, P.r2) ^ rotr(x, P.r3);
    }
    constexpr void transform() noexcept {
        state_type w[rounds];
        for (u8 i = 0; i < 16; ++i) {
            w[i] = std::byteswap(*(state_type *)(m_data + i * sizeof(state_type)));
        }
        for (u8 k = 16; k < rounds; ++k) {
            w[k] = sigma<s[1]>(w[k - 2]) + w[k - 7] + sigma<s[0]>(w[k - 15]) + w[k - 16];
        }
        auto state = h;
        for (u8 i = 0; i < rounds; ++i) {
            auto maj = majority(state[0], state[1], state[2]);
            auto ch = choose(state[4], state[5], state[6]);
            auto s = w[i] + K[i] + state[7] + ch + sum<S[1]>(state[4]);

            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = state[3] + s;
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = sum<S[0]>(state[0]) + maj + s;
        }
        for (u8 i = 0; i < state_size; ++i) {
            h[i] += state[i];
        }
    }
    constexpr void pad() noexcept {
        constexpr auto padding_size = chunk_size_bytes;
        constexpr auto bigint_size = padding_size / 8;
        constexpr auto padding_minus_bigint = padding_size - bigint_size;
        u8 end = blockpos < padding_minus_bigint ? padding_minus_bigint : padding_size;

        auto i = blockpos;
        m_data[i++] = 0x80;
        memset(m_data + i, 0, end - i);
        if (blockpos >= padding_minus_bigint) {
            transform();
            memset(m_data, 0, padding_minus_bigint);
        }

        // Append to the padding the total message's length in bits and transform.
        for (int i = 0; i < bigint_size; ++i) {
            //                              vvvvvvv msvc
            m_data[padding_size - i - 1] = (u8)(bitlen >> (i * 8));
        }
        transform();
    }

    friend struct sha2_data;
};

template <auto ShaType, auto DigestSizeBits = ShaType>
struct sha2;

template <> struct sha2<224> : sha2_base<256,224> {};
template <> struct sha2<256> : sha2_base<256> {};
template <> struct sha2<384> : sha2_base<512,384> {};
template <> struct sha2<512> : sha2_base<512> {};
template <> struct sha2<512,224> : sha2_base<512,224> {};
template <> struct sha2<512,256> : sha2_base<512,256> {};

using sha256 = sha2<256>;
using sha512 = sha2<512>;

} // namespace crypto
