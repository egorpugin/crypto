// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include <array>
#include <bit>
#include <cstdint>
#include <type_traits>

namespace crypto {

template <auto StateBits_>
struct keccak_p {
    static inline constexpr auto StateBits = StateBits_;
    static inline constexpr auto b = StateBits;
    static inline constexpr auto state_square_size = 5;
    static inline constexpr auto state_size = state_square_size * state_square_size;
    static inline constexpr auto w = b / state_size;
    static consteval unsigned log2floor(auto x) {
        return x == 1 ? 0 : 1+log2floor(x >> 1);
    }
    static inline constexpr auto l = log2floor(w);
    using state_type = std::conditional_t<
            w == 64, u64, std::conditional_t<
                    w == 32, u32, std::conditional_t<
                            w == 16, uint16_t, std::conditional_t<
                                    w == 8, u8, u8 // also 4,2,1
                            >
                    >
            >
    >;
    static inline constexpr auto n_rounds = 12 + 2 * l;

    static constexpr int index(int x) {
        return x < 0 ? index(x + state_square_size) : x % state_square_size;
    }
    static constexpr int index(int x, int y) {
        return index(x) + state_square_size * index(y);
    }

    state_type A[state_size]{};

    void permute() noexcept {
        static constexpr int R[] = {
                0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
                25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
        };
        static constexpr u64 RC[] = {
                0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
                0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
                0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
                0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
                0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
                0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
                0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
                0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
        };

        decltype(A) B;
        state_type C[state_square_size], D[state_square_size];
        for (int r = 0; r < n_rounds; ++r) {
            for (int x = 0; x < state_square_size; ++x) {
                C[x] = A[index(x,0)] ^ A[index(x,1)] ^ A[index(x,2)] ^ A[index(x,3)] ^ A[index(x,4)];
            }
            for (int x = 0; x < state_square_size; ++x) {
                D[x] = C[index(x - 1)] ^ std::rotl(C[index(x + 1)], 1);
            }
            for (int x = 0; x < state_square_size; ++x) {
                for (int y = 0; y < state_square_size; ++y) {
                    A[index(x, y)] ^= D[x];
                }
            }
            for (int x = 0; x < state_square_size; ++x) {
                for (int y = 0; y < state_square_size; ++y) {
                    B[index(y, 2 * x + 3 * y)] = std::rotl(A[index(x, y)], R[index(x, y)]);
                }
            }
            for (int x = 0; x < state_square_size; ++x) {
                for (int y = 0; y < state_square_size; ++y) {
                    A[index(x, y)] = B[index(x, y)] ^ (~B[index(x + 1, y)] & B[index(x + 2, y)]);
                }
            }
            A[0] ^= RC[r];
        }
    }
};

// Padding: bits are counted from right to left (01234567), not as usual (76543210)!
// So, 0b10 in code means 01000000
template <auto Capacity, auto Padding>
struct keccak : keccak_p<1600>, hash_traits<keccak<Capacity, Padding>> {
    static inline constexpr auto rate = StateBits - Capacity;

    using hash_traits_type = hash_traits<keccak<Capacity, Padding>>;
    using hash_traits_type::update;

    int blockpos{};
    u64 bitlen{};

    void absorb(auto &&s) noexcept requires requires { s.size(); } {
        absorb((const u8 *)s.data(), s.size());
    }
    void absorb(const u8 *buf, size_t len) noexcept {
        update(buf, len);
    }
    void update(const u8 *buf, size_t len) noexcept {
        bitlen += len * 8;
        auto *d = (u8 *)A;
        for (int i = 0; i < len; ++i) {
            d[blockpos++] ^= buf[i];
            if (blockpos == rate / 8) {
                permute();
                blockpos = 0;
            }
        }
    }
    void pad() noexcept {
        auto *d = (u8 *)A;
        auto q = (rate - (bitlen % rate)) / 8;
        u8 q21 = Padding | (1 << (log2floor(Padding) + 1));
        u8 q22 = 0x80;
        d[blockpos++] ^= q21;
        blockpos += q - 2;
        d[blockpos++] ^= q22;
        permute();
    }
};

template <auto DigestSizeBits>
struct sha3_base : keccak<2 * DigestSizeBits, 0b10> {
    using base = keccak<2 * DigestSizeBits, 0b10>;
    static inline constexpr auto digest_size_bytes = DigestSizeBits / 8;

    auto digest() noexcept {
        base::pad(); // finalize()
        array<digest_size_bytes> hash;
        memcpy(hash.data(), (u8 *)base::A, hash.size());
        return hash;
    }
    static auto digest(auto &&v) noexcept {
        sha3_base h;
        h.update(v);
        return h.digest();
    }
};

template <auto ShakeType>
struct shake_base : keccak<2 * ShakeType, 0b1111> {
    using base = keccak<2 * ShakeType, 0b1111>;
    static inline constexpr auto digest_size_bytes = base::rate / 8;

    size_t offset{};

    auto finalize() noexcept {
        base::pad();
    }
    auto squeeze(auto &out) noexcept {
        auto ptr = out.data();
        auto end = ptr + out.size();
        auto step = [&](){
            auto len = std::min<size_t>(digest_size_bytes - offset, end - ptr);
            memcpy(ptr, (u8 *)base::A + offset, len);
            ptr += len;
            offset += len;
        };
        step();
        while (offset == digest_size_bytes) {
            base::permute();
            offset = 0;
            step();
        }
    }
    template <auto Bits>
    auto squeeze() noexcept {
        array<Bits / 8> hash;
        squeeze(hash);
        return hash;
    }
    auto squeeze() noexcept {
        array<digest_size_bytes> hash;
        squeeze(hash);
        return hash;
    }
};

template <auto DigestSizeBits> struct sha3;
template <auto ShakeType> struct shake;

template <> struct sha3<224> : sha3_base<224> {};
template <> struct sha3<256> : sha3_base<256> {};
template <> struct sha3<384> : sha3_base<384> {};
template <> struct sha3<512> : sha3_base<512> {};
template <> struct shake<128> : shake_base<128> {};
template <> struct shake<256> : shake_base<256> {};

} // namespace crypto
