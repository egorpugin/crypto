#pragma once

#include <cstdint>

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
            w == 64, uint64_t, std::conditional_t<
                    w == 32, uint32_t, std::conditional_t<
                            w == 16, uint16_t, std::conditional_t<
                                    w == 8, uint8_t, uint8_t // also 4,2,1
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

    void permute() {
        static constexpr int R[] = {
                0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
                25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
        };
        static constexpr uint64_t RC[] = {
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

template <auto DigestSizeBits, auto c = 2 * DigestSizeBits, auto Padding = 0b10>
struct keccak : keccak_p<1600> {
    static inline constexpr auto r = StateBits - c;

    int blockpos{};
    int64_t bitlen{};

    template <auto N> void update(const char (&s)[N]) {
        update((uint8_t*)s, N-1);
    }
    void update(auto &&s) requires requires { s.size(); } {
        update((const uint8_t *)s.data(), s.size());
    }
    void update(const uint8_t *buf, auto len) {
        bitlen += len * 8;
        auto *d = (uint8_t *)A;
        for (int i = 0; i < len; ++i) {
            d[blockpos++] ^= buf[i];
            check_permute();
        }
    }
    void check_permute() {
        if (blockpos == r / 8) {
            permute();
            blockpos = 0;
        }
    }
    void pad() {
        auto *d = (uint8_t *)A;
        auto q = (r - (bitlen % r)) / 8;
        uint8_t q21 = Padding | ((1 << log2floor(Padding) + 1));
        uint8_t q22 = 0x80;
        if (q == 1) {
            d[blockpos++] = q21 | q22;
        } else {
            d[blockpos++] = q21;
            memset(d + blockpos, 0, q - 2);
            blockpos += q - 2;
            d[blockpos++] = q22;
        }
        permute();
    }
    auto digest() {
        pad();
        std::array<uint8_t, DigestSizeBits / 8> hash;
        memcpy(hash.data(), (uint8_t *)A, hash.size());
        return hash;
    }
};

template <auto DigestSizeBits>
struct sha3;
template <auto ShakeType, auto DigestSizeBits>
struct shake;

template <> struct sha3<224> : keccak<224> {};
template <> struct sha3<256> : keccak<256> {};
template <> struct sha3<384> : keccak<384> {};
template <> struct sha3<512> : keccak<512> {};
template <auto DigestSizeBits> struct shake<128,DigestSizeBits> : keccak<DigestSizeBits,256,0b1111> {};
template <auto DigestSizeBits> struct shake<256,DigestSizeBits> : keccak<DigestSizeBits,512,0b1111> {};

} // namespace crypto
