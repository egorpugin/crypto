#pragma once

#include "helpers.h"

namespace crypto {

struct magma_data {
    // "TC26_Z" "1.2.643.7.1.2.5.1.1"
    //static inline constexpr auto keymeshing = 1;
    static inline constexpr uint8_t S[16 * 8] = {
        0xc, 0x6, 0xb, 0xc, 0x7, 0x5, 0x8, 0x1,
        0x4, 0x8, 0x3, 0x8, 0xf, 0xd, 0xe, 0x7,
        0x6, 0x2, 0x5, 0x2, 0x5, 0xf, 0x2, 0xe,
        0x2, 0x3, 0x8, 0x1, 0xa, 0x6, 0x5, 0xd,

        0xa, 0x9, 0x2, 0xd, 0x8, 0x9, 0x6, 0x0,
        0x5, 0xa, 0xf, 0x4, 0x1, 0x2, 0x9, 0x5,
        0xb, 0x5, 0xa, 0xf, 0x6, 0xc, 0x1, 0x8,
        0x9, 0xc, 0xd, 0x6, 0xd, 0xa, 0xc, 0x3,

        0xe, 0x1, 0xe, 0x7, 0x0, 0xb, 0xf, 0x4,
        0x8, 0xe, 0x1, 0x0, 0x9, 0x7, 0x4, 0xf,
        0xd, 0x4, 0x7, 0xa, 0x3, 0x8, 0xb, 0xa,
        0x7, 0x7, 0x4, 0x5, 0xe, 0x1, 0x0, 0x6,

        0x0, 0xb, 0xc, 0x3, 0xb, 0x4, 0xd, 0x9,
        0x3, 0xd, 0x9, 0xe, 0x4, 0x3, 0xa, 0xc,
        0xf, 0x0, 0x6, 0x9, 0x2, 0xe, 0x3, 0xb,
        0x1, 0xf, 0x0, 0xb, 0xc, 0x0, 0x7, 0x2,
    };

    static inline constexpr uint8_t seq_encrypt[] = {
        0, 1, 2, 3, 4, 5, 6, 7,
        0, 1, 2, 3, 4, 5, 6, 7,
        0, 1, 2, 3, 4, 5, 6, 7,
        7, 6, 5, 4, 3, 2, 1, 0,
    };
    static inline constexpr uint8_t seq_decrypt[] = {
        0, 1, 2, 3, 4, 5, 6, 7,
        7, 6, 5, 4, 3, 2, 1, 0,
        7, 6, 5, 4, 3, 2, 1, 0,
        7, 6, 5, 4, 3, 2, 1, 0,
    };
};

struct magma : magma_data {
    static inline constexpr auto block_size_bytes = 8;
    static inline constexpr auto key_size_bytes = 32;

    using vect = array<block_size_bytes>;
    using key_type = array<key_size_bytes>;

    uint32_t key[8];

    void expand_key(const key_type &key) noexcept {
        for (int i = 0; i < 8; ++i) {
            this->key[i] = std::byteswap(*(uint32_t*)(key.data() + i * sizeof(uint32_t)));
        }
    }
    auto crypt(const vect &blk, auto &&seq) noexcept {
        auto out = blk;

        *(uint64_t *)out.data() = std::byteswap(*(uint64_t *)out.data());
        auto n1 = *(uint32_t *)out.data();
        auto n2 = *(uint32_t *)(out.data() + 4);

        for (auto i : seq) {
            auto t = n1;
            n1 = gost_val(key[i], n1) ^ n2;
            n2 = t;
        }

        *(uint32_t *)out.data() = n2;
        *(uint32_t *)(out.data() + 4) = n1;
        *(uint64_t *)out.data() = std::byteswap(*(uint64_t *)out.data());

        return out;
    }
    auto encrypt(const vect &blk) noexcept {
        return crypt(blk, seq_encrypt);
    }
    auto decrypt(const vect &blk) noexcept {
        return crypt(blk, seq_decrypt);
    }

    uint32_t gost_val(uint32_t subkey, uint32_t cm1) {
        cm1 += subkey;
        uint32_t cm2{};
        for (int i = 0; i < 8; ++i) {
            cm2 += S[((cm1 >> i * 4) & 0x0f) * 8 + i] << i * 4;
        }
        cm1 = std::rotl(cm2, 11);
        return cm1;
    }
};

} // namespace crypto
