// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "helpers.h"

namespace crypto {

struct sm3 : hash_traits<sm3> {
    using hash_traits = hash_traits<sm3>;
    using hash_traits::digest;
    using hash_traits::update;

    static inline constexpr auto digest_size_bytes = 256 / 8;
    static inline constexpr auto chunk_size_bytes = 64;

    u32 h[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
    };
    u8 m_data[chunk_size_bytes];
    u64 bitlen{};
    int blockpos{};

    void update(const u8 *data, size_t length) noexcept {
        bitlen += length * 8;
        hash_traits::update_fast_post(data, length, m_data, sizeof(m_data), blockpos, [&]() {
            transform();
        });
    }
    auto digest() {
        pad();
        array<digest_size_bytes> r;
        for (int i = 0; i < 8; ++i) {
            *(u32 *)(r.data() + i * 4) = std::byteswap(h[i]);
        }
        return r;
    }

/*
  Transform the message X which consists of 16 32-bit-words. See
  GM/T 004-2012 for details.  */
#define R(i, a, b, c, d, e, f, g, h, t, w1, w2)                                                                                                                \
    do {                                                                                                                                                       \
        ss1 = std::rotl((std::rotl((a), 12) + (e) + (t)), 7);                                                                                                  \
        ss2 = ss1 ^ std::rotl((a), 12);                                                                                                                        \
        d += FFx##i(a, b, c) + ss2 + ((w1) ^ (w2));                                                                                                             \
        h += GG##i(e, f, g) + ss1 + (w1);                                                                                                                      \
        b = std::rotl((b), 9);                                                                                                                                 \
        f = std::rotl((f), 19);                                                                                                                                \
        h = P0((h));                                                                                                                                           \
    } while (0)

#define R1(a, b, c, d, e, f, g, h, t, w1, w2) R(1, a, b, c, d, e, f, g, h, t, w1, w2)
#define R2(a, b, c, d, e, f, g, h, t, w1, w2) R(2, a, b, c, d, e, f, g, h, t, w1, w2)

#define FFx1(x, y, z) (x ^ y ^ z)
#define FFx2(x, y, z) ((x & y) | (x & z) | (y & z))

#define GG1(x, y, z) (x ^ y ^ z)
#define GG2(x, y, z) ((x & y) | (~x & z))

/* Message expansion */
#define P0(x) ((x) ^ std::rotl((x), 9) ^ std::rotl((x), 17))
#define P1(x) ((x) ^ std::rotl((x), 15) ^ std::rotl((x), 23))
#define I(i) (w[i] = std::byteswap(*(u32 *)(m_data + i * 4)))
#define W1(i) (w[i & 0x0f])
#define W2(i) (w[i & 0x0f] = P1(w[i & 0x0f] ^ w[(i - 9) & 0x0f] ^ std::rotl(w[(i - 3) & 0x0f], 15)) ^ std::rotl(w[(i - 13) & 0x0f], 7) ^ w[(i - 6) & 0x0f])

    void transform() {
        static const u32 K[64] = {0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb, 0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc, 0xcc451979, 0x988a32f3,
                                  0x311465e7, 0x6228cbce, 0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6, 0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c,
                                  0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce, 0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1,
                                  0x9ea1e762, 0x3d43cec5, 0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53, 0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
                                  0x879d8a7a, 0x0f3b14f5, 0x1e7629ea, 0x3cec53d4, 0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43, 0x9d8a7a87, 0x3b14f50f,
                                  0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce, 0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
                                  0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5};

        u32 a, b, c, d, e, f, g, h, ss1, ss2;
        u32 w[16];

        a = this->h[0];
        b = this->h[1];
        c = this->h[2];
        d = this->h[3];
        e = this->h[4];
        f = this->h[5];
        g = this->h[6];
        h = this->h[7];

        R1(a, b, c, d, e, f, g, h, K[0], I(0), I(4));
        R1(d, a, b, c, h, e, f, g, K[1], I(1), I(5));
        R1(c, d, a, b, g, h, e, f, K[2], I(2), I(6));
        R1(b, c, d, a, f, g, h, e, K[3], I(3), I(7));
        R1(a, b, c, d, e, f, g, h, K[4], W1(4), I(8));
        R1(d, a, b, c, h, e, f, g, K[5], W1(5), I(9));
        R1(c, d, a, b, g, h, e, f, K[6], W1(6), I(10));
        R1(b, c, d, a, f, g, h, e, K[7], W1(7), I(11));
        R1(a, b, c, d, e, f, g, h, K[8], W1(8), I(12));
        R1(d, a, b, c, h, e, f, g, K[9], W1(9), I(13));
        R1(c, d, a, b, g, h, e, f, K[10], W1(10), I(14));
        R1(b, c, d, a, f, g, h, e, K[11], W1(11), I(15));
        R1(a, b, c, d, e, f, g, h, K[12], W1(12), W2(16));
        R1(d, a, b, c, h, e, f, g, K[13], W1(13), W2(17));
        R1(c, d, a, b, g, h, e, f, K[14], W1(14), W2(18));
        R1(b, c, d, a, f, g, h, e, K[15], W1(15), W2(19));

        R2(a, b, c, d, e, f, g, h, K[16], W1(16), W2(20));
        R2(d, a, b, c, h, e, f, g, K[17], W1(17), W2(21));
        R2(c, d, a, b, g, h, e, f, K[18], W1(18), W2(22));
        R2(b, c, d, a, f, g, h, e, K[19], W1(19), W2(23));
        R2(a, b, c, d, e, f, g, h, K[20], W1(20), W2(24));
        R2(d, a, b, c, h, e, f, g, K[21], W1(21), W2(25));
        R2(c, d, a, b, g, h, e, f, K[22], W1(22), W2(26));
        R2(b, c, d, a, f, g, h, e, K[23], W1(23), W2(27));
        R2(a, b, c, d, e, f, g, h, K[24], W1(24), W2(28));
        R2(d, a, b, c, h, e, f, g, K[25], W1(25), W2(29));
        R2(c, d, a, b, g, h, e, f, K[26], W1(26), W2(30));
        R2(b, c, d, a, f, g, h, e, K[27], W1(27), W2(31));
        R2(a, b, c, d, e, f, g, h, K[28], W1(28), W2(32));
        R2(d, a, b, c, h, e, f, g, K[29], W1(29), W2(33));
        R2(c, d, a, b, g, h, e, f, K[30], W1(30), W2(34));
        R2(b, c, d, a, f, g, h, e, K[31], W1(31), W2(35));

        R2(a, b, c, d, e, f, g, h, K[32], W1(32), W2(36));
        R2(d, a, b, c, h, e, f, g, K[33], W1(33), W2(37));
        R2(c, d, a, b, g, h, e, f, K[34], W1(34), W2(38));
        R2(b, c, d, a, f, g, h, e, K[35], W1(35), W2(39));
        R2(a, b, c, d, e, f, g, h, K[36], W1(36), W2(40));
        R2(d, a, b, c, h, e, f, g, K[37], W1(37), W2(41));
        R2(c, d, a, b, g, h, e, f, K[38], W1(38), W2(42));
        R2(b, c, d, a, f, g, h, e, K[39], W1(39), W2(43));
        R2(a, b, c, d, e, f, g, h, K[40], W1(40), W2(44));
        R2(d, a, b, c, h, e, f, g, K[41], W1(41), W2(45));
        R2(c, d, a, b, g, h, e, f, K[42], W1(42), W2(46));
        R2(b, c, d, a, f, g, h, e, K[43], W1(43), W2(47));
        R2(a, b, c, d, e, f, g, h, K[44], W1(44), W2(48));
        R2(d, a, b, c, h, e, f, g, K[45], W1(45), W2(49));
        R2(c, d, a, b, g, h, e, f, K[46], W1(46), W2(50));
        R2(b, c, d, a, f, g, h, e, K[47], W1(47), W2(51));

        R2(a, b, c, d, e, f, g, h, K[48], W1(48), W2(52));
        R2(d, a, b, c, h, e, f, g, K[49], W1(49), W2(53));
        R2(c, d, a, b, g, h, e, f, K[50], W1(50), W2(54));
        R2(b, c, d, a, f, g, h, e, K[51], W1(51), W2(55));
        R2(a, b, c, d, e, f, g, h, K[52], W1(52), W2(56));
        R2(d, a, b, c, h, e, f, g, K[53], W1(53), W2(57));
        R2(c, d, a, b, g, h, e, f, K[54], W1(54), W2(58));
        R2(b, c, d, a, f, g, h, e, K[55], W1(55), W2(59));
        R2(a, b, c, d, e, f, g, h, K[56], W1(56), W2(60));
        R2(d, a, b, c, h, e, f, g, K[57], W1(57), W2(61));
        R2(c, d, a, b, g, h, e, f, K[58], W1(58), W2(62));
        R2(b, c, d, a, f, g, h, e, K[59], W1(59), W2(63));
        R2(a, b, c, d, e, f, g, h, K[60], W1(60), W2(64));
        R2(d, a, b, c, h, e, f, g, K[61], W1(61), W2(65));
        R2(c, d, a, b, g, h, e, f, K[62], W1(62), W2(66));
        R2(b, c, d, a, f, g, h, e, K[63], W1(63), W2(67));

        this->h[0] ^= a;
        this->h[1] ^= b;
        this->h[2] ^= c;
        this->h[3] ^= d;
        this->h[4] ^= e;
        this->h[5] ^= f;
        this->h[6] ^= g;
        this->h[7] ^= h;
    }
#undef P0
#undef P1
#undef R
#undef R1
#undef R2
#undef FF1
#undef FF2
#undef GG1
#undef GG2

    void pad() {
        if (blockpos < 56) {
            m_data[blockpos++] = 0x80;
            memset(m_data + blockpos, 0, 56 - blockpos);
            blockpos = 56;
        } else {
            m_data[blockpos++] = 0x80;
            memset(m_data + blockpos, 0, 64 - blockpos);
            transform();
            memset(m_data, 0, blockpos = 56);
        }
        *(u64 *)(m_data + blockpos) = std::byteswap(bitlen);
        transform();
    }
};

} // namespace crypto
