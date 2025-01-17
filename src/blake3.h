#pragma once

#include "helpers.h"
#include "sha2.h"

namespace crypto {

struct blake3 {
    enum flags {
        CHUNK_START         = 0x01,
        CHUNK_END           = 0x02,
        PARENT              = 0x04,
        ROOT                = 0x08,
        KEYED_HASH          = 0x10,
        DERIVE_KEY_CONTEXT  = 0x20,
        DERIVE_KEY_MATERIAL = 0x40,
    };
    inline static constexpr auto iv = sha2_data::h<32 * 8, 32 * 8>();
    inline static constexpr uint8_t P[7][16] = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
        {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
        {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
        {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
        {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
        {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
    };

    uint32_t h[8];
    uint8_t m[64];
    uint64_t n_chunks{};
    int blockpos{};

    blake3() {
        memcpy(h, iv.data(), sizeof(h));
    }

    void compress(bytes_concept in, uint64_t counter, uint8_t flags) {
        memcpy(m, in.data(), in.size());
        memset(m + in.size(), 0, sizeof(m) - in.size());

        uint32_t v[16];
        memcpy(v, h, sizeof(h));
        memcpy(v+8, iv.data(), iv.size() * sizeof(uint32_t) / 2);
        v[12] = counter;
        v[13] = counter >> 32;
        v[14] = in.size();
        v[15] = flags;

        for (int i = 0; i < 7; ++i) {
            round(v, (uint32_t*)m, (uint8_t*)P[i]);
        }
        for (int i = 0; i < 8; ++i) {
            h[i] = v[i] ^ v[i + 8];
        }
    }
    static void G(uint32_t *v, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t y) {
        v[a] = v[a] + v[b] + x;
        v[d] = std::rotr(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = std::rotr(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + y;
        v[d] = std::rotr(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d];
        v[b] = std::rotr(v[b] ^ v[c], 7);
    }
    static void round(uint32_t *v, uint32_t *m, uint8_t *s) {
        G(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        G(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        G(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        G(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);

        G(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        G(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }
};

} // namespace crypto
