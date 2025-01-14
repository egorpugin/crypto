#pragma once

#include "helpers.h"

namespace crypto {

struct salsa_chacha_index {
    int round1[16];
    int round2[16];
};

template <auto idx>
void salsa_chacha_block(auto &&f, uint32_t *in, uint32_t *out, int num_rounds) {
	uint32_t x[16];
    memcpy(x, in, sizeof(x));
    auto round = [&](auto &&v) {
		f(x, v[0], v[1], v[2], v[3]);
		f(x, v[4], v[5], v[6], v[7]);
		f(x, v[8], v[9], v[10], v[11]);
		f(x, v[12], v[13], v[14], v[15]);
    };
	for (int i = 0; i < num_rounds; i += 2) {
        round(idx.round1);
        round(idx.round2);
	}
	for (int i = 0; i < 16; ++i) {
		out[i] = x[i] + in[i];
    }
}
void salsa_block(uint32_t *in, uint32_t *out, int num_rounds = 20) {
    constexpr salsa_chacha_index idx{{
         0,  4,  8, 12,
         5,  9, 13,  1,
        10, 14,  2,  6,
        15,  3,  7, 11,
    }, {
         0,  1,  2,  3,
         5,  6,  7,  4,
        10, 11,  8,  9,
        15, 12, 13, 14,
    }};
    constexpr auto f = [](uint32_t *x, int a, int b, int c, int d) {
        x[b] ^= std::rotl(x[a] + x[d], 7);
        x[c] ^= std::rotl(x[b] + x[a], 9);
        x[d] ^= std::rotl(x[c] + x[b], 13);
        x[a] ^= std::rotl(x[d] + x[c], 18);
    };
    salsa_chacha_block<idx>(f, in, out, num_rounds);
}
void chacha_block(uint32_t *in, uint32_t *out, int num_rounds) {
    constexpr salsa_chacha_index idx{{
        0, 4, 8, 12,
        1, 5, 9, 13,
        2, 6, 10, 14,
        3, 7, 11, 15,
    }, {
        0, 5, 10, 15,
        1, 6, 11, 12,
        2, 7, 8, 13,
        3, 4, 9, 14
    }};
    constexpr auto f = [](uint32_t *x, int a, int b, int c, int d) {
        x[a] += x[b];
        x[d] = std::rotl(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = std::rotl(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = std::rotl(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = std::rotl(x[b] ^ x[c], 7);
    };
    salsa_chacha_block<idx>(f, in, out, num_rounds);
}

template <auto N>
struct chacha {
    uint32_t s[4]{
        0x61707865,
        0x3320646e,
        0x79622d32,
        0x6b206574,
    };
    uint32_t key[8];
    uint32_t counter;
    uint32_t nonce[3];
    uint8_t block[64];

    chacha(uint8_t *key, uint8_t *nonce, uint32_t counter = 0) {
        memcpy(this->key, key, sizeof(this->key));
        set_counter(counter);
        memcpy(this->nonce, nonce, sizeof(this->nonce));
        chacha_block(s, (uint32_t*)block, N);
    }
    void cipher(uint8_t *in, uint8_t *out, uint32_t inlen) {
        for (int i = 0; i < inlen; i += 64) {
            chacha_block(s, (uint32_t*)block, N);
            ++counter;
            for (int j = i; j < i + 64; j++) {
                if (j >= inlen) {
                    break;
                }
                out[j] = in[j] ^ block[j - i];
            }
        }
    }
    void set_counter(uint32_t counter) {
        this->counter = counter;
    }
};
using chacha20 = chacha<20>;

} // namespace crypto
