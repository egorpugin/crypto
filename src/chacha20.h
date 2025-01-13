#pragma once

#include "helpers.h"

namespace crypto {

void salsa_quarterround(uint32_t *x, int a, int b, int c, int d) {
    x[b] ^= std::rotl(x[a] + x[d], 7);
    x[c] ^= std::rotl(x[b] + x[a], 9);
    x[d] ^= std::rotl(x[c] + x[b], 13);
    x[a] ^= std::rotl(x[d] + x[c], 18);
}
void salsa_block(uint32_t *in, uint32_t *out, int num_rounds = 20) {
	uint32_t x[16];
    memcpy(x, in, sizeof(uint32_t) * 16);
	for (int i = 0; i < num_rounds; i += 2) {
		// odd round
		salsa_quarterround(x,  0,  4,  8, 12); // column 1
		salsa_quarterround(x,  5,  9, 13,  1); // column 2
		salsa_quarterround(x, 10, 14,  2,  6); // column 3
		salsa_quarterround(x, 15,  3,  7, 11); // column 4
		// even round
		salsa_quarterround(x,  0,  1,  2,  3); // row 1
		salsa_quarterround(x,  5,  6,  7,  4); // row 2
		salsa_quarterround(x, 10, 11,  8,  9); // row 3
		salsa_quarterround(x, 15, 12, 13, 14); // row 4
	}
	for (int i = 0; i < 16; ++i) {
		out[i] = x[i] + in[i];
    }
}

//
void chacha_quarterround(uint32_t *x, int a, int b, int c, int d) {
    x[a] += x[b];
    x[d] = std::rotl(x[d] ^ x[a], 16);
    x[c] += x[d];
    x[b] = std::rotl(x[b] ^ x[c], 12);
    x[a] += x[b];
    x[d] = std::rotl(x[d] ^ x[a], 8);
    x[c] += x[d];
    x[b] = std::rotl(x[b] ^ x[c], 7);
}
void chacha_block(uint32_t in[16], uint8_t out[64], int num_rounds) {
    uint32_t x[16];
    memcpy(x, in, sizeof(uint32_t) * 16);
    for (int i = num_rounds; i > 0; i -= 2) {
        chacha_quarterround(x, 0, 4, 8, 12);
        chacha_quarterround(x, 1, 5, 9, 13);
        chacha_quarterround(x, 2, 6, 10, 14);
        chacha_quarterround(x, 3, 7, 11, 15);
        //
        chacha_quarterround(x, 0, 5, 10, 15);
        chacha_quarterround(x, 1, 6, 11, 12);
        chacha_quarterround(x, 2, 7, 8, 13);
        chacha_quarterround(x, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) {
        x[i] += in[i];
    }
    for (int i = 0; i < 16; i++) {
        *(uint32_t*)(out + (i << 2)) = x[i];
    }
}
void chacha_init_state(uint32_t s[16], uint8_t key[32], uint32_t counter, uint8_t nonce[12]) {
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) {
        s[4 + i] = *(uint32_t*)(key + i * 4);
    }
    s[12] = counter;
    for (int i = 0; i < 3; i++) {
        s[13 + i] = *(uint32_t*)(nonce + i * 4);
    }
}
/*void chacha20_raw(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t *in, uint8_t *out, int inlen) {
    uint32_t s[16];
    uint8_t block[64];
    chacha20_init_state(s, key, counter, nonce);
    for (int i = 0; i < inlen; i += 64) {
        chacha20_block(s, block, 20);
        ++s[12];
        for (int j = i; j < i + 64; j++) {
            if (j >= inlen) {
                break;
            }
            out[j] = in[j] ^ block[j - i];
        }
    }
}*/

template <auto N>
struct chacha {
    uint32_t s[16];
    uint8_t block[64];

    chacha(uint8_t *key, uint8_t *nonce, uint32_t counter = 0) {
        chacha_init_state(s, key, counter, nonce);
        chacha_block(s, block, N);
    }
    void cipher(uint8_t *in, uint8_t *out, uint32_t inlen) {
        for (int i = 0; i < inlen; i += 64) {
            chacha_block(s, block, N);
            ++s[12];
            for (int j = i; j < i + 64; j++) {
                if (j >= inlen) {
                    break;
                }
                out[j] = in[j] ^ block[j - i];
            }
        }
    }
    void set_counter(uint32_t counter) {
        s[12] = counter;
    }
};
using chacha20 = chacha<20>;

} // namespace crypto
