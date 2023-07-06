#pragma once

#include <bit>
#include <cstdint>

namespace crypto {

static void chacha20_quarterround(uint32_t *x, int a, int b, int c, int d) {
    x[a] += x[b];
    x[d] = std::rotl(x[d] ^ x[a], 16);
    x[c] += x[d];
    x[b] = std::rotl(x[b] ^ x[c], 12);
    x[a] += x[b];
    x[d] = std::rotl(x[d] ^ x[a], 8);
    x[c] += x[d];
    x[b] = std::rotl(x[b] ^ x[c], 7);
}
static void chacha20_serialize(uint32_t in[16], uint8_t output[64]) {
    for (int i = 0; i < 16; i++) {
        //*(uint32_t*)(output + (i << 2)) = std::byteswap(in[i]);
        *(uint32_t*)(output + (i << 2)) = in[i];
    }
}
static void chacha20_block(uint32_t in[16], uint8_t out[64], int num_rounds) {
    uint32_t x[16];

    memcpy(x, in, sizeof(uint32_t) * 16);

    for (int i = num_rounds; i > 0; i -= 2) {
        chacha20_quarterround(x, 0, 4, 8, 12);
        chacha20_quarterround(x, 1, 5, 9, 13);
        chacha20_quarterround(x, 2, 6, 10, 14);
        chacha20_quarterround(x, 3, 7, 11, 15);
        chacha20_quarterround(x, 0, 5, 10, 15);
        chacha20_quarterround(x, 1, 6, 11, 12);
        chacha20_quarterround(x, 2, 7, 8, 13);
        chacha20_quarterround(x, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) {
        x[i] += in[i];
    }
    chacha20_serialize(x, out);
}
static void chacha20_init_state(uint32_t s[16], uint8_t key[32], uint32_t counter, uint8_t nonce[12]) {
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) {
        s[4 + i] = *(uint32_t*)(key + i * 4);
        //s[4 + i] = std::byteswap(*(uint32_t*)(key + i * 4));
    }
    s[12] = counter;
    for (int i = 0; i < 3; i++) {
        s[13 + i] = *(uint32_t*)(nonce + i * 4);
        //s[13 + i] = std::byteswap(*(uint32_t*)(nonce + i * 4));
    }
}
void chacha20(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t *in, uint8_t *out, int inlen) {
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
}

// tls13 specific
auto poly1305_key_gen(uint8_t key[32], uint8_t nonce[12]) {
    uint32_t s[16];
    uint8_t block[64];
    auto counter = 0;
    chacha20_init_state(s, key, counter, nonce);
    chacha20_block(s, block, 20);
    array<32> out;
    memcpy(out.data(), block, 32);
    for (int i = 0; i < 32 / 4; ++i) {
        //*(uint32_t*)(out.data() + i * 4) = std::byteswap(*(uint32_t*)(out.data() + i * 4));
    }
    return out;
}
auto poly1305_key_gen(uint8_t key[32], uint8_t nonce[12], uint8_t *in, uint8_t *out, int inlen) {
    uint32_t s[16];
    uint8_t block[64];
    auto counter = 0;
    chacha20_init_state(s, key, counter, nonce);
    chacha20_block(s, block, 20);
    array<32> outk;
    memcpy(outk.data(), block, 32);
    for (int i = 0; i < 32 / 4; ++i) {
        //*(uint32_t *)(outk.data() + i * 4) = std::byteswap(*(uint32_t *)(outk.data() + i * 4));
    }
    counter = 1;
    s[12] = counter;
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
    return outk;
}

} // namespace crypto
