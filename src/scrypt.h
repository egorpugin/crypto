// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "hmac.h"
#include "chacha20.h"

namespace crypto {

void scryptBlockMix(uint8_t *B, uint8_t *out, int r) {
    constexpr auto block_size = 64;

    uint8_t X[block_size];
    std::vector<uint8_t> Y(block_size * 2 * r);
    memcpy(X, B + block_size * (2 * r - 1), block_size);
    for (int i = 0; i < 2 * r; ++i) {
        for (int j = 0; j < block_size; ++j) {
            X[j] ^= B[i * block_size + j];
        }
        salsa_block((uint32_t*)X, (uint32_t*)X, 8);
        memcpy(Y.data() + block_size * (i / 2 + (i % 2) * r), X, block_size);
    }
    memcpy(out, Y.data(), Y.size());
}

void scryptROMix(bytes_concept B, bytes_concept out, int r, int N) {
    auto sz = B.size();
    std::vector<uint8_t> X(sz);
    memcpy(X.data(), B.data(), sz);
    std::vector<uint8_t> V(sz * N);
    for (int i = 0; i < N; ++i) {
        memcpy(V.data() + sz * i, X.data(), sz);
        scryptBlockMix(X.data(), X.data(), r);
    }
    for (int i = 0; i < N; ++i) {
        auto j = *(uint32_t*)&X[(2 * r - 1) * 64] % N;
        for (int k = 0; k < sz; ++k) {
            X[k] ^= V[j * sz + k];
        }
        scryptBlockMix(X.data(), X.data(), r);
    }
    memcpy(out.data(), X.data(), sz);
}

auto scrypt(bytes_concept password, bytes_concept salt, int N, int r, int p, int dklen) {
    auto B = pbkdf2<sha2<256>>(password, salt, 1, p * 128 * r);
    for (int i = 0; i < p; ++i) {
        std::span<uint8_t> part(B.data() + i * 128 * r, 128 * r);
        scryptROMix(part, part, r, N);
    }
    return pbkdf2<sha2<256>>(password, B, 1, dklen);
}

}
