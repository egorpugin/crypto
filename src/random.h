// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "helpers.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <wincrypt.h>
#elif __APPLE__
#include <sys/random.h>
#else
#include <unistd.h>
#endif

namespace crypto {

auto get_random_secure_bytes(uint8_t *p, size_t len) {
#ifdef _WIN32
    BCryptGenRandom(0, p, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    if (getentropy(p, len) == -1) {
        throw std::runtime_error{"cannot get entropy"};
    }
#endif
}
auto get_random_secure_bytes(unsigned n) {
    std::vector<uint8_t> v;
    v.resize(n);
    get_random_secure_bytes(v.data(), n);
    return v;
}
template <auto N>
void get_random_secure_bytes(uint8_t (&v)[N]) {
    get_random_secure_bytes(v, N);
}
void get_random_secure_bytes(auto &v) {
    get_random_secure_bytes((uint8_t*)v.data(), v.size());
}

} // namespace crypto
