#include "helpers.h"

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <wincrypt.h>

namespace crypto {

auto get_random_secure_bytes(unsigned n) {
    std::vector<uint8_t> v;
    v.resize(n);
    BCryptGenRandom(0, v.data(), n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return v;
}
template <auto N>
void get_random_secure_bytes(uint8_t (&v)[N]) {
    BCryptGenRandom(0, v, N, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}
void get_random_secure_bytes(auto &v) {
    BCryptGenRandom(0, (uint8_t*)v.data(), v.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

} // namespace crypto
