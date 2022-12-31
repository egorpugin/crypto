#pragma once

#include "bigint.h"

// what about timing attacks & gmp?
#include <gmpxx.h>

namespace crypto {

struct bigint : mpz_class {
    using mpz_class::mpz_class;
    using mpz_class::operator=;

    bigint(const char *c) : mpz_class{c} {}

    operator mpz_ptr() { return __get_mp(); }
    operator mpz_srcptr() const { return __get_mp(); }

    auto &operator%=(const bigint &m) {
        mpz_mod(*this, *this, m);
        return *this;
    }
    auto operator%(const bigint &m) {
        auto b = *this;
        b %= m;
        return b;
    }
};

auto operator""_bi(const char *p, size_t len) {
    return bigint{p};
}

template <auto N>
bigint bytes_to_bigint(uint8_t (&v)[N], int order = 1) {
    bigint b;
    mpz_import(b.__get_mp(), N, order, sizeof(v[0]), 0, 0, v);
    return b;
}

} // namespace crypto
