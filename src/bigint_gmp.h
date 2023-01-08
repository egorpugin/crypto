#pragma once

#include "helpers.h"

// what about timing attacks & gmp?
#include <gmpxx.h>

namespace crypto {

struct bigint : mpz_class {
    using mpz_class::mpz_class;
    using mpz_class::operator=;

    bigint(const char *c) : mpz_class{c} {}
    bigint(string_view sv) {
        std::string s;
        s += sv;
        mpz_init_set_str(*this, s.data(), 0);
    }

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
    template <auto N>
    operator array<N>() const {
        array<N> d;
        auto ptr = mpz_export(d.data(), 0, 1, 1, 0, 0, *this);
        if (ptr != d.data()) {
            throw std::runtime_error{"bigint error"};
        }
        return d;
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
template <auto N>
bigint bytes_to_bigint(const array<N> &v, int order = 1) {
    bigint b;
    mpz_import(b.__get_mp(), N, order, sizeof(v[0]), 0, 0, v.data());
    return b;
}

} // namespace crypto
