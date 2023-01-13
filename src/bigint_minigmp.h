#pragma once

#include "helpers.h"

// what about timing attacks & gmp?
#include "mini-gmp-impl.h"

namespace crypto {

struct bigint {
    mpz_t p;

    bigint() {
        mpz_init(*this);
    }
    bigint(const char *c) {
        mpz_init_set_str(*this, c, 0);
    }
    bigint(string_view sv) {
        std::string s;
        s += sv;
        mpz_init_set_str(*this, s.data(), 0);
    }
    ~bigint() {
        mpz_clear(*this);
    }

    operator __mpz_struct*() { return &p[0]; }
    operator const __mpz_struct*() const { return &p[0]; }

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

    bigint operator*(const bigint &p) const {
        auto b = *this;
        mpz_mul(b, b, p);
        return b;
    }
    bigint operator*(uint64_t p) const {
        auto b = *this;
        mpz_mul_ui(b, b, p);
        return b;
    }
    bigint operator+(auto &&p) const {
        auto b = *this;
        if constexpr (requires { mpz_add(b, b, p); }) {
            mpz_add(b, b, p);
        } else if constexpr (requires { mpz_add_ui(b, b, p); }) {
            mpz_add_ui(b, b, p);
        }
        return b;
    }
    bigint operator-(auto &&p) const {
        auto b = *this;
        if constexpr (requires { mpz_sub(b, b, p); }) {
            mpz_sub(b, b, p);
        } else if constexpr (requires { mpz_sub_ui(b, b, p); }) {
            mpz_sub_ui(b, b, p);
        }
        return b;
    }
    bigint &operator=(const bigint &p) {
        return *this;
    }
    bigint &operator=(uint64_t p) {
        return *this;
    }
    bool operator==(const bigint &p) const {
        return *this;
    }
    bool operator==(uint64_t p) const {
        return *this;
    }
};

auto operator""_bi(const char *p, size_t len) {
    return bigint{p};
}

template <auto N>
bigint bytes_to_bigint(uint8_t (&v)[N], int order = 1) {
    bigint b;
    mpz_import(b, N, order, sizeof(v[0]), 0, 0, v);
    return b;
}
template <auto N>
bigint bytes_to_bigint(const array<N> &v, int order = 1) {
    bigint b;
    mpz_import(b, N, order, sizeof(v[0]), 0, 0, v.data());
    return b;
}

} // namespace crypto
