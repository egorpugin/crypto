#pragma once

#include "helpers.h"

// what about timing attacks & gmp?
#include "mini-gmp-impl.h"

namespace crypto {

struct bigint {
    mpz_t p;

    bigint() {
        mpz_init_set_ui(*this, 0);
    }
    bigint(uint64_t v) {
        mpz_init_set_ui(*this, v);
    }
    bigint(int64_t v) {
        mpz_init_set_si(*this, v);
    }
    bigint(int v) {
        mpz_init_set_si(*this, v);
    }
    bigint(const char *c) {
        mpz_init_set_str(*this, c, 0);
    }
    bigint(string_view sv) {
        std::string s;
        s += sv;
        mpz_init_set_str(*this, s.data(), 0);
    }
    bigint(bigint &&v) noexcept {
        p[0] = v.p[0];
        v.p[0]._mp_alloc = 0;
    }
    bigint &operator=(bigint &&v) noexcept {
        mpz_clear(*this);
        p[0] = v.p[0];
        v.p[0]._mp_alloc = 0;
        return *this;
    }
    bigint(const bigint &v) {
        mpz_init_set(*this, v);
    }
    ~bigint() {
        mpz_clear(*this);
    }

    operator __mpz_struct *() {
        return &p[0];
    }
    operator const __mpz_struct *() const {
        return &p[0];
    }

    auto &operator%=(const bigint &m) {
        mpz_mod(*this, *this, m);
        return *this;
    }
    auto operator%(const bigint &m) {
        auto b = *this;
        b %= m;
        return b;
    }
    template <template <auto> typename A, auto N, int Order = 1>
    A<N> to_array() const {
        auto size = 1;
        auto nail = 0;
        auto numb = 8 * size - nail;
        auto count1 = (mpz_sizeinbase(*this, 2) + numb - 1) / numb;
        if (count1 > N) {
            throw std::runtime_error{"bigint error"};
        }

        A<N> d;
        mpz_export(d.data(), 0, Order, 1, 0, 0, *this);
        return d;
    }
    template <auto N, int Order = 1>
    operator array<N>() const {
        return to_array<array, N>();
    }
    template <auto N>
    operator array_gost<N>() const {
        return to_array<array_gost, N, -1>();
    }

    bigint operator*(const bigint &p) const {
        auto b = *this;
        mpz_mul(b, b, p);
        return b;
    }
    /*bigint operator/(const bigint &p) const {
        auto b = *this;
        mpz_fdiv_q(b, b, p);
        return b;
    }*/
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
        mpz_init_set(*this, p);
        return *this;
    }
    bigint &operator=(uint64_t p) {
        mpz_init_set_ui(*this, p);
        return *this;
    }
    bool operator==(const bigint &p) const {
        return mpz_cmp(*this, p) == 0;
    }
    bool operator==(uint64_t p) const {
        return mpz_cmp_ui(*this, p) == 0;
    }
    bool operator==(int64_t p) const {
        return mpz_cmp_si(*this, p) == 0;
    }
    bool operator==(int p) const {
        return mpz_cmp_si(*this, p) == 0;
    }
    auto operator<=>(const bigint &p) const {
        return mpz_cmp(*this, p) <=> 0;
    }
    auto operator<=>(uint64_t p) const {
        return mpz_cmp_ui(*this, p) <=> 0;
    }
    auto operator<=>(int64_t p) const {
        return mpz_cmp_si(*this, p) <=> 0;
    }
    auto operator<=>(int p) const {
        return mpz_cmp_si(*this, p) <=> 0;
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
template <auto N>
bigint bytes_to_bigint(const array_gost<N> &v) {
    return bytes_to_bigint(v, -1);
}

auto bytes_to_string(auto &&bytes) {
    std::string s;
    s.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        constexpr auto alph = "0123456789abcdef";
        s += alph[b >> 4];
        s += alph[b & 0xF];
    }
    return s;
}

std::ostream &operator<<(std::ostream &o, const bigint &v) {
    auto size = 1;
    auto nail = 0;
    auto numb = 8 * size - nail;
    auto count1 = (mpz_sizeinbase(v, 2) + numb - 1) / numb;

    std::string d(count1, ' ');
    mpz_export(d.data(), 0, 1, 1, 0, 0, v);
    return o << "0x" << bytes_to_string(d);
}

} // namespace crypto
