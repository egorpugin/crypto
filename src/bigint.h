// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

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
    bigint(u64 v) {
        mpz_init_set_ui(*this, v);
    }
    bigint(i64 v) {
        mpz_init_set_si(*this, v);
    }
    bigint(int v) {
        mpz_init_set_si(*this, v);
    }
    bigint(const char *c) {
        mpz_init_set_str(*this, c, 0);
    }
    bigint(string_view sv) : bigint{std::string(sv)} {
    }
    bigint(const std::string &s) {
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

    auto data() const {
        return (u8*)p[0]._mp_d;
    }
    auto size() const {
        return mpz_size(*this) * sizeof(mp_limb_t);
    }
    auto powm(const bigint &e, const bigint &m) const {
        bigint r;
        mpz_powm(r, *this, e, m);
        return r;
    }

    operator __mpz_struct *() {
        return &p[0];
    }
    operator const __mpz_struct *() const {
        return &p[0];
    }

    auto operator-() {
        bigint r;
        mpz_neg(r, *this);
        return r;
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
    /*auto &operator/=(const bigint &m) {
        mpz_divexact(*this, *this, m);
        return *this;
    }
    auto operator/(const bigint &m) {
        auto b = *this;
        b /= m;
        return b;
    }*/
    template <template <auto> typename A, auto N, int Order = 1>
    A<N> to_array() const {
        auto size = 1;
        auto nail = 0;
        auto numb = 8 * size - nail;
        auto count1 = (mpz_sizeinbase(*this, 2) + numb - 1) / numb;
        if (count1 > N) {
            throw std::runtime_error{"bigint error"};
        }

        auto count = N;
        A<N> d{};
        auto p = d.data();
        if (count > count1 && Order == 1) {
            p += count - count1;
        }
        mpz_export(p, 0, Order, 1, 0, 0, *this);
        return d;
    }
    auto to_string(int count) {
        auto size = 1;
        auto nail = 0;
        auto numb = 8 * size - nail;
        auto count1 = (mpz_sizeinbase(*this, 2) + numb - 1) / numb;

        std::string s(count, 0);
        auto p = s.data();
        if (count > count1) {
            p += count - count1;
        }
        mpz_export(p, 0, 1, 1, 0, 0, *this);
        return s;
    }
    // this one is dangerous to be just 'to_string()' because we may lose initial zeros
    auto to_shortest_string() {
        auto size = 1;
        auto nail = 0;
        auto numb = 8 * size - nail;
        auto count1 = (mpz_sizeinbase(*this, 2) + numb - 1) / numb;

        return to_string(count1);
    }
    template <auto N, int Order = 1>
    operator array<N>() const {
        return to_array<array, N>();
    }
    template <auto N>
    operator array_gost<N>() const {
        return to_array<array_gost, N, -1>();
    }

    bigint invert(const bigint &q) {
        bigint r;
        mpz_invert(r, *this, q);
        return r;
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
    bigint operator*(u64 p) const {
        auto b = *this;
        mpz_mul_ui(b, b, p);
        return b;
    }
    bigint operator*(i64 p) const {
        auto b = *this;
        mpz_mul_si(b, b, p);
        return b;
    }
    bigint operator*(int p) const {
        auto b = *this;
        mpz_mul_si(b, b, p);
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
    bigint operator>>(u64 p) {
        mpz_fdiv_q_2exp(*this, *this, p);
        return *this;
    }
    bigint &operator=(const bigint &p) {
        mpz_init_set(*this, p);
        return *this;
    }
    bigint &operator=(u64 p) {
        mpz_init_set_ui(*this, p);
        return *this;
    }
    bigint &operator=(i64 p) {
        mpz_init_set_si(*this, p);
        return *this;
    }
    bigint &operator=(int p) {
        mpz_init_set_si(*this, p);
        return *this;
    }
    bool operator==(const bigint &p) const {
        return mpz_cmp(*this, p) == 0;
    }
    bool operator==(u64 p) const {
        return mpz_cmp_ui(*this, p) == 0;
    }
    bool operator==(i64 p) const {
        return mpz_cmp_si(*this, p) == 0;
    }
    bool operator==(int p) const {
        return mpz_cmp_si(*this, p) == 0;
    }
    auto operator<=>(const bigint &p) const {
        return mpz_cmp(*this, p) <=> 0;
    }
    auto operator<=>(u64 p) const {
        return mpz_cmp_ui(*this, p) <=> 0;
    }
    auto operator<=>(i64 p) const {
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
bigint bytes_to_bigint(u8 (&v)[N], int order = 1) {
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
bigint bytes_to_bigint(const auto &v, int order = 1) {
    bigint b;
    mpz_import(b, v.size(), order, 1, 0, 0, v.data());
    return b;
}

auto bytes_to_string(auto &&bytes) {
    std::string s;
    s.reserve(bytes.size() * 2);
    for (u8 b : bytes) {
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
