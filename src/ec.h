#pragma once

#include "bigint.h"

// https://neuromancer.sk/std/

namespace crypto::ec {

template <typename T>
struct point {
    T x, y;
};

// y^2 = x^3 + ax + b
struct weierstrass {
    bigint a,b,p;
};

struct ec_field_point : point<bigint> {
    weierstrass &ec;

    ec_field_point(weierstrass &ec) : ec{ec} {
    }
    ec_field_point(weierstrass &ec, auto &&x, auto &&y) : ec{ec} {
        this->x = x;
        this->y = y;
    }

    bool operator==(const ec_field_point &rhs) const {
        return x == rhs.x && y == rhs.y;
    }
    bool operator==(const bigint &b) const {
        return x == b && y == b;
    }
    ec_field_point &operator=(const ec_field_point &rhs) {
        x = rhs.x;
        y = rhs.y;
        return *this;
    }
    ec_field_point &operator%=(const bigint &b) {
        x %= b;
        y %= b;
        return *this;
    }
    ec_field_point double_() const {
        if (y == 0) {
            return ec_field_point{ec};
        }
        bigint temp = y * 2u;
        mpz_invert(temp, temp, ec.p);
        bigint slope = (x * x * 3u + ec.a) * temp;
        slope %= ec.p;
        ec_field_point r{ec};
        r.x = slope * slope - x * 2u;
        r.x %= ec.p;
        r.y = slope * (x - r.x) - y;
        r.y %= ec.p;
        return r;
    }
    ec_field_point operator+(ec_field_point q) {
        if (*this == 0) {
            return q;
        }
        if (q == 0) {
            return *this;
        }
        bigint temp1;
        if (q.y != 0) {
            temp1 = (q.y - ec.p);
            temp1 %= ec.p;
        }
        if (y == temp1 && x == q.x) {
            return {ec};
        }
        if (*this == q) {
            return double_();
        }
        bigint temp = q.x - x;
        temp %= ec.p;
        mpz_invert(temp, temp, ec.p);
        bigint slope = (q.y - y) * temp;
        slope %= ec.p;
        ec_field_point r{ec};
        r.x = slope * slope - x - q.x;
        r.x %= ec.p;
        r.y = slope * (x - r.x) - y;
        r.y %= ec.p;
        return r;
    }
};

ec_field_point operator*(const bigint &m, const ec_field_point &p) {
    if (m == 0) {
        return {p.ec};
    }
    // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Montgomery_ladder
    // prevent timing attack
    ec_field_point r0{p.ec};
    ec_field_point r1 = p;
    for (int bit = mpz_sizeinbase(m, 2) - 0; bit >= 0; --bit) {
        if (mpz_tstbit(m, bit) == 0) {
            r1 = r0 + r1;
            r0 = r0.double_();
        } else {
            r0 = r0 + r1;
            r1 = r1.double_();
        }
    }
    return r0;
}

template <typename T, typename CurveForm = weierstrass>
struct parameters {
    T p;
    T a,b;
    point<T> G;

    struct curve_type {
        CurveForm ec;
        ec_field_point G{ec};
    };

    auto curve() const {
        curve_type c;
        c.ec.p = p;
        c.ec.a = a;
        c.ec.b = b;
        c.G.x = G.x;
        c.G.y = G.y;
        return c;
    }
};

struct secp256r1 {
    static inline constexpr ec::parameters<string_view> parameters{
        .p = "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"sv,
        .a = "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc"sv,
        .b = "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"sv,
        .G = {
            "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"sv,
            "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"sv,
        }};

    static inline constexpr auto key_size = 32;
    using private_key_type = array<key_size>;
    using public_key_type = private_key_type;

    private_key_type private_key;

    auto public_key() {
        public_key_type public_key;
        //curve25519_f(private_key.data(), public_key.data());
        return public_key;
    }
    auto public_key(auto &&out) {
        //curve25519_f(private_key.data(), out);
    }
    auto shared_secret(const public_key_type &peer_public_key) {
        public_key_type shared_secret;
        //curve25519_f(private_key.data(), peer_public_key.data(), shared_secret.data());
        return shared_secret;
    }
};

} // namespace crypto::ec
