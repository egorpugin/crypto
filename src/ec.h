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
    ec_field_point operator+(const ec_field_point &q) {
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

template <auto PointSizeBytes, auto P, auto A, auto B, auto Gx, auto Gy>
struct secp {
    static inline const auto parameters = ec::parameters<string_view>{.p = P,
                                                                      .a = A,
                                                                      .b = B,
                                                                      .G = {
                                                                          Gx,
                                                                          Gy,
                                                                      }};

    static inline constexpr auto point_size_bytes = ((PointSizeBytes / 8) * 8 == PointSizeBytes) ? PointSizeBytes / 8 : (PointSizeBytes / 8 + 1);

#pragma pack(push, 1)
    struct key_type {
        uint8_t legacy{4};
        array<point_size_bytes> x;
        array<point_size_bytes> y;
    };
#pragma pack(pop)

    static inline constexpr auto key_size = sizeof(key_type);
    using private_key_type = array<key_size>;
    using public_key_type = private_key_type;

    private_key_type private_key;

    auto public_key() {
        auto c = parameters.curve();
        auto m = bytes_to_bigint(private_key);
        auto p = m * c.G;
        return key_type{4,p.x,p.y};
    }
    auto public_key(auto &&out) {
        auto k = public_key();
        memcpy(out, (uint8_t *)&k, key_size);
    }
    auto shared_secret(const public_key_type &peer_public_key) {
        array<point_size_bytes> shared_secret;
        auto &k = *(key_type *)peer_public_key.data();
        auto c = parameters.curve();
        ec_field_point p{c.ec};
        p.x = bytes_to_bigint(k.x);
        p.y = bytes_to_bigint(k.y);
        auto m = bytes_to_bigint(private_key);
        auto p2 = m * p;
        key_type k2{4,p2.x,p2.y};
        memcpy(shared_secret.data(), (uint8_t *)&k2.x, point_size_bytes);
        return shared_secret;
    }
};

// https://neuromancer.sk/std/secg/secp256r1
using secp256r1 = secp<256,
                       "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"_s,
                       "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc"_s,
                       "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"_s,

                       "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"_s,
                       "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"_s>;

using secp384r1 = secp<384,
                       "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"_s,
                       "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc"_s,
                       "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"_s,

                       "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"_s,
                       "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"_s>;

// not tested
/*template <auto PointSizeBytes, auto P, auto A, auto B, auto Gx, auto Gy>
struct gost {
    static inline const auto parameters = ec::parameters<string_view>{.p = P,
                                                                      .a = A,
                                                                      .b = B,
                                                                      .G = {
                                                                          Gx,
                                                                          Gy,
                                                                      }};

    static inline constexpr auto point_size_bytes =
        ((PointSizeBytes / 8) * 8 == PointSizeBytes) ? PointSizeBytes / 8 : (PointSizeBytes / 8 + 1);

#pragma pack(push, 1)
    struct key_type {
        array<point_size_bytes> x;
        array<point_size_bytes> y;
    };
#pragma pack(pop)

    static inline constexpr auto key_size = sizeof(key_type);
    using private_key_type = array<key_size>;
    using public_key_type = private_key_type;

    private_key_type private_key;

    auto public_key() {
        auto c = parameters.curve();
        auto m = bytes_to_bigint(private_key);
        auto p = m * c.G;
        return key_type{p.x, p.y};
    }
    auto public_key(auto &&out) {
        auto k = public_key();
        memcpy(out, (uint8_t *)&k, key_size);
    }
    auto shared_secret(const public_key_type &peer_public_key) {
        array<point_size_bytes> shared_secret;
        auto &k = *(key_type *)peer_public_key.data();
        auto c = parameters.curve();
        ec_field_point p{c.ec};
        p.x = bytes_to_bigint(k.x);
        p.y = bytes_to_bigint(k.y);
        auto m = bytes_to_bigint(private_key);
        auto p2 = m * p;
        key_type k2{p2.x, p2.y};
        memcpy(shared_secret.data(), (uint8_t *)&k2.x, point_size_bytes);
        return shared_secret;
    }
};*/

// https://neuromancer.sk/std/gost
using gostr34102012_512a = secp<512,
                       "0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"_s,
                       "0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4"_s,
                       "0x00E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760"_s,

                       "0x03"_s,
                       "0x7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"_s>;

using gostr34102012_512b = secp<512,
                       "0x008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F"_s,
                       "0x008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C"_s,
                       "0x687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116"_s,

                       "0x02"_s,
                       "0x1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD"_s>;

// ShangMi (SM) Cipher Suites for TLS 1.3
// https://www.rfc-editor.org/rfc/rfc8998.html
/*
using sm2 = ...<256,
                       "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"_s,
                       "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"_s,
                       "0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"_s,

                       "0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"_s,
                       "0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"_s>;
*/

} // namespace crypto::ec
