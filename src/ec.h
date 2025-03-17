// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "bigint.h"
#include "hmac.h"
#include "random.h"

// https://neuromancer.sk/std/
// https://safecurves.cr.yp.to/index.html

namespace crypto::ec {

template <typename T>
struct point {
    T x, y;
};

// y^2 = x^3 + ax + b
struct weierstrass_prime_field {
    bigint a, b, p;
};

// y^2 + xy = x^3 + ax + b
struct weierstrass_binary_field {
    bigint a, b, p;
};

// a * x^2 + y^2 = 1 + d * x^2 * y^2
struct twisted_edwards_field {
    bigint a, d, p;
};

template <typename Curve>
struct ec_field_point : point<bigint> {
    Curve ec; // TODO: not a ref atm, slow

    ec_field_point(const Curve &ec) : ec{ec} {}
    ec_field_point(const Curve &ec, auto &&x, auto &&y) : ec{ec} {
        this->x = x;
        this->y = y;
    }

    bool operator==(const ec_field_point &rhs) const { return x == rhs.x && y == rhs.y; }
    bool operator==(const bigint &b) const { return x == b && y == b; }
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

    ec_field_point double_() const
        requires std::same_as<Curve, weierstrass_prime_field>
    {
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
    ec_field_point operator+(const ec_field_point &q)
        requires std::same_as<Curve, weierstrass_prime_field>
    {
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
    /*ec_field_point double_() const
        requires std::same_as<Curve, weierstrass_binary_field>
    {
        //TODO: binary field checks for doubling
        //if (y == 0) {
        //    return ec_field_point{ec};
        //}
        bigint temp = x;
        mpz_invert(temp, temp, ec.p);
        bigint slope = x + y * temp;
        slope %= ec.p;
        ec_field_point r{ec};
        r.x = slope * slope + ec.a;
        r.x %= ec.p;
        r.y = x * x + (slope + 1) * r.x;
        r.y %= ec.p;
        return r;
    }
    ec_field_point operator+(const ec_field_point &q)
        requires std::same_as<Curve, weierstrass_binary_field>
    {
        //TODO: binary field checks for addition
        //if (*this == 0) {
        //    return q;
        //}
        //if (q == 0) {
        //    return *this;
        //}
        //bigint temp1;
        //if (q.y != 0) {
        //    temp1 = (q.y - ec.p);
        //    temp1 %= ec.p;
        //}
        //if (y == temp1 && x == q.x) {
        //    return {ec};
        //}
        //if (*this == q) {
        //    return double_();
        //}
        bigint temp = x + q.x;
        temp %= ec.p;
        mpz_invert(temp, temp, ec.p);
        bigint slope = (y + q.y) * temp;
        slope %= ec.p;
        ec_field_point r{ec};
        r.x = slope * slope + slope + x + q.x + ec.a;
        r.x %= ec.p;
        r.y = slope * (x + r.x) + r.x + y;
        r.y %= ec.p;
        return r;
    }
    ec_field_point double_() const
        requires std::same_as<Curve, twisted_edwards_field>
    {
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
    ec_field_point operator+(const ec_field_point &q)
        requires std::same_as<Curve, twisted_edwards_field>
    {
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
    }*/
};

template <typename Curve>
std::ostream &operator<<(std::ostream &o, const ec_field_point<Curve> &v) {
    o << "x = " << v.x << "\n";
    o << "y = " << v.y << "\n";
    return o;
}

template <typename Curve>
ec_field_point<Curve> operator*(const bigint &m, const ec_field_point<Curve> &p) {
    if (m == 0) {
        return ec_field_point<Curve>{p.ec};
    }
    // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Montgomery_ladder
    // prevent timing attack
    ec_field_point r0{p.ec};
    ec_field_point r1 = p;
    for (int bit = mpz_sizeinbase(m, 2); bit >= 0; --bit) {
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

auto prepare_hash_for_signature(auto &&h, auto &&q, bitlen qlen) {
    std::string hs(h.begin(), h.end());
    take_left_bits(hs, qlen);
    auto hsz = hs.size();
    if (hsz < qlen) {
        hs = expand_bytes(hs, qlen);
    }
    if (auto hb = bytes_to_bigint(hs); hb >= q) {
        hb = hb - q; // equal to 'hb % q'
        hs = hb.to_string(qlen);
    }
    return hs;
}

template <typename T, typename CurveForm>
struct parameters;

template <typename T>
struct parameters<T, weierstrass_prime_field> {
    using CurveForm = weierstrass_prime_field;

    T p;
    T a, b;
    point<T> G;
    T order;
    T cofactor;

    struct curve_type {
        CurveForm ec;
        ec_field_point<CurveForm> G{ec};
        bigint order;
        bigint cofactor;
    };

    auto curve() const {
        curve_type c;
        c.ec.p = p;
        c.ec.a = a;
        c.ec.b = b;
        c.G.ec = c.ec;
        c.G.x = G.x;
        c.G.y = G.y;
        c.order = order;
        c.cofactor = cofactor;
        return c;
    }
};

template <typename T>
struct parameters<T, twisted_edwards_field> {
    using CurveForm = twisted_edwards_field;

    T p;
    T a, d;
    point<T> G;
    T order;
    T cofactor;

    struct curve_type {
        CurveForm ec;
        ec_field_point<CurveForm> G{ec};
        bigint order;
        bigint cofactor;
    };

    auto curve() const {
        curve_type c;
        c.ec.p = p;
        c.ec.a = a;
        c.ec.d = d;
        c.G.ec = c.ec;
        c.G.x = G.x;
        c.G.y = G.y;
        c.order = order;
        c.cofactor = cofactor;
        return c;
    }
};

template <auto PointSizeBits, auto P, auto A, auto B, auto Gx, auto Gy, auto Order, auto Cofactor>
struct secp {
    static inline const auto parameters = ec::parameters<string_view, weierstrass_prime_field>{.p = P,
                                                                                   .a = A,
                                                                                   .b = B,
                                                                                   .G =
                                                                                       {
                                                                                           Gx,
                                                                                           Gy,
                                                                                       },
                                                                                   .order = Order,
                                                                                   .cofactor = Cofactor};

    static inline constexpr auto point_size_bytes =
        ((PointSizeBits / 8) * 8 == PointSizeBits) ? PointSizeBits / 8 : (PointSizeBits / 8 + 1);

#pragma pack(push, 1)
    struct key_type {
        u8 legacy{4};
        array<point_size_bytes> x;
        array<point_size_bytes> y;

        operator bytes_concept() {
            return bytes_concept{&legacy, sizeof(key_type)};
        }
    };
#pragma pack(pop)

    static inline constexpr auto key_size = sizeof(key_type);
    using private_key_type = array<point_size_bytes>;
    using public_key_type = array<key_size>;

    private_key_type private_key_;

    void private_key() { get_random_secure_bytes(private_key_); }
    auto public_key() {
        auto c = parameters.curve();
        auto q = bigint{parameters.order};
        auto m = bytes_to_bigint(private_key_);
        auto p = m * c.G;
        return key_type{4, p.x, p.y};
    }
    auto public_key(auto &&out) {
        auto k = public_key();
        memcpy(out.data(), (u8 *)&k, key_size);
    }
    auto shared_secret(bytes_concept peer_public_key) {
        array<point_size_bytes> shared_secret;
        auto &k = *(key_type *)peer_public_key.data();
        auto c = parameters.curve();
        ec_field_point p{c.ec};
        p.x = bytes_to_bigint(k.x);
        p.y = bytes_to_bigint(k.y);
        auto m = bytes_to_bigint(private_key_);
        auto p2 = m * c.cofactor * p;
        key_type k2{4, p2.x, p2.y};
        memcpy(shared_secret.data(), (u8 *)&k2.x, point_size_bytes);
        return shared_secret;
    }

    static auto prepare_hash_for_signature(auto &&h) {
        auto q = bigint{parameters.order};
        bitlen qlen{PointSizeBits};
        return ec::prepare_hash_for_signature(h, q, qlen);
    }
    // rfc6979
    // it can be weak?
    // see https://github.com/openssl/openssl/issues/2078#issuecomment-309278772
    // see scheme for more secure gen https://github.com/openssl/openssl/commit/190c615d4398cc6c8b61eb7881d7409314529a75#diff-a17f5d7191d322b0645cdf359f2a3f9b38ca43d09a85ee6255600c46dd772b51L107
    // this impl is not well tested and have bugs
    // https://github.com/openssl/openssl/pull/18809
    // verify works as expected
    template <typename Hash>
    auto sign_deterministic(auto &&hash) {
        auto pubkey = public_key();

        auto ec = parameters.curve();
        auto q = bigint{parameters.order};
        auto hs = prepare_hash_for_signature(hash);

        bigint k,r;
        hmac_drbg<Hash> d{private_key_, hs, {}};
        while (1) {
            auto t = d.digest({}, PointSizeBits);
            k = bytes_to_bigint(t);
            if (0 < k && k < q) {
                r = (k * ec.G).x % q;
                if (r != 0) {
                    break;
                }
            }
        }

        auto hb = bytes_to_bigint(hs) % q;
        auto pk = bytes_to_bigint(private_key_);
        mpz_invert(k, k, q);
        auto s = (k * (hb + pk * r)) % q;

        return std::tuple{r.to_string(bitlen{PointSizeBits}),s.to_string(bitlen{PointSizeBits})};
    }
    static auto verify(auto &&hash, auto &&pubkey_in, auto &&r, auto &&s) {
        auto &pubkey = *(key_type *)pubkey_in.data();

        auto ec = parameters.curve();
        auto q = bigint{parameters.order};
        auto hs = prepare_hash_for_signature(hash);

        auto hb = bytes_to_bigint(hs) % q;
        auto rb = bytes_to_bigint(r);

        decltype(ec.G) Q{ec.G.ec};
        Q.x = bytes_to_bigint(pubkey.x);
        Q.y = bytes_to_bigint(pubkey.y);

        bigint w;
        mpz_invert(w, bytes_to_bigint(s), q);
        auto u1 = (hb * w) % q;
        auto u2 = (rb * w) % q;
        auto ug = u1 * ec.G;
        auto uq = u2 * Q;
        auto r2 = ug + uq;
        if (r2.x == 0) {
            return false;
        }
        auto v = r2.x % q;
        return v == rb;
    }
};

// https://neuromancer.sk/std/secg/secp256r1

using secp256r1 = secp<256, "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"_s,
                       "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc"_s,
                       "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"_s,

                       "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"_s,
                       "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"_s,
                       "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"_s, "1"_s>;

using secp384r1 =
    secp<384, "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"_s,
         "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc"_s,
         "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"_s,

         "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"_s,
         "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"_s,
         "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"_s, "1"_s>;

using secp521r1 =
    secp<521, "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_s,
         "0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc"_s,
         "0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"_s,

         "0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"_s,
         "0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"_s,
         "0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"_s, "1"_s>;

namespace gost::r34102012 {

template <auto PointSizeBits, auto P, auto A, auto B, auto Gx, auto Gy, auto Order, auto Cofactor>
struct curve {
    static inline const auto parameters = ec::parameters<string_view, weierstrass_prime_field>{.p = P,
                                                                                   .a = A,
                                                                                   .b = B,
                                                                                   .G =
                                                                                       {
                                                                                           Gx,
                                                                                           Gy,
                                                                                       },
                                                                                   .order = Order,
                                                                                   .cofactor = Cofactor};

    static inline constexpr auto point_size_bytes =
        ((PointSizeBits / 8) * 8 == PointSizeBits) ? PointSizeBits / 8 : (PointSizeBits / 8 + 1);

#pragma pack(push, 1)
    struct key_type {
        array_gost<point_size_bytes> x;
        array_gost<point_size_bytes> y;
    };
#pragma pack(pop)

    static inline constexpr auto key_size = sizeof(key_type);
    using private_key_type = array_gost<point_size_bytes>;
    using public_key_type = array<key_size>; // just a simple array

    private_key_type private_key_;

    void private_key() {
        auto c = parameters.curve();
        while (1) {
            get_random_secure_bytes(private_key_);
            auto m = bytes_to_bigint(private_key_);
            if (m > 0 && m < c.order) {
                break;
            }
        }
    }
    auto public_key() {
        auto c = parameters.curve();
        auto m = bytes_to_bigint(private_key_);
        auto p = m * c.G;
        return key_type{.x = p.x, .y = p.y};
    }
    auto public_key(auto &&out) {
        auto k = public_key();
        memcpy(out.data(), (u8 *)&k, key_size);
    }
    auto shared_secret(const public_key_type &peer_public_key) {
        array_gost<point_size_bytes> shared_secret;
        auto &k = *(key_type *)peer_public_key.data();
        auto c = parameters.curve();
        ec_field_point p{c.ec};
        p.x = bytes_to_bigint(k.x);
        p.y = bytes_to_bigint(k.y);
        auto m = bytes_to_bigint(private_key_);
        auto p2 = m * c.cofactor * p;
        key_type k2{.x = p2.x, .y = p2.y};
        memcpy(shared_secret.data(), (u8 *)&k2.x, point_size_bytes);
        return shared_secret;
    }

    static auto prepare_hash_for_signature(auto &&h) {
        auto q = bigint{parameters.order};
        bitlen qlen{PointSizeBits};
        return ec::prepare_hash_for_signature(h, q, qlen);
    }
    static auto sign(auto &&d, auto &&hash) {
        auto ec = parameters.curve();
        auto q = bigint{parameters.order};
        auto hs = prepare_hash_for_signature(hash);
        auto e = bytes_to_bigint(hs) % q;
        if (e == 0) {
            e = 1;
        }

        bigint k = q, r, s;
        while (1) {
            get_random_secure_bytes(k.data(), k.size());
            if (k > 0 && k < q) {
                auto c = k * ec.G;
                r = c.x % q;
                if (r == 0) {
                    continue;
                }
                s = (r * d + k * e) % q;
                if (s == 0) {
                    continue;
                }
                break;
            }
        }
        return s.to_string(bitlen{PointSizeBits}) + r.to_string(bitlen{PointSizeBits});
    }
    auto sign(auto &&hash) {
        return sign(bytes_to_bigint(private_key_), hash);
    }
    static auto verify(auto &&hash, auto &&pubkey_in, bytes_concept sig) {
        auto &pubkey = *(key_type *)pubkey_in.data();

        auto ec = parameters.curve();
        auto q = bigint{parameters.order};

        auto s = sig.subspan(0, sig.size() / 2);
        auto r = sig.subspan(sig.size() / 2);
        auto rb = bytes_to_bigint(r);
        auto sb = bytes_to_bigint(s);
        if (!(0 < rb && rb < q && 0 < sb && sb < q)) {
            return false;
        }

        auto hs = prepare_hash_for_signature(hash);
        auto e = bytes_to_bigint(hs) % q;
        if (e == 0) {
            e = 1;
        }

        decltype(ec.G) Q{ec.G.ec};
        Q.x = bytes_to_bigint(pubkey.x);
        Q.y = bytes_to_bigint(pubkey.y);

        auto w = e.invert(q);
        auto z1 = (sb * w) % q;
        auto z2 = (-rb * w) % q;
        auto ug = z1 * ec.G;
        auto uq = z2 * Q;
        auto r2 = ug + uq;
        if (r2.x == 0) {
            return false;
        }
        auto v = r2.x % q;
        return v == rb;
    }
};

template <auto PointSizeBits, auto P, auto A, auto D, auto Gx, auto Gy, auto Order, auto Cofactor, typename Wcurve>
struct twisted_edwards {
    static inline const auto parameters = ec::parameters<string_view, ec::twisted_edwards_field>{.p = P,
                                                                                           .a = A,
                                                                                           .d = D,
                                                                                           .G =
                                                                                               {
                                                                                                   Gx,
                                                                                                   Gy,
                                                                                               },
                                                                                           .order = Order,
                                                                                           .cofactor = Cofactor};

    static inline constexpr auto point_size_bytes =
        ((PointSizeBits / 8) * 8 == PointSizeBits) ? PointSizeBits / 8 : (PointSizeBits / 8 + 1);

#pragma pack(push, 1)
    struct key_type {
        array_gost<point_size_bytes> x;
        array_gost<point_size_bytes> y;
    };
#pragma pack(pop)

    static inline constexpr auto key_size = sizeof(key_type);
    using private_key_type = array_gost<point_size_bytes>;
    using public_key_type = array<key_size>; // just a simple array

    private_key_type private_key_;

    void private_key() {
        auto c = parameters.curve();
        while (1) {
            get_random_secure_bytes(private_key_);
            auto m = bytes_to_bigint(private_key_);
            if (m > 0 && m < c.order) {
                break;
            }
        }
    }
    auto public_key() {
        auto m = bytes_to_bigint(this->private_key_);
        auto wc = Wcurve::parameters.curve();
        auto wp = m * wc.G;
        return key_type{.x = wp.x, .y = wp.y};
    }
    auto public_key(auto &&out) {
        auto k = public_key();
        memcpy(out.data(), (u8 *)&k, this->key_size);
    }
    auto shared_secret(const public_key_type &peer_public_key) {
        array_gost<point_size_bytes> shared_secret;
        auto &k = *(key_type *)peer_public_key.data();
        auto c = parameters.curve();
        auto m = bytes_to_bigint(this->private_key_);

        auto wc = Wcurve::parameters.curve();
        ec_field_point<typename decltype(Wcurve::parameters)::CurveForm> p{wc.ec};
        p.x = bytes_to_bigint(k.x);
        p.y = bytes_to_bigint(k.y);

        p = m * c.cofactor * p;

        key_type k2{.x = p.x, .y = p.y};
        memcpy(shared_secret.data(), (u8 *)&k2.x, this->point_size_bytes);
        return shared_secret;
    }

    auto sign(auto &&hash) {
        return Wcurve::sign(bytes_to_bigint(private_key_), hash);
    }
    static auto verify(auto &&hash, auto &&pubkey_in, bytes_concept sig) {
        return Wcurve::verify(hash, pubkey_in, sig);
    }
};

// https://neuromancer.sk/std/gost

// id-tc26-gost-3410-2012-256-paramSetA
using ec256a_w = curve<256, "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97"_s,
                       "0xc2173f1513981673af4892c23035a27ce25e2013bf95aa33b22c656f277e7335"_s,
                       "0x295f9bae7428ed9ccc20e7c359a9d41a22fccd9108e17bf7ba9337a6f8ae9513"_s,

                       "0x91e38443a5e82c0d880923425712b2bb658b9196932e02c78b2582fe742daa28"_s,
                       "0x32879423ab1a0375895786c4bb46e9565fde0b5344766740af268adb32322e5c"_s,

                        // this is m, not q
                        //"0x1000000000000000000000000000000003f63377f21ed98d70456bd55b0d8319c"_s,
                        "0x400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"_s,
                        "4"_s>;

using ec256a = twisted_edwards<256, "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97"_s, "1"_s,
                               "0x605f6b7c183fa81578bc39cfad518132b9df62897009af7e522c32d6dc7bffb"_s,

                               "0x0d"_s, "0x60ca1e32aa475b348488c38fab07649ce7ef8dbe87f22e81f92b2592dba300e7"_s,
                               "0x400000000000000000000000000000000fd8cddfc87b6635c115af556c360c67"_s, "4"_s, ec256a_w>;

using ec256b = curve<256, "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97"_s,
                     "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94"_s, "0xa6"_s,

                     "0x01"_s, "0x8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14"_s,
                     "0xffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893"_s, "1"_s>;

using ec256c = curve<256, "0x8000000000000000000000000000000000000000000000000000000000000c99"_s,
                     "0x8000000000000000000000000000000000000000000000000000000000000c96"_s,
                     "0x3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc8b"_s,

                     "0x01"_s, "0x3fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717efc"_s,
                     "0x800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f"_s, "1"_s>;

using ec256d = curve<256, "0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b"_s,
                     "0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598"_s, "0x805a"_s,

                     "0"_s, "0x41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67"_s,
                     "0x9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9"_s, "1"_s>;

using ec512a = curve<
    512,
    "0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"_s,
    "0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4"_s,
    "0x00E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760"_s,

    "0x03"_s,
    "0x7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"_s,

    "0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275"_s,
    "1"_s>;

using ec512b = curve<
    512,
    "0x008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F"_s,
    "0x008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C"_s,
    "0x687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116"_s,

    "0x02"_s,
    "0x1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD"_s,

    "0x00800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD"_s,
    "1"_s>;

using ec512c_w = curve<
    512,
    "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7"_s,
    "0xdc9203e514a721875485a529d2c722fb187bc8980eb866644de41c68e143064546e861c0e2c9edd92ade71f46fcf50ff2ad97f951fda9f2a2eb6546f39689bd3"_s,
    "0xb4c4ee28cebc6c2c8ac12952cf37f16ac7efb6a9f69f4b57ffda2e4f0de5ade038cbc2fff719d2c18de0284b8bfef3b52b8cc7a5f5bf0a3c8d2319a5312557e1"_s,

    "0xe2e31edfc23de7bdebe241ce593ef5de2295b7a9cbaef021d385f7074cea043aa27272a7ae602bf2a7b9033db9ed3610c6fb85487eae97aac5bc7928c1950148"_s,
    "0xf5ce40d95b5eb899abbccff5911cb8577939804d6527378b8c108c3d2090ff9be18e2d33e3021ed2ef32d85822423b6304f726aa854bae07d0396e9a9addc40f"_s,

    // this is m, not q
    //"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff26336e91941aac0130cea7fd451d40b323b6a79e9da6849a5188f3bd1fc08fb4"_s,
    "0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc98cdba46506ab004c33a9ff5147502cc8eda9e7a769a12694623cef47f023ed"_s,
    "4"_s>;
using ec512c = twisted_edwards<
    512,
    "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7"_s,
    "1"_s,
    "0x9e4f5d8c017d8d9f13a5cf3cdf5bfe4dab402d54198e31ebde28a0621050439ca6b39e0a515c06b304e2ce43e79e369e91a0cfc2bc2a22b4ca302dbb33ee7550"_s,

    "0x12"_s,
    "0x469af79d1fb1f5e16b99592b77a01e2a0fdfb0d01794368d9a56117f7b38669522dd4b650cf789eebf068c5d139732f0905622c04b2baae7600303ee73001a3d"_s,

    "0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc98cdba46506ab004c33a9ff5147502cc8eda9e7a769a12694623cef47f023ed"_s,
    "4"_s, ec512c_w>;

} // namespace gost::r34102012

namespace gost::r34102001 {

using ec256a = r34102012::ec256b;
using ec256b = r34102012::ec256c;
using ec256c = r34102012::ec256d;
using ec256xcha = ec256a;
using ec256xchb = ec256c;

}  // namespace gost::r34102001

// ShangMi (SM) Cipher Suites for TLS 1.3
// https://www.rfc-editor.org/rfc/rfc8998.html

template <auto PointSizeBits, auto ... Params>
struct sm2_base : secp<PointSizeBits, Params...> {
    using base = secp<PointSizeBits, Params...>;

    template <typename Hash>
    static auto za(auto &&id, auto &&pubk) {
        Hash h;
        uint16_t entla = id.size() * 8;
        entla = std::byteswap(entla);
        h.update((u8*)&entla, 2);
        h.update(id);
        auto add_param = [&](auto &&v) {
            array<PointSizeBits / 8> a = bigint{v};
            h.update(a);
        };
        add_param(base::parameters.a);
        add_param(base::parameters.b);
        add_param(base::parameters.G.x);
        add_param(base::parameters.G.y);
        h.update(pubk.x);
        h.update(pubk.y);
        return h.digest();
    }
    template <typename Hash>
    static auto hash(auto &&id, auto &&message, auto &&pubkey) {
        Hash h;
        h.update(za<Hash>(id, pubkey));
        h.update(message);
        return h.digest();
    }

    template <typename Hash>
    auto sign(auto &&id, auto &&message) {
        auto ec = base::parameters.curve();
        auto q = bigint{base::parameters.order};
        auto e = bytes_to_bigint(hash<Hash>(id, message, base::public_key()));

        bigint k = q, r, s;
        while (1) {
            get_random_secure_bytes(k.data(), k.size());
            if (0 < k && k < q) {
                auto x1 = (k * ec.G).x;
                r = (e + x1) % q;
                if (r == 0 || r + k == q) {
                    continue;
                }
                auto da = bytes_to_bigint(base::private_key_);
                s = (da + 1).invert(q) * (k - r * da) % q;
                if (s == 0) {
                    continue;
                }
                break;
            }
        }
        return std::tuple{r.to_string(bitlen{PointSizeBits}),s.to_string(bitlen{PointSizeBits})};
    }
    template <typename Hash>
    static auto verify(auto &&id, auto &&message, const base::key_type &pubkey, auto &&r, auto &&s) {
        auto q = bigint{base::parameters.order};

        auto rb = bytes_to_bigint(r);
        auto sb = bytes_to_bigint(s);
        if (!(0 < rb && rb < q && 0 < sb && sb < q)) {
            return false;
        }

        auto ec = base::parameters.curve();
        auto e = bytes_to_bigint(hash<Hash>(id, message, pubkey));

        auto t = (rb + sb) % q;
        if (t == 0) {
            return false;
        }

        decltype(ec.G) Q{ec.G.ec};
        Q.x = bytes_to_bigint(pubkey.x);
        Q.y = bytes_to_bigint(pubkey.y);

        auto p = sb * ec.G + t * Q;
        auto R = (e + p.x) % q;
        return rb == R;
    }
    template <typename Hash>
    static auto verify(auto &&id, auto &&message, bytes_concept pubkey_in, auto &&r, auto &&s) {
        auto &pubkey = *(typename base::key_type *)pubkey_in.data();
        return verify<sm3>(id,message,pubkey,r,s);
    }
};

using sm2 = sm2_base<256,
                 "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"_s,
                 "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"_s,
                 "0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"_s,

                 "0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"_s,
                 "0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"_s,
                 "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"_s, "1"_s>;

} // namespace crypto::ec
