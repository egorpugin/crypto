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

std::ostream &operator<<(std::ostream &o, const ec_field_point &v) {
    o << "x = " << v.x << "\n";
    o << "y = " << v.y << "\n";
    return o;
}

ec_field_point operator*(const bigint &m, const ec_field_point &p) {
    if (m == 0) {
        return {p.ec};
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

template <typename T, typename CurveForm = weierstrass>
struct parameters {
    T p;
    T a,b;
    point<T> G;
    T order;

    struct curve_type {
        CurveForm ec;
        ec_field_point G{ec};
        bigint order;
    };

    auto curve() const {
        curve_type c;
        c.ec.p = p;
        c.ec.a = a;
        c.ec.b = b;
        c.G.x = G.x;
        c.G.y = G.y;
        c.order = order;
        return c;
    }
};

template <auto PointSizeBytes, auto P, auto A, auto B, auto Gx, auto Gy, auto Order>
struct secp {
    static inline const auto parameters = ec::parameters<string_view>{.p = P,
                                                                      .a = A,
                                                                      .b = B,
                                                                      .G =
                                                                          {
                                                                              Gx,
                                                                              Gy,
                                                                          },
                                                                      .order = Order};

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

    private_key_type private_key_;

    void private_key() {
        get_random_secure_bytes(private_key_);
    }
    auto public_key() {
        auto c = parameters.curve();
        auto m = bytes_to_bigint(private_key_);
        auto p = m * c.G;
        return key_type{4,p.x,p.y};
    }
    auto public_key(auto &&out) {
        auto k = public_key();
        memcpy(out.data(), (uint8_t *)&k, key_size);
    }
    auto shared_secret(const public_key_type &peer_public_key) {
        array<point_size_bytes> shared_secret;
        auto &k = *(key_type *)peer_public_key.data();
        auto c = parameters.curve();
        ec_field_point p{c.ec};
        p.x = bytes_to_bigint(k.x);
        p.y = bytes_to_bigint(k.y);
        auto m = bytes_to_bigint(private_key_);
        auto p2 = m * p;
        key_type k2{4,p2.x,p2.y};
        memcpy(shared_secret.data(), (uint8_t *)&k2.x, point_size_bytes);
        return shared_secret;
    }
};

// https://neuromancer.sk/std/secg/secp256r1
using secp256r1 = secp<256, "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"_s,
                       "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc"_s,
                       "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"_s,

                       "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"_s,
                       "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"_s,
                       "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"_s>;

using secp384r1 =
    secp<384, "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"_s,
         "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc"_s,
         "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"_s,

         "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"_s,
         "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"_s,
         "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"_s>;

namespace gost::r34102012 {

template <auto PointSizeBytes, auto P, auto A, auto B, auto Gx, auto Gy, auto Order>
struct curve {
    static inline const auto parameters = ec::parameters<string_view>{.p = P,
                                                                      .a = A,
                                                                      .b = B,
                                                                      .G =
                                                                          {
                                                                              Gx,
                                                                              Gy,
                                                                          },
                                                                      .order = Order};

    static inline constexpr auto point_size_bytes =
        ((PointSizeBytes / 8) * 8 == PointSizeBytes) ? PointSizeBytes / 8 : (PointSizeBytes / 8 + 1);

#pragma pack(push, 1)
    struct key_type {
        array_gost<point_size_bytes> x;
        array_gost<point_size_bytes> y;
    };
#pragma pack(pop)

    static inline constexpr auto key_size = sizeof(key_type);
    using private_key_type = array_gost<point_size_bytes>;
    using public_key_type = array_gost<key_size>;

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
        memcpy(out.data(), (uint8_t *)&k, key_size);
    }
    auto shared_secret(const public_key_type &peer_public_key) {
        array_gost<point_size_bytes> shared_secret;
        auto &k = *(key_type *)peer_public_key.data();
        auto c = parameters.curve();
        ec_field_point p{c.ec};
        p.x = bytes_to_bigint(k.x);
        p.y = bytes_to_bigint(k.y);
        auto m = bytes_to_bigint(private_key_);
        auto p2 = m * p;
        key_type k2{.x = p2.x, .y = p2.y};
        memcpy(shared_secret.data(), (uint8_t *)&k2.x, point_size_bytes);
        return shared_secret;
    }
};

template <auto Sz, auto A, auto D, auto ... Params>
struct twisted_edwards : curve<Sz, Params...> {
    using base = curve<Sz, Params...>;

    auto to_weierstrass(bigint x, bigint y) {
        auto c = base::parameters.curve();
        bigint a = string_view{A};
        bigint d = string_view{D};

        bigint p2 = "12"_bi - y * 12;
        mpz_invert(p2, p2, c.ec.p);
        bigint x1 = (a * 5 + a * y - d * y * 5 - d) * p2;

        p2 = x * 4 - x * y * 4;
        mpz_invert(p2, p2, c.ec.p);
        bigint y1 = (a + a * y - d * y - d) * p2;

        return std::tuple{x1 % c.ec.p, y1 % c.ec.p};
    }
    auto to_twistededwards(bigint u, bigint v) {
        auto c = base::parameters.curve();
        bigint a = string_view{A};
        bigint d = string_view{D};

        bigint p2 = "-12"_bi * u - a + d * 5;
        mpz_invert(p2, p2, c.ec.p);
        bigint y = (a * 5 - u * 12 - d) * p2;

        p2 = v * 4 - v * y * 4;
        mpz_invert(p2, p2, c.ec.p);
        bigint x = (a + a * y - d * y - d) * p2;

        return std::tuple{x % c.ec.p, y % c.ec.p};
    }

    auto public_key() {
        auto c = base::parameters.curve();
        auto m = bytes_to_bigint(this->private_key_);
        auto p = m * c.G;
        //std::tie(p.x, p.y) = to_twistededwards(p.x, p.y);
        return typename base::key_type{.x = p.x, .y = p.y};
    }
    auto public_key(auto &&out) {
        auto k = public_key();
        memcpy(out.data(), (uint8_t *)&k, this->key_size);
    }
    auto shared_secret(const typename base::public_key_type &peer_public_key) {
        array_gost<base::point_size_bytes> shared_secret;
        auto &k = *(typename base::key_type *)peer_public_key.data();
        auto c = base::parameters.curve();
        ec_field_point p{c.ec};
        p.x = bytes_to_bigint(k.x);
        p.y = bytes_to_bigint(k.y);
        std::cout << "received twisted:\n" << p << "\n";
        std::tie(p.x, p.y) = to_weierstrass(p.x, p.y);
        std::cout << "received weierstrass:\n" << p << "\n";
        auto m = bytes_to_bigint(this->private_key_);
        auto p2 = m * p;
        std::cout << "m = " << m << "\n";
        std::cout << "multiplied weierstrass:\n" << p2 << "\n";
        std::tie(p2.x, p2.y) = to_twistededwards(p2.x, p2.y);
        std::cout << "multiplied twisted:\n" << p2 << "\n";
        typename base::key_type k2{.x = p2.x, .y = p2.y};
        memcpy(shared_secret.data(), (uint8_t *)&k2.x, this->point_size_bytes);
        return shared_secret;
    }
};

// https://neuromancer.sk/std/gost
// use SAGE to convert twisted edwards A,B,Gx,Gy to weierstrass form

// id-tc26-gost-3410-2012-256-paramSetA
// twisted twisted_edwards
using ec256a = twisted_edwards<256, "0x01"_s, "0x605f6b7c183fa81578bc39cfad518132b9df62897009af7e522c32d6dc7bffb"_s,

                     "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97"_s,
                     "87789765485885808793369751294406841171614589925193456909855962166505018127157"_s,
                     "18713751737015403763890503457318596560459867796169830279162511461744901002515"_s,

                     "65987350182584560790308640619586834712105545126269759365406768962453298326056"_s,
                     "22855189202984962870421402504110399293152235382908105741749987405721320435292"_s,
                     "0x400000000000000000000000000000000fd8cddfc87b6635c115af556c360c67"_s>;

using ec256b = curve<256, "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97"_s,
                     "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94"_s, "0xa6"_s,

                     "0x01"_s, "0x8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14"_s,
                     "0xffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893"_s>;

using ec256c = curve<256, "0x8000000000000000000000000000000000000000000000000000000000000c99"_s,
                     "0x8000000000000000000000000000000000000000000000000000000000000c96"_s,
                     "0x3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc8b"_s,

                     "0x01"_s, "0x3fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717efc"_s,
                     "0x800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f"_s>;

using ec256d = curve<256, "0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b"_s,
                     "0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598"_s, "0x805a"_s,

                     "0"_s, "0x41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67"_s,
                     "0x9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9"_s>;

using ec512a = curve<
    512,
    "0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"_s,
    "0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4"_s,
    "0x00E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760"_s,

    "0x03"_s,
    "0x7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"_s,

    "0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275"_s>;

using ec512b = curve<
    512,
    "0x008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F"_s,
    "0x008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C"_s,
    "0x687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116"_s,

    "0x02"_s,
    "0x1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD"_s,

    "0x00800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD"_s>;

// twisted edwards
using ec512c = curve<
    512,
    "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7"_s,
    "11552207741726624081384854431754270453419990958158536547453630472753284279856029013033421730195977772912484970560977054897563749457966985165428182284278739"_s,
    "9467654314974239364849779893497935997616546680893642377235981868741051215651032446828994750528267630604306101610711521055955290148577159125187794668181473"_s,

    "11883046340949417535959253611031637438486121989357748247963585015455167053565085942161130870937622596747831459979590245849590330315393322885186213222089032"_s,
    "12873887912291418762163219174899249027788909354964279561044704584079894283286935688639587101137346765264237830933785897290140286858111689735138773336704015"_s,

    "0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc98cdba46506ab004c33a9ff5147502cc8eda9e7a769a12694623cef47f023ed"_s>;

} // namespace r34102012

// ShangMi (SM) Cipher Suites for TLS 1.3
// https://www.rfc-editor.org/rfc/rfc8998.html

using sm2 = secp<256, "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"_s,
                 "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"_s,
                 "0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"_s,

                 "0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"_s,
                 "0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"_s,
                 "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"_s>;

} // namespace crypto::ec
