// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "bigint.h"
#include "random.h"
#include "sha2.h"

namespace crypto {

struct ed25519 {
    struct edwards_point {
        bigint x,y,z,t;
    };
    struct edwards_calc {
        bigint p, q, d;

        edwards_calc() {
            p = 2;
            mpz_pow_ui(p, p, 255);
            p = p - 19;

            q = 2;
            mpz_pow_ui(q, q, 252);
            q = q + bigint{"27742317777372353535851937790883648493"sv};

            d = -121665;
            d = d * bigint{121666}.invert(p) % p;
        }
        auto g() const {
            edwards_point g;
            g.y = bigint{5}.invert(p) * 4 % p;
            g.x = recover_x(g.y, 0);
            g.z = 1;
            g.t = g.x * g.y % p;
            return g;
        }
        bigint recover_x(auto &&y, auto &&sign) const {
            if (y >= p) {
                throw std::runtime_error{"bad y"};
            }
            auto x2 = (y*y-1) * (d*y*y+1).invert(p);
            if (x2 == 0) {
                if (sign) {
                    throw std::runtime_error{"..."};
                }
                return 0;
            }
            // square root of x2
            auto x = x2.powm((p+3) >> 3, p);
            if ((x*x - x2) % p != 0) {
                x = x * bigint{2}.powm((p-1) >> 2, p) % p;
            }
            if ((x*x - x2) % p != 0) {
                throw std::runtime_error{"..."};
            }
            if (mpz_tstbit(x, 0) != sign) {
                x = p - x;
            }
            return x;
        }
        auto point_add(auto &&P, auto &&Q) const {
            auto A = (P.y - P.x) * (Q.y - Q.x) % p;
            auto B = (P.y + P.x) * (Q.y + Q.x) % p;
            auto C = P.t * Q.t * d * 2 % p;
            auto D = P.z * Q.z * 2 % p;
            auto E = B-A;
            auto F = D-C;
            auto G = D+C;
            auto H = B+A;
            return edwards_point{E*F, G*H, F*G, E*H};
        }
        auto point_mul(auto &&s, auto &&P) const {
            edwards_point Q{0,1,1,0};
            auto sz = mpz_sizeinbase(s, 2);
            for (int bit = 0; bit <= sz; ++bit) {
                if (mpz_tstbit(s, bit) == 1) {
                    Q = point_add(Q, P);
                }
                P = point_add(P, P);
            }
            return Q;
        }
        auto point_compress(auto &&P) const {
            auto zinv = P.z.invert(p);
            auto x = P.x * zinv % p;
            auto y = P.y * zinv % p;
            mpz_tstbit(x, 0) ? mpz_setbit(y, 255) : mpz_clrbit(y, 255);
            return y;
        }
        auto point_decompress(auto &&s) const {
            auto y = bytes_to_bigint(s, -1);
            auto sign = mpz_tstbit(y, 255);
            mpz_clrbit(y, 255);
            auto x = recover_x(y, sign);
            return edwards_point{x,y,1,x*y%p};
        }
        bool point_equal(auto &&P, auto &&Q) const {
            if ((P.x * Q.z - Q.x * P.z) % p != 0)
                return false;
            if ((P.y * Q.z - Q.y * P.z) % p != 0)
                return false;
            return true;
        }
    };

    static inline constexpr auto key_size = 32;
    using private_key_type = array<key_size>;
    using public_key_type = array_little<key_size>;

    private_key_type private_key_;

    void private_key() { get_random_secure_bytes(private_key_); }
    auto private_key_expand() {
        auto h = sha512::digest(private_key_);
        h[0] &= 0xf8;
        h[0x1f] &= 0x7f;
        h[0x1f] |= 0x40;

        struct x {
            bigint a;
            array<32> r;
        };
        x v;
        v.a = bytes_to_bigint(bytes_concept{h.data(), 0x20}, -1);
        memcpy(v.r.data(), h.data() + 0x20, 0x20);
        return v;
    }
    public_key_type public_key() {
        auto h = private_key_expand();
        edwards_calc c;
        return c.point_compress(c.point_mul(h.a, c.g()));
    }
    auto sign(auto &&msg) {
        auto [a,prefix] = private_key_expand();
        edwards_calc c;
        auto A = c.point_compress(c.point_mul(a, c.g()));
        auto r = bytes_to_bigint(sha512::digest(prefix, msg), -1) % c.q;
        auto Rs = c.point_compress(c.point_mul(r, c.g()));
        auto h = bytes_to_bigint(sha512::digest(Rs, A, msg), -1) % c.q;
        auto s = (r + h * a) % c.q;
        array<64> ret;
        array_little<32> ret1 = Rs;
        memcpy(ret.data(), ret1.data(), ret1.size());
        array_little<32> ret2 = s;
        memcpy(ret.data() + 0x20, ret2.data(), ret2.size());
        return ret;
    }
    static bool verify(auto &&pubk, auto &&msg, bytes_concept sig) {
        edwards_calc c;
        auto A = c.point_decompress(pubk);
        auto R = c.point_decompress(sig.subspan(0,32));
        auto s = bytes_to_bigint(sig.subspan(32), -1);
        if (s > c.q) {
            return false;
        }
        auto h = bytes_to_bigint(sha512::digest(sig.subspan(0,32), pubk, msg), -1) % c.q;
        auto sB = c.point_mul(s, c.g());
        auto hA = c.point_mul(h, A);
        return c.point_equal(sB, c.point_add(R, hA));
    }
};

} // namespace crypto
