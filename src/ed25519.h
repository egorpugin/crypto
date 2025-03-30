// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "ed.h"
#include "sha2.h"

namespace crypto {

// rfc8032, also ed448 is there; or NIST.FIPS.186-5
struct ed25519 : ed_base<ed25519, 32> {
    struct edwards_point {
        bigint x,y,z,t;
    };
    struct edwards_calc : edwards_calc_base {
        //static inline constexpr auto cofactor{8u};
        //static inline constexpr auto c{std::countr_zero(cofactor)};

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
            auto x2 = (y*y-1) * (d*y*y+1).invert(p) % p;
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
        auto point_double(auto &&P) const {
            return point_add(P, P);
        }
        auto point_mul(auto &&s, auto &&P) const {
            edwards_point Q{0,1,1,0};
            return edwards_calc_base::point_mul(s, P, Q);
        }
        auto point_decompress(auto &&s) const {
            auto [x,y] = edwards_calc_base::point_decompress(s);
            return edwards_point{x,y,1,x*y%p};
        }
    };

    auto private_key_expand() {
        auto h = sha512::digest(private_key_);
        h[0] &= 0xf8;
        h[key_size-1] &= 0x7f;
        h[key_size-1] |= 0x40;

        struct x {
            bigint a;
            array<key_size> r;
        };
        x v;
        v.a = bytes_to_bigint(bytes_concept{h.data(), key_size}, -1);
        memcpy(v.r.data(), h.data() + key_size, key_size);
        return v;
    }

    // dom2
    static auto dom(u8 f, auto &ctx) {
        return [f, &ctx](auto &&...vals){
            sha512 h;
            h.update("SigEd25519 no Ed25519 collisions"sv);
            u8 v = f;
            h.update(bytes_concept{&v,1});
            v = ctx.size();
            h.update(bytes_concept{&v,1});
            h.update(ctx);
            h.update(vals...);
            return h.digest();
        };
    }
    template <int F>
    static auto ph() {
        if constexpr (F == 1) {
            return [](auto &&v){return sha512::digest(v);};
        } else if constexpr (F == 0) {
            return [](auto &&v){return v;};
        } else {
            static_assert(false);
        }
    }
    static auto non_dom() {
        return [](auto &&...vals){return sha512::digest(vals...);};
    }

    using ed_base::sign;
    auto sign(auto &&msg) {
        return sign(msg, non_dom(), ph<0>());
    }

    using ed_base::verify;
    static bool verify(auto &&pubk, auto &&msg, bytes_concept sig) {
        return verify(pubk, msg, non_dom(), ph<0>(), sig);
    }
};

} // namespace crypto
