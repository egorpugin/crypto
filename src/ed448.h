// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "ed.h"
#include "sha3.h"

namespace crypto {

// rfc8032, also ed448 is there; or NIST.FIPS.186-5
struct ed448 : ed_base<ed448, 57> {
    struct edwards_point {
        bigint x,y,z;
    };
    struct edwards_calc : edwards_calc_base {
        //static inline constexpr auto cofactor{4u};
        //static inline constexpr auto c{std::countr_zero(cofactor)};

        edwards_calc() {
            p = bigint{2}.pow(448);
            p = p - bigint{2}.pow(224) - 1;

            q = bigint{2}.pow(446);
            q = q - bigint{"13818066809895115352007386748515426880336692474882178609894547503885"sv};

            d = -39081;
            //d = d % p;
        }
        auto g() const {
            edwards_point g;
            g.x = "224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710"sv;
            g.y = "298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660"sv;
            g.z = 1;
            return g;
        }
        bigint recover_x(auto &&y, auto &&sign) const {
            if (y >= p) {
                throw std::runtime_error{"bad y"};
            }
            auto x2 = (y*y-1) * (d*y*y-1).invert(p) % p;
            if (x2 == 0) {
                if (sign) {
                    throw std::runtime_error{"..."};
                }
                return 0;
            }
            // square root of x2
            auto x = x2.powm((p+1) >> 2, p);
            if ((x*x - x2) % p != 0) {
                throw std::runtime_error{"..."};
            }
            if (mpz_tstbit(x, 0) != sign) {
                x = p - x;
            }
            return x;
        }
        auto point_add(auto &&P, auto &&Q) const {
            auto A = P.z * Q.z % p;
            auto B = A * A % p;
            auto C = P.x * Q.x % p;
            auto D = P.y * Q.y % p;
            auto E = d * C * D % p;
            auto F = (B-E)%p;
            auto G = (B+E)%p;
            auto H = (P.x + P.y) * (Q.x + Q.y) % p;
            return edwards_point{A*F*(H-C-D)%p, A*G*(D-C)%p, F*G%p};
        }
        auto point_double(auto &&P) const {
            auto B = (P.x + P.y) % p;
            B = B * B % p;
            auto C = P.x * P.x % p;
            auto D = P.y * P.y % p;
            auto E = (C + D) % p;
            auto H = P.z * P.z % p;
            auto J = (E - H * 2) % p;
            return edwards_point{(B-E)*J%p, E*(C-D)%p, E*J%p};
        }
        auto point_decompress(auto &&s) const {
            auto [x,y] = edwards_calc_base::point_decompress(s);
            return edwards_point{x,y,1};
        }
    };

    auto private_key_expand() {
        shake<256> s;
        s.update(private_key_);
        s.finalize();
        auto h = s.squeeze<key_size*2*8>();
        h[0] &= 0xfc;
        h[key_size-2] |= 0x80;
        h[key_size-1] = 0;

        struct x {
            bigint a;
            array<key_size> r;
        };
        x v;
        v.a = bytes_to_bigint(bytes_concept{h.data(), key_size}, -1);
        memcpy(v.r.data(), h.data() + key_size, key_size);
        return v;
    }

    // dom4
    static auto dom(u8 f, auto &ctx) {
        return [f, &ctx](auto &&...vals){
            shake<256> h;
            h.update("SigEd448"sv);
            u8 v = f;
            h.update(bytes_concept{&v,1});
            v = ctx.size();
            h.update(bytes_concept{&v,1});
            h.update(ctx);
            h.update(vals...);
            h.finalize();
            return h.squeeze<key_size*2*8>();
        };
    }
    template <int F>
    static auto ph() {
        if constexpr (F == 1) {
            return [](auto &&v){
                shake<256> h;
                h.update(v);
                h.finalize();
                return h.squeeze<64*8>();
            };
        } else if constexpr (F == 0) {
            return [](auto &&v){return v;};
        } else {
            static_assert(false);
        }
    }

    using ed_base::sign;
    auto sign(auto &&msg) {
        return sign(msg, bytes_concept{});
    }

    using ed_base::verify;
    static bool verify(auto &&pubk, auto &&msg, bytes_concept sig) {
        return verify(pubk, msg, bytes_concept{}, sig);
    }
};

} // namespace crypto
