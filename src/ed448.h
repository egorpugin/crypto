// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "bigint.h"
#include "random.h"
#include "sha3.h"

namespace crypto {

// rfc8032, also ed448 is there; or NIST.FIPS.186-5
// check for mont. ladder in multiplication to prevent side-channel attacks
struct ed448 {
    struct edwards_point {
        bigint x,y,z;
    };
    struct edwards_calc {
        bigint p, q, d;
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
        auto point_mul(auto &&s, auto &&P) const {
            edwards_point Q{0,1,1};
            auto sz = mpz_sizeinbase(s, 2);
            for (int bit = 0; bit <= sz; ++bit) {
                if (mpz_tstbit(s, bit) == 1) {
                    Q = point_add(Q, P);
                }
                P = point_double(P);
            }
            return Q;
        }
        auto point_compress(auto &&P) const {
            auto zinv = P.z.invert(p);
            auto x = P.x * zinv % p;
            auto y = P.y * zinv % p;
            mpz_tstbit(x, 0) ? mpz_setbit(y, key_size * 8 - 1) : mpz_clrbit(y, key_size * 8 - 1);
            return y;
        }
        auto point_decompress(auto &&s) const {
            auto y = bytes_to_bigint(s, -1);
            auto sign = mpz_tstbit(y, key_size * 8 - 1);
            mpz_clrbit(y, key_size * 8 - 1);
            auto x = recover_x(y, sign);
            return edwards_point{x,y,1};
        }
        bool point_equal(auto &&P, auto &&Q) const {
            if ((P.x * Q.z - Q.x * P.z) % p != 0)
                return false;
            if ((P.y * Q.z - Q.y * P.z) % p != 0)
                return false;
            return true;
        }
    };

    static inline constexpr auto key_size = 57;
    using private_key_type = array<key_size>;
    using public_key_type = array_little<key_size>;

    private_key_type private_key_;

    void private_key() { get_random_secure_bytes(private_key_); }
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
    public_key_type public_key() {
        auto h = private_key_expand();
        edwards_calc c;
        return c.point_compress(c.point_mul(h.a, c.g()));
    }

    static auto dom4(u8 f, auto &ctx) {
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

    auto sign(auto &&msg, auto &&hash, auto &&ph) {
        auto [a,prefix] = private_key_expand();
        edwards_calc c;
        array_little<key_size> A = c.point_compress(c.point_mul(a, c.g()));
        auto r = bytes_to_bigint(hash(prefix, ph(msg)), -1) % c.q;
        array_little<key_size> Rs = c.point_compress(c.point_mul(r, c.g()));
        auto h = bytes_to_bigint(hash(Rs, A, ph(msg)), -1) % c.q;
        auto s = (r + h * a) % c.q;
        array<key_size*2> ret;
        memcpy(ret.data(), Rs.data(), Rs.size());
        array_little<key_size> ret2 = s;
        memcpy(ret.data() + key_size, ret2.data(), ret2.size());
        return ret;
    }
    template <int PH>
    auto sign(auto &&msg, bytes_concept ctx = {}) {
        return sign(msg, dom4(PH, ctx), ph<PH>());
    }
    auto sign(auto &&msg, bytes_concept ctx = {}) {
        return sign<0>(msg, ctx);
    }
    auto sign_ph(auto &&msg, auto &&ctx) {
        return sign<1>(msg, ctx);
    }

    static bool verify(auto &&pubk, auto &&msg, auto &&hash, auto &&ph, bytes_concept sig) {
        if (pubk.size() != key_size) {
            throw std::runtime_error{"bad pubk"};
        }
        if (sig.size() != key_size*2) {
            throw std::runtime_error{"bad sig"};
        }
        edwards_calc c;
        auto A = c.point_decompress(pubk);
        auto R = c.point_decompress(sig.subspan(0,key_size));
        auto s = bytes_to_bigint(sig.subspan(key_size), -1);
        if (s > c.q) {
            return false;
        }
        auto h = bytes_to_bigint(hash(sig.subspan(0,key_size), pubk, ph(msg)), -1) % c.q;
        auto sB = c.point_mul(s, c.g());
        auto hA = c.point_mul(h, A);
        return c.point_equal(sB, c.point_add(R, hA));
    }
    static bool verify(auto &&pubk, auto &&msg, bytes_concept sig) {
        return verify(pubk, msg, bytes_concept{}, sig);
    }
    template <int PH>
    static bool verify(auto &&pubk, auto &&msg, auto &&ctx, bytes_concept sig) {
        return verify(pubk, msg, dom4(PH, ctx), ph<PH>(), sig);
    }
    static bool verify(auto &&pubk, auto &&msg, auto &&ctx, bytes_concept sig) {
        return verify<0>(pubk, msg, ctx, sig);
    }
    static bool verify_ph(auto &&pubk, auto &&msg, auto &&ctx, bytes_concept sig) {
        return verify<1>(pubk, msg, ctx, sig);
    }
};

} // namespace crypto
