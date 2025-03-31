// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "bigint.h"
#include "random.h"

namespace crypto {

template <typename T, auto KeySize>
struct ed_base {
    struct edwards_calc_base {
        bigint p, q, d;

        // check for mont. ladder in multiplication to prevent side-channel attacks
        auto point_mul(this auto &&obj, auto &&s, auto &&P, auto &&Q) {
            auto sz = mpz_sizeinbase(s, 2);
            for (int bit = 0; bit <= sz; ++bit) {
                if (mpz_tstbit(s, bit) == 1) {
                    Q = obj.point_add(Q, P);
                }
                P = obj.point_double(P);
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
        auto point_decompress(this auto &&obj, auto &&s) {
            auto y = bytes_to_bigint(s, -1);
            auto sign = mpz_tstbit(y, key_size * 8 - 1);
            mpz_clrbit(y, key_size * 8 - 1);
            auto x = obj.recover_x(y, sign);
            return std::tuple{x,y};
        }
        bool point_equal(auto &&P, auto &&Q) const {
            if ((P.x * Q.z - Q.x * P.z) % p != 0)
                return false;
            if ((P.y * Q.z - Q.y * P.z) % p != 0)
                return false;
            return true;
        }
    };

    static inline constexpr auto key_size = KeySize;
    using private_key_type = array<key_size>;
    using public_key_type = array_little<key_size>;

    private_key_type private_key_;

    void private_key(this auto &&obj) { get_random_secure_bytes(obj.private_key_); }
    public_key_type public_key(this auto &&obj) {
        auto h = obj.private_key_expand();
        typename T::edwards_calc c;
        return c.point_compress(c.point_mul(h.a, c.g()));
    }
    auto sign(this auto &&obj, auto &&msg, auto &&hash, auto &&ph) {
        auto [a,prefix] = obj.private_key_expand();
        typename T::edwards_calc c;
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
    auto sign(this auto &&obj, auto &&msg, auto &&ctx) {
        return obj.sign(msg, obj.dom(PH, ctx), obj.template ph<PH>());
    }
    auto sign(this auto &&obj, auto &&msg, auto &&ctx) {
        return obj.template sign<0>(msg, ctx);
    }
    auto sign_ph(this auto &&obj, auto &&msg, auto &&ctx) {
        return obj.template sign<1>(msg, ctx);
    }

    static bool verify(auto &&pubk, auto &&msg, auto &&hash, auto &&ph, bytes_concept sig) {
        if (pubk.size() != key_size) {
            throw std::runtime_error{"bad pubk"};
        }
        if (sig.size() != key_size * 2) {
            throw std::runtime_error{"bad sig"};
        }
        typename T::edwards_calc c;
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
    template <int PH>
    static bool verify(auto &&pubk, auto &&msg, auto &&ctx, bytes_concept sig) {
        return T::verify(pubk, msg, T::dom(PH, ctx), T::template ph<PH>(), sig);
    }
    static bool verify(auto &&pubk, auto &&msg, auto &&ctx, bytes_concept sig) {
        return verify<0>(pubk, msg, ctx, sig);
    }
    static bool verify_ph(auto &&pubk, auto &&msg, auto &&ctx, bytes_concept sig) {
        return verify<1>(pubk, msg, ctx, sig);
    }
};

}
