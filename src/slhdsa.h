// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2026 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "sha2.h"
#include "sha3.h"
#include "hmac.h"

namespace crypto {

namespace slh_dsa_detail {

auto rev8_be32(u32 x) {
    return std::byteswap(x);
}

uint64_t slh_toint(const u8 *x, unsigned n) {
    unsigned i;
    uint64_t t;

    if (n == 0)
        return 0;
    t = (uint64_t)x[0];
    for (i = 1; i < n; i++) {
        t <<= 8;
        t += (uint64_t)x[i];
    }
    return t;
}
void slh_tobyte(u8 *x, uint64_t t, unsigned n) {
    unsigned i;

    if (n == 0)
        return;
    for (i = n - 1; i > 0; i--) {
        x[i] = (u8)(t & 0xFF);
        t >>= 8;
    }
    x[0] = (u8)t;
}

size_t base_2b(u32 *v, const u8 *x, u32 b, size_t v_len) {
    size_t i, j;
    u32 l, t, m;

    j = 0;
    l = 0;
    t = 0;
    m = (1 << b) - 1;
    for (i = 0; i < v_len; i++) {
        while (l < b) {
            t = (t << 8) + x[j++];
            l += 8;
        }
        l -= b;
        v[i] = (t >> l) & m;
    }
    return j;
}
size_t base_16(u32 *v, const u8 *x, int v_len) {
    int i, j, l, t;

    j = 0;
    for (i = 0; i < v_len - 2; i += 2) {
        t = x[j++];
        v[i] = t >> 4;
        v[i + 1] = t & 0xF;
    }

    l = 0;
    t = 0;
    for (; i < v_len; i++) {
        while (l < 4) {
            t = (t << 8) + x[j++];
            l += 8;
        }
        l -= 4;
        v[i] = (t >> l) & 0xF;
    }
    return j;
}

struct adrs {
    enum adrs_type : u32 {
        WOTS_HASH,
        WOTS_PK,
        TREE,
        FORS_TREE,
        FORS_ROOTS,
        WOTS_PRF,
        FORS_PRF,
    };

    std::array<u32, 8> value;

    void zero() {
        memset(value.data(), 0, sizeof(u32) * value.size());
    }
    auto data() {
        return (u8*)value.data();
    }

    void set_layer_address(u32 x) {
        value[0] = rev8_be32(x);
    }
    void set_tree_address(uint64_t x) {
        // bytes a[4:8] of tree address are always zero
        value[2] = rev8_be32(x >> 32);
        value[3] = rev8_be32(x & 0xFFFFFFFF);
    }
    void set_type(u32 x) {
        value[4] = rev8_be32(x);
    }
    void set_key_pair_address(u32 x) {
        value[5] = rev8_be32(x);
    }
    void set_tree_height(u32 x) {
        value[6] = rev8_be32(x);
    }
    void set_chain_address(u32 x) {
        value[6] = rev8_be32(x);
    }
    void set_hash_address(u32 x) {
        value[7] = rev8_be32(x);
    }
    void set_tree_index(u32 x) {
        value[7] = rev8_be32(x);
    }

    void set_type_and_clear(u32 x) {
        value[4] = rev8_be32(x);
        value[5] = 0;
        value[6] = 0;
        value[7] = 0;
    }
    void set_type_and_clear_not_kp(u32 x) {
        value[4] = rev8_be32(x);
        value[6] = 0;
        value[7] = 0;
    }
};

}

struct param_set {
    using param_type = size_t;

    size_t n;
    size_t h;
    size_t d;
    size_t hp;
    size_t a;
    size_t k;
    size_t lg_w;
    size_t m;

    constexpr u32 get_len1() const {
        return ((8 * n + lg_w - 1) / lg_w);
    }
    constexpr u32 get_len2() const {
        //  Appendix B:
        //  "When lg_w = 4 and 9 <= n <= 136, the value of len2 will be 3."
        //assert(lg_w == 4 && n >= 9 && n <= 136);
        // w = 2^lg_w
        // log2(len1() * (w-1))/lg_w + 1
        return 3;
    }
    constexpr u32 get_len() const {
        return get_len1() + get_len2();
    }

    constexpr u32 get_max_n() const {
        return 32;
    }
    constexpr u32 get_max_len() const {
        //return 2 * n + 3;
        //return 2 * get_max_n() + 3;
        return get_len();
    }

    constexpr u32 sig_bytes() const {
        return (1 + k * (1 + a) + h + d * get_len()) * n;
    }
};

// s for small signatures
// f for fast signature generation

template <int, char>
constexpr param_set slh_dsa_params;
template <> constexpr param_set slh_dsa_params<128, 's'> = { 16, 63, 7, 9, 12, 14, 4, 30 };
template <> constexpr param_set slh_dsa_params<128, 'f'> = { 16, 66, 22, 3, 6, 33, 4, 34 };
template <> constexpr param_set slh_dsa_params<192, 's'> = { 24, 63, 7, 9, 14, 17, 4, 39 };
template <> constexpr param_set slh_dsa_params<192, 'f'> = { 24, 66, 22, 3, 8, 33, 4, 42 };
template <> constexpr param_set slh_dsa_params<256, 's'> = { 32, 64, 8, 8, 14, 22, 4, 47 };
template <> constexpr param_set slh_dsa_params<256, 'f'> = { 32, 68, 17, 4, 9, 35, 4, 49 };

//
template <auto param_set>
struct slh_dsa_base {
    static constexpr inline auto pk_bytes = param_set.n * 2;
    static constexpr inline auto sig_bytes = param_set.sig_bytes();
    static constexpr inline auto params = param_set;

    struct public_key {
        u8 seed[param_set.n];
        u8 root[param_set.n];

        operator u8*() { return seed; }
        operator bytes_concept() { return { seed,param_set.n * 2 }; }
    };
    struct private_key {
        u8 seed[param_set.n];
        u8 prf[param_set.n];
        public_key pk;

        operator u8*() {return seed;}
        u8 *data() {return seed;}
        operator bytes_concept() {return {seed,param_set.n * 4};}
    };

    private_key sk;
    slh_dsa_detail::adrs t_adrs;
    slh_dsa_detail::adrs *adrs;

    slh_dsa_base() {
        adrs = &t_adrs;
    }
    void keygen(this auto &&obj, std::span<const u8, param_set.n * 3> seed) {
        constexpr auto n = param_set.n;

        memcpy(obj.sk.seed, seed.data(), seed.size()); // SK.seed || SK.prf || PK.seed
        memset(obj.sk.pk.root, 0x00, n); // PK.root not generated yet

        // only for static function
        //memcpy(obj.sk.seed, sk, n);
        //memcpy(obj.sk.prf, sk + n, n);
        //memcpy(obj.sk.pk.seed, sk + 2 * n, n);
        //memcpy(obj.sk.pk.root, sk + 3 * n, n);

        obj.adrs->zero();
        obj.adrs->set_layer_address(param_set.d - 1);
        obj.xmss_node(obj.sk.pk.root, 0, param_set.hp);
    }
    auto sign(this auto &&obj, auto &&msg, auto &&rand, auto &&ctx) {
        if (ctx.size() > 255) {
            throw std::runtime_error{"too long ctx"};
        }

        //auto msg_f = [&](auto &s){s.update(msg);}; // pure or 'internal' non fips or pre fips version
        // pure fips version
        auto msg_f = [&](auto &s) {
            s.update(array<1>{0});
            s.update(array<1>{(u8)ctx.size()});
            s.update(ctx);
            s.update(msg);
        };
        // prehash versipn
        /*auto msg_f = [&](auto &s) {
            s.update(array<1>{1});
            s.update(array<1>{(u8)ctx.size()});
            s.update(ctx);
            s.update(oid);
            s.update(ph(m));
            s.update(msg);
        };*/

        array<sig_bytes> sig{};
        // randomized hashing; R
        obj.PRF_msg(sig.data(), rand, msg_f);
        u8 digest[param_set.m];
        obj.H_msg(digest, sig.data(), msg_f);
        // create FORS and HT signature parts
        obj.do_sign(sig.data() + param_set.n, digest);
        return sig;
    }
    auto sign(this auto &&obj, auto &&msg) {
        return obj.sign(msg, obj.sk.pk.seed, bytes_concept{});
    }
    auto sign_with_ctx(this auto &&obj, auto &&msg, auto &&ctx) {
        return obj.sign(msg, obj.sk.pk.seed, ctx);
    }
    bool verify(this auto &&obj, auto &&msg, auto &&sig, auto &&ctx) {
        if (ctx.size() > 255) {
            throw std::runtime_error{ "too long ctx" };
        }

        auto msg_f = [&](auto &s) {
            s.update(array<1>{0});
            s.update(array<1>{(u8)ctx.size()});
            s.update(ctx);
            s.update(msg);
        };

        u8 digest[param_set.m];
        u8 pk_fors[param_set.n];

        const u8 *r = sig.data();
        const u8 *sig_fors = sig.data() + param_set.n;
        const u8 *sig_ht = sig.data() + ((1 + param_set.k * (1 + param_set.a)) * param_set.n);

        // mk_ctx - only for static function
        //memcpy(obj.sk.pk.seed, pk, n);
        //memcpy(obj.sk.pk.root, pk + n, n);

        obj.H_msg(digest, r, msg_f);

        const u8 *md = digest;
        uint64_t i_tree = 0;
        u32 i_leaf = 0;
        split_digest(&i_tree, &i_leaf, digest);

        obj.adrs->zero();
        obj.adrs->set_tree_address(i_tree);
        obj.adrs->set_type_and_clear_not_kp(obj.adrs->FORS_TREE);
        obj.adrs->set_key_pair_address(i_leaf);

        obj.fors_pk_from_sig(pk_fors, sig_fors, md);

        return obj.ht_verify(pk_fors, sig_ht, i_tree, i_leaf);
    }
    bool verify(this auto &&obj, auto &&msg, auto &&sig) {
        return obj.verify(msg, sig, bytes_concept{});
    }

private:
    void do_sign(this auto &&obj, u8 *sig, const u8 *digest) {
        const u8 *md = digest;
        uint64_t i_tree = 0;
        u32 i_leaf = 0;
        u8 pk_fors[param_set.n];

        split_digest(&i_tree, &i_leaf, digest);

        obj.adrs->zero();
        obj.adrs->set_tree_address(i_tree);
        obj.adrs->set_type_and_clear_not_kp(obj.adrs->FORS_TREE);
        obj.adrs->set_key_pair_address(i_leaf);

        // SIG_FORS
        auto sig_sz = obj.fors_sign(sig, md);
        obj.fors_pk_from_sig(pk_fors, sig, md);

        // SIG_HT
        sig += sig_sz;
        sig_sz += obj.ht_sign(sig, pk_fors, i_tree, i_leaf);
    }
    bool ht_verify(this auto &&obj, const u8 *m, const u8 *sig_ht, uint64_t i_tree, u32 i_leaf) {
        u32 i, j;
        u8 node[param_set.n];
        size_t st_sz;

        obj.adrs->zero();
        obj.adrs->set_tree_address(i_tree);

        obj.xmss_pk_from_sig(node, i_leaf, sig_ht, m);

        st_sz = (param_set.hp + param_set.get_len()) * param_set.n;
        for (j = 1; j < param_set.d; j++) {
            i_leaf = i_tree & ((1 << param_set.hp) - 1);
            i_tree >>= param_set.hp;
            obj.adrs->set_layer_address(j);
            obj.adrs->set_tree_address(i_tree);
            sig_ht += st_sz;
            obj.xmss_pk_from_sig(node, i_leaf, sig_ht, node);
        }

        u8 t;
        t = 0;
        for (i = 0; i < param_set.n; i++) {
            t |= node[i] ^ obj.sk.pk.root[i];
        }
        return t == 0;
    }
    static void split_digest(uint64_t *i_tree, u32 *i_leaf, const u8 *digest) {
        size_t md_sz = (param_set.k * param_set.a + 7) / 8;
        const u8 *pi_tree = digest + md_sz;
        size_t i_tree_sz = (param_set.h - param_set.hp + 7) / 8;
        *i_tree = slh_dsa_detail::slh_toint(pi_tree, i_tree_sz);
        size_t i_leaf_sz = (param_set.hp + 7) / 8;
        const u8 *pi_leaf = pi_tree + i_tree_sz;
        *i_leaf = slh_dsa_detail::slh_toint(pi_leaf, i_leaf_sz);
        if ((param_set.h - param_set.hp) != 64) {
            *i_tree &= (UINT64_C(1) << (param_set.h - param_set.hp)) - UINT64_C(1);
        }
        *i_leaf &= (1 << param_set.hp) - 1;
    }
    size_t fors_sign(this auto &&obj, u8 *sf, const u8 *md) {
        u32 i, j, s;
        u32 vi[param_set.k];
        size_t  n = param_set.n;

        slh_dsa_detail::base_2b(vi, md, param_set.a, param_set.k);

        for (i = 0; i < param_set.k; i++) {

            //  fors_SKgen()
            obj.adrs->set_tree_index((i << param_set.a) + vi[i]);
            obj.fors_hash(sf, 0);
            sf += n;

            for (j = 0; j < param_set.a; j++) {
                s = (vi[i] >> j) ^ 1;
                obj.fors_node(sf, (i << (param_set.a - j)) + s, j);
                sf += n;
            }
        }
        return n * param_set.k * (1 + param_set.a);
    }
    void fors_node(this auto &&obj, u8 *node, u32 i, u32 z) {
        u8 h[param_set.a][param_set.n], *h0;
        u32 j, k;
        int p;

        p = -1;
        i <<= z;
        for (j = 0; j < (1u << z); j++) {

            // fors_SKgen() + hash
            obj.adrs->set_tree_index(i);
            h0 = p >= 0 ? h[p] : node;
            p++;
            obj.fors_hash(h0, 1);

            // this fors_node() implementation is non-recursive
            for (k = 0; (j >> k) & 1; k++) {
                obj.adrs->set_tree_height(k + 1);
                obj.adrs->set_tree_index(i >> (k + 1));
                p--;
                h0 = p > 0 ? h[p - 1] : node;
                obj.H(h0, h0, h[p]);
            }
            i++;        //  advance index
        }
    }
    void fors_pk_from_sig(this auto &&obj, u8 *pk, const u8 *sf, const u8 *md) {
        u32 i, j, idx;
        u32 vi[param_set.k];
        u8 root[param_set.k * param_set.n];
        u8 *node;
        size_t n = param_set.n;

        slh_dsa_detail::base_2b(vi, md, param_set.a, param_set.k);

        node = root;
        for (i = 0; i < param_set.k; i++) {
            obj.adrs->set_tree_height(0);

            idx = (i << param_set.a) + vi[i];
            obj.adrs->set_tree_index(idx);

            obj.F(node, sf);
            sf += n;

            for (j = 0; j < param_set.a; j++) {
                obj.adrs->set_tree_height(j + 1);
                obj.adrs->set_tree_index(idx >> (j + 1));

                if (((vi[i] >> j) & 1) == 0) {
                    obj.H(node, node, sf);
                } else {
                    obj.H(node, sf, node);
                }
                sf += n;
            }
            node += n;
        }

        obj.adrs->set_type_and_clear_not_kp(obj.adrs->FORS_ROOTS);
        obj.T(pk, root, param_set.k * n);
    }
    size_t ht_sign(this auto &&obj, u8 *sh, u8 *m, uint64_t i_tree, u32 i_leaf) {
        u32 j;
        size_t sx_sz;

        obj.adrs->zero();
        obj.adrs->set_tree_address(i_tree);
        sx_sz = obj.xmss_sign(sh, m, i_leaf);

        for (j = 1; j < param_set.d; j++) {
            obj.xmss_pk_from_sig(m, i_leaf, sh, m);
            sh += sx_sz;

            i_leaf = i_tree & ((1 << param_set.hp) - 1);
            i_tree >>= param_set.hp;
            obj.adrs->set_layer_address(j);
            obj.adrs->set_tree_address(i_tree);
            obj.xmss_sign(sh, m, i_leaf);
        }

        return sx_sz * param_set.d;
    }
    size_t xmss_sign(this auto &&obj, u8 *sx, const u8 *m, u32 idx) {
        u32 j, k;
        u8 *auth;
        size_t sx_sz = 0;
        size_t n = param_set.n;

        sx_sz = param_set.get_len() * n;
        auth = sx + sx_sz;

        for (j = 0; j < param_set.hp; j++) {
            k = (idx >> j) ^ 1;
            obj.xmss_node(auth, k, j);
            auth += n;
        }
        sx_sz += param_set.hp * n;

        obj.adrs->set_type_and_clear_not_kp(obj.adrs->WOTS_HASH);
        obj.adrs->set_key_pair_address(idx);
        obj.wots_sign(sx, m);

        return sx_sz;
    }
    void xmss_node(this auto &&obj, u8 *node, u32 i, u32 z) {
        u8 h[param_set.hp][param_set.n];
        u8 tmp[param_set.get_max_len() * param_set.n];
        auto n = param_set.n;
        constexpr auto len = param_set.get_len();

        int p = -1;
        i <<= z;
        for (u32 j = 0; j < (1u << z); ++j, ++i) {
            obj.adrs->set_key_pair_address(i);

            // === Generate a WOTS+ public key.
            // Algorithm 5: wots_PKgen(SK.seed, PK.seed, ADRS)
            auto sk = tmp;
            for (auto k = 0; k < len; k++) {
                obj.adrs->set_chain_address(k);
                obj.wots_chain(sk, 15);   // w-1 = (1 << param_set.lg_w) - 1;
                sk += n;
            }
            obj.adrs->set_type_and_clear_not_kp(obj.adrs->WOTS_PK);
            auto h0 = p >= 0 ? h[p] : node;
            ++p;
            obj.T(h0, tmp, len * n);

            // this xmss_node() implementation is non-recursive
            for (auto k = 0; (j >> k) & 1; k++) {
                obj.adrs->set_type_and_clear(obj.adrs->TREE);
                obj.adrs->set_tree_height(k + 1);
                obj.adrs->set_tree_index(i >> (k + 1));
                --p;
                h0 = p >= 1 ? h[p - 1] : node;
                obj.H(h0, h0, h[p]);
            }
        }
    }
    void xmss_pk_from_sig(this auto &&obj, u8 *root, u32 idx, const u8 *sig, const u8 *m) {
        u32 k;
        const u8 *auth;
        size_t n = param_set.n;

        obj.adrs->set_type_and_clear_not_kp(obj.adrs->WOTS_HASH);
        obj.adrs->set_key_pair_address(idx);

        obj.wots_pk_from_sig(root, sig, m);
        obj.adrs->set_type_and_clear(obj.adrs->TREE);

        auth = sig + (param_set.get_len() * n);

        for (k = 0; k < param_set.hp; k++) {
            obj.adrs->set_tree_height(k + 1);
            obj.adrs->set_tree_index(idx >> (k + 1));

            if (((idx >> k) & 1) == 0) {
                obj.H(root, root, auth);
            } else {
                obj.H(root, auth, root);
            }
            auth += n;
        }
    }
    size_t wots_sign(this auto &&obj, u8 *sig, const u8 *m) {
        u32 i, len;
        u32 vm[param_set.get_max_len()];
        size_t n = param_set.n;

        len = param_set.get_len();
        obj.wots_csum(vm, m);

        for (i = 0; i < len; i++) {
            obj.adrs->set_chain_address(i);
            obj.wots_chain(sig, vm[i]);
            sig += n;
        }
        return n * len;
    }
    void wots_csum(u32 *vm, const u8 *m) {
        u32 csum, i, t;
        u32 len1, len2;
        u8 buf[4];

        len1 = param_set.get_len1();
        len2 = param_set.get_len2();

        //base_2b(vm, m, prm->lg_w, len1);
        slh_dsa_detail::base_16(vm, m, len1);

        csum = 0;
        t = (1 << param_set.lg_w) - 1;
        for (i = 0; i < len1; i++) {
            csum += t - vm[i];
        }
        csum <<= (8 - ((len2 * param_set.lg_w) & 7)) & 7;

        t = (len2 * param_set.lg_w + 7) / 8;
        memset(buf, 0, sizeof(buf));
        slh_dsa_detail::slh_tobyte(buf, csum, t);

        //base_2b(&vm[len1], buf, prm->lg_w, len2);
        slh_dsa_detail::base_16(&vm[len1], buf, len2);
    }
    void wots_pk_from_sig(this auto &&obj, u8 *pk, const u8 *sig, const u8 *m) {
        u32 i, t, len;
        u32 vm[param_set.get_max_len()];
        u8 tmp[param_set.get_max_len() * param_set.n];
        size_t n = param_set.n;
        size_t tmp_sz;

        obj.wots_csum(vm, m);

        len = param_set.get_len();
        t = 15; // (1 << prm->lg_w) - 1;
        tmp_sz = 0;
        for (i = 0; i < len; i++) {
            obj.adrs->set_chain_address(i);
            obj.chain(tmp + tmp_sz, sig + tmp_sz, vm[i], t - vm[i]);
            tmp_sz += n;
        }

        obj.adrs->set_type_and_clear_not_kp(obj.adrs->WOTS_PK);
        obj.T(pk, tmp, tmp_sz);
    }
    void chain(this auto &&obj, u8 *tmp, const u8 *x, u32 i, u32 s) {
        memcpy(tmp, x, param_set.n);
        for (int j = i; j < s + i; j++) {
            obj.adrs->set_hash_address(j);
            obj.F(tmp, tmp);
        }
    }
    void wots_chain(this auto &&obj, u8 *tmp, u32 s) {
        // PRF secret key
        obj.adrs->set_type(obj.adrs->WOTS_PRF);
        obj.adrs->set_tree_index(0);
        obj.PRF(tmp);

        // chain
        obj.adrs->set_type(obj.adrs->WOTS_HASH);
        obj.chain(tmp, tmp, 0, s);
    }
    void fors_hash(this auto &&obj, u8 *tmp, u32 s) {
        // PRF secret key
        obj.adrs->set_type(obj.adrs->FORS_PRF);
        obj.adrs->set_tree_height(0);
        obj.PRF(tmp);

        // hash it again
        if (s == 1) {
            obj.adrs->set_type(obj.adrs->FORS_TREE);
            obj.F(tmp, tmp);
        }
    }
};

//
template <typename HashAlgo1, typename HashAlgo2, auto param_set>
struct slh_dsa_sha2_base : slh_dsa_base<param_set> {
    using sha2_type1 = HashAlgo1;
    using sha2_type2 = HashAlgo2;

    auto H_msg(u8 *h, const u8 *r, auto &&msg_f) {
        sha2_type2 s;
        s.update(r, param_set.n);
        s.update(this->sk.pk.seed);
        s.update(this->sk.pk.root);
        msg_f(s);
        auto dgst = s.digest();

        mgf1_f<sha2_type2>(h, param_set.m, [&](auto &h) {
            h.update(r, param_set.n);
            h.update(this->sk.pk.seed);
            h.update(dgst);
        });
    }
    auto PRF_msg(u8 *h, u8 *rand, auto &&msg_f) {
        hmac_t<sha2_type2> s{this->sk.prf};
        s.update(rand, param_set.n);
        msg_f(s);
        auto dgst = s.digest();
        memcpy(h, dgst.data(), param_set.n);
    }
    auto PRF(u8 *h) {
        sha2_type1 s;
        s.update(this->sk.pk.seed);
        s.update(array<s.chunk_size_bytes - param_set.n>{});
        update_adrsc(s);
        s.update(this->sk.seed);
        auto dgst = s.digest();
        memcpy(h, dgst.data(), param_set.n);
    }
    auto F(u8 *h, const u8 *m1) {
        sha2_type1 s;
        s.update(this->sk.pk.seed);
        s.update(array<s.chunk_size_bytes - param_set.n>{});
        update_adrsc(s);
        s.update(m1, param_set.n);
        auto dgst = s.digest();
        memcpy(h, dgst.data(), param_set.n);
    }
    auto H(u8 *h, const u8 *m1, const u8 *m2) {
        sha2_type2 s;
        s.update(this->sk.pk.seed);
        s.update(array<s.chunk_size_bytes - param_set.n>{});
        update_adrsc(s);
        s.update(m1, param_set.n);
        s.update(m2, param_set.n);
        auto dgst = s.digest();
        memcpy(h, dgst.data(), param_set.n);
    }
    auto T(u8 *h, const u8 *m, size_t m_sz) {
        sha2_type2 s;
        s.update(this->sk.pk.seed);
        s.update(array<s.chunk_size_bytes - param_set.n>{});
        update_adrsc(s);
        s.update(m, m_sz);
        auto dgst = s.digest();
        memcpy(h, dgst.data(), param_set.n);
    }
    void update_adrsc(auto &&s) {
        auto *p = this->adrs->data();
        s.update(p + 3, 1);
        s.update(p + 8, 8);
        s.update(p + 19, 32-19);
    }
};

// something is wrong with out sha2 version
template <auto> struct slh_dsa_sha2_s;
template <> struct slh_dsa_sha2_s<128> : slh_dsa_sha2_base<sha256, sha256, slh_dsa_params<128, 's'>> {};
template <> struct slh_dsa_sha2_s<192> : slh_dsa_sha2_base<sha256, sha512, slh_dsa_params<192, 's'>> {};
template <> struct slh_dsa_sha2_s<256> : slh_dsa_sha2_base<sha256, sha512, slh_dsa_params<256, 's'>> {};

// something is wrong with out sha2 version
template <auto> struct slh_dsa_sha2_f;
template <> struct slh_dsa_sha2_f<128> : slh_dsa_sha2_base<sha256, sha256, slh_dsa_params<128, 'f'>> {};
template <> struct slh_dsa_sha2_f<192> : slh_dsa_sha2_base<sha256, sha512, slh_dsa_params<192, 'f'>> {};
template <> struct slh_dsa_sha2_f<256> : slh_dsa_sha2_base<sha256, sha512, slh_dsa_params<256, 'f'>> {};

//
template <auto param_set>
struct slh_dsa_shake_base : slh_dsa_base<param_set> {
    using shake_type = shake<256>;

    auto H_msg(u8 *h, const u8 *r, auto &&msg_f) {
        shake_type s;
        s.update(r, param_set.n);
        s.update(this->sk.pk.seed);
        s.update(this->sk.pk.root);
        msg_f(s);
        s.finalize();
        s.squeeze(h, param_set.m);
    }
    auto PRF_msg(u8 *h, u8 *rand, auto &&msg_f) {
        auto n = param_set.n;

        shake_type s;
        s.update(this->sk.prf);
        s.update(rand, n);
        msg_f(s);
        s.finalize();
        s.squeeze(h, n);
    }
    void PRF(u8 *h) {
        F(h, this->sk.seed);
    }
    void F(u8 *h, const u8 *m1) {
        auto n = param_set.n;

        shake_type s;
        s.update(this->sk.pk.seed);
        s.update(this->adrs->value);
        s.update(m1, n);
        s.finalize();
        s.squeeze(h, n);
    }
    void H(u8 *h, const u8 *m1, const u8 *m2) {
        auto n = param_set.n;

        shake_type s;
        s.update(this->sk.pk.seed);
        s.update(this->adrs->value);
        s.update(m1, n);
        s.update(m2, n);
        s.finalize();
        s.squeeze(h, n);
    }
    void T(u8 *h, const u8 *m, size_t m_sz) {
        auto n = param_set.n;

        shake_type s;
        s.update(this->sk.pk.seed);
        s.update(this->adrs->value);
        s.update(m, m_sz);
        s.finalize();
        s.squeeze(h, n);
    }
};

template <auto> struct slh_dsa_shake_s;
template <> struct slh_dsa_shake_s<128> : slh_dsa_shake_base<slh_dsa_params<128, 's'>> {};
template <> struct slh_dsa_shake_s<192> : slh_dsa_shake_base<slh_dsa_params<192, 's'>> {};
template <> struct slh_dsa_shake_s<256> : slh_dsa_shake_base<slh_dsa_params<256, 's'>> {};

template <auto> struct slh_dsa_shake_f;
template <> struct slh_dsa_shake_f<128> : slh_dsa_shake_base<slh_dsa_params<128, 'f'>> {};
template <> struct slh_dsa_shake_f<192> : slh_dsa_shake_base<slh_dsa_params<192, 'f'>> {};
template <> struct slh_dsa_shake_f<256> : slh_dsa_shake_base<slh_dsa_params<256, 'f'>> {};

}
