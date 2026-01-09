// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2026 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "sha2.h"
#include "sha3.h"

/*

      id-slh-dsa-sha2-128s:  SHA-256
      id-slh-dsa-sha2-128f:  SHA-256
      id-slh-dsa-sha2-192s:  SHA-512
      id-slh-dsa-sha2-192f:  SHA-512
      id-slh-dsa-sha2-256s:  SHA-512
      id-slh-dsa-sha2-256f:  SHA-512
      id-slh-dsa-shake-128s: SHAKE128 with 256-bit output
      id-slh-dsa-shake-128f: SHAKE128 with 256-bit output
      id-slh-dsa-shake-192s: SHAKE256 with 512-bit output
      id-slh-dsa-shake-192f: SHAKE256 with 512-bit output
      id-slh-dsa-shake-256s: SHAKE256 with 512-bit output
      id-slh-dsa-shake-256f: SHAKE256 with 512-bit output

*/

namespace crypto {

namespace slh_dsa_detail {

struct adrs_base {
    u32 layer_address;
    u32 tree_address[3];
    u32 type;
};

struct wots_hash : adrs_base {
    u32 key_pair_address;
    u32 chain_address;
    u32 hash_address;
};
struct wots_pk : adrs_base {
    u32 key_pair_address;
    u32 padding[2]{};
};
struct tree : adrs_base {
    u32 padding{};
    u32 tree_height;
    u32 tree_index;
};
struct fors_tree : adrs_base {
    u32 key_pair_address;
    u32 tree_height;
    u32 tree_index;
};
struct fors_roots : adrs_base {
    u32 key_pair_address;
    u32 padding[2]{};
};
struct wots_prf : adrs_base {
    u32 key_pair_address;
    u32 chain_address;
    u32 hash_address{};
};
struct fors_prf : fors_tree {
    u32 key_pair_address;
    u32 tree_height{};
    u32 tree_index;
};

auto rev8_be32(u32 x) {
    return std::byteswap(x);
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
    void set_type(uint32_t x) {
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

    constexpr uint32_t get_len1() const {
        return ((8 * n + lg_w - 1) / lg_w);
    }
    constexpr uint32_t get_len2() const {
        //  Appedix B:
        //  "When lg_w = 4 and 9 <= n <= 136, the value of len2 will be 3."
        //assert(prm->lg_w == 4 && prm->n >= 9 && prm->n <= 136);
        return 3;
    }
    constexpr uint32_t get_len() const {
        return get_len1() + get_len2();
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

    struct public_key {
        u8 seed[param_set.n];
        u8 root[param_set.n];
        operator bytes_concept() { return { seed,param_set.n * 2 }; }
    };
    struct private_key {
        u8 seed[param_set.n];
        u8 prf[param_set.n];
        public_key pk;

        operator u8*() {return seed;}
        operator bytes_concept() {return {seed,param_set.n * 4};}
    };

    private_key sk;
    slh_dsa_detail::adrs t_adrs;
    slh_dsa_detail::adrs *adrs;

    void keygen(this auto &&obj, std::span<const u8, param_set.n * 3> seed) {
        uint8_t pk_root[param_set.n];

        memcpy(obj.sk.seed, seed.data(), seed.size()); // SK.seed || SK.prf || PK.seed
        memset(obj.sk.pk.root, 0x00, param_set.n); // PK.root not generated yet
        obj.mk_ctx(nullptr, obj.sk); // fill in partial

        obj.adrs->zero();
        obj.adrs->set_layer_address(param_set.d - 1);
        obj.xmss_node(pk_root, 0, param_set.hp);

        // fill pk_root
        memcpy(obj.sk.pk.root, pk_root, param_set.n);
    }
    auto sign(this auto &&obj, auto &&msg, auto &&rand) {
        array<param_set.n + param_set.m> sig{};
        //  randomized hashing; R
        obj.PRF_msg(sig.data(), rand, msg);
        obj.H_msg(sig.data() + param_set.n, sig.data(), msg);
        //  create FORS and HT signature parts
        //slh_do_sign(r + param_set.n, digest);
        return sig;
    }
    auto sign(this auto &&obj, auto &&msg) {
        obj.sign(msg, obj.sk.pk.seed);
    }
    void verify() {

    }

    void xmss_node(this auto &&obj, uint8_t *node, uint32_t i, uint32_t z) {
        uint8_t h[param_set.hp][param_set.n];
        // SLH_MAX_LEN == (2 * SLH_MAX_N + 3)
        uint8_t tmp[(2 * param_set.n + 3) * param_set.n];
        auto n = param_set.n;
        constexpr auto len = param_set.get_len();

        int p = -1;
        i <<= z;
        for (u32 j = 0; j < (1u << z); ++j, ++i) {
            obj.adrs->set_key_pair_address(i);

            //  === Generate a WOTS+ public key.
            //  Algorithm 5: wots_PKgen(SK.seed, PK.seed, ADRS)
            auto sk = tmp;
            for (auto k = 0; k < len; k++) {
                obj.adrs->set_chain_address(k);
                obj.wots_chain(sk, 15);   //  w-1 =  (1 << prm->lg_w) - 1;
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
    /*size_t slh_do_sign(uint8_t *sig, const uint8_t *digest) {
        const uint8_t *md = digest;
        uint64_t i_tree = 0;
        uint32_t i_leaf = 0;
        uint8_t pk_fors[SLH_MAX_N];
        size_t sig_sz;

        split_digest(&i_tree, &i_leaf, digest, ctx->prm);

        adrs_zero(ctx);
        adrs_set_tree_address(ctx, i_tree);
        adrs_set_type_and_clear_not_kp(ctx, ADRS_FORS_TREE);
        adrs_set_key_pair_address(ctx, i_leaf);

        //  SIG_FORS
        sig_sz = fors_sign(ctx, sig, md);
        fors_pk_from_sig(ctx, pk_fors, sig, md);

        //  SIG_HT
        sig += sig_sz;
        sig_sz += ht_sign(ctx, sig, pk_fors, i_tree, i_leaf);
    }*/
};

//
template <typename HashAlgo1, typename HashAlgo2, auto param_set>
struct slh_dsa_sha2_base : slh_dsa_base<param_set> {
    auto H_msg() {}
    auto PRF() {}
    auto PRF_msg() {}
    auto F() {}
    auto H() {}
    auto Tl() {}
};

template <auto> struct slh_dsa_sha2_s;
template <> struct slh_dsa_sha2_s<128> : slh_dsa_sha2_base<sha256, sha256, slh_dsa_params<128, 's'>> {};
template <> struct slh_dsa_sha2_s<192> : slh_dsa_sha2_base<sha256, sha512, slh_dsa_params<192, 's'>> {};
template <> struct slh_dsa_sha2_s<256> : slh_dsa_sha2_base<sha256, sha512, slh_dsa_params<256, 's'>> {};

template <auto> struct slh_dsa_sha2_f;
template <> struct slh_dsa_sha2_f<128> : slh_dsa_sha2_base<sha256, sha256, slh_dsa_params<128, 'f'>> {};
template <> struct slh_dsa_sha2_f<192> : slh_dsa_sha2_base<sha256, sha512, slh_dsa_params<192, 'f'>> {};
template <> struct slh_dsa_sha2_f<256> : slh_dsa_sha2_base<sha256, sha512, slh_dsa_params<256, 'f'>> {};

//
template <auto param_set>
struct slh_dsa_shake_base : slh_dsa_base<param_set> {
    using shake_type = shake<256>;

    void mk_ctx(const u8 *pk, const u8 *sk) {
        auto n = param_set.n;
        if (sk) {
            memcpy(this->sk.seed, sk, n);
            memcpy(this->sk.prf, sk + n, n);
            memcpy(this->sk.pk.seed, sk + 2 * n, n);
            memcpy(this->sk.pk.root, sk + 3 * n, n);
        } else if (pk) {
            memcpy(this->sk.pk.seed, pk, n);
            memcpy(this->sk.pk.root, pk + n, n);
        }

        //  local ADRS buffer
        this->adrs = &this->t_adrs;
    }
    void wots_chain(uint8_t *tmp, uint32_t s) {
        //  PRF secret key
        this->adrs->set_type(this->adrs->WOTS_PRF);
        this->adrs->set_tree_index(0);
        PRF(tmp);

        //  chain
        this->adrs->set_type(this->adrs->WOTS_HASH);
        shake_chain(tmp, tmp, 0, s);
    }
    void shake_chain(uint8_t *tmp, const uint8_t *x, uint32_t i, uint32_t s) {
        uint32_t j, k;
        keccak_p<1600> kc;
        auto &ks = kc.A;
        auto n = param_set.n;

        if (s == 0) {                           //  no-op
            memcpy(tmp, x, n);
            return;
        }

        const uint32_t r = shake_type::rate / 64;     //  SHAKE256 rate
        uint32_t n8 = n / 8;                    //  number of words
        uint32_t h = n8 + (32 / 8);             //  static part len
        uint32_t l = h + n8;                    //  input length

        memcpy(ks + h, x, n);                   //  start node
        for (j = 0; j < s; j++) {
            if (j > 0) {
                memcpy(ks + h, ks, n);          //  chaining
            }
            memcpy(ks, this->sk.pk.seed, n);        //  PK.seed
            this->adrs->set_hash_address(i + j);  //  address
            memcpy(ks + n8, this->adrs->data(), 32);

            //  padding
            ks[l] = 0x1F;                       //  shake padding
            for (k = l + 1; k < r - 1; k++) {
                ks[k] = 0;
            }
            ks[r - 1] = UINT64_C(1) << 63;      //  rate padding
            for (k = r; k < 25; k++) {
                ks[k] = 0;
            }

            kc.permute();
        }
        memcpy(tmp, ks, n);
    }

    auto H_msg(uint8_t *h, u8 *r, auto &&msg) {
        shake_type s;
        s.update(r, param_set.n);
        s.update(this->sk.pk.seed);
        s.update(this->sk.pk.root);
        s.update(msg);
        s.finalize();
        s.squeeze(h, param_set.m);
    }
    auto PRF_msg(uint8_t *h, u8 *rand, auto &&msg) {
        auto n = param_set.n;

        shake_type s;
        s.update(this->sk.prf);
        s.update(rand, n);
        s.update(msg);
        s.finalize();
        s.squeeze(h, n);
    }
    void PRF(uint8_t *h) {
        F(h, this->sk.seed);
    }
    void F(uint8_t *h, const uint8_t *m1) {
        auto n = param_set.n;

        shake_type s;
        s.update(this->sk.pk.seed);
        s.update(this->adrs->value);
        s.update(m1, n);
        s.finalize();
        s.squeeze(h, n);
    }
    void H(uint8_t *h, const uint8_t *m1, const uint8_t *m2) {
        auto n = param_set.n;

        shake_type s;
        s.update(this->sk.pk.seed);
        s.update(this->adrs->value);
        s.update(m1, n);
        s.update(m2, n);
        s.finalize();
        s.squeeze(h, n);
    }
    void T(uint8_t *h, const uint8_t *m, size_t m_sz) {
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
template <> struct slh_dsa_shake_f<192> : slh_dsa_shake_base<slh_dsa_params<192, 'f'>> {};
template <> struct slh_dsa_shake_f<128> : slh_dsa_shake_base<slh_dsa_params<128, 'f'>> {};
template <> struct slh_dsa_shake_f<256> : slh_dsa_shake_base<slh_dsa_params<256, 'f'>> {};

}
