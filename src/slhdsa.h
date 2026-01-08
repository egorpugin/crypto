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
        memcpy(obj.sk.prf, pk_root, param_set.n);
    }

    static inline uint32_t get_len1() {
        return ((8 * param_set.n + param_set.lg_w - 1) / param_set.lg_w);
    }
    static inline uint32_t get_len2() {
        return 3;
    }
    static inline uint32_t get_len() {
        return get_len1() + get_len2();
    }

    void xmss_node(this auto &&obj, uint8_t *node, uint32_t i, uint32_t z) {
        uint32_t j, k;
        int p;
        uint8_t *h0, h[param_set.hp][param_set.n];
        // SLH_MAX_LEN == (2 * SLH_MAX_N + 3)
        uint8_t tmp[(2 * param_set.n + 3) * param_set.n];
        uint8_t *sk;
        size_t n = param_set.n;
        size_t len = get_len();

        p = -1;
        i <<= z;
        for (j = 0; j < (1u << z); j++) {
            obj.adrs->set_key_pair_address(i);

            //  === Generate a WOTS+ public key.
            //  Algorithm 5: wots_PKgen(SK.seed, PK.seed, ADRS)
            sk = tmp;
            for (k = 0; k < len; k++) {
                obj.adrs->set_chain_address(k);
                obj.wots_chain(sk, 15);   //  w-1 =  (1 << prm->lg_w) - 1;
                sk += n;
            }
            obj.adrs->set_type_and_clear_not_kp(obj.adrs->WOTS_PK);
            h0 = p >= 0 ? h[p] : node;
            p++;
            obj.h_t(h0, tmp, len * n);

            //  this xmss_node() implementation is non-recursive
            for (k = 0; (j >> k) & 1; k++) {
                obj.adrs->set_type_and_clear(obj.adrs->TREE);
                obj.adrs->set_tree_height(k + 1);
                obj.adrs->set_tree_index(i >> (k + 1));
                p--;
                h0 = p >= 1 ? h[p - 1] : node;
                obj.h_h(h0, h0, h[p]);
            }
            i++;        //  advance index
        }
    }
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

    auto H_msg() {}
    auto PRF() {}
    auto PRF_msg() {}
    auto F() {}
    auto H() {}
    auto Tl() {}

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
        shake_prf(tmp);

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

            kc.permute();                   //  permutation
        }
        memcpy(tmp, ks, n);
    }
    void shake_prf(uint8_t *h) {
        shake_f(h, this->sk.seed);
    }
    void shake_f(uint8_t *h, const uint8_t *m1) {
        auto n = param_set.n;

        shake_type s;
        s.update(this->sk.pk.seed);
        s.update(this->adrs->data(), 32);
        s.update(m1, n);
        s.finalize();
        s.squeeze(h, n);
    }
    void h_t(uint8_t *h, const uint8_t *m, size_t m_sz) {
        auto n = param_set.n;

        shake_type s;
        s.update(this->sk.pk.seed);
        s.update(this->adrs->data(), 32);
        s.update(m, m_sz);
        s.finalize();
        s.squeeze(h, n);
    }
    void h_h(uint8_t *h, const uint8_t *m1, const uint8_t *m2) {
        auto n = param_set.n;

        shake_type s;
        s.update(this->sk.pk.seed);
        s.update(this->adrs->data(), 32);
        s.update(m1, n);
        s.update(m2, n);
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
