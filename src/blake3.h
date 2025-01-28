// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "helpers.h"
#include "sha2.h"

namespace crypto {

struct blake3 : hash_traits<blake3> {
    using hash_traits::digest;
    using hash_traits::update;

    enum flag_type : u32 {
        CHUNK_START         = 0x01,
        CHUNK_END           = 0x02,
        PARENT              = 0x04,
        ROOT                = 0x08,
        KEYED_HASH          = 0x10,
        DERIVE_KEY_CONTEXT  = 0x20,
        DERIVE_KEY_MATERIAL = 0x40,
    };
    static inline constexpr auto digest_size_bytes = 32;
    static inline constexpr auto chunk_size_bytes = 1024;
    static inline constexpr auto block_size_bytes = 64;
    static inline constexpr auto max_block = chunk_size_bytes / block_size_bytes;
    static inline constexpr auto iv = sha2_data::h<digest_size_bytes * 8, digest_size_bytes * 8>();
    static inline constexpr u8 P[7][16] = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
        {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
        {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
        {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
        {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
        {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
    };

    u32 h0[8];
    u32 h[16];
    u8 m[block_size_bytes];
    u64 n_chunks{};
    u8 n_blocks{};
    u8 blockpos{};
    u32 flags{};
    std::vector<array<block_size_bytes / 2>> tree;

    blake3() {
        memcpy(h0, iv.data(), sizeof(h) / 2);
        reset_h();
    }
    blake3(bytes_concept key) {
        if (key.size() != 32) {
            throw std::runtime_error{"invalid key size"};
        }
        flags = KEYED_HASH;
        memcpy(h0, key.data(), sizeof(h0));
        reset_h();
    }
    void reset_h() {
        memcpy(h, h0, sizeof(h0));
        memset((u8*)h + sizeof(h) / 2, 0, sizeof(h) / 2);
    }
    void add_to_tree(u8 *h0_and_final_flag = nullptr) {
        auto &v = tree.emplace_back();
        memcpy(v.data(), h, block_size_bytes / 2);

        u32 fl{PARENT | flags & ~(CHUNK_START | CHUNK_END)};
        auto must_left = std::popcount(n_chunks);
        while (tree.size() > must_left || (h0_and_final_flag && tree.size() > 1)) {
            reset_h();
            memcpy(m, tree[tree.size() - 2].data(), block_size_bytes / 2);
            memcpy(m + block_size_bytes / 2, tree.back().data(), block_size_bytes / 2);
            if (h0_and_final_flag && tree.size() == 2) {
                fl |= ROOT;
                // save and setup data for extendable output
                memcpy(h0_and_final_flag, h, sizeof(h));
                flags = fl;
                n_chunks = 1;
                blockpos = sizeof(m);
            }
            compress(h, m, sizeof(m), 0, fl);
            tree.pop_back();
            memcpy(tree.back().data(), h, block_size_bytes / 2);
        }
    }
    void update(const u8 *data, size_t length) noexcept {
        update_fast_pre(data, length, m, sizeof(m), blockpos, [&]() {
            u32 fl{flags};
            if (n_blocks++ == 0) {
                fl |= CHUNK_START;
            }
            if (n_blocks == max_block) {
                fl |= CHUNK_END;
            }
            compress(h, m, sizeof(m), n_chunks, fl);
            if (n_blocks == max_block) {
                ++n_chunks;
                add_to_tree();
                reset_h();
                n_blocks = 0;
            }
        });
    }
    auto digest(size_t outlen = digest_size_bytes) noexcept {
        decltype(h) h0;
        if (!n_blocks) {
            flags |= CHUNK_START;
        }
        memset(m + blockpos, 0, sizeof(m) - blockpos);
        flags |= CHUNK_END;
        if (tree.empty()) {
            flags |= ROOT;
            memcpy(h0, h, sizeof(h));
        }
        compress(h, m, blockpos, n_chunks++, flags);
        if (!tree.empty()) {
            add_to_tree((u8*)h0);
        }
        std::vector<u8> hash(outlen);
        auto p = hash.data();
        auto to_copy = std::min<size_t>(outlen, sizeof(h));
        memcpy(p, h, to_copy);
        outlen -= to_copy;
        while (outlen > 0) {
            p += to_copy;
            compress(h0, m, blockpos, n_chunks++, flags);
            to_copy = std::min<size_t>(outlen, sizeof(h));
            memcpy(p, h0, to_copy);
            outlen -= to_copy;
        }
        return hash;
    }
    static auto derive_key(bytes_concept key, bytes_concept salt, size_t outlen = digest_size_bytes) {
        blake3 bs;
        bs.flags = DERIVE_KEY_CONTEXT;
        bs.update(salt);
        blake3 bk{bs.digest()};
        bk.flags = DERIVE_KEY_MATERIAL;
        bk.update(key);
        return bk.digest(outlen);
    }
    static void compress(auto &&h, auto &&m, int sz, u64 counter, u32 flags) {
        u32 v[16];
        memcpy(v, h, sizeof(h) / 2);
        memcpy(v+8, iv.data(), sizeof(u32) * 4);
        v[12] = counter;
        v[13] = counter >> 32;
        v[14] = sz;
        v[15] = flags;
        for (int i = 0; i < 7; ++i) {
            round(v, (u32*)m, P[i]);
        }
        for (int i = 0; i < 8; ++i) {
            v[i] ^= v[i + 8];
            v[i + 8] ^= h[i];
        }
        memcpy(h, v, sizeof(h));
    }
    static void G(u32 *v, u32 a, u32 b, u32 c, u32 d, u32 x, u32 y) {
        v[a] = v[a] + v[b] + x;
        v[d] = std::rotr(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];

        v[b] = std::rotr(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + y;
        v[d] = std::rotr(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d];
        v[b] = std::rotr(v[b] ^ v[c], 7);
    }
    static void round(u32 *v, const u32 *m, const u8 *s) {
        G(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        G(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        G(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        G(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);

        G(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        G(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }
};

} // namespace crypto
