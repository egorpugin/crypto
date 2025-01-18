#pragma once

#include "helpers.h"
#include "sha2.h"

namespace crypto {

struct blake3 {
    enum flag_type : uint32_t {
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
    static inline constexpr auto iv = sha2_data::h<digest_size_bytes * 8, digest_size_bytes * 8>();
    static inline constexpr uint8_t P[7][16] = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
        {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
        {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
        {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
        {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
        {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
    };

    uint32_t h0[8];
    uint32_t h[16];
    uint8_t m[block_size_bytes];
    uint64_t n_chunks{};
    uint8_t n_blocks{};
    uint8_t blockpos{};
    uint32_t flags{};
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
    static auto derive_key(bytes_concept key, bytes_concept salt, size_t outlen = digest_size_bytes) {
        blake3 bs;
        bs.flags = DERIVE_KEY_CONTEXT;
        bs.update(salt);
        auto key2 = bs.digest();

        blake3 bk{key2};
        bk.flags = DERIVE_KEY_MATERIAL;
        bk.update(key);
        return bk.digest(outlen);
    }
    void reset_h() {
        memcpy(h, h0, sizeof(h0));
        memset((uint8_t*)h + sizeof(h) / 2, 0, sizeof(h) / 2);
    }
    void add_to_tree(uint8_t *h0_and_final_flag = nullptr) {
        auto &v = tree.emplace_back();
        memcpy(v.data(), h, block_size_bytes / 2);

        uint32_t fl{PARENT};
        fl |= flags & ~(CHUNK_START | CHUNK_END); // without CHUNK flags
        auto must_left = std::popcount(n_chunks);
        while (tree.size() > must_left || (h0_and_final_flag && tree.size() > 1)) {
            reset_h();
            memcpy(m, tree[tree.size() - 2].data(), block_size_bytes / 2);
            memcpy(m + block_size_bytes / 2, tree[tree.size() - 1].data(), block_size_bytes / 2);
            if (h0_and_final_flag && tree.size() == 2) {
                memcpy(h0_and_final_flag, h, sizeof(h)); // save for extendable output
                fl |= ROOT;
                flags = fl;
                n_chunks = 1;
            }
            compress(h, m, sizeof(m), 0, fl);
            tree.pop_back();
            memcpy(tree[tree.size() - 1].data(), h, block_size_bytes / 2);
        }
    }
    void update(bytes_concept b) noexcept {
        update(b.data(), b.size());
    }
    void update(const uint8_t *data, size_t length) noexcept {
        return update_slow(data, length);
    }
    void update_slow(const uint8_t *data, size_t length) noexcept {
        for (size_t i = 0; i < length; ++i) {
            if (blockpos == sizeof(m)) {
                uint32_t fl{flags};
                auto blkid = n_blocks++;
                if (blkid == 0) {
                    fl |= CHUNK_START;
                }
                if (blkid == chunk_size_bytes / block_size_bytes - 1) {
                    fl |= CHUNK_END;
                }
                compress(h, m, sizeof(m), n_chunks, fl);
                if (blkid == chunk_size_bytes / block_size_bytes - 1) {
                    ++n_chunks;
                    add_to_tree();
                    reset_h();
                    n_blocks = 0;
                }
                blockpos = 0;
            }
            ((uint8_t*)m)[blockpos++] = data[i];
        }
    }
    std::vector<uint8_t> digest(size_t outlen = digest_size_bytes) noexcept {
        decltype(h) hsaved;
        auto empty = !n_chunks && !n_blocks;
        if (blockpos || empty) {
            if (empty) {
                flags |= CHUNK_START;
            }
            memset(m + blockpos, 0, sizeof(m) - blockpos);
            flags |= CHUNK_END;
            if (tree.empty()) {
                flags |= ROOT;
                memcpy(hsaved, h, sizeof(h));
            }
            compress(h, m, blockpos, n_chunks++, flags);
            if (!tree.empty()) {
                add_to_tree((uint8_t*)hsaved);
            }
        }
        std::vector<uint8_t> hash(outlen);
        auto p = hash.data();
        auto to_copy = std::min<size_t>(outlen, sizeof(h));
        memcpy(p, h, to_copy);
        p += to_copy;
        outlen -= to_copy;
        while (outlen > 0) {
            compress(hsaved, m, blockpos, n_chunks++, flags);
            auto to_copy = std::min<size_t>(outlen, sizeof(h));
            memcpy(p, hsaved, to_copy);
            p += to_copy;
            outlen -= to_copy;
        }
        return hash;
    }
    /*static auto digest(auto &&v) noexcept {
        blake3 h;
        h.update(v);
        return h.digest();
    }*/

    static void compress(auto &&h, auto &&m, int sz, uint64_t counter, auto flags) {
        uint32_t v[16];
        memcpy(v, h, sizeof(h) / 2);
        memcpy(v+8, iv.data(), sizeof(uint32_t) * 4);
        v[12] = counter;
        v[13] = counter >> 32;
        v[14] = sz;
        v[15] = (uint32_t)flags;
        for (int i = 0; i < 7; ++i) {
            round(v, (uint32_t*)m, (uint8_t*)P[i]);
        }
        for (int i = 0; i < 8; ++i) {
            v[i] ^= v[i + 8];
            v[i + 8] ^= h[i];
        }
        memcpy(h, v, sizeof(h));
    }
    static void G(uint32_t *v, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t y) {
        v[a] = v[a] + v[b] + x;
        v[d] = std::rotr(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = std::rotr(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + y;
        v[d] = std::rotr(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d];
        v[b] = std::rotr(v[b] ^ v[c], 7);
    }
    static void round(uint32_t *v, uint32_t *m, uint8_t *s) {
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
