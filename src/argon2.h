// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "blake2.h"

namespace crypto {

// make fully templated?
struct argon2 {
    enum type : u32 {
        argon2d, // not recommended
        argon2i,
        argon2id,
    };
    using hash_type = blake2b<512>;
    static inline constexpr auto hash_size = 512 / 8;
    static inline constexpr auto block_size = 1024; // memory unit

    bytes_concept password;
    bytes_concept salt;
    bytes_concept key;
    bytes_concept associated_data;
    u32 taglen;
    u32 p; // parallelism
    u32 m; // memsize KB
    u32 t; // iters
    type y{argon2id};

    auto operator()() {
        constexpr u32 v{0x13}; // current version v1.3

        hash_type b;
        auto add = [&](auto &&v) {
            b.update((u8 *)&v, sizeof(v));
        };
        auto add_array = [&](auto &&v) {
            auto sz = (u32)v.size();
            add(sz);
            b.update(v);
        };
        add(p);
        add(taglen);
        add(m);
        add(t);
        add(v);
        add(y);
        add_array(password);
        add_array(salt);
        add_array(key);
        add_array(associated_data);
        auto h0 = b.digest();

        auto block_count = 4 * p * (m / (4 * p));
        auto q = block_count / p; // column count
        constexpr auto SL = 4; // number of vertical slices
        auto cols_in_slice = q / SL;

        std::vector<u8> B(block_count * block_size);
        struct {
            u8 *p;
            u32 q;
            u8 *operator()(int i, int j) {
                return p + (q * i + j) * block_size;
            }
        } pb{B.data(), q};

        for (u32 i = 0; i < p; ++i) {
            u8 tmp[hash_size + sizeof(u32) + sizeof(i)];
            memcpy(tmp, h0.data(), h0.size());
            *(u32*)(tmp + h0.size() + sizeof(u32)) = i;

            *(u32*)(tmp + h0.size()) = 0;
            hash(tmp, block_size, pb(i, 0));
            *(u32*)(tmp + h0.size()) = 1;
            hash(tmp, block_size, pb(i, 1));
        }

        u8 tmp[block_size];
        for (u32 it = 0; it < t; ++it) { // iterations
            for (u32 is = 0; is < SL; ++is) { // slices
                auto calc_l = [&](u32 j2, u32 i) {
                    if (it == 0 && is == 0) {
                        return i;
                    }
                    return j2 % p;
                };
                auto calc_z = [&](u32 j1, u32 j, bool same_lane) {
                    u32 W;
                    if (it == 0 && is == 0) {
                        W = j - 1;
                    } else {
                        W = (it == 0 ? is : SL - 1) * cols_in_slice + (same_lane ? j - 1 : ((j == 0) * (-1)));
                    }

                    u64 x = j1;
                    x = x * x >> 32;
                    auto y = W * x >> 32;
                    auto zz = W - 1 - y;

                    u32 start_position{};
                    if (it != 0) {
                        start_position = (is == SL - 1) ? 0 : (is + 1) * cols_in_slice;
                    }
                    u32 absolute_position = (start_position + zz) % q;
                    return absolute_position;
                };
                auto use_pseudorandom = (y == argon2i) || (y == argon2id && it == 0 && (is == 0 || is == 1));
                for (u32 i = 0; i < p; ++i) {
                    using pseudo_rand_type = u64;
                    std::vector<pseudo_rand_type> pseudo_rands(cols_in_slice);
                    if (use_pseudorandom) { // gen random numbers
                        u64 Z[block_size / sizeof(u64)] { it, i, is, block_count, t, y, };
                        u8 out[block_size];
                        for (int i = 0; i < cols_in_slice; ++i) {
                            auto i_out = i % (block_size / sizeof(pseudo_rand_type));
                            if (i_out == 0) {
                                ++Z[6];
                                u8 z[block_size]{};
                                G(z, G(z, (u8*)&Z, out), out);
                            }
                            memcpy(&pseudo_rands[i], out + i_out * sizeof(pseudo_rand_type), sizeof(pseudo_rand_type));
                        }
                    }
                    auto j_start = it > 0 ? is * cols_in_slice : std::max(2u, is * cols_in_slice);
                    for (u32 j = j_start, j_end = (is + 1) * cols_in_slice; j < j_end; ++j) {
                        u32 j1, j2;
                        if (use_pseudorandom) {
                            auto base = (u32*)&pseudo_rands[j % cols_in_slice];
                            j1 = base[0];
                            j2 = base[1];
                        } else {
                            j1 = *(u32*)(pb(i, (j == 0 ? q : j) - 1));
                            j2 = *(u32*)(pb(i, (j == 0 ? q : j) - 1) + sizeof(j1));
                        }
                        auto l = calc_l(j2, i);
                        auto z = calc_z(j1, j % cols_in_slice, l == i);
                        auto Bij = pb(i, j);
                        if (it > 0) {
                            memcpy(tmp, Bij, block_size);
                            G(pb(i, (j == 0 ? q : j) - 1), pb(l, z), Bij);
                            for (int i = 0; i < block_size; ++i) {
                                Bij[i] ^= tmp[i];
                            }
                        } else {
                            G(pb(i, j - 1), pb(l, z), Bij);
                        }
                    }
                }
            }
        }

        // calc C
        memcpy(tmp, pb(0, q - 1), block_size);
        for (u32 i = 1; i < p; ++i) {
            auto p = pb(i, q - 1);
            for (int i = 0; i < block_size; ++i) {
                tmp[i] ^= p[i];
            }
        }

        // final
        std::vector<u8> out(taglen);
        hash(tmp, taglen, out.data());
        return out;
    }
    static u8 *G(u8 *X, u8 *Y, u8 *out) {
        u8 R[block_size], Q[block_size], Z[block_size];
        for (int i = 0; i < block_size; ++i) {
            R[i] = X[i] ^ Y[i];
        }
        memcpy(Q, R, block_size);
        for (int i = 0; i < 8; ++i) {
            P(Q + i * 128);
        }
        for (int i = 0; i < 8; ++i) {
            // here we can make P(a1,a2...a16) and pass all integers at once
            // instead of double memcpy back and forth
            u8 Qinput[128];
            for (int j = 0; j < 8; ++j) {
                memcpy(Qinput + j * 16, Q + j * 128 + i * 16, 16);
            }
            P(Qinput);
            for (int j = 0; j < 8; ++j) {
                memcpy(Z + j * 128 + i * 16, Qinput + j * 16, 16);
            }
        }
        for (int i = 0; i < block_size; ++i) {
            out[i] = R[i] ^ Z[i];
        }
        return out;
    }
    static void P(u8 *in) {
        auto v = (u64 *)in;
        GB(v, 0, 4,  8, 12);
        GB(v, 1, 5,  9, 13);
        GB(v, 2, 6, 10, 14);
        GB(v, 3, 7, 11, 15);

        GB(v, 0, 5, 10, 15);
        GB(v, 1, 6, 11, 12);
        GB(v, 2, 7,  8, 13);
        GB(v, 3, 4,  9, 14);
    }
    static void GB(auto &&v, int a, int b, int c, int d) {
        auto blamka = [](u64 x, u64 y) {
            constexpr auto m = 0xFFFFFFFFull;
            auto xy = (x & m) * (y & m);
            return x + y + 2 * xy;
        };
        v[a] = blamka(v[a], v[b]);
        v[d] = std::rotr(v[d] ^ v[a], 32);
        v[c] = blamka(v[c], v[d]);
        v[b] = std::rotr(v[b] ^ v[c], 24);
        v[a] = blamka(v[a], v[b]);
        v[d] = std::rotr(v[d] ^ v[a], 16);
        v[c] = blamka(v[c], v[d]);
        v[b] = std::rotr(v[b] ^ v[c], 63);
    }
    static void hash(bytes_concept m, u32 digest_size, u8 *res) {
        constexpr auto halfsz = hash_size / 2;

        hash_type b{{}, (u8)std::min<u32>(digest_size, hash_size)};
        b.update((u8 *)&digest_size, sizeof(digest_size));
        b.update(m);
        auto h0 = b.digest();

        if (digest_size <= hash_size) {
            memcpy(res, h0.data(), digest_size);
            return;
        }

        auto r = (digest_size + halfsz - 1) / halfsz - 2;
        auto partial_bytes = digest_size - halfsz * r;

        u8 V[hash_size];
        memcpy(V, h0.data(), h0.size());
        memcpy(res, V, halfsz);
        for (int i = 1; i < r; ++i) {
            hash_type b;
            b.update(V);
            auto d = b.digest();
            memcpy(V, d.data(), d.size());
            memcpy(res + i * halfsz, V, halfsz);
        }
        if (partial_bytes) {
            hash_type b;
            b.update(V);
            auto d = b.digest();
            memcpy(res + r * halfsz, d.data(), partial_bytes);
        }
    }
};

}
