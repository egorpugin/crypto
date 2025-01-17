#pragma once

#include "blake2.h"

namespace crypto {

// make fully templated?
struct argon2 {
    enum type : uint32_t {
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
    uint32_t taglen;
    uint32_t p; // parallelism
    uint32_t m; // memsize KB
    uint32_t t; // iters
    type y{argon2id};

    auto operator()() {
        constexpr uint32_t v{0x13}; // current version v1.3

        hash_type b;
        auto add = [&](auto &&v) {
            b.update((uint8_t *)&v, sizeof(v));
        };
        auto add_array = [&](auto &&v) {
            auto sz = (uint32_t)v.size();
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

        std::vector<uint8_t> B(block_count * block_size);
        auto pd = B.data();

        for (uint32_t i = 0; i < p; ++i) {
            uint8_t tmp[hash_size + sizeof(uint32_t) + sizeof(i)];
            memcpy(tmp, h0.data(), h0.size());
            *(uint32_t*)(tmp + h0.size() + sizeof(uint32_t)) = i;

            *(uint32_t*)(tmp + h0.size()) = 0;
            hash(tmp, block_size, B.data() + (q * i + 0) * block_size);
            *(uint32_t*)(tmp + h0.size()) = 1;
            hash(tmp, block_size, B.data() + (q * i + 1) * block_size);
        }

        uint8_t tmp[block_size];
        for (uint32_t it = 0; it < t; ++it) { // iterations
            for (uint32_t is = 0; is < SL; ++is) { // slices
                auto calc_l = [&](uint32_t j2, uint32_t i) {
                    if (it == 0 && is == 0) {
                        return i;
                    }
                    return j2 % p;
                };
                auto calc_z = [&](uint32_t j1, uint32_t j, bool same_lane) {
                    uint32_t W;
                    if (it == 0 && is == 0) {
                        W = j - 1;
                    } else {
                        W = (it == 0 ? is : SL - 1) * cols_in_slice + (same_lane ? j - 1 : ((j == 0) * (-1)));
                    }

                    uint64_t x = j1;
                    x = x * x >> 32;
                    auto y = W * x >> 32;
                    auto zz = W - 1 - y;

                    uint32_t start_position{};
                    if (it != 0) {
                        start_position = (is == SL - 1) ? 0 : (is + 1) * cols_in_slice;
                    }
                    uint32_t absolute_position = (start_position + zz) % q;
                    return absolute_position;
                };
                auto use_pseudorandom = (y == argon2i) || (y == argon2id && it == 0 && (is == 0 || is == 1));
                for (uint32_t i = 0; i < p; ++i) {
                    using pseudo_rand_type = uint64_t;
                    std::vector<pseudo_rand_type> pseudo_rands(cols_in_slice);
                    if (use_pseudorandom) {
                        struct z {
                            uint64_t r;
                            uint64_t l;
                            uint64_t sl;
                            uint64_t m;
                            uint64_t t;
                            uint64_t y;
                            uint64_t qsl;
                            uint8_t zeros[968];
                        };
                        static_assert(sizeof(z) == block_size);

                        z Z {
                            .r = it,
                            .l = i,
                            .sl = is,
                            .m = block_count,
                            .t = t,
                            .y = y,
                        };

                        // gen random numbers
                        uint8_t out[block_size];
                        for (int i = 0; i < cols_in_slice; ++i) {
                            auto i_out = i % (block_size / sizeof(pseudo_rand_type));
                            if (i_out == 0) {
                                ++Z.qsl;
                                uint8_t z[block_size]{};
                                G(z, G(z, (uint8_t*)&Z, out), out);
                            }
                            memcpy(&pseudo_rands[i], out + i_out * sizeof(pseudo_rand_type), sizeof(pseudo_rand_type));
                        }
                    }
                    auto j_start = it > 0 ? is * cols_in_slice : std::max(2u, is * cols_in_slice);
                    for (uint32_t j = j_start; j < (is + 1) * cols_in_slice; ++j) {
                        uint32_t j1,j2;
                        if (use_pseudorandom) {
                            auto base = j % cols_in_slice;
                            j1 = ((uint32_t*)(&pseudo_rands[base]))[0];
                            j2 = ((uint32_t*)(&pseudo_rands[base]))[1];
                        } else {
                            j1 = *(uint32_t*)(B.data() + (q * i + (j == 0 ? q : j) - 1) * block_size);
                            j2 = *(uint32_t*)(B.data() + (q * i + (j == 0 ? q : j) - 1) * block_size + sizeof(j1));
                        }

                        auto l = calc_l(j2, i);
                        auto z = calc_z(j1, j % cols_in_slice, l == i);
                        auto Bij = B.data() + (q * i + j) * block_size;
                        if (it > 0) {
                            memcpy(tmp, Bij, block_size);
                            G(
                                B.data() + (q * i + (j == 0 ? q : j) - 1) * block_size,
                                B.data() + (q * l + z) * block_size,
                                Bij
                            );
                            for (int i = 0; i < block_size; ++i) {
                                Bij[i] ^= tmp[i];
                            }
                        } else {
                            G(
                                B.data() + (q * i + j - 1) * block_size,
                                B.data() + (q * l + z) * block_size,
                                Bij
                            );
                        }
                    }
                }
            }
        }

        // calc C
        memcpy(tmp, B.data() + (q * 0 + q - 1) * block_size, block_size);
        for (uint32_t i = 1; i < p; ++i) {
            auto p = B.data() + (q * i + q - 1) * block_size;
            for (int i = 0; i < block_size; ++i) {
                tmp[i] ^= p[i];
            }
        }

        std::vector<uint8_t> out(taglen);
        hash(tmp, taglen, out.data());
        return out;
    }
    static uint8_t *G(uint8_t *X, uint8_t *Y, uint8_t *out) {
        uint8_t R[block_size], Q[block_size], Z[block_size];
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
            uint8_t Qinput[128];
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
    static void P(uint8_t *in) {
        auto v = (uint64_t *)in;
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
        auto blamka = [](uint64_t x, uint64_t y) {
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
    static void hash(bytes_concept m, uint32_t digest_size, uint8_t *res) {
        constexpr auto halfsz = hash_size / 2;

        hash_type b{{}, (uint8_t)std::min<uint32_t>(digest_size, hash_size)};
        b.update((uint8_t *)&digest_size, sizeof(digest_size));
        b.update(m);
        auto h0 = b.digest();

        if (digest_size <= hash_size) {
            memcpy(res, h0.data(), digest_size);
            return;
        }

        auto r = (digest_size + halfsz - 1) / halfsz - 2;
        auto partial_bytes = digest_size - halfsz * r;

        uint8_t V[hash_size];
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
