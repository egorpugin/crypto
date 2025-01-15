#pragma once

#include "blake2.h"

namespace crypto {

struct argon2 {
    enum hash_type : uint32_t {
        argon2d,
        argon2i,
        argon2id,
    };

    bytes_concept password;
    bytes_concept salt;
    bytes_concept key;
    bytes_concept associated_data;
    uint32_t taglen;
    uint32_t p; // parallelism
    uint32_t m; // memsize KB
    uint32_t t; // iters
    hash_type y{argon2d};

    auto operator()() {
        const uint32_t v{0x13}; // current version

        blake2b<512> b;
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
        auto col_count_in_slice = q / SL;

        std::vector<uint8_t> B(block_count * 1024);

        for (uint32_t i = 0; i < p; ++i) {
            uint8_t tmp[h0.size() + sizeof(uint32_t) + sizeof(i)];
            memcpy(tmp, h0.data(), h0.size());
            *(uint32_t*)(tmp + h0.size()) = 0;
            *(uint32_t*)(tmp + h0.size() + sizeof(uint32_t)) = i;
            hash(tmp, 1024, B.data() + (q * i + 0) * 1024);
            *(uint32_t*)(tmp + h0.size()) = 1;
            hash(tmp, 1024, B.data() + (q * i + 1) * 1024);
        }

        uint32_t it{};

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
        static_assert(sizeof(z) == 1024);

        auto calc_l = [&](uint32_t j2, uint32_t j) -> uint32_t {
            if (it == 0 && j / SL == 0) {
                return j;
            }
            return j2 % p;
        };
        auto calc_z = [](uint32_t j1) {
            uint64_t x = j1;
            x *= x;
            x &= 0xffffffff;
            //auto
            x &= 0xffffffff;
            return x;
        };

        //for (it = 0; it < t; ++it) {
        for (uint32_t iq = 0; iq < col_count_in_slice; ++iq) {
            for (uint32_t j = 2; j < q; ++j) {
                for (uint32_t i = 0; i < p; ++i) {
                    if (y == argon2d) {
                        // untested
                        auto j1 = *(uint32_t*)(B.data() + (q * i + j - 1) * 1024);
                        auto j2 = *(uint32_t*)(B.data() + (q * i + j - 1) * 1024 + sizeof(j1));
                        auto l = calc_l(j2, j);
                        auto z = calc_z(j1);
                        G(
                            B.data() + (q * i + j - 1) * 1024,
                            B.data() + (q * l + z + 0) * 1024,
                            B.data() + (q * i + j + 0) * 1024
                        );
                    }
                    if (y == argon2i) {
                        z Z {
                            .r = it,
                            .l = i,
                            .sl = j / SL,
                            .m = block_count,
                            .t = t,
                            .y = y,
                        };

                        // gen random numbers
                        uint8_t out[1024];
                        for (int i = 1; i <= col_count_in_slice; ++i) {
                            // TODO: see libsodium argon2-fill-block-ref.c:generate_addresses()
                            Z.qsl = i;
                            uint8_t z[1024]{};
                            G(z, G(z, (uint8_t*)&Z, out), out);
                            break; // is first block of numbers enough?
                        }
                        auto j1 = *(uint32_t*)(out + 0);
                        auto j2 = *(uint32_t*)(out + 8);
                        auto l = calc_l(j2, j);
                        auto z = calc_z(j1);

                    }
                }
            }
        }
        //}

        for (it = 1; it < t; ++it) {
            for (uint32_t i = 0; i < p; ++i) {
                for (uint32_t j = 0; j < q; ++j) {
                    if (y == argon2d) {
                        auto l = *(uint32_t*)(B.data() + (q * i + j - 1) * 1024) % p;
                        auto z = *(uint32_t*)(B.data() + (q * i + j - 1) * 1024 + sizeof(l)) % q;
                        uint8_t out[1024];
                        if (j == 0) {
                            G(
                                B.data() + (q * i + q - 1) * 1024,
                                B.data() + (q * l + z + 0) * 1024,
                                out
                            );
                        } else {
                            G(
                                B.data() + (q * i + j - 1) * 1024,
                                B.data() + (q * l + z + 0) * 1024,
                                out
                            );
                        }
                        auto b = B.data() + (q * i + j + 0) * 1024;
                        for (int i = 0; i < 1024; ++i) {
                            b[i] ^= out[i];
                        }
                    }
                }
            }
        }


        int a = 5;
        a++;
    }
    static uint8_t *G(uint8_t *X, uint8_t *Y, uint8_t *out) {
        uint8_t R[1024], Q[1024], Z[1024];
        for (int i = 0; i < 1024; ++i) {
            R[i] = X[i] ^ Y[i];
        }
        memcpy(Q, R, 1024);
        for (int i = 0; i < 8; ++i) {
            P(Q + i * 128);
        }
        for (int i = 0; i < 8; ++i) {
            uint8_t Qinput[128];
            for (int j = 0; j < 8; ++j) {
                memcpy(Qinput + j * 16, Q + j * 128 + i * 16, 16);
            }
            P(Qinput);
            for (int j = 0; j < 8; ++j) {
                memcpy(Z + j * 128 + i * 16, Qinput + j * 16, 16);
            }
        }
        for (int i = 0; i < 1024; ++i) {
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
        auto BlaMka = [](uint64_t x, uint64_t y) {
            constexpr auto m  = 0xFFFFFFFFull;
            auto xy = (x & m) * (y & m);
            return x + y + 2 * xy;
        };
        v[a] = BlaMka(v[a], v[b]);
        v[d] = std::rotr(v[d] ^ v[a], 32);
        v[c] = BlaMka(v[c], v[d]);
        v[b] = std::rotr(v[b] ^ v[c], 24);
        v[a] = BlaMka(v[a], v[b]);
        v[d] = std::rotr(v[d] ^ v[a], 16);
        v[c] = BlaMka(v[c], v[d]);
        v[b] = std::rotr(v[b] ^ v[c], 63);
    }
    static void hash(bytes_concept m, uint32_t digest_size, uint8_t *res) {
        blake2b<512> b;
        b.update((uint8_t *)&digest_size, sizeof(digest_size));
        b.update(m);
        auto h0 = b.digest();

        if (digest_size <= 64) {
            memcpy(res, h0.data(), digest_size);
        }

        auto r = (digest_size + 32 - 1) / 32 - 2;
        auto partial_bytes = digest_size - 32 * r;

        uint8_t V[64];
        memcpy(V, h0.data(), h0.size());
        memcpy(res, V, 32);
        for (int i = 1; i < r; ++i) {
            blake2b<512> b;
            b.update(V);
            auto d = b.digest();
            memcpy(V, d.data(), d.size());
            memcpy(res + i * 32, V, 32);
        }
        if (partial_bytes) {
            blake2b<512> b;
            b.update(V);
            auto d = b.digest();
            memcpy(res + r * 32, d.data(), partial_bytes);
        }
    }
};

}
