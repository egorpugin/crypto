#pragma once

#include "helpers.h"
#include "bigint.h"
#include "random.h"

namespace crypto {

using f25519 = bigint;

// y^2 = x^3 + 486662x^2 + x
struct x25519 {
    static f25519 make_p() {
        f25519 p{1};
        p <<= 255;
        p -= 19;
        return p;
    }

    static inline const f25519 p{make_p()};
    static inline const f25519 basepoint{9};
    //static inline const f25519 basepoint{make_basepoint()};

    auto test1(string s) {
        string t;
        for (auto &&v : s | std::views::chunk(2) | std::views::reverse) {
            t.append(std::begin(v), v.end());
        }
        return "0x" + t;
    }
    auto test(string s) {
        return "0x" + s;
    }

    auto keygen(f25519 seed) {
        auto private_key = seed;
        private_key = test1("f3c540c8e59f03264c719619a8042536b3c6684731bfc3cf347bb2fe28150c0b");
        //seed = 0; // wipe
        f25519 public_key = basepoint * private_key;
        public_key %= p;
        //public_key /= 8;
        return std::tuple{private_key,public_key};
    }
    auto keygen() {
        uint8_t key[32];
        get_random_secure_bytes(key);

        key[0] &= 0xf8;
        key[31] &= 0x7f;
        key[31] |= 0x40;

        return keygen(bytes_to_bigint(key, -1));
    }
};

} // namespace crypto
