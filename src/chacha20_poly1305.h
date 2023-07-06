#pragma once

#include "helpers.h"

#include "chacha20.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <span>
#include <stdexcept>

namespace crypto {

struct chacha20_poly1305_aead {
    static inline constexpr auto block_size_bytes = 32;
    static inline constexpr auto iv_size_bytes = 12; // 8 + 4
    static inline constexpr auto tag_size_bytes = 16;
    static inline constexpr auto key_size_bytes = 32;

//#define CHACHA_KEYLEN 32 /* 2 x 256 bit keys */
//#define CHACHA20_POLY1305_AEAD_KEY_LEN 32
//#define CHACHA20_POLY1305_AEAD_AAD_LEN 3 /* 3 bytes length */
//#define CHACHA20_ROUND_OUTPUT 64         /* 64 bytes per round */
//#define AAD_PACKAGES_PER_ROUND 21        /* 64 / 3 round down*/

    /*struct chacha_ctx {
        uint32_t input[16];
    };
    struct chachapolyaead_ctx {
        chacha_ctx main_ctx, header_ctx;
        uint8_t aad_keystream_buffer[CHACHA20_ROUND_OUTPUT];
        uint64_t cached_aad_seqnr;
    };*/

    array<block_size_bytes> k;

    chacha20_poly1305_aead() = default;
    chacha20_poly1305_aead(auto &&k) : k{k} {
    }
    void set_iv(auto &&iv) {
        /*counter = array<block_size_bytes>{};
        memcpy(counter.data(), iv.data(), iv.size());
        inc_counter();
        Ek0 = c.encrypt(counter);
        h = h0;*/
    }
    void inc_counter() {
        // BUG: overflow is possible!
        /*for (int i = 16; i > 12; i--) {
            if (++counter[i - 1] != 0)
                break;
        }*/
    }
    auto encrypt_and_tag(auto &&nonce, auto &&data, auto &&auth_data) {
        set_iv(nonce);
        std::string out(data.size(), 0);
        return out;
    }
    auto decrypt_with_tag(auto &&nonce, auto &&data, auto &&auth_data) {
        set_iv(nonce);
        auto ciphered_data = data.subspan(0, data.size() - tag_size_bytes);
        std::string out(data.size() - tag_size_bytes, 0);
        return out;
    }
};

} // namespace crypto
