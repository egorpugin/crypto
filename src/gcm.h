#pragma once

#include "helpers.h"

#include <array>
#include <algorithm>
#include <cstring>
#include <span>
#include <stdexcept>

// no need to implement ccm

namespace crypto {

// mostly tls 1.3 variant with additional length etc.
template <typename Cipher>
struct gcm {
    // when iv_size_bytes != there is non implemented special handling of Ek0
    // see
    // https://csrc.nist.gov/publications/detail/sp/800-38d/final
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf (7.1)
    // also https://github.com/mko-x/SharedAES-GCM/blob/master/Sources/gcm.c#L275
    static inline constexpr auto block_size_bytes = Cipher::block_size_bytes;
    static inline constexpr auto iv_size_bytes = 12; // 8 + 4
    static inline constexpr auto tag_size_bytes = 16;
    static inline constexpr auto key_size_bytes = Cipher::key_size_bytes;

    Cipher aes;
    array<block_size_bytes> counter;
    array<block_size_bytes> Ek0;
    array<block_size_bytes> h0{}, h;

    gcm() = default;
    gcm(auto &&k) : aes{k} {
        h0 = aes.encrypt(h0);
    }
    void set_iv(auto &&iv) {
        counter = array<block_size_bytes>{};
        memcpy(counter.data(), iv.data(), iv.size());
        inc_counter();
        Ek0 = aes.encrypt(counter);
        h = h0;
    }
    void inc_counter() {
        // BUG: overflow is possible!
        for (int i = 16; i > 12; i--) {
            if (++counter[i - 1] != 0)
                break;
        }
    }
    auto encrypt1(std::span<uint8_t> input, std::span<uint8_t> output) noexcept {
        array<block_size_bytes> Ek;
        while (!input.empty()) {
            inc_counter();
            Ek = aes.encrypt(counter);
            auto sz = std::min(input.size(), block_size_bytes);
            for (int i = 0; i < sz; ++i) {
                output[i] = Ek[i] ^ input[i];
            }
            input = input.subspan(sz);
            output = output.subspan(sz);
        }
    }
    auto encrypt(auto &&data, auto &&auth_data) {
        std::string out(data.size(), 0);
        encrypt1(std::span<uint8_t>((uint8_t*)data.data(), data.size()), std::span<uint8_t>((uint8_t*)out.data(), out.size()));
        auto auth_tag = make_tag(auth_data, out);
        out.resize(out.size() + tag_size_bytes);
        memcpy(out.data() + data.size(), auth_tag.data(), tag_size_bytes);
        return out;
    }
    auto decrypt(auto &&data, auto &&auth_data) {
        auto ciphered_data = data.subspan(0, data.size() - tag_size_bytes);
        std::string out(data.size() - tag_size_bytes, 0);
        encrypt1(ciphered_data, std::span<uint8_t>((uint8_t*)out.data(), out.size()));
        auto check_tag = make_tag(auth_data, ciphered_data);
        auto auth_tag = data.subspan(data.size() - tag_size_bytes);
        if (memcmp(check_tag.data(), auth_tag.data(), tag_size_bytes) != 0) {
            throw std::runtime_error{"aes auth tag is incorrect"};
        }
        return out;
    }

    // T = S ^ Ek0
    auto make_tag(auto &&auth_data, auto &&ciphered_data) {
        auto buf = ghash(auth_data, ciphered_data);
        for (int i = 0; i < block_size_bytes; ++i) {
            Ek0[i] ^= buf[i];
        }
        return Ek0;
    }
    // S = GHASH (A || 0v || C || 0u || [len(A)]64 || [len(C)]64)
    auto ghash(bytes_concept auth_data, bytes_concept ciphered_data) {
        uint64_t ciphered_len = ciphered_data.size() * 8;
        uint64_t auth_len = auth_data.size() * 8;
        array<block_size_bytes> buf{};
        while (!auth_data.empty()) {
            auto sz = std::min(auth_data.size(), block_size_bytes);
            for (int i = 0; i < sz; i++) {
                buf[i] ^= auth_data[i];
            }
            gmult(buf);
            auth_data = auth_data.subspan(sz);
        }
        while (!ciphered_data.empty()) {
            auto sz = std::min(ciphered_data.size(), block_size_bytes);
            for (int i = 0; i < sz; ++i) {
                buf[i] ^= ciphered_data[i];
            }
            gmult(buf);
            ciphered_data = ciphered_data.subspan(sz);
        }
        if (ciphered_len || auth_len) {
            array<block_size_bytes> work_buf;
            *(uint64_t *)(work_buf.data() + 0) = std::byteswap(auth_len);
            *(uint64_t *)(work_buf.data() + 8) = std::byteswap(ciphered_len);
            for (int i = 0; i < block_size_bytes; ++i) {
                buf[i] ^= work_buf[i];
            }
            gmult(buf);
        }
        return buf;
    }
    void gmult(auto &&buf) {
        // for now
        *(uint64_t *)(buf.data() + 0) = std::byteswap(*(uint64_t *)(buf.data() + 0));
        *(uint64_t *)(buf.data() + 8) = std::byteswap(*(uint64_t *)(buf.data() + 8));
        *(uint64_t *)(h.data() + 0) = std::byteswap(*(uint64_t *)(h.data() + 0));
        *(uint64_t *)(h.data() + 8) = std::byteswap(*(uint64_t *)(h.data() + 8));

        gmult2((uint64_t *)buf.data(), (uint64_t *)h.data());

        *(uint64_t *)(buf.data() + 0) = std::byteswap(*(uint64_t *)(buf.data() + 0));
        *(uint64_t *)(buf.data() + 8) = std::byteswap(*(uint64_t *)(buf.data() + 8));
        *(uint64_t *)(h.data() + 0) = std::byteswap(*(uint64_t *)(h.data() + 0));
        *(uint64_t *)(h.data() + 8) = std::byteswap(*(uint64_t *)(h.data() + 8));
    }
    void gmult2(uint64_t *X, uint64_t *Y) {
        uint64_t Z[2] = {0, 0};
        uint64_t V[2];
        int i, j;
        V[0] = X[0];
        V[1] = X[1];
        for (i = 0; i < 2; i++) {
            auto y = Y[i];
            for (j = 0; j < 64; j++) {
                uint64_t mask = 0 - (y >> 63);
                Z[0] ^= V[0] & mask;
                Z[1] ^= V[1] & mask;
                auto v1 = (0 - (V[1] & 1)) & 0xE100000000000000ULL;
                V[1] >>= 1;
                V[1] |= V[0] << 63;
                V[0] >>= 1;
                V[0] ^= v1;
                y <<= 1;
            }
        }
        X[0] = Z[0];
        X[1] = Z[1];
    }
};

} // namespace crypto
