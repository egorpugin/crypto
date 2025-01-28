// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "helpers.h"

#include "chacha20.h"
#include "poly1305.h"

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

    array<block_size_bytes> k;

    auto encrypt_and_tag(auto &&nonce, auto &&data, auto &&auth_data) {
        chacha20 c{k.data(), nonce.data()};
        c.set_counter(1);

        array<32> otk;
        memcpy(otk.data(), c.block, 32);

        auto aad_pad = pad(auth_data.size());
        auto data_pad = pad(data.size());
        std::string out2(auth_data.size() + aad_pad + data.size() + data_pad + 8 + 8 + tag_size_bytes, 0);
        auto p = (u8*)out2.data();
        memcpy(p, auth_data.data(), auth_data.size());
        p += auth_data.size();
        p += aad_pad;
        c.cipher((u8*)data.data(), p, data.size());
        p += data.size();
        p += data_pad;
        *(u64 *)p = auth_data.size();
        p += 8;
        *(u64 *)p = data.size();
        p += 8;
        poly1305_auth(p, (u8 *)out2.data(), out2.size() - tag_size_bytes, otk.data());

        std::string out(data.size() + tag_size_bytes, 0);
        memcpy(out.data(), out2.data() + auth_data.size() + aad_pad, data.size());
        memcpy(out.data() + data.size(), out2.data() + out2.size() - tag_size_bytes, tag_size_bytes);
        return out;
    }
    auto decrypt_with_tag(auto &&nonce, auto &&data, auto &&auth_data) {
        chacha20 c{k.data(), nonce.data()};
        c.set_counter(1);

        array<32> otk;
        memcpy(otk.data(), c.block, 32);

        auto aad_pad = pad(auth_data.size());
        auto data_size = data.size() - tag_size_bytes;
        auto data_pad = pad(data_size);
        std::string out2(auth_data.size() + aad_pad + data_size + data_pad + 8 + 8, 0);
        auto p = (u8 *)out2.data();
        memcpy(p, auth_data.data(), auth_data.size());
        p += auth_data.size();
        p += aad_pad;
        memcpy(p, data.data(), data_size);
        p += data_size;
        p += data_pad;
        *(u64 *)p = auth_data.size();
        p += 8;
        *(u64 *)p = data_size;
        p += 8;

        array<tag_size_bytes> tag;
        poly1305_auth((u8 *)tag.data(), (u8 *)out2.data(), out2.size(), otk.data());

        if (memcmp(tag.data(), data.data() + data_size, tag_size_bytes) != 0) {
            throw std::runtime_error{"auth tag is incorrect"};
        }

        std::string out(data.size() - tag_size_bytes, 0);
        c.cipher((u8 *)data.data(), (u8 *)out.data(), data_size);
        return out;
    }
    auto pad(auto sz) {
        constexpr auto alignment = tag_size_bytes;
        auto v = alignment - (sz - sz / alignment * alignment);
        return v == alignment ? 0 : v;
    }
};

} // namespace crypto
