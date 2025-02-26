// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "helpers.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"
#include "streebog.h"
#include "sm3.h"

namespace crypto {

namespace detail {

template <auto ... Settings>
constexpr auto hmac_bytes(sha2_base<Settings...>) {
    return sha2_base<Settings...>::small_sha ? 64 : 128;
}
template <auto... Settings>
constexpr auto hmac_bytes(streebog_base<Settings...>) {
    return streebog_base<Settings...>::block_size;
}
template <auto... Settings>
constexpr auto hmac_bytes(sm3) {
    return sm3::chunk_size_bytes;
}
template <auto... Settings>
constexpr auto hmac_bytes(sha1) {
    return 64;
}
// but don't allow hmac for shake algos
template <auto... Settings>
constexpr auto hmac_bytes(sha3<Settings...>) {
    return sha3<Settings...>::r / 8;
}

// see table on wiki for more hmac byte sizes

} // namespace detail

// https://en.wikipedia.org/wiki/HMAC
template <typename Hash>
struct hmac2 {
    Hash inner;
    Hash outer;

    hmac2(bytes_concept key) {
        constexpr int b = detail::hmac_bytes(Hash{});
        constexpr int hash_bytes = Hash::digest_size_bytes;

        array<b> k0{};
        if (key.size() <= b) {
            memcpy(k0.data(), key.data(), key.size());
        } else {
            memcpy(k0.data(), Hash::digest(key).data(), hash_bytes);
        }
        auto So = k0, Si = k0;
        for (auto &&c : So) c ^= 0x5C;
        for (auto &&c : Si) c ^= 0x36;

        inner.update(Si);
        outer.update(So);
    }
    void update(auto &&...args) {
        inner.update(args...);
    }
    auto digest() {
        outer.update(inner.digest());
        return outer.digest();
    }
};
template <typename Hash>
auto hmac(bytes_concept key, bytes_concept message) {
    hmac2<Hash> h{key};
    h.update(message);
    return h.digest();
}

// NIST SP 800-90A Rev. 1
template <typename Hash>
struct hmac_drbg {
    using arr = array<Hash::digest_size_bytes>;

    arr k{}, v;
    int reseed_counter{1};

    hmac_drbg(bytes_concept entropy_input, bytes_concept nonce, bytes_concept personalization_string) {
        for (auto &b : v) b = 1;
        update(entropy_input, nonce, personalization_string);
    }
    void update(auto &&...provided_data) {
        size_t len{};
        auto update1 = [&](u8 byte) {
            hmac2<Hash> hmk{k};
            hmk.update(v);
            hmk.update(&byte, 1);
            ((hmk.update(provided_data),len+=provided_data.size()),...);
            k = hmk.digest();

            hmac2<Hash> hmv{k};
            hmv.update(v);
            v = hmv.digest();
        };
        update1(0);
        if (len) {
            update1(1);
        }
    }
    void reseed(bytes_concept entropy_input, bytes_concept additional_input) {
        update(entropy_input, additional_input);
        reseed_counter = 1;
    }
    auto digest(bytes_concept additional_input = {}, bitlen len = Hash::digest_size_bytes * 8) {
        //if (reseed_counter > reseed_interval) {
        //  reseed();
        //}
        // happens after reseed
        if (!additional_input.empty()) {
            update(additional_input);
        }
        std::string t(len, 0);
        size_t tlen = 0;
        while (tlen < len) {
            v = hmac<Hash>(k, v);
            auto to_copy = std::min(len - tlen, v.size());
            memcpy(t.data() + tlen, v.data(), to_copy);
            tlen += to_copy;
        }
        update(additional_input);
        ++reseed_counter;
        take_left_bits(t, len);
        return t;
    }
};

// https://datatracker.ietf.org/doc/html/rfc2898
auto pbkdf2_raw(auto &&prf, auto &&pass, std::string salt, u32 c, u32 i) {
    u32 tail{i};
    tail = std::byteswap(tail);
    salt.resize(salt.size() + sizeof(tail));
    memcpy(salt.data() + salt.size() - sizeof(tail), &tail, sizeof(tail));
    auto u = prf(pass, salt);
    auto r = u;
    auto len = r.size();
    while (--c) {
        u = prf(pass, u);
        for (int i = 0; i < len; ++i) {
            r[i] ^= u[i];
        }
    }
    return r;
}
auto pbkdf2(auto &&prf, auto &&pass, bytes_concept salt, auto &&c, u32 derived_key_bytes) {
    std::vector<u8> res;
    res.resize(derived_key_bytes);
    int i = 0;
    auto r = pbkdf2_raw(prf, pass, salt, c, i + 1);
    auto iter_size = r.size();
    memcpy(res.data() + iter_size * i, r.data(), std::min<u32>(derived_key_bytes - i * iter_size, iter_size));
    ++i;
    auto iters = std::max<u32>(1, (derived_key_bytes + iter_size - 1) / iter_size);
    for (; i < iters; ++i) {
        auto r = pbkdf2_raw(prf, pass, salt, c, i + 1);
        memcpy(res.data() + iter_size * i, r.data(), std::min<u32>(derived_key_bytes - i * iter_size, iter_size));
    }
    return res;
}
template <typename Hash>
auto pbkdf2(auto &&pass, auto &&salt, auto &&c, u32 derived_key_bytes = Hash::digest_size_bytes) {
    return pbkdf2([](auto &&pass, auto &&u) { return hmac<Hash>(pass, u); }, pass, salt, c, derived_key_bytes);
}

// https://www.rfc-editor.org/rfc/rfc5869
template <typename Hash>
auto hkdf_extract(bytes_concept salt, bytes_concept input_key_material) {
    return hmac<Hash>(salt, input_key_material);
}
template <typename Hash>
auto hkdf_extract(bytes_concept input_key_material) {
    array<Hash::digest_size_bytes> salt{};
    return hkdf_extract(salt, input_key_material);
}
// constexpr info?
template <typename Hash, auto Len = Hash::digest_size_bytes>
auto hkdf_expand(bytes_concept pseudorandom_key, bytes_concept info) {
    static_assert(Len <= 255 * Hash::digest_size_bytes);

    constexpr auto hash_bytes = Hash::digest_size_bytes;
    constexpr auto n = ceil(Len, hash_bytes);
    std::array<u8, Len> r;
    for (int i = 1, pos = 0; i <= n; ++i) {
        hmac2<Hash> h{pseudorandom_key};
        if (i > 1) {
            h.update(r.data() + pos - hash_bytes, hash_bytes);
        }
        h.update(info);
        h.update(bytes_concept{&i, 1});
        auto sz = i == n ? Len - pos : hash_bytes;
        memcpy(r.data() + pos, h.digest().data(), sz);
        pos += sz;
    }
    return r;
}
template <typename Hash>
struct hkdf {
    static inline constexpr auto digest_size_bytes = Hash::digest_size_bytes;

    static auto extract(bytes_concept salt, bytes_concept input_key_material) {
        return hkdf_extract<Hash>(salt, input_key_material);
    }
    static auto extract(bytes_concept input_key_material) {
        array<digest_size_bytes> salt{};
        return extract(salt, input_key_material);
    }
    template <auto Len = Hash::digest_size_bytes>
    static auto expand(bytes_concept pseudorandom_key, bytes_concept info) {
        return hkdf_expand<Hash, Len>(pseudorandom_key, info);
    }
};

// tls 1.3
template <typename Hash, auto Len = Hash::digest_size_bytes>
auto hkdf_expand_label(auto &&secret, auto &&label, auto &&ctx) {
    auto protocol = "tls13 "s;
    auto plabel = protocol + label;
    string info(2 + 1 + plabel.size() + 1 + ctx.size(), 0);
    *(uint16_t *)info.data() = Len;
    *(uint16_t *)info.data() = std::byteswap(*(uint16_t *)info.data());
    info[2] = plabel.size();
    memcpy(info.data() + 3, plabel.data(), plabel.size());
    info[3 + info[2]] = ctx.size();
    memcpy(info.data() + 3 + info[2] + 1, ctx.data(), ctx.size());
    return hkdf_expand<Hash, Len>(secret, info);
}
template <typename Hash, auto Len = Hash::digest_size_bytes>
auto hkdf_expand_label(auto &&secret, auto &&label) {
    return hkdf_expand_label<Hash, Len>(secret, label, ""sv);
}
template <typename Hash>
auto derive_secret(auto &&secret, auto &&label, Hash h = {}) {
    return hkdf_expand_label<Hash>(secret, label, h.digest());
}

namespace gost {

template <typename Hash>
auto kdf(auto &&key, auto &&label, auto &&seed) {
    std::string message(1 + label.size() + 1 + seed.size() + 2, 0);
    message[0] = 1;
    memcpy(message.data() + 1, label.data(), label.size());
    memcpy(message.data() + 1 + label.size() + 1, seed.data(), seed.size());
    message[1 + label.size() + 1 + seed.size()] = 1;
    return hmac<Hash>(key, message);
}
template <typename Suite>
auto tlstree_needs_new_key(u64 seqnum) {
    return !(seqnum > 0 && std::ranges::all_of(Suite::C, [&](auto C){return (seqnum & C) == ((seqnum - 1) & C);}));
}
template <typename Hash, typename Suite>
auto tlstree(auto &&key, u64 seqnum) {
    auto label = "level0"s;
    auto k = key;
    for (int l = 1; auto &&C : Suite::C) {
        label[5] = l++ + '0';
        auto d = seqnum & C;
        d = std::byteswap(d);
        k = kdf<Hash>(k, label, bytes_concept{(u8 *)&d, sizeof(d)});
    }
    return k;
}

} // namespace gost

} // namespace crypto
