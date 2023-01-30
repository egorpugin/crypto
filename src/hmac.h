#pragma once

#include "helpers.h"
#include "sha2.h"
#include "streebog.h"

namespace crypto {

template <auto ... Settings>
constexpr auto hmac_b(sha2_base<Settings...>) {
    return sha2_base<Settings...>::small_sha ? 64 : 128;
}
template <auto... Settings>
constexpr auto hmac_b(streebog_base<Settings...>) {
    return streebog_base<Settings...>::block_size;
}

// https://en.wikipedia.org/wiki/HMAC
template <typename Hash>
auto hmac(bytes_concept key, bytes_concept message) {
    constexpr int b = hmac_b(Hash{});
    constexpr int hash_bytes = Hash::digest_size_bytes;

    auto hash = [](auto &&i) {
        Hash h;
        h.update(i);
        return h.digest();
    };

    array<b> k0{};
    if (key.size() <= b) {
        memcpy(k0.data(), key.data(), key.size());
    } else {
        memcpy(k0.data(), hash(key).data(), hash_bytes);
    }
    auto So = k0, Si = k0;
    for (auto &&c : So) c ^= 0x5C;
    for (auto &&c : Si) c ^= 0x36;

    Hash inner;
    inner.update(Si);
    inner.update(message);

    Hash outer;
    outer.update(So);
    outer.update(inner.digest());
    return outer.digest();
}

// https://www.rfc-editor.org/rfc/rfc5869
template <typename Hash>
auto hkdf_extract(bytes_concept salt, bytes_concept input_keying_material) {
    return hmac<Hash>(salt, input_keying_material);
}
// constexpr info?
template <typename Hash, auto Len = Hash::digest_size_bytes>
auto hkdf_expand(bytes_concept pseudorandom_key, bytes_concept info) {
    constexpr auto hash_bytes = Hash::digest_size_bytes;
    auto n = Len / hash_bytes + (Len % hash_bytes == 0 ? 0 : 1);
    string r;
    r.reserve(hash_bytes + info.size() + 1);
    r.append((const char *)info.data(), info.size());
    r.resize(r.size() + 1);
    std::array<uint8_t, Len> r2;
    int pos = 0;
    for (int i = 0; i < n; ++i) {
        if (i == 1) {
            memcpy(r.data() + hash_bytes, info.data(), info.size());
        }
        r[r.size() - 1] = i + 1;
        memcpy(r.data(), hkdf_extract<Hash>(pseudorandom_key, r).data(), hash_bytes);
        auto sz = (i == n - 1) ? Len - pos : hash_bytes;
        memcpy(r2.data() + pos, r.data(), sz);
        pos += sz;
    }
    return r2;
}

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
auto tlstree_needs_new_key(uint64_t seqnum) {
    return !(seqnum > 0 && std::ranges::all_of(Suite::C, [&](auto C){return (seqnum & C) == ((seqnum - 1) & C);}));
}
template <typename Hash, typename Suite>
auto tlstree(auto &&key, uint64_t seqnum) {
    auto label = "level0"s;
    auto k = key;
    for (int l = 1; auto &&C : Suite::C) {
        label[5] = l++ + '0';
        auto d = seqnum & C;
        d = std::byteswap(d);
        k = kdf<Hash>(k, label, bytes_concept{(uint8_t *)&d, sizeof(d)});
    }
    return k;
}

} // namespace gost

} // namespace crypto
