#pragma once

#include "sha2.h"

namespace crypto {

template <auto ... Settings>
constexpr auto hmac_b(sha2<Settings...>) {
    return sha2<Settings...>::small_sha ? 64 : 128;
}

// not available for sha3?
/*template <auto DigestSizeBits>
constexpr auto hmac_b(sha3<DigestSizeBits>) {
    return sha2<Settings...>::small_sha ? 64 : 128;
}*/

// https://en.wikipedia.org/wiki/HMAC
template <typename Hash>
auto hmac(auto &&key, auto &&message) {
    constexpr int b = hmac_b(Hash{});
    constexpr int hash_bytes = Hash::digest_size_bytes;

    auto sz = [](auto &&d) {
        int msz;
        if constexpr (requires { d.size(); }) {
            msz = d.size();
        } else if constexpr (requires { strlen(d); }) {
            msz = strlen(d);
        } else {
            msz = sizeof(d);
        }
        return msz;
    };
    auto ksz = sz(key);
    auto msz = sz(message);

    auto hash = [](auto &&i) {
        Hash h;
        h.update(i);
        return h.digest();
    };

    std::array<uint8_t, b> k0{};
    if (ksz <= b) {
        memcpy(k0.data(), key, ksz);
    } else {
        memcpy(k0.data(), hash(key).data(), hash_bytes);
    }
    auto So = k0, Si = k0;
    for (auto &&c : So) c ^= 0x5C;
    for (auto &&c : Si) c ^= 0x36;

    Hash inner;
    inner.update(Si);
    inner.update((const uint8_t *)message, msz);

    Hash outer;
    outer.update(So);
    outer.update(inner.digest());
    return outer.digest();
}

} // namespace crypto
