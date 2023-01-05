#pragma once

#include "helpers.h"
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
auto hmac(bytes_concept key, bytes_concept message) {
    constexpr int b = hmac_b(Hash{});
    constexpr int hash_bytes = Hash::digest_size_bytes;

    auto hash = [](auto &&i) {
        Hash h;
        h.update(i);
        return h.digest();
    };

    std::array<uint8_t, b> k0{};
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
template <typename Hash, auto Len>
auto hkdf_expand(bytes_concept pseudorandom_key, bytes_concept info) {
    constexpr int hash_bytes = Hash::digest_size_bytes;
    constexpr auto n = Len / hash_bytes + (Len % hash_bytes == 0 ? 0 : 1);
    std::vector<uint8_t> r(Len + info.size() + 1);
    for (int i = 0; i <= n; ++i) {
        memcpy(r.data() + Len, info.data(), info.size());
        r[r.size() - 1] = i + 1;
        memcpy(r.data(), hkdf_extract<Hash>(pseudorandom_key, r).data(), Len);
    }
    std::array<uint8_t, Len> r2;
    memcpy(r2.data(), r.data(), Len);
    return r2;
}

} // namespace crypto
