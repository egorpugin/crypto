// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "ec25519_impl.h"
#include "random.h"

namespace crypto {

// kBasePoint is the base point (generator) of the elliptic curve group.
// It is little-endian version of '9' followed by 31 zeros.
// See "Computing public keys" section of http://cr.yp.to/ecdh.html.

void curve25519_f(const u8 *private_key, u8 *public_key) {
    static const unsigned char kBasePoint[32] = {9};
    ec::curve25519::curve25519_donna(public_key, private_key, kBasePoint);
}

void curve25519_f(const u8 *private_key, const u8 *peer_public_key, u8 *shared_key) {
    ec::curve25519::curve25519_donna(shared_key, private_key, peer_public_key);
}

// also x25519
struct curve25519 {
    static inline constexpr auto key_size = 32;
    using private_key_type = array<key_size>;
    using public_key_type = private_key_type;

    private_key_type private_key_;

    void private_key() { get_random_secure_bytes(private_key_); }
    auto public_key() {
        public_key_type public_key;
        curve25519_f(private_key_.data(), public_key.data());
        return public_key;
    }
    auto public_key(auto &&out) { curve25519_f(private_key_.data(), out.data()); }
    auto shared_secret(const public_key_type &peer_public_key) {
        public_key_type shared_secret;
        curve25519_f(private_key_.data(), peer_public_key.data(), shared_secret.data());
        return shared_secret;
    }
};

} // namespace crypto
