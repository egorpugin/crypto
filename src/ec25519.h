#pragma once

#include "helpers.h"
#include "ec25519_impl.h"

namespace crypto {

// kBasePoint is the base point (generator) of the elliptic curve group.
// It is little-endian version of '9' followed by 31 zeros.
// See "Computing public keys" section of http://cr.yp.to/ecdh.html.

void curve25519(const uint8_t *private_key, uint8_t *public_key) {
    static const unsigned char kBasePoint[32] = {9};
    ec::curve25519::curve25519_donna(public_key, private_key, kBasePoint);
}

void curve25519(const uint8_t *private_key, const uint8_t *peer_public_key, uint8_t *shared_key) {
    ec::curve25519::curve25519_donna(shared_key, private_key, peer_public_key);
}

}
