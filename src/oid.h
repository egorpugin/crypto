// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "asn1.h"

namespace crypto::oid {

constexpr auto common_name                  = make_oid<2, 5, 4, 3>();
constexpr auto country                      = make_oid<2, 5, 4, 6>();
constexpr auto state                        = make_oid<2, 5, 4, 8>();
constexpr auto locality                     = make_oid<2, 5, 4, 7>();
constexpr auto organization                 = make_oid<2, 5, 4, 10>();
constexpr auto organization_unit            = make_oid<2, 5, 4, 11>();

constexpr auto old_authority_keyid          = make_oid<2, 5, 29, 1>();
constexpr auto subject_keyid                = make_oid<2, 5, 29, 14>();
constexpr auto subjectAltName               = make_oid<2, 5, 29, 17>();
constexpr auto authority_keyid              = make_oid<2, 5, 29, 35>();

//
constexpr auto gost_r34102001_param_set_a   = make_oid<1, 2, 643, 2, 2, 35, 1>();

constexpr auto gost_3410_12_256_param_set_a = make_oid<1, 2, 643, 7, 1, 2, 1, 1, 1>();
constexpr auto gost_3410_12_256_param_set_b = make_oid<1, 2, 643, 7, 1, 2, 1, 1, 2>();
constexpr auto gost_3410_12_256_param_set_c = make_oid<1, 2, 643, 7, 1, 2, 1, 1, 3>();
constexpr auto gost_3410_12_256_param_set_d = make_oid<1, 2, 643, 7, 1, 2, 1, 1, 4>();

constexpr auto gost_3410_12_512_param_set_a = make_oid<1, 2, 643, 7, 1, 2, 1, 2, 1>();
constexpr auto gost_3410_12_512_param_set_b = make_oid<1, 2, 643, 7, 1, 2, 1, 2, 2>();
constexpr auto gost_3410_12_512_param_set_c = make_oid<1, 2, 643, 7, 1, 2, 1, 2, 3>();

constexpr auto gost2012PublicKey256         = make_oid<1, 2, 643, 7, 1, 1, 1, 1>();
constexpr auto gost2012PublicKey512         = make_oid<1, 2, 643, 7, 1, 1, 1, 2>();

constexpr auto gost2012Digest256            = make_oid<1, 2, 643, 7, 1, 1, 2, 2>();
constexpr auto gost2012Digest512            = make_oid<1, 2, 643, 7, 1, 1, 2, 3>();

constexpr auto gost2012Signature256         = make_oid<1, 2, 643, 7, 1, 1, 3, 2>();
constexpr auto gost2012Signature512         = make_oid<1, 2, 643, 7, 1, 1, 3, 3>();

// https://www.rfc-editor.org/rfc/rfc8017 pkcs #1
// 1.3.6.1.5.5.7.3.1 serverAuth

// rsaEncryption (PKCS #1)
constexpr auto rsaEncryption                = make_oid<1, 2, 840, 113549, 1, 1, 1>();
constexpr auto sha256WithRSAEncryption      = make_oid<1, 2, 840, 113549, 1, 1, 11>();
constexpr auto sha384WithRSAEncryption      = make_oid<1, 2, 840, 113549, 1, 1, 12>();
constexpr auto sha512WithRSAEncryption      = make_oid<1, 2, 840, 113549, 1, 1, 13>();
constexpr auto ecdsa_with_SHA256            = make_oid<1, 2, 840, 10045, 4, 3, 2>();
constexpr auto ecdsa_with_SHA384            = make_oid<1, 2, 840, 10045, 4, 3, 3>();
constexpr auto ecdsa_with_SHA512            = make_oid<1, 2, 840, 10045, 4, 3, 4>();

constexpr auto sm2sm3                       = make_oid<1, 2, 156, 10197, 1, 501>();

//constexpr auto ecPublicKey = make_oid<1, 2, 840, 10045, 2, 1>();
//constexpr auto Ed25519 = make_oid<1, 3, 101, 112>();

constexpr auto prime256v1 = make_oid<1, 2, 840, 10045, 3, 1, 7>();
constexpr auto secp384r1 = make_oid<1, 3, 132, 0, 34>();

}
