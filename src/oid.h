// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "asn1.h"

namespace crypto::oid {

constexpr auto subject_keyid = make_oid<2, 5, 29, 14>();

constexpr auto gost_r34102001_param_set_a = make_oid<1,2,643,2,2,35,1>();

constexpr auto gost2012PublicKey256 = make_oid<1,2,643,7,1,1,1,1>();
constexpr auto gost2012PublicKey512 = make_oid<1,2,643,7,1,1,1,2>();

constexpr auto gost2012Digest256 = make_oid<1,2,643,7,1,1,2,2>();
constexpr auto gost2012Digest512 = make_oid<1,2,643,7,1,1,2,3>();

constexpr auto gost2012Signature256 = make_oid<1,2,643,7,1,1,3,2>();
constexpr auto gost2012Signature512 = make_oid<1,2,643,7,1,1,3,3>();

}
