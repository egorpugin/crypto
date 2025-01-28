// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

// https://www.rfc-editor.org/rfc/rfc8446
// https://tls.dxdt.ru/tls.html
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

#pragma once

#include <array>
#include <algorithm>
#include <cstdint>
#include <ranges>
#include <type_traits>
#include <variant>

namespace crypto::parameters {
#include "tls_parameters.h"
}

namespace crypto::tls13 {

#pragma pack(push, 1)

template <auto Bytes>
using length_type = bigendian_unsigned<Bytes>;

using ube16 = bigendian_unsigned<2>;
using Random = std::array<u8,32>;

// selected ciphers:
// aes+gcm, chacha20+poly1305, russian gost, chineese sm4
// no ccm when gcm is present
enum class CipherSuite : uint16_t {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,

    TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L = 0xC103,
    TLS_GOSTR341112_256_WITH_MAGMA_MGM_L = 0xC104,
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S = 0xC105,
    TLS_GOSTR341112_256_WITH_MAGMA_MGM_S = 0xC106,

    TLS_SM4_GCM_SM3 = 0x00C6,

    // helper mechanism
    TLS_FALLBACK_SCSV = 0x5600,
};

enum class ExtensionType : uint16_t {
    server_name = 0,
    supported_versions = 43,
    ec_point_formats = 11,
    signature_algorithms = 13,
    supported_groups = 10,
    psk_key_exchange_modes = 45,
    padding = 21,

    max_fragment_length = 1,                     /* RFC 6066 */
    status_request = 5,                          /* RFC 6066 */
    use_srtp = 14,                               /* RFC 5764 */
    heartbeat = 15,                              /* RFC 6520 */
    application_layer_protocol_negotiation = 16, /* RFC 7301 */
    signed_certificate_timestamp = 18,           /* RFC 6962 */
    client_certificate_type = 19,                /* RFC 7250 */
    server_certificate_type = 20,                /* RFC 7250 */

    pre_shared_key = 41,         /* RFC 8446 */
    early_data = 42,             /* RFC 8446 */
    cookie = 44,                 /* RFC 8446 */

    certificate_authorities = 47,   /* RFC 8446 */
    oid_filters = 48,               /* RFC 8446 */
    post_handshake_auth = 49,       /* RFC 8446 */
    signature_algorithms_cert = 50, /* RFC 8446 */
    key_share = 51,                 /* RFC 8446 */

    message_hash = 254,

    renegotiation_info = 0xff01,
};

enum class tls_version : uint16_t {
    tls12 = 0x0303,
    tls13 = 0x0304,
};
using ProtocolVersion = ube16;

struct server_name {
    enum NameType : u8 { host_name = 0 };

    ube16 extension_type = ExtensionType::server_name;
    ube16 len = sizeof(server_name_list_length) + sizeof(name_type) + sizeof(server_name_length);
    ube16 server_name_list_length = sizeof(name_type) + sizeof(server_name_length);
    NameType name_type{host_name};
    ube16 server_name_length;
};
struct supported_versions {
    ube16 extension_type = ExtensionType::supported_versions;
    ube16 len = sizeof(length);
    length_type<1> length{};
};
struct signature_algorithms {
    ube16 extension_type = ExtensionType::signature_algorithms;
    ube16 len = sizeof(length);
    length_type<2> length;
};
struct cookie_extension_type {
    ube16 extension_type = ExtensionType::cookie;
    ube16 len = sizeof(length);
    length_type<2> length;
};
struct supported_groups {
    ube16 extension_type = ExtensionType::supported_groups;
    ube16 len = sizeof(length);
    ube16 length;
};
struct key_share {
    ube16 extension_type = ExtensionType::key_share;
    ube16 length;
};
struct padding {
    ube16 extension_type = ExtensionType::padding;
    ube16 length;
};
struct renegotiation_info {
    ube16 extension_type = ExtensionType::renegotiation_info;
    ube16 length;
};

struct alert {
    enum class level_type : u8 { warning = 1, fatal = 2 };

    level_type level;
    parameters::alerts description;
};

struct ServerHello {
    ProtocolVersion legacy_version = tls_version::tls12;
    Random random;
    u8 legacy_session_id_len{32};
    u8 legacy_session_id[32];
    ube16 cipher_suite;
    u8 legacy_compression_method;
};

struct TLSPlaintext {
    parameters::content_type type;
    ProtocolVersion legacy_record_version = tls_version::tls12;
    length_type<2> length;

    size_t size() const { return length; }
};

struct TLSCiphertext {
    parameters::content_type opaque_type;
    ProtocolVersion legacy_record_version = tls_version::tls12;
    uint16_t length;
};

struct Handshake {
    parameters::handshake_type msg_type;
    length_type<3> length;

    /*select (Handshake.msg_type) {
        case end_of_early_data:     EndOfEarlyData;
        case certificate_request:   CertificateRequest;
    };*/
};

struct ClientHello {
    ProtocolVersion legacy_version = 0x0303; /* TLS v1.2 */
    Random random{};
    u8 legacy_session_id_len{32};
    u8 legacy_session_id[32];
};

enum class CertificateType : u8 {
    X509 = 0,
    OpenPGP_RESERVED = 1,
    RawPublicKey = 2,
};

enum class KeyUpdateRequest : u8 {
    update_not_requested = 0,
    update_requested = 1,
};

#pragma pack(pop)

} // namespace crypto::tls::tls13
