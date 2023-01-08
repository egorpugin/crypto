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

using uint8 = uint8_t;
using uint16 = uint16_t;
using uint32 = uint32_t;
using uint64 = uint64_t;

template <auto Bytes>
using length = bigendian_unsigned<Bytes>;

using ube16 = bigendian_unsigned<2>;

template <typename T, auto N, auto MinDataLength, auto MaxDataLength>
struct repeated {
    static consteval unsigned log2floor(auto x) {
        return x == 1 ? 0 : 1 + log2floor(x >> 1);
    }
    static consteval unsigned length_size() {
        auto bits = log2floor(MaxDataLength) + 1;
        auto bytes = bits / 8;
        if (!bytes) {
            bytes = 1;
        }
        return bytes;
    }

    length<length_size()> length{sizeof(data)};
    T data[N]{};

    repeated() = default;
    repeated(T) = delete;
    void operator=(auto) = delete;

    T &operator[](int i){return data[i];}
};

using Random = std::array<uint8,32>;

struct CipherSuite {
    enum : uint16 {
        TLS_AES_128_GCM_SHA256 = 0x1301,
        TLS_AES_256_GCM_SHA384 = 0x1302,
        TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
        TLS_AES_128_CCM_SHA256 = 0x1304,
        TLS_AES_128_CCM_8_SHA256 = 0x1305,

        TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L = 0xC103,
        TLS_GOSTR341112_256_WITH_MAGMA_MGM_L = 0xC104,
        TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S = 0xC105,
        TLS_GOSTR341112_256_WITH_MAGMA_MGM_S = 0xC106,

        TLS_SM4_GCM_SM3 = 0x00C6,
        TLS_SM4_CCM_SM3 = 0x00C7,
    };

    uint16 suite;

    constexpr CipherSuite() = default;
    constexpr CipherSuite(uint16_t v) {
        suite = std::byteswap(v);
    }
    constexpr auto &operator=(uint16_t v) {
        suite = std::byteswap(v);
        return *this;
    }
};
template <auto N>
using cipher_suite = repeated<CipherSuite, N, 2, (1<<16)-2>;

enum class ExtensionType : uint16 {
    server_name = 0,
    supported_versions = 43,
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
};

enum class tls_version : uint16_t {
    tls12 = 0x0303,
    tls13 = 0x0304,
};
using ProtocolVersion = ube16;

struct server_name {
    enum NameType : uint8 { host_name = 0 };

    ube16 extension_type = ExtensionType::server_name;
    ube16 len = sizeof(server_name_list_length) + sizeof(name_type) + sizeof(server_name_length);
    ube16 server_name_list_length = sizeof(name_type) + sizeof(server_name_length);
    NameType name_type{host_name};
    ube16 server_name_length;
};
struct supported_versions {
    ube16 extension_type = ExtensionType::supported_versions;
    ube16 len = sizeof(length) + sizeof(supported_version);
    length<1> length{sizeof(supported_version)};
    ProtocolVersion supported_version = tls_version::tls13; // tls13
};
struct signature_algorithms {
    ube16 extension_type = ExtensionType::signature_algorithms;
    ube16 len = sizeof(length) + sizeof(scheme);

    using SignatureScheme = uint16;
/*
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    // EdDSA algorithms
    ed25519 = 0x0807,
    ed448 = 0x0808,
*/

    length<2> length{8 * sizeof(SignatureScheme)};
    SignatureScheme scheme[8] = {
        0x0708, 0x0302, 0x0304, 0x0305, 0x0306, 0x0104,
        0x0408, 0x0908
    };
    //SignatureScheme scheme = 0x0302; // ecdsa_sha1
    //SignatureScheme scheme = 0x0708; // ed25519
    //SignatureScheme scheme = 0x0304; // google works (passes more)
    //SignatureScheme scheme = 0x0104; // rsa_pkcs1_sha256
};
struct supported_groups {
    ube16 extension_type = ExtensionType::supported_groups;
    ube16 len = sizeof(length);
    ube16 length;
};
template <auto KeySize>
struct key_share {
    ube16 extension_type = ExtensionType::key_share;
    ube16 len = sizeof(length) + sizeof(e);

    struct entry {
        ube16 scheme;
        ::crypto::tls13::length<2> length{KeySize};
        uint8 key[KeySize];
    };

    length<2> length{sizeof(e)}; // only on client
    entry e;
};
struct padding {
    ube16 extension_type = ExtensionType::padding;
    ube16 len;
};

struct Alert {
    enum class level_type : uint8 { warning = 1, fatal = 2 };

    level_type level;
    parameters::alerts description;
};

struct ServerHello {
    static constexpr auto message_type = parameters::handshake_type::server_hello;

    ProtocolVersion legacy_version = tls_version::tls12;
    Random random;
    repeated<uint8, 32, 0, 32> legacy_session_id; //<0..32>;
    CipherSuite cipher_suite;
    uint8 legacy_compression_method;
};

int make_buffers1(auto &&vec, auto &&obj, auto &&variable_field) {
    auto sz_obj = sizeof(obj) - sizeof(variable_field);
    vec.emplace_back(&obj, sz_obj);
    int variable_field_size{};
    if constexpr (requires { variable_field.make_buffers(vec); }) {
        variable_field_size = variable_field.make_buffers(vec);
    } else {
        variable_field_size = sizeof(variable_field);
        vec.emplace_back(&variable_field, variable_field_size);
    }
    if constexpr (requires { obj.length; }) {
        obj.length = variable_field_size;
    }
    return sz_obj + variable_field_size;
}

struct TLSPlaintext {
    parameters::content_type type;
    ProtocolVersion legacy_record_version = tls_version::tls12;
    length<2> length;

    size_t size() const { return (size_t)length; }
};

struct TLSCiphertext {
    parameters::content_type opaque_type;
    ProtocolVersion legacy_record_version = tls_version::tls12;
    uint16 length;
};

struct Handshake {
    static constexpr auto content_type = parameters::content_type::handshake;

    parameters::handshake_type msg_type;
    length<3> length;

    /*select (Handshake.msg_type) {
        case end_of_early_data:     EndOfEarlyData;
        case certificate_request:   CertificateRequest;
        case certificate_verify:    CertificateVerify;
    };*/
};

struct ClientHello {
    static constexpr auto message_type = parameters::handshake_type::client_hello;

    ProtocolVersion legacy_version = 0x0303; /* TLS v1.2 */
    Random random{};
    repeated<uint8, 32, 0, 32> legacy_session_id;//<0..32>;
};

enum class CertificateType : uint8_t {
    X509 = 0,
    OpenPGP_RESERVED = 1,
    RawPublicKey = 2,
};

enum class KeyUpdateRequest : uint8 {
    update_not_requested = 0,
    update_requested = 1,
};

#pragma pack(pop)

} // namespace crypto::tls::tls13
