// https://www.rfc-editor.org/rfc/rfc8446
// https://tls.dxdt.ru/tls.html
// https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art080
// https://owasp.org/www-chapter-london/assets/slides/OWASPLondon20180125_TLSv1.3_Andy_Brodie.pdf

#pragma once

#include <array>
#include <algorithm>
#include <cstdint>
#include <ranges>
#include <type_traits>
#include <variant>

namespace crypto::tls13 {

#pragma pack(push, 1)

using uint8 = uint8_t;
using uint16 = uint16_t;
using uint32 = uint32_t;

template <auto Bytes>
struct length {
    using bad_type = uint64_t;
    using internal_type = std::conditional_t<Bytes == 1, uint8,
                           std::conditional_t<Bytes == 2, uint16,
        std::conditional_t<Bytes == 4, uint32, bad_type>>
    >;

    uint8 data[Bytes]{};

    length() = default;
    length(int v) {
        *this = v;
    }

    void operator=(uint32_t v) requires (Bytes == 3) {
        *(uint32_t*)data |= std::byteswap(v << 8);
    }
    void operator=(internal_type v) requires (Bytes != 3) {
        *(internal_type *)data = std::byteswap(v);
    }
    operator auto() const requires (Bytes == 3) { return std::byteswap(*(uint32_t*)data) >> 8; }
    operator auto() const requires !std::same_as<internal_type, bad_type> { return std::byteswap(*(internal_type*)data); }
};
template <auto Bytes>
auto operator+(auto &&v, const length<Bytes> &l) {
    return v + (uint32_t)l;
}
template <auto Bytes>
auto operator+(const length<Bytes> &l, auto &&v) {
    return v + (uint32_t)l;
}

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
    T data[N];
};

//template <auto Bytes>
//using opaque = repeated<uint8, Bytes>;

using ProtocolVersion = uint16;
using Random = std::array<uint8,32>;

enum class CipherSuite : uint16 {
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
    // SignatureScheme sm2sig_sm3 = 0x0708;
    // NamedGroup curveSM2 = {41};
};
template <auto N>
using cipher_suite = repeated<CipherSuite, N, 2, (1<<16)-2>;

enum class ContentType : uint8 {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    heartbeat = 24, /* RFC 6520 */
};

struct client{};
struct server{};
struct empty {
    static constexpr auto content_type = ContentType::invalid;
};

template <typename T>
constexpr bool is_client = std::same_as<T,client>;

struct Alert {
    enum class Level : uint8 { warning = 1, fatal = 2 };

    enum class Description : uint8 {
        close_notify = 0,
        unexpected_message = 10,
        bad_record_mac = 20,
        decryption_failed_RESERVED = 21,
        record_overflow = 22,
        decompression_failure_RESERVED = 30,
        handshake_failure = 40,
        no_certificate_RESERVED = 41,
        bad_certificate = 42,
        unsupported_certificate = 43,
        certificate_revoked = 44,
        certificate_expired = 45,
        certificate_unknown = 46,
        illegal_parameter = 47,
        unknown_ca = 48,
        access_denied = 49,
        decode_error = 50,
        decrypt_error = 51,
        export_restriction_RESERVED = 60,
        protocol_version = 70,
        insufficient_security = 71,
        internal_error = 80,
        inappropriate_fallback = 86,
        user_canceled = 90,
        no_renegotiation_RESERVED = 100,
        missing_extension = 109,
        unsupported_extension = 110,
        certificate_unobtainable_RESERVED = 111,
        unrecognized_name = 112,
        bad_certificate_status_response = 113,
        bad_certificate_hash_value_RESERVED = 114,
        unknown_psk_identity = 115,
        certificate_required = 116,
        no_application_protocol = 120,
    };

    Level level;
    Description description;
};

using content_type = std::variant<Alert>;

template <typename Peer, typename Fragment = empty>
struct TLSPlaintext {
    ContentType type = Fragment::content_type;
    ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
    length<2> length;
    std::conditional_t<is_client<Peer>, Fragment, content_type> fragment;

    static constexpr auto recv_size() { return sizeof(TLSPlaintext) - sizeof(fragment); }

    int make_buffers(auto &&vec) {
        int sz{};
        if constexpr (requires { fragment.make_buffers(vec); }) {
            vec.emplace_back(this, sizeof(*this) - sizeof(fragment));
            length = fragment.make_buffers(vec);
            sz += length + sizeof(*this) - sizeof(fragment);
        } else {
            length = sizeof(fragment);
            sz += sizeof(*this);
            vec.emplace_back(this, sz);
        }
        return sz;
    }
};

struct TLSInnerPlaintext {
    // opaque content[TLSPlaintext.length];
    ContentType type;
    // uint8 zeros[length_of_padding];
};

struct TLSCiphertext {
    ContentType opaque_type = ContentType::application_data;     /* 23 */
    ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
    uint16 length;
    //opaque encrypted_record[1];
};

// B.3.  Handshake Protocol

enum class HandshakeType : uint8 {
    hello_request_RESERVED = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request_RESERVED = 3,
    new_session_ticket = 4,
    end_of_early_data = 5,
    hello_retry_request_RESERVED = 6,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange_RESERVED = 12,
    certificate_request = 13,
    server_hello_done_RESERVED = 14,
    certificate_verify = 15,
    client_key_exchange_RESERVED = 16,
    finished = 20,
    certificate_url_RESERVED = 21,
    certificate_status_RESERVED = 22,
    supplemental_data_RESERVED = 23,
    key_update = 24,
    message_hash = 254,
};

template <typename MessageType>
struct Handshake {
    static constexpr auto content_type = ContentType::handshake;

    HandshakeType msg_type = MessageType::message_type;
    length<3> length;
    MessageType message;

    int make_buffers(auto &&vec) {
        int sz{};
        if constexpr (requires { message.make_buffers(vec); }) {
            vec.emplace_back(this, sizeof(*this) - sizeof(message));
            length = message.make_buffers(vec);
            sz += length + sizeof(*this) - sizeof(message);
        } else {
            length = sizeof(message);
            sz += sizeof(*this);
            vec.emplace_back(this, sz);
        }
        return sz;
    }

    /*select (Handshake.msg_type) {
        case server_hello:          ServerHello;
        case end_of_early_data:     EndOfEarlyData;
        case encrypted_extensions:  EncryptedExtensions;
        case certificate_request:   CertificateRequest;
        case certificate:           Certificate;
        case certificate_verify:    CertificateVerify;
        case finished:              Finished;
        case new_session_ticket:    NewSessionTicket;
        case key_update:            KeyUpdate;
    };*/
};

// B.3.1.  Key Exchange Messages

enum class ExtensionType : uint16 {
    server_name = 0,                             /* RFC 6066 */
    max_fragment_length = 1,                     /* RFC 6066 */
    status_request = 5,                          /* RFC 6066 */
    supported_groups = 10,                       /* RFC 8422, 7919 */
    signature_algorithms = 13,                   /* RFC 8446 */
    use_srtp = 14,                               /* RFC 5764 */
    heartbeat = 15,                              /* RFC 6520 */
    application_layer_protocol_negotiation = 16, /* RFC 7301 */
    signed_certificate_timestamp = 18,           /* RFC 6962 */
    client_certificate_type = 19,                /* RFC 7250 */
    server_certificate_type = 20,                /* RFC 7250 */
    padding = 21,                                /* RFC 7685 */
    // RESERVED = 40,                               /* Used but never assigned */
    pre_shared_key = 41,         /* RFC 8446 */
    early_data = 42,             /* RFC 8446 */
    supported_versions = 43,     /* RFC 8446 */
    cookie = 44,                 /* RFC 8446 */
    psk_key_exchange_modes = 45, /* RFC 8446 */
    // RESERVED = 46,                               /* Used but never assigned */
    certificate_authorities = 47,   /* RFC 8446 */
    oid_filters = 48,               /* RFC 8446 */
    post_handshake_auth = 49,       /* RFC 8446 */
    signature_algorithms_cert = 50, /* RFC 8446 */
    key_share = 51,                 /* RFC 8446 */
};

template <typename E>
struct Extension {
    uint16 extension_type = std::byteswap(E::extension_type);
    length<2> length;
    E e;

    int make_buffers(auto &&vec) {
        int sz{};
        if constexpr (requires { e.make_buffers(vec); }) {
            vec.emplace_back(this, sizeof(*this) - sizeof(e));
            length = e.make_buffers(vec);
            sz += length + sizeof(*this) - sizeof(e);
        } else {
            length = sizeof(*this);
            sz += length;
            vec.emplace_back(this, sizeof(*this));
        }
        return length;
    }
};

struct server_name {
    static constexpr uint16 extension_type = 0;

    enum NameType : uint8 { host_name = 0 };

    length<2> server_name_list_length;
    NameType name_type{host_name};
    length<2> server_name_length;
    string server_name_;

    int make_buffers(auto &&vec) {
        server_name_length = server_name_.size();
        server_name_list_length = sizeof(name_type) + sizeof(server_name_length) + server_name_length;

        vec.emplace_back(this, sizeof(*this) - sizeof(server_name_));
        vec.emplace_back(server_name_.data(), server_name_.size());
        return server_name_list_length + sizeof(server_name_list_length);
    }
};
struct padding {
    static constexpr uint16 extension_type = 21;

    uint8_t padding_[512]{};

    int make_buffers(auto &&vec) {
        int sz{};
        for (auto &&v : vec | std::views::drop(1)) {
            sz += v.size();
        }
        vec.emplace_back(padding_, sizeof(*this) - sz);
        return vec.back().size();
    }
};

template <typename... Types>
struct type_list {
    using variant_type = variant<Types...>;
    using variant_pointer_type = variant<Types*...>;

    //static variant_type make_type(auto type) {
        //variant_type v;
    //}
};

template <template <typename> typename T, typename... Types>
struct wrap_type_list {
    using variant_type = variant<T<Types>...>;
    using variant_pointer_type = variant<T<Types *>...>;

    // static variant_type make_type(auto type) {
    // variant_type v;
    //}
};

using extension_list = type_list<Extension<server_name>, Extension<padding>>;
using extension_type = extension_list::variant_type;

struct extensions_type {
    length<2> length;
    std::vector<extension_type> extensions;

    int make_buffers(auto &&vec) {
        vec.emplace_back(this, sizeof(length));
        int sz{};
        for (auto &&e : extensions) {
            visit(e, [&](auto &&v) {
                if constexpr (requires { v.make_buffers(vec); }) {
                    sz += v.make_buffers(vec);
                } else {
                    vec.emplace_back(&v, sizeof(v));
                    sz += sizeof(v);
                }
            });
        }
        length = sz;
        return sz + sizeof(length);
    }
};

template <auto NumberOfCipherSuites>
struct ClientHello {
    static constexpr auto message_type = HandshakeType::client_hello;

    ProtocolVersion legacy_version = 0x0303; /* TLS v1.2 */
    Random random;
    repeated<uint8, 32, 0, 32> legacy_session_id;//<0..32>;
    cipher_suite<NumberOfCipherSuites> cipher_suites_;
    repeated<uint8, 1, 1, (1 << 8) - 1> legacy_compression_methods{}; //<1..2^8-1>;
    extensions_type extensions;

    int make_buffers(auto &&vec) {
        vec.emplace_back(this, sizeof(*this) - sizeof(extensions));
        int sz = vec.back().size();
        sz += extensions.make_buffers(vec);
        return sz;
    }
};

struct ServerHello {
    static constexpr auto message_type = HandshakeType::server_hello;

    ProtocolVersion legacy_version = 0x0303; /* TLS v1.2 */
    Random random;
    /*opaque legacy_session_id_echo<0..32>;
    CipherSuite cipher_suite;
    uint8 legacy_compression_method = 0;
    Extension extensions<6..2^16-1>;*/
};

enum class NamedGroup : uint16 {
    unallocated_RESERVED = 0x0000,

    /* Elliptic Curve Groups (ECDHE) */
    // obsolete_RESERVED(0x0001..0x0016),
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    // obsolete_RESERVED(0x001A..0x001C),
    x25519 = 0x001D,
    x448 = 0x001E,

    /* Finite Field Groups (DHE) */
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,

    /* Reserved Code Points */
    // ffdhe_private_use(0x01FC..0x01FF),
    // ecdhe_private_use(0xFE00..0xFEFF),
    // obsolete_RESERVED(0xFF01..0xFF02),
};

struct KeyShareEntry {
    NamedGroup group;
    // opaque key_exchange<1..2^16-1>;
};

struct KeyShareClientHello {
    // KeyShareEntry client_shares<0..2^16-1>;
};

struct {
    NamedGroup selected_group;
} KeyShareHelloRetryRequest;

struct {
    KeyShareEntry server_share;
} KeyShareServerHello;

struct {
    uint8 legacy_form = 4;
    // opaque X[coordinate_length];
    // opaque Y[coordinate_length];
} UncompressedPointRepresentation;

enum class PskKeyExchangeMode : uint8 {
    psk_ke = 0,
    psk_dhe_ke = 1,
};

struct {
    // PskKeyExchangeMode ke_modes<1..255>;
} PskKeyExchangeModes;

struct {
} Empty;

struct EarlyDataIndication {
    /*select (Handshake.msg_type) {
    case new_session_ticket:   uint32 max_early_data_size;
    case client_hello:         Empty;
    case encrypted_extensions: Empty;
    };*/
};

struct {
    // opaque identity<1..2^16-1>;
    // uint32 obfuscated_ticket_age;
} PskIdentity;

// opaque PskBinderEntry<32..255>;

struct {
    // PskIdentity identities<7..2^16-1>;
    // PskBinderEntry binders<33..2^16-1>;
} OfferedPsks;

struct {
    /*select (Handshake.msg_type) {
    case client_hello: OfferedPsks;
    case server_hello: uint16 selected_identity;
    };*/
} PreSharedKeyExtension;

// B.3.1.1.  Version Extension

struct {
    /*select (Handshake.msg_type) {
        case client_hello:
            ProtocolVersion versions<2..254>;

        case server_hello: // and HelloRetryRequest
            ProtocolVersion selected_version;
    };*/
} SupportedVersions;

// B.3.1.2.  Cookie Extension

struct {
    // opaque cookie<1..2^16-1>;
} Cookie;

// B.3.1.3.  Signature Algorithm Extension

enum class SignatureScheme : uint16 {
    /* RSASSA-PKCS1-v1_5 algorithms */
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    /* ECDSA algorithms */
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    /* EdDSA algorithms */
    ed25519 = 0x0807,
    ed448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    /* Legacy algorithms */
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,

    /* Reserved Code Points */
    // obsolete_RESERVED(0x0000..0x0200),
    dsa_sha1_RESERVED = 0x0202,
    // obsolete_RESERVED(0x0204..0x0400),
    dsa_sha256_RESERVED = 0x0402,
    // obsolete_RESERVED(0x0404..0x0500),
    dsa_sha384_RESERVED = 0x0502,
    // obsolete_RESERVED(0x0504..0x0600),
    dsa_sha512_RESERVED = 0x0602,
    // obsolete_RESERVED(0x0604..0x06FF),
    // private_use(0xFE00..0xFFFF),
};

struct {
    // SignatureScheme supported_signature_algorithms<2..2^16-2>;
} SignatureSchemeList;

// B.3.1.4.  Supported Groups Extension

struct {
    // NamedGroup named_group_list<2..2^16-1>;
} NamedGroupList;

// B.3.2.  Server Parameters Messages

// opaque DistinguishedName<1..2^16-1>;

struct {
    // DistinguishedName authorities<3..2^16-1>;
} CertificateAuthoritiesExtension;

struct {
    // opaque certificate_extension_oid<1..2^8-1>;
    // opaque certificate_extension_values<0..2^16-1>;
} OIDFilter;

struct {
    // OIDFilter filters<0..2^16-1>;
} OIDFilterExtension;

struct {
} PostHandshakeAuth;

struct {
    // Extension extensions<0..2^16-1>;
} EncryptedExtensions;

struct {
    // opaque certificate_request_context<0..2^8-1>;
    // Extension extensions<2..2^16-1>;
} CertificateRequest;

// B.3.3.  Authentication Messages

enum class CertificateType : uint8 {
    X509 = 0,
    OpenPGP_RESERVED = 1,
    RawPublicKey = 2,
};

struct {
    /*select (certificate_type) {
        case RawPublicKey:
        // From RFC 7250 ASN.1_subjectPublicKeyInfo
        opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

        case X509:
        opaque cert_data<1..2^24-1>;
    };
    Extension extensions<0..2^16-1>;*/
} CertificateEntry;

struct {
    // opaque certificate_request_context<0..2^8-1>;
    // CertificateEntry certificate_list<0..2^24-1>;
} Certificate;

struct {
    SignatureScheme algorithm;
    // opaque signature<0..2^16-1>;
} CertificateVerify;

struct {
    // opaque verify_data[Hash.length];
} Finished;

// B.3.4.  Ticket Establishment

struct {
    uint32 ticket_lifetime;
    uint32 ticket_age_add;
    // opaque ticket_nonce<0..255>;
    // opaque ticket<1..2^16-1>;
    // Extension extensions<0..2^16-2>;
} NewSessionTicket;

// B.3.5.  Updating Keys

struct {
} EndOfEarlyData;

enum class KeyUpdateRequest : uint8 {
    update_not_requested = 0,
    update_requested = 1,
};

struct KeyUpdate {
    KeyUpdateRequest request_update;
};

#pragma pack(pop)

} // namespace crypto::tls::tls13