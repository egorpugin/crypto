// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
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

//template <auto Bytes>
//using opaque = repeated<uint8, Bytes>;

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

using extension_type_type = uint16;

template <typename E>
struct Extension {
    extension_type_type extension_type = std::byteswap(E::extension_type);
    length<2> length;
    E e;

    int make_buffers(auto &&vec) {
        return make_buffers1(vec, *this, e);
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
struct supported_versions {
    static constexpr extension_type_type extension_type = 43;

    length<1> length{sizeof(supported_version)};
    ProtocolVersion supported_version = tls_version::tls13; // tls13
};
struct signature_algorithms {
    static constexpr extension_type_type extension_type = 13;
    using SignatureScheme = uint16;
/*
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    // EdDSA algorithms
    ed25519 = 0x0807,
    ed448 = 0x0808,
*/

    length<2> length{5 * sizeof(SignatureScheme)};
    SignatureScheme scheme[5] = {0x0708, 0x0302, 0x0304, 0x0104, 0x0305};
    //SignatureScheme scheme = 0x0302; // ecdsa_sha1
    //SignatureScheme scheme = 0x0708; // ed25519
    //SignatureScheme scheme = 0x0304; // google works (passes more)
    //SignatureScheme scheme = 0x0104; // rsa_pkcs1_sha256
};
struct signature_algorithms_cert {
    static constexpr extension_type_type extension_type = 50;
    using SignatureScheme = uint16;
/*
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    // EdDSA algorithms
    ed25519 = 0x0807,
    ed448 = 0x0808,
*/

    length<2> length{4 * sizeof(SignatureScheme)};
    SignatureScheme scheme[4] = {0x0708,0x0302,0x0304,0x0104};
};
struct supported_groups {
    static constexpr extension_type_type extension_type = 10;
    using NamedGroup = uint16;

    length<2> length{sizeof(scheme)};
    NamedGroup scheme = 0x1D00;
};
struct key_share {
    static constexpr extension_type_type extension_type = 51;
    using NamedGroup = uint16;

    struct entry {
        NamedGroup scheme = 0x1D00;
        ::crypto::tls13::length<2> length{sizeof(key)};
        uint8 key[32];
    };

    length<2> length{sizeof(e)}; // only on client
    entry e;
};
struct psk_key_exchange_modes {
    static constexpr extension_type_type extension_type = 45;

    length<1> length{sizeof(mode)};
    parameters::psk_key_exchange_mode mode{parameters::psk_key_exchange_mode::psk_dhe_ke};
};
struct padding {
    static constexpr extension_type_type extension_type = 21;

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

    template <template <typename> typename T>
    using wrap_list = type_list<T<Types>...>;

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

using extension_list = type_list<
    server_name,
    padding,
    supported_versions,
    signature_algorithms,
    signature_algorithms_cert,
    supported_groups,
    key_share,
    psk_key_exchange_modes
>::wrap_list<Extension>;
using extension_type = extension_list::variant_type;

struct extensions_type {
    length<2> length;
    std::vector<extension_type> extensions;

    int make_buffers(auto &&vec) {
        vec.emplace_back(this, sizeof(length));
        int sz{};
        for (auto &&e : extensions) {
            visit(e, [&](auto &&v) {
                sz += v.make_buffers(vec);
            });
        }
        length = sz;
        return sz + sizeof(length);
    }

    template <typename T>
    T &add() {
        return std::get<Extension<T>>(extensions.emplace_back(Extension<T>{})).e;
    }
    void add(auto &&v) {
        extensions.emplace_back(v);
    }
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
    //extensions_type extensions;
};

using content_type = std::variant<Alert, ServerHello>;

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

    size_t size() const { return (int)length; }
};

struct {
    //opaque content[TLSPlaintext.length];
    parameters::content_type type;
    //uint8 zeros[length_of_padding];
} TLSInnerPlaintext;

struct TLSCiphertext {
    parameters::content_type opaque_type;
    ProtocolVersion legacy_record_version = tls_version::tls12;
    uint16 length;
    //opaque encrypted_record[1];
};

// B.3.  Handshake Protocol

struct Handshake {
    static constexpr auto content_type = parameters::content_type::handshake;

    parameters::handshake_type msg_type;
    length<3> length;

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


template <auto NumberOfCipherSuites>
struct ClientHello {
    static constexpr auto message_type = parameters::handshake_type::client_hello;

    ProtocolVersion legacy_version = 0x0303; /* TLS v1.2 */
    Random random{};
    repeated<uint8, 32, 0, 32> legacy_session_id;//<0..32>;
    cipher_suite<NumberOfCipherSuites> cipher_suites_;
    repeated<uint8, 1, 1, (1 << 8) - 1> legacy_compression_methods{}; //<1..2^8-1>;
    extensions_type extensions;

    int make_buffers(auto &&vec) {
        return make_buffers1(vec, *this, extensions);
    }
};

enum class CertificateType : uint8_t {
    X509 = 0,
    OpenPGP_RESERVED = 1,
    RawPublicKey = 2,
};

#pragma pack(pop)

} // namespace crypto::tls::tls13
