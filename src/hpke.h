#pragma once

#include "hmac.h"
#include "ec.h"
#include "ec25519.h"
#include "chacha20_poly1305.h"

namespace crypto {

enum class mode_type : uint8_t {
    base,
    psk,
    auth,
    auth_psk,
};

template <auto n_sk>
auto hpke_derive_key_pair_ec(auto &&obj, bytes_concept version, auto &&input_key_material, u8 byte) {
    auto dkp_prk = obj.labeled_extract(version, ""sv, "dkp_prk"sv, input_key_material);
    memset(obj.c.private_key_.data(), 0, n_sk);
    int counter{};
    bigint sk;
    while (sk == 0 || sk >= decltype(obj.c)::parameters.curve().order) {
        if (counter > 255) {
            throw std::runtime_error{"derive key pair error"};
        }
        auto d = obj.labeled_expand<n_sk>(version, dkp_prk, "candidate"sv, bytes_concept{&counter, 1});
        d[0] &= byte;
        memcpy(obj.c.private_key_.data(), d.data(), d.size());
        sk = bytes_to_bigint(obj.c.private_key_);
        ++counter;
    }
    auto pk = obj.c.public_key();
    return std::tuple{obj.c.private_key_,pk};
}
template <auto n_sk>
auto hpke_derive_key_pair_edwards(auto &&obj, bytes_concept version, auto &&input_key_material) {
    auto dkp_prk = obj.labeled_extract(version, ""sv, "dkp_prk"sv, input_key_material);
    auto sk = obj.labeled_expand<n_sk>(version, dkp_prk, "sk"sv, ""sv);
    memcpy(obj.c.private_key_.data(), sk.data(), sk.size());
    auto pk = obj.c.public_key();
    return std::tuple{obj.c.private_key_,pk};
}

template <typename Curve, typename Hkdf>
struct dhkem_params;

template <> struct dhkem_params<curve25519, hkdf<sha256>> {
    static inline constexpr uint16_t id = 0x20;
    static inline constexpr auto n_secret = 32;
    static inline constexpr auto n_enc = 32;
    static inline constexpr auto n_pk = 32;
    static inline constexpr auto n_sk = 32;

    static auto derive_key_pair(auto &&obj, bytes_concept version, auto &&input_key_material) {
        return hpke_derive_key_pair_edwards<n_sk>(obj, version, input_key_material);
    }
};
// x448 // 64 |56  |56 |56
template <> struct dhkem_params<ec::secp256r1, hkdf<sha256>> {
    static inline constexpr uint16_t id = 0x10;
    static inline constexpr auto n_secret = 32;
    static inline constexpr auto n_enc = 65;
    static inline constexpr auto n_pk = 65;
    static inline constexpr auto n_sk = 32;

    static auto derive_key_pair(auto &&obj, bytes_concept version, auto &&input_key_material) {
        return hpke_derive_key_pair_ec<n_sk>(obj, version, input_key_material, 0xff);
    }
};
template <> struct dhkem_params<ec::secp384r1, hkdf<sha2<384>>> {
    static inline constexpr uint16_t id = 0x11;
    static inline constexpr auto n_secret = 48;
    static inline constexpr auto n_enc = 97;
    static inline constexpr auto n_pk = 97;
    static inline constexpr auto n_sk = 48;

    static auto derive_key_pair(auto &&obj, bytes_concept version, auto &&input_key_material) {
        return hpke_derive_key_pair_ec<n_sk>(obj, version, input_key_material, 0xff);
    }
};
template <> struct dhkem_params<ec::secp521r1, hkdf<sha2<512>>> {
    static inline constexpr uint16_t id = 0x12;
    static inline constexpr auto n_secret = 64;
    static inline constexpr auto n_enc = 133;
    static inline constexpr auto n_pk = 133;
    static inline constexpr auto n_sk = 66;

    static auto derive_key_pair(auto &&obj, bytes_concept version, auto &&input_key_material) {
        return hpke_derive_key_pair_ec<n_sk>(obj, version, input_key_material, 0x01);
    }
};

template <typename Curve, typename Hkdf>
struct dhkem {
    using params_type = dhkem_params<Curve, Hkdf>;
    static_assert(Curve::key_size == params_type::n_pk);

    Curve c;

    static auto suite_id() {
        auto kem_id = std::byteswap(params_type::id);
        auto suite_id = concat("KEM"sv, bytes_concept{&kem_id, sizeof(kem_id)});
        return suite_id;
    }

    static auto labeled_extract(bytes_concept version, bytes_concept salt, bytes_concept label, bytes_concept input_key_material) {
        auto labeled_ikm = concat(version, suite_id(), label, input_key_material);
        return Hkdf::extract(salt, labeled_ikm);
    }
    template <uint16_t Len>
    static auto labeled_expand(bytes_concept version, bytes_concept prk, bytes_concept label, bytes_concept info) {
        auto len = std::byteswap(Len);
        auto labeled_info = concat(bytes_concept{&len, sizeof(len)}, version, suite_id(), label, info);
        return Hkdf::expand<Len>(prk, labeled_info);
    }
    static auto extract_and_expand(bytes_concept version, bytes_concept dh, bytes_concept kem_context) {
        auto eae_prk = labeled_extract(version, ""sv, "eae_prk"sv, dh);
        auto shared_secret = labeled_expand<params_type::n_secret>(version, eae_prk, "shared_secret"sv, kem_context);
        return shared_secret;
    }

    // only x25519 and x448
    auto derive_key_pair(bytes_concept version, auto &&input_key_material) {
        return params_type::derive_key_pair(*this, version, input_key_material);
    }
};

struct hpke_export_only;

template <typename Kem, typename Hkdf, typename Sym>
struct hpke {
    static inline constexpr auto version = "HPKE-v1"sv;
    static inline constexpr auto export_only = std::same_as<Sym, hpke_export_only>;

    Kem kem;
    //static auto kem() {return Kem{};}

    static consteval uint16_t kdf_id_() {
        if constexpr (std::same_as<Hkdf, hkdf<sha2<256>>>) return 1;
        if constexpr (std::same_as<Hkdf, hkdf<sha2<384>>>) return 2;
        if constexpr (std::same_as<Hkdf, hkdf<sha2<512>>>) return 3;
        throw;
    }
    static consteval uint16_t aead_id_() {
        if constexpr (std::same_as<Sym, gcm<aes_ecb<128>>>) return 1;
        if constexpr (std::same_as<Sym, gcm<aes_ecb<256>>>) return 2;
        if constexpr (std::same_as<Sym, chacha20_poly1305_aead>) return 3;
        if constexpr (std::same_as<Sym, hpke_export_only>) return 0xFFFF;
        throw;
    }
    static auto suite_id() {
        auto kem_id = std::byteswap(Kem::params_type::id);
        auto kdf_id = std::byteswap(kdf_id_());
        auto aead_id = std::byteswap(aead_id_());
        auto suite_id = concat("HPKE"sv
            , bytes_concept{&kem_id, sizeof(kem_id)}
            , bytes_concept{&kdf_id, sizeof(kdf_id)}
            , bytes_concept{&aead_id, sizeof(aead_id)}
        );
        return suite_id;
    }
    struct context_base {
        array<Hkdf::digest_size_bytes> exporter_secret;

        template <auto Len = Hkdf::digest_size_bytes>
        auto export_(bytes_concept exporter_context) {
            return labeled_expand<Len>(exporter_secret, "sec"sv, exporter_context);
        }
    };

    static auto labeled_extract(bytes_concept salt, bytes_concept label, bytes_concept input_key_material) {
        auto labeled_ikm = concat(version, suite_id(), label, input_key_material);
        return Hkdf::extract(salt, labeled_ikm);
    }
    template <uint16_t Len>
    static auto labeled_expand(bytes_concept prk, bytes_concept label, bytes_concept info) {
        auto len = std::byteswap(Len);
        auto labeled_info = concat(bytes_concept{&len, sizeof(len)}, version, suite_id(), label, info);
        return Hkdf::expand<Len>(prk, labeled_info);
    }

    auto derive_key_pair(auto &&input_key_material) {
        return kem.derive_key_pair(version, input_key_material);
    }
    template <char Role>
    auto shared_secret(bytes_concept peer_public_key) {
        auto dh = kem.c.shared_secret(peer_public_key);
        auto kem_context = Role == 'S' ? concat((bytes_concept)kem.c.public_key(), peer_public_key) : concat(peer_public_key, (bytes_concept)kem.c.public_key());
        return kem.extract_and_expand(version, dh, kem_context);
    }
    template <char Role>
    auto shared_secret(bytes_concept peer_public_key, bytes_concept s_key) {
        if constexpr (Role == 'S') { // AuthEncap
            Kem s;
            memcpy(s.c.private_key_.data(), s_key.data(), s_key.size());
            auto dh = concat(kem.c.shared_secret(peer_public_key), s.c.shared_secret(peer_public_key));
            auto kem_context = concat((bytes_concept)kem.c.public_key(), peer_public_key, (bytes_concept)s.c.public_key());
            return kem.extract_and_expand(version, dh, kem_context);
        } else { // AuthDecap
            auto dh = concat(kem.c.shared_secret(peer_public_key), kem.c.shared_secret(s_key));
            auto kem_context = concat(peer_public_key, (bytes_concept)kem.c.public_key(), s_key);
            return kem.extract_and_expand(version, dh, kem_context);
        }
    }

    template <char Role>
    auto key_schedule(auto mode, auto &&shared_secret, auto &&info, auto &&psk, auto &&psk_id) {
        if (psk.empty() != psk_id.empty()) {
            throw std::runtime_error{"inconsistent PSK inputs"};
        }
        if (!psk.empty() && (mode == mode_type::base || mode == mode_type::auth)) {
            throw std::runtime_error{"PSK input provided when not needed"};
        }
        if (psk.empty() && (mode == mode_type::psk || mode == mode_type::auth_psk)) {
            throw std::runtime_error{"missing required PSK input"};
        }

        auto psk_id_hash = labeled_extract(""sv, "psk_id_hash"sv, psk_id);
        auto info_hash = labeled_extract(""sv, "info_hash"sv, info);
        auto key_schedule_context = concat(bytes_concept{&mode, sizeof(mode)}, psk_id_hash, info_hash);
        auto secret = labeled_extract(shared_secret, "secret"sv, psk);
        auto exporter_secret = labeled_expand<Hkdf::digest_size_bytes>(secret, "exp"sv, key_schedule_context);
        if constexpr (export_only) {
            return context_base{exporter_secret};
        } else {
            auto key = labeled_expand<Sym::key_size_bytes>(secret, "key"sv, key_schedule_context);
            auto base_nonce = labeled_expand<Sym::iv_size_bytes>(secret, "base_nonce"sv, key_schedule_context);

            struct context : context_base {
                array<Sym::key_size_bytes> key;
                array<Sym::iv_size_bytes> base_nonce;
                Sym s{key};
                array<Sym::iv_size_bytes> seq_bytes{};

                auto compute_nonce() {
                    auto n = seq_bytes;
                    for (int i = 0; i < Sym::iv_size_bytes; ++i) {
                        n[i] ^= base_nonce[i];
                    }
                    return n;
                }
                void increment_seq() {
                    int i = Sym::iv_size_bytes - 1;
                    for (; i >= 0; --i) {
                        if (++seq_bytes[i] != 0) {
                            break;
                        }
                    }
                    if (i < 0) {
                        // probably this is one more message than in rfc (0xff..f instead of 0xff..e max)
                        // seq must be: seq < (1 << (8*Nn)) - 1
                        throw std::runtime_error{"message limit reached"};
                    }
                }
                auto seal(bytes_concept aad, bytes_concept plaintext) requires (Role == 'S') {
                    auto ct = s.encrypt_and_tag(compute_nonce(), plaintext, aad);
                    increment_seq();
                    return ct;
                }
                auto open(bytes_concept aad, bytes_concept ciphertext) requires (Role == 'R') {
                    auto ct = s.decrypt_with_tag(compute_nonce(), ciphertext, aad);
                    increment_seq();
                    return ct;
                }
            };
            return context{exporter_secret, key, base_nonce};
        }
    }
};

}
