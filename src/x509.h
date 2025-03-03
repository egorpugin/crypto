// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "asn1.h"
#include "base64.h"
#include "mmap.h"
#include "rsa.h"
#include "sha1.h"
#include "oid.h"

#include "ec.h"
#include "streebog.h"

namespace crypto {

// rfc5280
struct x509 {
    enum {
        main, // main object
    };
    enum {
        certificate, // tbsCertificate
        certificate_signature_algorithm,
        certificate_signature,
    };
    enum {
        version_number,
        serial_number,
        signature_algorithm_id,
        issuer_name,
        validity,
        subject_name,
        subject_public_key_info,
        // x509v3 extensions?
    };
    enum {
        not_before,
        not_after,
    };
    enum {
        public_key_algorithm,
        subject_public_key,
    };
};

struct asn1_x509_extensions : asn1_base {
    static inline constexpr auto tag = 0xA3;

    std::optional<asn1_sequence> get_extension(bytes_concept oid) {
        for (auto &&seq : get<asn1_sequence>(0, 0)) {
            if (auto s = seq.get<asn1_sequence>(); s.get<asn1_oid>(0) == oid) {
                return asn1_sequence{seq};
            }
        }
        return {};
    }
};

struct x509_storage {
    using clock = std::chrono::system_clock;
    struct key {
        bytes_concept subject;
        bytes_concept keyid;

        auto operator<=>(const key &rhs) const {
            return std::tie(subject, keyid) <=> std::tie(rhs.subject, rhs.keyid);
        }
    };
    struct value {
        bytes_concept data;
        bool trusted{};

        bool is_valid(auto &&now) const {
            if (!trusted) {
                return false;
            }
            asn1 a{data};
            auto validity = a.get<asn1_sequence>(x509::main, x509::certificate, x509::validity);
            auto decode_time = [&](int i) {
                return visit(validity.get<asn1_utc_time,asn1_generalized_time>(i), [](auto &&at) {
                    tm t = at.decode();
                    if (auto t2 = mktime(&t); t2 != -1) {
                        return clock::from_time_t(t2);
                    }
                    throw std::runtime_error{"bad time"};
                });
            };
            return decode_time(0) <= now && now <= decode_time(1);
        }
    };
    std::map<key, value> index;
    std::vector<std::string> storage;

    static auto &trusted_storage() {
        static x509_storage s;
        return s;
    }
    void load_pem(std::string_view data, bool trusted = false) {
        auto delim = "-----BEGIN CERTIFICATE-----"sv;
        auto p = data.find(delim);
        if (p == -1) {
            return;
        }
        data = data.substr(p);
        for (auto &&cert : data | std::views::split(delim)) {
            std::string_view sv(cert);
            if (sv.empty()) {
                continue;
            }
            sv = sv.substr(0, sv.find("---"sv));
            auto decoded = base64::decode<true>(sv);
            std::string_view data = storage.emplace_back(decoded);
            auto &v = add(data);
            v.trusted = trusted;
        }
    }
    void load_der(std::string_view data, bool trusted = false) {
        add(storage.emplace_back(data)).trusted = trusted;
    }
    value &add(auto &&data) {
        asn1 a{data};
        auto subject = a.get<asn1_sequence>(x509::main, x509::certificate, x509::subject_name);
        bytes_concept keyid;
        auto cert = a.get<asn1_sequence>(x509::main, x509::certificate);
        if (auto exts = cert.get_next<asn1_x509_extensions>()) {
            if (auto sk = exts->get_extension(oid::subject_keyid)) {
                auto keystor = sk->get<asn1_octet_string>(0, 1);
                if (keystor.get_tag() == asn1_octet_string::tag) {
                    keyid = keystor.get<asn1_octet_string>(0);
                } else if (keystor.get_tag() == asn1_sequence::tag) {
                    keyid = keystor.get(0, 0);
                }
            }
        }
        if (keyid.empty()) {
            // see 4.2.1.2.  Subject Key Identifier
            auto [data,_] = a.get_raw(x509::main, x509::certificate, x509::subject_public_key_info, x509::subject_public_key);
            if (asn1::get_tag(data) == asn1_bit_string::tag) {
                auto spk = a.get<asn1_bit_string>(x509::main, x509::certificate, x509::subject_public_key_info, x509::subject_public_key);
                auto h = sha1::digest(spk.data.subspan(1));
                keyid = storage.emplace_back(h.begin(), h.end());
            } else if (asn1::get_tag(data) == asn1_null::tag) {
            } else {
                throw std::runtime_error{"not impl"};
            }
        }
        return index.emplace(key{subject,keyid}, data).first->second;
    }
    // TODO: add verify one
    // verify all
    bool verify() {
        return verify(trusted_storage());
    }
    bool verify(auto &&trusted_storage) {
        auto now = clock::now();
        while (1) {
            bool did_verify{};
            for (auto &&[sk,v] : index) {
                if (v.trusted) {
                    continue;
                }
                asn1 current_cert{v.data};
                auto [cert_raw,cert_start] = current_cert.get_raw(x509::main, x509::certificate);
                asn1_sequence cert{cert_raw.subspan(cert_start)}; // tbsCertificate

                auto issuer = cert.get<asn1_sequence>(x509::issuer_name);
                auto subject = cert.get<asn1_sequence>(x509::subject_name);
                auto root_cert = issuer == subject;
                if (root_cert) {
                    if (auto exts = cert.get_next<asn1_x509_extensions>()) {
                        constexpr auto subject_keyid = make_oid<2, 5, 29, 14>();
                        if (auto sk = exts->get_extension(subject_keyid)) {
                            auto keystor = sk->get<asn1_octet_string>(0, 1);
                            bytes_concept keyid;
                            if (keystor.get_tag() == asn1_octet_string::tag) {
                                keyid = keystor.get<asn1_octet_string>(0);
                            } else if (keystor.get_tag() == asn1_sequence::tag) {
                                keyid = keystor.get(0, 0);
                            }
                            bytes_concept issuer_cert_data;
                            auto find = [&](auto &&store) {
                                auto i = store.index.find(key{issuer,keyid});
                                if (i != store.index.end() && i->second.is_valid(now)) {
                                    issuer_cert_data = i->second.data;
                                }
                            };
                            find(trusted_storage);
                            if (!issuer_cert_data.empty()) {
                                v.trusted = true;
                            }
                        }
                    }
                    continue;
                }

                if (auto exts = cert.get_next<asn1_x509_extensions>()) {
                    constexpr auto old_authority_keyid = make_oid<2, 5, 29, 1>();
                    constexpr auto authority_keyid = make_oid<2, 5, 29, 35>(); // old authority_keyid = 1
                    if (auto sk = exts->get_extension(authority_keyid)) {
                        auto keystor = sk->get<asn1_octet_string>(0, 1);
                        bytes_concept keyid;
                        if (keystor.get_tag() == asn1_octet_string::tag) {
                            keyid = keystor.get<asn1_octet_string>(0);
                        } else if (keystor.get_tag() == asn1_sequence::tag) {
                            keyid = keystor.get(0, 0);
                        }
                        bytes_concept issuer_cert_data;
                        auto find = [&](auto &&store) {
                            auto i = store.index.find(key{issuer,keyid});
                            if (i != store.index.end() && i->second.is_valid(now)) {
                                issuer_cert_data = i->second.data;
                            }
                        };
                        find(*this);
                        if (issuer_cert_data.empty()) {
                            find(trusted_storage);
                        }
                        if (issuer_cert_data.empty()) {
                            continue;
                        }

                        did_verify = true;

                        asn1 issuer_cert{issuer_cert_data};

                        auto alg = current_cert.get<asn1_oid>(x509::main, x509::certificate_signature_algorithm, 0);
                        auto sig = current_cert.get<asn1_bit_string>(x509::main, x509::certificate_signature).data.subspan(1);

                        // https://www.rfc-editor.org/rfc/rfc8017 pkcs #1
                        // 1.3.6.1.5.5.7.3.1 serverAuth

                        constexpr auto sha256WithRSAEncryption = make_oid<1, 2, 840, 113549, 1, 1, 11>();
                        constexpr auto sha384WithRSAEncryption = make_oid<1, 2, 840, 113549, 1, 1, 12>();
                        constexpr auto sha512WithRSAEncryption = make_oid<1, 2, 840, 113549, 1, 1, 13>();
                        constexpr auto ecdsa_with_SHA256 = make_oid<1,2,840,10045,4,3,2>();
                        constexpr auto ecdsa_with_SHA384 = make_oid<1,2,840,10045,4,3,3>();
                        constexpr auto ecdsa_with_SHA512 = make_oid<1,2,840,10045,4,3,4>();

                        // rsaEncryption (PKCS #1)
                        //constexpr auto rsaEncryption = make_oid<1, 2, 840, 113549, 1, 1, 1>();
                        //constexpr auto ecPublicKey = make_oid<1, 2, 840, 10045, 2, 1>();
                        //constexpr auto Ed25519 = make_oid<1, 3, 101, 112>();
                        //constexpr auto GOST_R3410_12_256 = make_oid<1, 2, 643, 7, 1, 1, 1, 1>();
                        //constexpr auto GOST_R3410_12_512 = make_oid<1, 2, 643, 7, 1, 1, 1, 2>();
                        //constexpr auto sm2 = make_oid<1, 2, 156, 10197, 1, 301>();

                        auto pubk_info = issuer_cert.get<asn1_sequence>(x509::main, x509::certificate, x509::subject_public_key_info);
                        auto issuer_pubkey = pubk_info.get<asn1_bit_string>(x509::subject_public_key);
                        auto issuer_pubkey_data = issuer_pubkey.data.subspan(1);

                        auto rsa_sha2 = [&]<auto Bits>() {
                            auto pubk = rsa::public_key::load(issuer_pubkey_data);
                            if (pubk.verify<Bits>(cert_raw, sig)) {
                                v.trusted = true;
                                if (v.is_valid(now)) {
                                    return true;
                                }
                            }
                            return false;
                        };
                        auto ecdsa_sha2 = [&]<auto Bits>() {
                            constexpr auto prime256v1 = make_oid<1,2,840,10045,3,1,7>();
                            constexpr auto secp384r1 = make_oid<1,3,132,0,34>();
                            auto curve = pubk_info.get<asn1_oid>(0, 1);

                            auto r = asn1_sequence{sig}.get<asn1_integer>(0,0).data;
                            auto s = asn1_sequence{sig}.get<asn1_integer>(0,1).data;

                            auto h = sha2<Bits>::digest(cert_raw);

                            auto f = [&]<typename Curve>(Curve **) {
                                if (Curve::verify(h, issuer_pubkey_data, r, s)) {
                                    v.trusted = true;
                                    if (v.is_valid(now)) {
                                        return true;
                                    }
                                }
                                return false;
                            };

                            if (curve == prime256v1) {
                                if (!f((ec::secp256r1**)nullptr)) {
                                    return false;
                                }
                            } else if (curve == secp384r1) {
                                if (!f((ec::secp384r1**)nullptr)) {
                                    return false;
                                }
                            } else {
                                string s = curve;
                                throw std::runtime_error{"curve is not impl: " + s};
                            }
                            return true;
                        };

                        if (alg == sha256WithRSAEncryption) {
                            if (!rsa_sha2.template operator()<256>()) {
                                return false;
                            }
                        } else if (alg == sha384WithRSAEncryption) {
                            if (!rsa_sha2.template operator()<384>()) {
                                return false;
                            }
                        } else if (alg == sha512WithRSAEncryption) {
                            if (!rsa_sha2.template operator()<512>()) {
                                return false;
                            }
                        } else if (alg == ecdsa_with_SHA256) {
                            if (!ecdsa_sha2.template operator()<256>()) {
                                return false;
                            }
                        } else if (alg == ecdsa_with_SHA384) {
                            if (!ecdsa_sha2.template operator()<384>()) {
                                return false;
                            }
                        } else if (alg == ecdsa_with_SHA512) {
                            if (!ecdsa_sha2.template operator()<512>()) {
                                return false;
                            }
                        } else if (alg == oid::gost2012Signature256) {
                            auto param_set = pubk_info.get<asn1_oid>(0, 1, 0);

                            auto f = [&](auto &&c) {
                                auto pubk = asn1{issuer_pubkey_data}.get<asn1_octet_string>().data;
                                auto h = streebog<256>::digest(cert_raw);
                                std::vector<u8> h2{std::from_range, h | std::views::reverse};
                                if (c.verify(h2, pubk, sig)) {
                                    v.trusted = true;
                                    if (v.is_valid(now)) {
                                        return true;
                                    }
                                }
                                return false;
                            };

                            if (param_set == oid::gost_r34102001_param_set_a) {
                                if (!f(ec::gost::r34102001::ec256a{})) {
                                    return false;
                                }
                            } else {
                                string s = param_set;
                                throw std::runtime_error{"param set is not impl: " + s};
                            }
                        } else if (alg == oid::gost2012Signature512) {
                            throw std::runtime_error{"gost2012Signature512 is not impl"};
                        } else {
                            string s = alg;
                            std::cerr << "unknown x509::signature_algorithm: " << s << "\n";
                            throw std::runtime_error{"unknown x509::signature_algorithm"};
                        }
                    } else if (auto sk = exts->get_extension(old_authority_keyid)) {
                        throw std::runtime_error{"not impl"}; // old_authority_keyid?
                    } else {
                        throw std::runtime_error{"not impl"};
                    }
                }
            }
            if (!did_verify) {
                return std::ranges::all_of(index | std::views::values, [](auto &&v){return v.trusted;});
            }
        }
    }
};

} // namespace crypto
