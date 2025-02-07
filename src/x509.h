// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "asn1.h"
#include "base64.h"
#include "mmap.h"
#include "rsa.h"
#include "sha1.h"

#include "ec.h"
#include "streebog.h"

namespace crypto {

// rfc5280
struct x509 {
    enum {
        main, // main object
    };
    enum {
        certificate,
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
        constexpr auto subject_keyid = make_oid<2, 5, 29, 14>();
        auto cert = a.get<asn1_sequence>(x509::main, x509::certificate);
        if (auto exts = cert.get_next<asn1_x509_extensions>();
            auto sk = exts->get_extension(subject_keyid)) {
            auto keystor = sk->get<asn1_octet_string>(0, 1);
            if (keystor.get_tag() == asn1_octet_string::tag) {
                keyid = keystor.get<asn1_octet_string>(0);
            } else if (keystor.get_tag() == asn1_sequence::tag) {
                keyid = keystor.get(0, 0);
            }
        }
        if (keyid.empty()) {
            // see 4.2.1.2.  Subject Key Identifier
            auto spk = a.get<asn1_bit_string>(x509::main, x509::certificate, x509::subject_public_key_info, x509::subject_public_key);
            auto h = sha1::digest(spk.data.subspan(1));
            keyid = storage.emplace_back(h.begin(), h.end());
        }
        return index.emplace(key{subject,keyid}, data).first->second;
    }
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
                did_verify = true;
                asn1 current_cert{v.data};
                auto issuer = current_cert.get<asn1_sequence>(x509::main, x509::certificate, x509::issuer_name);
                auto [cert_raw,cert_start] = current_cert.get_raw(x509::main, x509::certificate);
                asn1_sequence cert{cert_raw.subspan(cert_start)};
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
                            return false; // cannot find parent (issuer)
                        }

                        asn1 issuer_cert{issuer_cert_data};

                        auto alg = current_cert.get<asn1_oid>(x509::main, x509::certificate_signature_algorithm, 0);
                        auto sig = current_cert.get<asn1_bit_string>(x509::main, x509::certificate_signature).data.subspan(1);
                        constexpr auto sha256WithRSAEncryption = make_oid<1, 2, 840, 113549, 1, 1, 11>();
                        constexpr auto gost2012Signature256 = make_oid<1,2,643,7,1,1,3,2>();
                        constexpr auto gost2012Signature512 = make_oid<1,2,643,7,1,1,3,3>();

                        auto pubk_info = issuer_cert.get<asn1_sequence>(x509::main, x509::certificate, x509::subject_public_key_info);
                        auto issuer_pubkey = pubk_info.get<asn1_bit_string>(x509::subject_public_key).data.subspan(1);

                        if (alg == sha256WithRSAEncryption) {
                            auto pubk = rsa::public_key::load(issuer_pubkey);

                            if (pubk.verify<256>(cert_raw, sig)) {
                                v.trusted = true;
                                if (!v.is_valid(now)) {
                                    return false;
                                }
                            } else {
                                return false;
                            }
                        } else if (alg == gost2012Signature256) {
                            ec::gost::r34102012::ec256a c;
                            auto r = issuer_pubkey.subspan(0, sig.size() / 2);
                            auto s = issuer_pubkey.subspan(sig.size() / 2);
                            if (c.verify(streebog<256>::digest(cert_raw), issuer_pubkey, r, s)) {
                                v.trusted = true;
                                if (!v.is_valid(now)) {
                                    return false;
                                }
                            } else {
                                return false;
                            }
                        } else if (alg == gost2012Signature512) {
                            throw std::runtime_error{"gost2012Signature512 not impl"};
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
                return true;
            }
        }
    }
};

} // namespace crypto
