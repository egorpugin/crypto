// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "x509.h"
#include "oid.h"
#include "streebog.h"

namespace crypto {

auto make_pem(auto &&name, auto &&data) {
    auto b64 = base64::encode(data);
    for (int i = 64; i < b64.size(); i += 64) {
        b64.insert(b64.begin() + i++, '\n');
    }
    return std::format("-----BEGIN {}-----\n{}\n-----END {}-----\n", name, b64, name);
}

struct certificate_authority {
    auto issue_certificate() {
    }
    // sign certificate
};

struct subject {
    std::string common_name;
    std::string organization_unit;
    std::string organization;
    std::string locality;
    std::string state;
    std::string country;

    auto operator<=>(const subject &) const = default;
};

template <typename Curve, typename Settings>
struct gost_sig_base {
    Curve c;
    std::string signature;
    std::string public_key;
    std::string keyid;

    gost_sig_base() {
        c.private_key();
        auto pub = c.public_key();

        signature = asn1_sequence::make(asn1_oid::make(Settings::sig_type));
        auto public_key_bits = asn1_octet_string::make(bytes_concept{&pub,sizeof(pub)});
        public_key = asn1_sequence::make(
            asn1_sequence::make(
                asn1_oid::make(Settings::pubk_type),
                asn1_sequence::make(
                    asn1_oid::make(Settings::curve_oid),
                    asn1_oid::make(Settings::digest_type)
                )
            ),
            asn1_bit_string::make(public_key_bits)
        );
        keyid = asn1_octet_string::make(asn1_octet_string::make(sha1::digest(public_key_bits)));
    }
    auto private_key() {
        auto pub = c.public_key();

        auto oid = asn1_sequence::make(
            asn1_oid::make(Settings::curve_oid)
        );
        oid[0] = 0xA0;
        auto pubk = asn1_sequence::make(
            asn1_bit_string::make(bytes_concept{&pub,sizeof(pub)})
        );
        pubk[0] = 0xA1;
        auto pk = asn1_sequence::make(
            asn1_integer::make(1),
            asn1_octet_string::make(c.private_key_),
            oid,
            pubk
        );
        return pk;
    }
    auto private_key_pem() {
        return make_pem("EC PRIVATE KEY"sv, private_key());
    }
    auto sign(auto &&tbs_certificate) {
        auto h = Settings::hash_type::digest(tbs_certificate);
        std::vector<u8> h2{std::from_range, h | std::views::reverse};
        auto rsig = c.sign(h2);
        auto sig = asn1_bit_string::make(rsig);
        auto cert = asn1_sequence::make(tbs_certificate, signature, sig);
        return cert;
    }
};
template <typename Curve, auto CurveOid, typename Hash>
struct gost_sig;
template <typename Curve, auto CurveOid>
struct gost_sig<Curve, CurveOid, streebog<256>> : gost_sig_base<Curve, gost_sig<Curve, CurveOid, streebog<256>>> {
    static inline constexpr auto sig_type = oid::gost2012Signature256;
    static inline constexpr auto pubk_type = oid::gost2012PublicKey256;
    static inline constexpr auto digest_type = oid::gost2012Digest256;
    using hash_type = streebog<256>;
    using curve_type = Curve;
    static inline constexpr auto curve_oid = CurveOid;
    static_assert(Curve::point_size_bytes * 8 == 256);
};
template <typename Curve, auto CurveOid>
struct gost_sig<Curve, CurveOid, streebog<512>> : gost_sig_base<Curve, gost_sig<Curve, CurveOid, streebog<512>>> {
    static inline constexpr auto sig_type = oid::gost2012Signature512;
    static inline constexpr auto pubk_type = oid::gost2012PublicKey512;
    static inline constexpr auto digest_type = oid::gost2012Digest512;
    using hash_type = streebog<512>;
    using curve_type = Curve;
    static inline constexpr auto curve_oid = CurveOid;
    static_assert(Curve::point_size_bytes * 8 == 512);
};

struct cert_request {
    using clock = std::chrono::system_clock;
    subject issuer;
    subject subject;
    clock::time_point not_before{clock::now()};
    clock::time_point not_after{not_before + std::chrono::years{1}};

    bool is_ca() const {return issuer == subject;}
};

struct public_key_infrastructure {
    struct key {
        std::string subject;
        std::string keyid;

        auto operator<=>(const key &rhs) const {
            return std::tie(subject, keyid) <=> std::tie(rhs.subject, rhs.keyid);
        }
    };

    path root;
    int serial_number{1};
    std::map<key, std::string> certs;

    static auto make_subject(const subject &s) {
        constexpr auto c = make_oid<2,5,4,6>();
        constexpr auto st = make_oid<2,5,4,8>();
        constexpr auto l = make_oid<2,5,4,7>();
        constexpr auto o = make_oid<2,5,4,10>();
        constexpr auto ou = make_oid<2,5,4,11>();
        constexpr auto cn = make_oid<2,5,4,3>();

        std::string str;
        auto f = [&](auto &&s, auto &&oid) {
            if (s.empty()) {
                return;
            }
            str += asn1_set::make(
                asn1_sequence::make(
                    asn1_oid::make(oid), asn1_utf8_string::make(s)
                )
            );
        };
        f(s.common_name, cn);
        f(s.organization_unit, ou);
        f(s.organization, o);
        f(s.locality, l);
        f(s.state, st);
        f(s.country, c);

        return asn1_sequence::make(str);
    }
    auto make_cert(auto &&name, auto &&issuer_sig, auto &&subject_sig, auto &&cert_request) {
        auto version = asn1_sequence::make(asn1_integer::make(3 - 1)); // ver 3
        version[0] = 0xA0;
        auto serial_number = asn1_integer::make(this->serial_number++);
        auto issuer = make_subject(cert_request.issuer);
        auto subject = make_subject(cert_request.subject);
        auto validity = asn1_sequence::make(
            asn1_generalized_time::make(std::chrono::system_clock::now()),
            asn1_generalized_time::make(std::chrono::system_clock::now() + std::chrono::years{1})
        );

        auto exts_string = asn1_sequence::make(
            asn1_oid::make(oid::subject_keyid),
            subject_sig.keyid
        );
        if (!cert_request.is_ca()) {
            auto a = asn1_sequence::make(issuer_sig.keyid.substr(4));
            a[0] = 0x80;
            exts_string += asn1_sequence::make(
                asn1_oid::make(oid::authority_keyid),
                asn1_octet_string::make(asn1_sequence::make(a))
            );
        }
        auto exts = asn1_sequence::make(exts_string);
        // asn1_x509_extensions
        auto x509_exts = asn1_sequence::make(exts);
        x509_exts[0] = 0xA3;

        auto tbs_certificate = asn1_sequence::make(version
            , serial_number
            , issuer_sig.signature
            , issuer
            , validity
            , subject
            , subject_sig.public_key
            , x509_exts
        );
        auto cert = issuer_sig.sign(tbs_certificate);

        auto fn = root / name;
        {
            mmap_file<> m{path{fn} += ".crt"};
            auto t = make_pem("CERTIFICATE"sv, cert);
            m.alloc_raw(t.size());
            memcpy(m.data(), t.data(), t.size());
        }
        // pk
        {
            mmap_file<> m{path{fn} += ".key"};
            auto t = subject_sig.private_key_pem();
            m.alloc_raw(t.size());
            memcpy(m.data(), t.data(), t.size());
        }

        auto [it,_] = certs.emplace(key{subject,subject_sig.keyid},cert);
        return std::tuple{it->first, cert_request.subject};
    }
    auto make_cert(auto &&name, auto &&issuer_subj, auto &&issuer_sig, auto &&subject_sig, auto cert_request) {
        cert_request.issuer = issuer_subj;
        return make_cert(name, issuer_sig, subject_sig, cert_request);
    }
    auto make_ca(auto &&name, auto &&sig, auto cert_request) {
        cert_request.issuer = cert_request.subject;
        return make_cert(name, sig, sig, cert_request);
    }
};

auto make_certificate() {
}

}
