// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "x509.h"
#include "oid.h"

namespace crypto {

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
};

struct public_key_infrastructure {
    path root;

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
    static auto make_pem(auto &&name, auto &&data) {
        auto b64 = base64::encode(data);
        for (int i = 64; i < b64.size(); i += 64) {
            b64.insert(b64.begin() + i++, '\n');
        }
        return std::format("-----BEGIN {}-----\n{}\n-----END {}-----\n", name, b64, name);
    }
    auto make_ca(auto &&name) {
        auto version = asn1_sequence::make(asn1_integer::make(3 - 1)); // ver 3
        version[0] = 0xA0;
        auto serial_number = asn1_integer::make(1);
        auto issuer = make_subject({.common_name = "localhost", .country = "RU"});
        auto subject = issuer;
        auto validity = asn1_sequence::make(
            asn1_generalized_time::make(std::chrono::system_clock::now()),
            asn1_generalized_time::make(std::chrono::system_clock::now() + std::chrono::years{1})
        );

        ec::gost::r34102001::ec256a c;
        c.private_key();
        auto pub = c.public_key();

        auto signature = asn1_sequence::make(asn1_oid::make(oid::gost2012Signature256));
        auto public_key_bits = asn1_octet_string::make(bytes_concept{&pub,sizeof(pub)});
        auto public_key = asn1_sequence::make(
            asn1_sequence::make(
                asn1_oid::make(oid::gost2012PublicKey256),
                asn1_sequence::make(
                    asn1_oid::make(oid::gost_r34102001_param_set_a),
                    asn1_oid::make(oid::gost2012Digest256)
                )
            ),
            asn1_bit_string::make(public_key_bits)
        );

        auto exts = asn1_sequence::make(
            asn1_sequence::make(
                asn1_oid::make(oid::subject_keyid),
                asn1_octet_string::make(asn1_octet_string::make(sha1::digest(public_key_bits)))
            )
        );
        // asn1_x509_extensions
        auto x509_exts = asn1_sequence::make(exts);
        x509_exts[0] = 0xA3;

        auto tbs_certificate = asn1_sequence::make(version
            , serial_number
            , signature
            , issuer
            , validity
            , subject
            , public_key
            , x509_exts
        );

        auto h = streebog<256>::digest(tbs_certificate);
        std::vector<u8> h2{std::from_range, h | std::views::reverse};
        auto rsig = c.sign(h2);

        auto sig = asn1_bit_string::make(rsig);

        auto cert = asn1_sequence::make(tbs_certificate, signature, sig);


        auto fn = root / name;
        {
            mmap_file<> m{path{fn} += ".crt"};
            auto t = make_pem("CERTIFICATE"sv, cert);
            m.alloc_raw(t.size());
            memcpy(m.data(), t.data(), t.size());
        }
        // pk
        {
            auto oid = asn1_sequence::make(
                asn1_oid::make(oid::gost_r34102001_param_set_a)
            );
            oid[0] = 0xA0;
            auto pubk = asn1_sequence::make(
                //public_key_bits,
                //asn1_bit_string::make(public_key_bits),
                asn1_bit_string::make(bytes_concept{&pub,sizeof(pub)})
            );
            pubk[0] = 0xA1;
            auto pk = asn1_sequence::make(
                asn1_integer::make(1),
                asn1_octet_string::make(c.private_key_),
                oid,
                pubk
            );

            mmap_file<> m{path{fn} += ".key"};
            auto t = make_pem("EC PRIVATE KEY"sv, pk);
            m.alloc_raw(t.size());
            memcpy(m.data(), t.data(), t.size());
        }


    }
};

auto make_certificate() {
}

}
