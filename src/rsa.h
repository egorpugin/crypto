// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "base64.h"
#include "bigint.h"
#include "sha2.h"

namespace crypto::rsa {

enum {unk, pkcs1, pkcs8, pkcs1_pubkey, pkcs8_pubkey};

auto prepare_string(auto &s) {
    // see <openssl/pem.h> for possible BEGIN markers
    auto type = s.contains("BEGIN PRIVATE KEY") ? pkcs8 : unk;
    type = s.contains("BEGIN RSA PRIVATE KEY") ? pkcs1 : type;
    type = s.contains("BEGIN PUBLIC KEY") ? pkcs8_pubkey : type;
    type = s.contains("BEGIN RSA PUBLIC KEY") ? pkcs1_pubkey : type;
    if (s.starts_with("-"sv)) {
        s = s.substr(s.find('\n') + 1);
    }
    if (auto p = s.find('-'); p != -1) {
        s = s.substr(0, p);
    }
    replace_all(s, "\n", "");
    replace_all(s, "\r", "");
    return std::tuple{base64::decode(s),type};
}

struct private_key {
    bigint n;
    bigint e;
    bigint d;

    bigint encrypt(const bigint &m) {
        return m.powm(d, n);
    }
    bigint decrypt(const bigint &m) {
        return m.powm(e, n);
    }
    bigint decrypt_from_public(const bigint &m) {
        return encrypt(m);
    }

    static auto load_from_string_container(std::string s) {
        auto [raw,type] = prepare_string(s);
        asn1 a{raw};

        private_key pk;
        auto get = [&](auto &&pkey, auto...args){
            return bytes_to_bigint(pkey.template get<asn1_integer>(args...).data);
        };
        asn1_sequence pkey;
        if (type == pkcs8) {
            auto pka = a.get<asn1_oid>(pkcs8::private_key::main,pkcs8::private_key::algorithm,pkcs8::private_key::algorithm_oid);

            //rsaEncryption (PKCS #1)
            auto rsaEncryption = make_oid<1,2,840,113549,1,1,1>();
            if (pka != rsaEncryption) {
                throw std::runtime_error{"unknown pkcs8::private_key_algorithm"};
            }

            pkey = a.get<asn1_sequence>(pkcs8::private_key::main,pkcs8::private_key::privatekey,rsa_private_key::main);
        } else if (type == pkcs1) {
            pkey = a.get<asn1_sequence>(pkcs8::private_key::main);
        } else {
            throw;
        }
        pk.n = get(pkey, rsa_private_key::modulus);
        pk.e = get(pkey, rsa_private_key::public_exponent);
        pk.d = get(pkey, rsa_private_key::private_exponent);
        return pk;
    }

    template <auto Bits>
    static consteval auto sha_id() {
        if (Bits == 256) return 1;
        if (Bits == 384) return 2;
        if (Bits == 512) return 3;
        throw;
    }
    template <auto Bits>
    static auto op(auto &&m, auto &&modulus) {
        // rsassa_pkcs1_v1_5_sha2
        // RSA_PKCS1
        // RSA_PKCS1_PADDING
        auto mhash = sha2<Bits>::digest(m);
        auto t = asn1_sequence::make(
            asn1_sequence::make(
                asn1_oid::make(make_oid<2,16,840,1,101,3,4,2,sha_id<Bits>()>()),
                asn1_null::make()
            ),
            asn1_octet_string::make(mhash)
        );
        auto tlen = t.size();
        auto emlen = modulus.size();
        constexpr auto RSA_PKCS1_PADDING_SIZE = 11;
        if (emlen < tlen + RSA_PKCS1_PADDING_SIZE) {
            throw std::runtime_error{"intended encoded message length too short"};
        }
        std::string ps(emlen - tlen - 3, 0xff);
        std::string em(emlen, 0);
        em[1] = 0x01;
        memcpy(em.data() + 2, ps.data(), ps.size());
        memcpy(em.data() + 2 + ps.size() + 1, t.data(), t.size());
        return em;
    }
    template <auto Bits>
    auto sign(auto &&m) {
        auto em = op<Bits>(m, n);
        auto h = bytes_to_bigint(em);
        h = h.powm(d, n);
        return h.to_string();
    }
};
struct public_key {
    bigint n;
    bigint e;

    bigint encrypt(const bigint &m) {
        return m.powm(e, n);
    }
    bigint decrypt(const bigint &m) {
        return m.powm(e, n);
    }

    static auto load(asn1 asn) {
        auto get = [&](auto &&pkey, auto...args){
            return bytes_to_bigint(pkey.template get<asn1_integer>(args...).data);
        };
        public_key pubk;
        auto pubkey = asn.get<asn1_sequence>(pkcs8::private_key::main);
        pubk.n = get(pubkey, pkcs1::public_key::modulus);
        pubk.e = get(pubkey, pkcs1::public_key::public_exponent);
        return pubk;
    }
    static auto load_from_string_container(std::string s) {
        auto [raw,type] = prepare_string(s);
        asn1 a{raw};

        auto get = [&](auto &&pkey, auto...args){
            return bytes_to_bigint(pkey.template get<asn1_integer>(args...).data);
        };
        asn1_sequence pubkey;
        if (type == pkcs8_pubkey) {
            auto pka = a.get<asn1_oid>(pkcs8::public_key::main,pkcs8::public_key::algorithm,pkcs8::public_key::algorithm_oid);

            //rsaEncryption (PKCS #1)
            auto rsaEncryption = make_oid<1,2,840,113549,1,1,1>();
            if (pka != rsaEncryption) {
                throw std::runtime_error{"unknown pkcs8::public_key_algorithm"};
            }

            pubkey = a.get<asn1_bit_string>(pkcs8::public_key::main,pkcs8::public_key::publickey);
            pubkey = pubkey.get<asn1_sequence>(pkcs8::private_key::main);
        } else if (type == pkcs1_pubkey) {
            pubkey = a.get<asn1_sequence>(pkcs8::private_key::main);
        } else {
            throw;
        }
        public_key pubk;
        pubk.n = get(pubkey, pkcs1::public_key::modulus);
        pubk.e = get(pubkey, pkcs1::public_key::public_exponent);
        return pubk;
    }

    template <auto Bits>
    bool verify(auto &&message, auto &&signature) {
        auto em = private_key::op<Bits>(message, n);
        auto h = bytes_to_bigint(signature);
        h = h.powm(e, n);
        return bytes_concept{em} == bytes_concept{h.to_string(n.size())};
    }
};

}
