// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "asn1.h"
#include "base64.h"
#include "hmac.h"
#include "json.h"
#include "random.h"
#include "rsa.h"

#include <algorithm>
#include <ranges>

namespace crypto {

struct jwt {
    template <auto Bits>
    struct hmac_sha2 {
        static auto name() {
            return std::format("HS{}", Bits);
        }
        auto sign(auto &&msg, auto &&secret) {
            return hmac<sha2<Bits>>(secret,msg);
        }
        auto verify(auto &&msg, auto &&signature, auto &&secret) {
            return bytes_concept{sign(msg, secret)} == bytes_concept{signature};
        }
    };
    template <auto Bits>
    struct rsassa_pkcs1_v1_5_sha2 {
        static auto name() {
            return std::format("RS{}", Bits);
        }
        auto sign(auto &&m, auto &&pkey) {
            return pkey.template sign_pkcs1<Bits>(m);
        }
        bool verify(auto &&m, auto &&signature, auto &&pubkey) {
            return pubkey.template verify_pkcs1<Bits>(m, signature);
        }
    };
    template <auto Bits>
    struct pkcs1_pss_mgf1_sha2 {
        static auto name() {
            return std::format("PS{}", Bits);
        }
        auto sign(auto &&m, auto &&pkey) {
            return pkey.template sign_pss_mgf1<Bits>(m);
        }
        bool verify(auto &&m, auto &&signature, auto &&pubkey) {
            return pubkey.template verify_pss_mgf1<Bits>(m, signature);
        }
    };

    using b64 = base64url<>;
    //using json_type = json_raw<true, true>;
    using json_type = json;
    template <auto Bits> using hs = hmac_sha2<Bits>;
    template <auto Bits> using rs = rsassa_pkcs1_v1_5_sha2<Bits>;
    template <auto Bits> using ps = pkcs1_pss_mgf1_sha2<Bits>;

    json_type header;
    json_type payload;
    std::string signature;

    jwt() {
        header["typ"] = "JWT";
    }
    jwt(const json_type &payload) : payload{payload} {
        header["typ"] = "JWT";
    }
    jwt(std::string_view s) {
        auto sp = std::views::split(s, '.');
        auto it = std::begin(sp);
        header = json::parse(b64::decode(std::string_view(*it++)));
        payload = json::parse(b64::decode(std::string_view(*it++)));
        signature = b64::decode(std::string_view(*it++));
    }

    std::string sign(auto h, auto &&...args) {
        make_header(h.name());
        auto sig = h.sign(concat(), args...);
        signature = std::string(sig.begin(), sig.end());
        return *this;
    }
    bool verify(auto h, auto &&...args) {
        return h.verify(concat(), signature, args...);
    }

    //auto operator<=>(const jwt &) const = default;
    bool operator==(const jwt &rhs) const {return std::tie(header,payload,signature) == std::tie(rhs.header,rhs.payload,rhs.signature);}
    operator std::string() const {
        return std::format("{}.{}.{}", b64::encode(header.dump()), b64::encode(payload.dump()), b64::encode(signature));
    }

private:
    void make_header(auto &&type) {
        header["alg"] = type;
    }
    std::string concat() {
        auto header_encoded = b64::encode(header.dump());
        auto payload_encoded = b64::encode(payload.dump());
        auto concat = header_encoded + "." + payload_encoded;
        return concat;
    }
};

auto operator""_jwt(const char *s, size_t len) {
    return jwt{std::string_view{s,len}};
}

}
