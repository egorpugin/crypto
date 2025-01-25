#pragma once

#include "asn1.h"
#include "base64.h"
#include "hmac.h"
#include "json.h"
#include "random.h"

#include <algorithm>

namespace crypto {

struct jwt {
    template <auto Bits>
    struct hmac_sha2 {
        static auto name() {
            return std::format("HS{}", Bits);
        }
        auto operator()(auto &&msg, auto &&secret) {
            return hmac<sha2<Bits>>(secret,msg);
        }
    };
    template <auto Bits>
    struct rsassa_pkcs1_v1_5_sha2 {
        static auto name() {
            return std::format("RS{}", Bits);
        }
        static consteval auto sha_id() {
            if (Bits == 256) return 1;
            if (Bits == 384) return 2;
            if (Bits == 512) return 3;
            throw;
        }
        auto operator()(auto &&m, auto &&pkey) {
            // RSA_PKCS1
            auto mhash = sha2<Bits>::digest(m);
            auto t = asn1_sequence::make(
                asn1_sequence::make(
                    asn1_oid::make(make_oid<2,16,840,1,101,3,4,2,sha_id()>()),
                    asn1_null::make()
                ),
                asn1_octet_string::make(mhash)
            );
            auto tlen = t.size();
            auto emlen = pkey.n.size();
            if (emlen < tlen + 11) {
                throw std::runtime_error{"intended encoded message length too short"};
            }
            std::string ps(emlen - tlen - 3, 0xff);
            std::string em(emlen, 0);
            em[1] = 0x01;
            memcpy(em.data() + 2, ps.data(), ps.size());
            memcpy(em.data() + 2 + ps.size() + 1, t.data(), t.size());
            auto h = bytes_to_bigint(em);
            h = h.powm(pkey.d, pkey.n);
            return h.to_string();
        }
    };
    template <auto Bits>
    struct pkcs1_pss_mgf1_sha2 {
        static auto name() {
            return std::format("PS{}", Bits);
        }
        auto operator()(auto &&m, auto &&pkey) {
            // PKCS1_PSS_mgf1
            auto mgf1 = [](auto &&m, auto &&outsz) {
                auto h = sha2<Bits>::digest(m);

                auto sha256 = make_oid<2,16,840,1,101,3,4,2,6>();
                return h;
            };

            auto mhash = sha2<Bits>::digest(m);
            std::string salt(mhash.size(), 0);
            get_random_secure_bytes(salt);
            auto embits = mhash.size() * 8 + salt.size() * 8 + 9;
            auto emlen = (embits + 8 - 1) / 8;
            if (emlen < mhash.size() + salt.size() + 2) {
                throw std::runtime_error{"encoding error"};
            }
            std::string m2(8 + mhash.size() + salt.size(), 0);
            memcpy(m2.data() + 8, mhash.data(), mhash.size());
            memcpy(m2.data() + 8 + mhash.size(), salt.data(), salt.size());
            auto h = sha2<Bits>::digest(m2);
            std::string ps(emlen - salt.size() - h.size() - 2, 0);
            auto db = ps + '\x01' + salt;
            auto dbsz = db.size();
            auto dbmask = mgf1(h, dbsz);
            for (int i = 0; i < dbsz; ++i) {
                db[i] ^= dbmask[i];
            }
            db[0] &= 1;
            std::string em(dbsz + h.size() + 1, 0);
            memcpy(em.data(), db.data(), dbsz);
            memcpy(em.data() + dbsz, h.data(), h.size());
            em[dbsz + h.size()] = '\xbc';
            return em;
        }
    };

    using b64 = base64url<false>;
    template <auto Bits> using hs = hmac_sha2<Bits>;
    template <auto Bits> using rs = rsassa_pkcs1_v1_5_sha2<Bits>;
    template <auto Bits> using ps = pkcs1_pss_mgf1_sha2<Bits>;

    json header;
    json payload;
    std::string signature;

    jwt(std::string_view s) {
        auto sp = std::views::split(s, '.');
        auto it = std::begin(sp);
        header = json::parse(b64::decode(std::string_view(*it++)));
        payload = json::parse(b64::decode(std::string_view(*it++)));
        signature = b64::decode(std::string_view(*it++));
    }
    template <auto Bits>
    jwt(hmac_sha2<Bits> h, auto &&payload, auto &&secret) {
        make_header(h.name());
        this->payload = payload;
        make_sig([&](auto &&msg){return h(msg, secret);});
    }
    jwt(rs<256> h, auto &&payload, auto &&private_key) {
        make_header(h.name());
        this->payload = payload;
        make_sig([&](auto &&msg){return h(msg, private_key);});
    }
    jwt(ps<256> h, auto &&payload, auto &&private_key) {
        make_header(h.name());
        this->payload = payload;
        make_sig([&](auto &&msg){return h(msg, private_key);});
    }

    auto operator<=>(const jwt &) const = default;
    operator std::string() const {
        return std::format("{}.{}.{}", b64::encode(header.dump()), b64::encode(payload.dump()), b64::encode(signature));
    }

private:
    void make_header(auto &&type) {
        header = json::parse(std::format(R"({{"alg":"{}","typ":"JWT"}})", type));
    }
    void make_sig(auto &&fsig) {
        auto header_encoded = b64::encode(header.dump());
        auto payload_encoded = b64::encode(payload.dump());
        auto concat = header_encoded + "." + payload_encoded;
        auto sig = fsig(concat);
        signature = std::string(sig.begin(), sig.end());
    }
};

auto operator""_jwt(const char *s, size_t len) {
    return jwt{std::string_view{s,len}};
}

}
