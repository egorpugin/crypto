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
            // RSA_PKCS1_PADDING
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
            constexpr auto RSA_PKCS1_PADDING_SIZE = 11;
            if (emlen < tlen + RSA_PKCS1_PADDING_SIZE) {
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
            // RSA_PKCS1_PSS_PADDING + salt size = hash size
            auto pkcs1_mgf1 = [](auto &&p, auto &&sz, auto &&seed) {
                for (uint32_t i = 0, outlen = 0; outlen < sz; ++i) {
                    sha2<Bits> h;
                    h.update(seed);
                    auto counter = std::byteswap(i);
                    h.update((const uint8_t *)&counter, 4);
                    auto r = h.digest();
                    auto to_copy = std::min<int>(sz - outlen, r.size());
                    memcpy(p + outlen, r.data(), to_copy);
                    outlen += to_copy;
                }
            };

            auto mhash = sha2<Bits>::digest(m);
            auto emlen = pkey.n.size();
            std::string em(emlen, 0);
            auto embits = (emlen * 8 - 1) & 0x7;
            auto EM = em.data();
            if (embits == 0) {
                *EM++ = 0;
                --emlen;
            }
            if (emlen < mhash.size() + 2) {
                throw std::runtime_error{"encoding error"};
            }
            std::string salt(mhash.size(), 0);
            get_random_secure_bytes(salt);

            auto masked_db_len = emlen - mhash.size() - 1;
            auto H = EM + masked_db_len;
            sha2<Bits> hh;
            hh.update((const uint8_t *)em.data(), 8);
            hh.update(mhash);
            hh.update(salt);
            auto h2 = hh.digest();
            memcpy(H, h2.data(), h2.size());

            pkcs1_mgf1(EM, masked_db_len, h2);

            auto p = EM;
            p += emlen - mhash.size() - salt.size() - 2;
            *p++ ^= 0x01;
            for (int i = 0; i < mhash.size(); ++i) {
                *p++ ^= salt[i];
            }
            if (embits) {
                EM[0] &= 0xFF >> (8 - embits);
            }
            EM[emlen - 1] = 0xbc;

            //
            auto h = bytes_to_bigint(em);
            h = h.powm(pkey.d, pkey.n);
            return h.to_string();
        }
    };

    using b64 = base64url<false>;
    //using json = json_raw<true, true>;
    using json = json;
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
