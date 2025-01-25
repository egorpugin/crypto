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
        static consteval auto sha_id() {
            if (Bits == 256) return 1;
            if (Bits == 384) return 2;
            if (Bits == 512) return 3;
            throw;
        }
        auto sign(auto &&m, auto &&pkey) {
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
        bool verify(auto &&m, auto &&signature, auto &&pkey) {
            return bytes_concept{sign(m, pkey)} == bytes_concept{signature};
        }
    };
    template <auto Bits>
    struct pkcs1_pss_mgf1_sha2 {
        static inline constexpr unsigned char zeroes[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
        static auto name() {
            return std::format("PS{}", Bits);
        }
        static auto pkcs1_mgf1(auto &&p, auto &&sz, auto &&seed) {
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
        }
        auto sign(auto &&m, auto &&pkey) {
            // PKCS1_PSS_mgf1
            // RSA_PKCS1_PSS_PADDING + salt size = hash size

            auto mhash = sha2<Bits>::digest(m);
            auto hlen = mhash.size();
            auto slen = hlen; // same size
            auto emlen = pkey.n.size();
            std::string em(emlen, 0);
            auto embits = (emlen * 8 - 1) & 0x7;
            auto EM = em.data();
            if (embits == 0) {
                *EM++ = 0;
                --emlen;
            }
            if (emlen < hlen + slen + 2) {
                throw std::runtime_error{"encoding error"};
            }
            std::string salt(hlen, 0);
            get_random_secure_bytes(salt);

            auto masked_db_len = emlen - hlen - 1;
            auto H = EM + masked_db_len;
            sha2<Bits> hh;
            hh.update(zeroes);
            hh.update(mhash);
            hh.update(salt);
            auto mseed = hh.digest();
            memcpy(H, mseed.data(), mseed.size());

            pkcs1_mgf1(EM, masked_db_len, mseed);

            auto p = EM;
            p += emlen - hlen - slen - 2;
            *p++ ^= 0x01;
            for (int i = 0; i < slen; ++i) {
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
        bool verify(auto &&m, auto &&signature, auto &&pkey) {
            auto h = bytes_to_bigint(signature);
            h = h.powm(pkey.e, pkey.n);
            auto em = h.to_string();

            auto mhash = sha2<Bits>::digest(m);
            auto hlen = mhash.size();
            auto slen = hlen;
            auto emlen = em.size();
            auto embits = (emlen * 8 - 1) & 0x7;
            auto EM = em.data();
            if (embits == 0) {
                *EM++ = 0;
                --emlen;
            }
            if (emlen < hlen + slen + 2) {
                return false; // inconsistent
            }
            if ((uint8_t)EM[emlen - 1] != 0xbc) {
                return false; // inconsistent
            }
            auto masked_db_len = emlen - hlen - 1;
            auto H = EM + masked_db_len;
            std::string db(masked_db_len, 9);
            std::string_view mseed{H, hlen};
            pkcs1_mgf1(db.data(), masked_db_len, mseed);
            for (int i = 0; i < masked_db_len; ++i) {
                db[i] ^= EM[i];
            }
            if (embits) {
                db[0] &= 0xFF >> (8 - embits);
            }
            int i;
            for (i = 0; db[i] == 0 && i < masked_db_len - 1; i++){}
            if (db[i++] != 0x1) {
                return false;
            }

            sha2<Bits> hh;
            hh.update(zeroes);
            hh.update(mhash);
            hh.update((const uint8_t *)db.data() + i, masked_db_len - i);
            return bytes_concept{mseed} == bytes_concept{hh.digest()};
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

    jwt() = default;
    jwt(std::string_view s) {
        auto sp = std::views::split(s, '.');
        auto it = std::begin(sp);
        header = json::parse(b64::decode(std::string_view(*it++)));
        payload = json::parse(b64::decode(std::string_view(*it++)));
        signature = b64::decode(std::string_view(*it++));
    }
    jwt(const json &payload) : payload{payload} {
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

    auto operator<=>(const jwt &) const = default;
    operator std::string() const {
        return std::format("{}.{}.{}", b64::encode(header.dump()), b64::encode(payload.dump()), b64::encode(signature));
    }

private:
    void make_header(auto &&type) {
        header = json::parse(std::format(R"({{"alg":"{}","typ":"JWT"}})", type));
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
