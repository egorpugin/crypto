#pragma once

#include "helpers.h"
#include "mmap.h"

namespace crypto {

// online decoder
// https://lapo.it/asn1js
struct asn1 {
    struct tlv {
        uint8_t tag;
        uint8_t len;
    };
    using tag_type = uint8_t;
    enum class tag : tag_type {
        sequence = 0x30,
    };

    template <typename ... Types>
    struct types {
        using variant_type = std::variant<Types...>;

        static constexpr auto size() {
            return sizeof...(Types);
        }
        static void for_each(auto &&f) {
            (f(Types{}), ...);
        }
    };

    struct sequence;
    using asn1_types = types<sequence>;
    struct sequence {
        static inline constexpr auto tag = 0x30;

        std::unique_ptr<asn1_types> value;
    };
    struct set {
        static inline constexpr auto tag = 0x31;

        std::unique_ptr<asn1_types> value;
    };
    struct bit_string {
        static inline constexpr auto tag = 0x03;

        bytes_concept data;
    };
    struct oid {
        static inline constexpr auto tag = 0x06;

        bytes_concept data;

        auto operator==(const oid &rhs) const {
            return data == rhs.data;
        }
        auto operator==(const bytes_concept &rhs) const {
            return data == rhs;
        }

        operator string() const {
            string s;
            auto p = data.data();
            auto n1 = *p / 40;
            auto n2 = *p - n1 * 40;
            ++p;
            s += format("{}.{}", n1, n2);
            while (p - data.data() < data.size()) {
                if (*p < 0x80) {
                    s += format(".{}", *p++);
                } else {
                    uint64_t v{};
                    while (*p > 0x80) {
                        v |= *p++ ^ 0x80;
                        v <<= 7;
                    }
                    v |= *p++;
                    s += format(".{}", v);
                }
            }
            return s;
        }
    };
    using asn1_types = types<sequence>;
    using asn1_variant = asn1_types::variant_type;

    bytes_concept data;

    template <typename T>
    auto subsequence(bytes_concept data, auto p, auto ... pos) {
        if (data.empty()) {
            throw std::runtime_error{"empty object"};
        }
        auto get_next_data = [](bytes_concept data, int expected_tag = -1) {
            auto tag = data[0];
            tag &= 0b0011'1111;
            // Universal (00xxxxxx)
            // Application(01xxxxxx)
            // Context-specific(10xxxxxx)
            // Private(11xxxxxx)
            if (expected_tag != -1 && data[0] != expected_tag) {
                throw std::runtime_error{"not a requested type"};
            }
            uint64_t len = 0;
            if (tag == 0x05) { // null
                return std::tuple{2, len};
            }
            len = data[1];
            uint8_t lenbytes = 1;
            if (len > 0x80) {
                lenbytes = len ^ 0x80;
                len = 0;
                int j = 2;
                for (int i = 0; i < lenbytes; ++i, ++j) {
                    len |= data[j] << ((lenbytes - 1 - i) * 8);
                }
                return std::tuple{j, len};
            }
            return std::tuple{2,len};
        };
        auto n = (int)p;
        while (n--) {
            auto [start,len] = get_next_data(data);
            data = data.subspan(start + len);
        }
        if constexpr (sizeof...(pos) > 0) {
            if ((tag)data[0] != tag::sequence) {
                throw std::runtime_error{"not a sequence"};
            }
            auto [start, len] = get_next_data(data);
            return subsequence<T>(data.subspan(start, len), pos...);
        } else {
            auto [start, len] = get_next_data(data, T::tag);
            return T{data.subspan(start, len)};
        }
    }
    template <typename T>
    T get(auto ... pos) {
        return subsequence<T>(data, pos...);
    }
};

struct x509 {
    /*
    struct certificate {
        struct version_number {};
    };
    struct certificate_signature_algorithm {};
    struct certificate_signature {};
    */
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

template <auto n1, auto n2, auto ... nodes>
constexpr auto make_oid() {
    auto count_bytes = [](auto v) {
        int bytes = 1;
        while (v >= 0x80) {
            ++bytes;
            v >>= 8;
        }
        return bytes;
    };
    auto make_bytes = [&](uint8_t *&p, auto v) {
        if (v < 0x80) {
            *p++ = v;
        } else {
            auto b = count_bytes(v);
            p += b - 1;
            *p-- = v & 0b0111'1111;
            v >>= 7;
            while (v >= 0x80) {
                *p-- = 0x80 | v;
                v >>= 7;
            }
            *p = 0x80 | v;
            p += b;
        }
    };
    constexpr int nbytes = (1 + ... + count_bytes(nodes));
    std::array<uint8_t, nbytes> data;
    data[0] = n1 * 40 + n2;
    auto p = data.data() + 1;
    (make_bytes(p, nodes),...);
    return data;
}

} // namespace crypto
