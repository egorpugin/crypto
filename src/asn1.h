#pragma once

#include "helpers.h"
#include "mmap.h"

namespace crypto {

// online decoder https://lapo.it/asn1js
// fields https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-der-encoding-of-asn-1-types
struct asn1_container {
    bytes_concept data;

    operator bytes_concept() const { return data; }
    auto operator==(const bytes_concept &rhs) const {
        return data == rhs;
    }

    static auto get_tag_raw(auto &&data) {
        return data[0];
    }
    static auto get_tag(auto &&data) {
        auto tag = get_tag_raw(data);
        tag &= 0b0011'1111;
        // Universal (00xxxxxx)
        // Application(01xxxxxx)
        // Context-specific(10xxxxxx)
        // Private(11xxxxxx)
        return tag;
    }
    static auto get_next_data(bytes_concept data) {
        auto tag = get_tag(data);
        int pos = 1;
        uint64_t len = 0;
        if (tag == 0x05) { // null
            return std::tuple{pos + 1, len};
        }
        len = data[pos];
        uint8_t lenbytes = 1;
        if (len > 0x80) {
            lenbytes = len ^ 0x80;
            len = 0;
            int j = pos + 1;
            for (int i = 0; i < lenbytes; ++i, ++j) {
                len |= data[j] << ((lenbytes - 1 - i) * 8);
            }
            return std::tuple{j, len};
        }
        return std::tuple{pos + 1, len};
    }
};
struct asn1_base : asn1_container {
    asn1_base() = default;
    asn1_base(bytes_concept b) {
        data = b;
    }
    asn1_base(const asn1_base &b) {
        data = b;
    }

    struct converter {
        bytes_concept data;
        operator bytes_concept() const {
            return data;
        }
        template <typename T>
        operator T() const {
            auto [start, len] = asn1_container::get_next_data(data);
            return T{data.subspan(start, len)};
        }
        bool operator==(auto &&v) const {
            return data == v;
        }
    };
    struct iterator {
        bytes_concept data;
        asn1_base operator*() const {
            return data; // converter{data};
        }
        void operator++() {
            auto [start, len] = get_next_data(data);
            data = data.subspan(start + len);
        }
        bool operator==(int) const {
            return data.size() == 0;
        }
    };
    auto begin() {
        return iterator{data};
    }
    auto end() {
        return 0;
    }

    template <typename T>
    bool is() const {
        return get_tag(data) == T::tag;
    }
    static auto subsequence1(bytes_concept data, auto p, auto... pos) {
        if (data.empty()) {
            throw std::runtime_error{"empty object"};
        }
        auto n = (int)p;
        while (n--) {
            auto [start, len] = get_next_data(data);
            data = data.subspan(start + len);
        }
        if constexpr (sizeof...(pos) > 0) {
            auto [start, len] = get_next_data(data);
            return subsequence1(data.subspan(start, len), pos...);
        } else {
            return data;
        }
    }
    auto subsequence(auto... pos) {
        return asn1_base{subsequence1(data, pos...)};
    }
    template <typename T>
    T get(auto... pos) {
        auto d = data;
        if constexpr (sizeof...(pos) > 0) {
            d = subsequence1(data, pos...);
            if (get_tag(d) != T::tag) {
                throw std::runtime_error{"not a requested type"};
            }
        }
        auto [start, len] = get_next_data(d);
        return T{d.subspan(start, len)};
    }

    auto data_as_strings() {
        struct x {
            bytes_concept data;
            struct iterator {
                bytes_concept data;
                auto operator*() const {
                    auto [start, len] = get_next_data(data);
                    return data.subspan(start, len);
                }
                void operator++() {
                    auto [start, len] = get_next_data(data);
                    data = data.subspan(start + len);
                }
                bool operator==(int) {
                    return data.empty();
                }
            };
            auto begin() {
                return iterator{data};
            }
            auto end() {
                return 0;
            }
        };
        return x{data};
    }
};
struct asn1_sequence : asn1_base {
    static inline constexpr auto tag = 0x30;
    using asn1_base::asn1_base;
};
struct asn1_set : asn1_base {
    static inline constexpr auto tag = 0x31;
};
struct asn1_bit_string : asn1_base {
    static inline constexpr auto tag = 0x03;
};
struct asn1_octet_string : asn1_base {
    static inline constexpr auto tag = 0x04;
};
struct asn1_printable_string : asn1_base {
    static inline constexpr auto tag = 0x13;
    operator string_view() const {
        return {(const char *)data.data(), data.size()};
    }
};
struct asn1_utf8_string : asn1_base {
    static inline constexpr auto tag = 0x0C;
    operator string_view() const {
        return {(const char *)data.data(), data.size()};
    }
};
struct asn1_oid : asn1_base {
    static inline constexpr auto tag = 0x06;

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
struct asn1 : asn1_sequence {
    using asn1_sequence::asn1_sequence;
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
