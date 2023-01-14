#pragma once

#include "helpers.h"
#include "mmap.h"

namespace crypto {

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
    struct bit_string {
        static inline constexpr auto tag = 0x03;

        bytes_concept data;
        int n_bits;
    };
    using asn1_types = types<sequence>;
    using asn1_variant = asn1_types::variant_type;

    struct reader {
        bytes_concept data;

        auto empty() const { return data.empty(); }
    };
    bytes_concept data;
    //reader r;

    /*void parse_object() {
    asn1_variant v;
        [&]<typename ... Types>(std::variant<Types...> **) {
            if (((Types::tag == r.data[0] && (true)) || ... || false)) {
                int a = 5;
                a++;
            } else {
                throw std::runtime_error{"unknown asn1 tag"};
            }
        }((asn1_variant**)nullptr);
    }*/

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
            //  Private(11xxxxxx)
            if (expected_tag != -1 && data[0] != expected_tag) {
                throw std::runtime_error{"not a requested type"};
            }
            uint64_t len = data[1];
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
            return subsequence<T>(data.subspan(start, len - start), pos...);
        } else {
            auto [start, len] = get_next_data(data, T::tag);
            return T{data.subspan(start, len - start)};
        }
    }
    template <typename T>
    T get(auto ... pos) {
        return subsequence<T>(data, pos...);
    }
};

} // namespace crypto
