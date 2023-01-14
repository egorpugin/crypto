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
    using asn1_types = types<sequence>;
    using asn1_variant = asn1_types::variant_type;

    struct reader {
        bytes_concept data;

        auto empty() const { return data.empty(); }
    };
    reader r;

    void parse() {
        while (!r.empty()) {
            parse_object();
        }
    }
    void parse_object() {
        asn1_variant v;
        [&]<typename ... Types>(std::variant<Types...> **) {
            if (((Types::tag == r.data[0] && (true)) || ... || false)) {
                int a = 5;
                a++;
            } else {
                throw std::runtime_error{"unknown asn1 tag"};
            }
        }((asn1_variant**)nullptr);
    }
};

} // namespace crypto
