#pragma once

#include "zip.h"

#include <bit>
#include <cstdint>
#include <string>
#include <vector>

struct bigint {
    using element_type = uint64_t;
    //using element_type = unsigned __int128;

    std::vector<element_type> data;

    bigint() = default;
    bigint(const bigint &) = default;
    bigint(auto v) {
        data.emplace_back(v);
    }

    bigint &operator<<=(int bits) {
        auto extra_elements = bits / 8 / sizeof(element_type);
        auto pre_bits = bits - extra_elements * 8 * sizeof(element_type);
        extra_elements += !!pre_bits;
        data.resize(data.size() + extra_elements);
        if (pre_bits) {
            for (auto it = data.rbegin() + extra_elements; it != data.rend(); ++it) {
                auto set_to_elem = [&](auto &&val, auto &&elem) {
                    auto mask = (element_type)-1;
                    mask <<= pre_bits;
                    elem &= val;
                    elem |= val;
                };
                auto &v = *it;
                auto b = v >> (sizeof(element_type) * 8 - pre_bits);
                set_to_elem(b, *(it - extra_elements));
                v <<= pre_bits;
                set_to_elem(v, *(it - extra_elements + 1));
            }
            for (int i = 0; i < extra_elements - 1; ++i) {
                data[i] = 0;
            }
            auto mask = (element_type)-1;
            mask <<= pre_bits;
            data[extra_elements-1] &= mask;
        } else {
            for (auto it = data.rbegin() + extra_elements; it != data.rend(); ++it) {
                *(it - extra_elements) = (*it);
            }
            for (int i = 0; i < extra_elements; ++i) {
                data[i] = 0;
            }
        }
        return *this;
    }
    bigint operator+(const bigint &rhs) const {
        bigint bn = *this;
        return bn += rhs;
    }
    bigint &operator+=(const bigint &rhs) {
        bool overflow = false;
        for (auto &&[l,r] : zip(data,rhs.data)) {
            element_type r2;
            overflow = __builtin_add_overflow_p(l, r, r2);
            l += r;
        }
        if (data.size() < rhs.data.size()) {
            for (auto it = rhs.data.begin() + data.size(); it != rhs.data.end(); ++it) {
                data.emplace_back(!!overflow);
                element_type r;
                overflow = __builtin_add_overflow_p(data.back(), *it, r);
                data.back() += *it;
            }
        } else {
            for (auto it = data.begin() + rhs.data.size(); it != data.end(); ++it) {
                element_type v = !!overflow;
                element_type r;
                overflow = __builtin_add_overflow_p(*it, v, r);
                *it += v;
            }
        }
        if (overflow) {
            data.emplace_back(!!overflow);
        }
        //add_to_pos(0, v);
        return *this;
    }
    /*bigint &operator*=(auto v) requires (sizeof(v) <= sizeof(element_type)) {
        mul_to_pos(0, v);
        return *this;
    }*/
    void add_to_pos(int pos, auto v) {
        while ((data.size() - pos) * sizeof(element_type) < sizeof(decltype(v))) {
            data.emplace_back();
        }
        auto &l = data[pos];
        element_type r;
        auto msb = __builtin_add_overflow_p(l, v, r);
        l += v;
        if (msb) {
            add_to_pos(pos + 1, 1u);
        }
    }
    /*void mul_to_pos(int pos, auto v) {
        while ((data.size() - pos) * sizeof(element_type) < sizeof(decltype(v))) {
            data.emplace_back();
        }
        auto &l = data[pos];
        element_type r;
        auto msb = __builtin_mul_overflow_p(l, v, r);
        l *= v;
        if (msb) {
            add_to_pos(pos + 1, 1u);
        }
    }*/

    bool operator==(const bigint &rhs) const {
        return data == rhs.data;
    }

    std::string to_string() const {
        if (data.empty()) {
            return "0";
        }
        return std::to_string(*(uint64_t*)data.data());
    }
};

std::ostream &operator<<(std::ostream &o, const bigint &bn) {
    return o << bn.to_string();
}

void test_bigint_own() {
    {
        bigint bn2{0xFFFFFFFFFFFFFFFFull};
        bn2 <<= 65;
    }
    {
        bigint bn2{0xFFFFFFFFFFFFFFFFull};
        bn2 <<= 1;
    }
    {
        bigint bn2{0xFFFFFFFFFFFFFFFFull};
        bn2 <<= 129;
    }
    {
        bigint bn2{0xFFFFFFFFFFFFFFFFull};
        bn2 <<= 128;
    }
    {
        bigint bn1;
        bn1 += 0xFFFFFFFFFFFFFFFFull;
        bigint bn2;
        bn2 += 0xFFFFFFFFFFFFFFFFull;
        bn2 <<= 64;
        bn2 += 1u;
        bn1 += bn2;
    }
    {
        bigint bn1;
        bn1 += 0xFFFFFFFFFFFFFFFFull;
        bigint bn2;
        bn2 += 0xFFFFFFFFFFFFFFFFull;
        bn2 <<= 64;
        bn1 += bn2;
        bn1 += 1u;
    }
    {
        bigint bn;
        std::cout << bn << "\n";
        std::cout << (bn += 1000u) << "\n";
        std::cout << bn + 1u << "\n";
        bn += 0xFFFFFFFFFFFFFFFFu;
        bn += 0xFFFFFFFFFFFFFFFFu;
        bn += 0xFFFFFFFFFFFFFFFFu;
        bn += 0xFFFFFFFFFFFFFFFFu;
        bn += 0xFFFFFFFFFFFFFFFFu;
        // bn *= 0xFFFFFFFFFFFFFFFFu;
    }
}
