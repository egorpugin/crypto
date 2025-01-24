// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "helpers.h"

#include <map>
#include <variant>

namespace crypto {

/*
some of replacements
    case 0:       stream << "\\0";  break;
    case 0x7:     stream << "\\a";  break;
    case 0x8:     stream << "\\b";  break;
    case 0x9:     stream << "\\t";  break;
    case 0xA:     stream << "\\n";  break;
    case 0xB:     stream << "\\v";  break;
    case 0xC:     stream << "\\f";  break;
    case 0xD:     stream << "\\r";  break;
    case 0x1B:    stream << "\\e";  break;
    case '"':     stream << "\\\""; break;
    case '\\':    stream << "\\\\"; break;
    case 0xA0:    stream << "\\_";  break;
    case 0x85:    stream << "\\N";  break;
    case 0x2028:  stream << "\\L";  break;
    case 0x2029:  stream << "\\P";  break;
*/

struct json {
    //using string_view = std::u8string_view;
    using string_type = std::string;

    using array = std::vector<json>;
    using object = ::std::map<string_type, json>;
    using simple_value = variant<string_type, int64_t, double, bool, nullptr_t>;
    //using simple_value = std::variant<string_type>;
    using value_type = std::variant<simple_value, array, object>;

    value_type value;

    auto operator<=>(const json &) const = default;
    auto &operator[](auto &&key) const {
        auto &p = std::get<object>(value);
        if (auto i = p.find(key); i != p.end()) {
            return i->second;
        }
        throw std::runtime_error{"not such key"};
    }
    /*template <typename T> requires std::same_as<T, string> || std::same_as<T, std::u8string>
    operator T() const {
        string_view sv = *this;
        T s;
        s.reserve(sv.size());
        for (auto i = sv.begin(); i != sv.end(); ++i) {
            if (*i == '\\') {
                switch (*(i+1)) {
                case '\\': s += (typename T::value_type)'\\'; ++i; break;
                case '\0': s += (typename T::value_type)'\0'; ++i; break;
                default:
                    throw std::runtime_error{"not implemented"};
                }
            } else {
                s += *i;
            }
        }
        return s;
    }
    operator vector<std::u8string>() const {
        auto &p = std::get<array>(value);
        vector<std::u8string> v;
        v.reserve(p.size());
        std::ranges::copy(p, std::back_inserter(v));
        return v;
    }
    operator vector<string>() const {
        auto &p = std::get<array>(value);
        vector<string> v;
        v.reserve(p.size());
        std::ranges::copy(p, std::back_inserter(v));
        return v;
    }
    operator string_view() const {
        return std::get<string_view>(std::get<simple_value>(value));
    }
    operator vector<string_view>() const {
        auto &p = std::get<array>(value);
        vector<string_view> v;
        v.reserve(p.size());
        std::ranges::copy(p, std::back_inserter(v));
        return v;
    }*/

    static void check_null(auto p) {
        if (!*p) {
            throw std::runtime_error{"unexpected eof"};
        }
    }
    static void eat_space(auto &p) {
        while (*p && isspace(*p)) {
            ++p;
        }
    }
    static auto get_symbol(auto &p) {
        eat_space(p);
        return *p;
    }
    static void eat_symbol(auto &p, auto c) {
        if (get_symbol(p) != c) {
            throw std::runtime_error{"unexpected '"s + c + "'"s};
        }
        ++p;
    }
    static auto eat_string(auto &p) {
        auto start = p;
        while (!(*p == '\"' && *(p - 1) != '\\')) {
            ++p;
        }
        return std::string_view{start, p};
    }
    static auto eat_string_quoted(auto &p) {
        eat_symbol(p, '\"');
        auto s = eat_string(p);
        eat_symbol(p, '\"');
        return s;
    }
    static simple_value eat_number(auto &p) {
        auto end = strpbrk(p, ",}]");
        int i;
        if (std::from_chars(p, end, i).ec != std::errc{}) {
            double d;
            if (std::from_chars(p, end, i).ec != std::errc{}) {
                throw std::runtime_error{"bad number"};
            }
            return d;
        }
        return i;
    }

    template <typename T, auto start_sym, auto end_sym>
    static auto parse(auto &p, auto &&f) {
        eat_symbol(p, start_sym);
        T v;
        while (*p != end_sym) {
            f(v);
            if (get_symbol(p) == ',') {
                ++p;
            }
        }
        eat_symbol(p, end_sym);
        return v;
    }
    static json parse(const char *&p) {
        switch (get_symbol(p)) {
        case '{':
            return {parse<object, '{', '}'>(p, [&](auto &&v) {
                auto key = eat_string_quoted(p);
                eat_symbol(p, ':');
                v.emplace(key, parse(p));
            })};
        case '[':
            return {parse<array, '[', ']'>(p, [&](auto &&v) {
                v.emplace_back(parse(p));
            })};
        case '\"':
            return {std::string{eat_string_quoted(p)}};
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
        case '+':
        case '-':
        case '.': // .123
            return {eat_number(p)};
        // null, true, false, ...
        default:
            throw std::runtime_error{"not implemented"};
        }
        return {};
    }
    static json parse(std::string_view s) {
        auto p = s.data();
        return parse(p);
    }

    static std::string dump(const value_type &value) {
        return visit(value
            , [](const simple_value &v) {
                return std::get<0>(v);
            }
            , [](const array &v) {
                std::string s = "[";
                for (auto &&k : v) {
                    s += std::format("\"{}\",", dump(k.value));
                }
                if (s.size() > 1) {
                    s.pop_back();
                }
                s += "]";
                return s;
            }
            , [](const object &m) {
                std::string s = "{";
                for (auto &&[k,v] : m) {
                    s += std::format("\"{}\":\"{}\",", k, dump(v.value));
                }
                if (s.size() > 1) {
                    s.pop_back();
                }
                s += "}";
                return s;
            }
        );
    }
    std::string dump() const {
        return dump(value);
    }
};

auto operator""_json(const char *s, size_t len) {
    return json::parse(s);
}

} // namespace crypto
