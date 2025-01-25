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

template <typename K, typename T, typename IgnoredLess = std::less<K>,
    typename Allocator = std::allocator<std::pair<const K, T>>>
struct ordered_map : std::vector<std::pair<const K, T>, Allocator>
{
    using key_type = K;
    using mapped_type = T;
    using base = std::vector<std::pair<const K, T>, Allocator>;
    using typename base::iterator;
    using typename base::value_type;

    auto find(this auto &&self, auto &&key) {
        return std::find_if(self.begin(), self.end(), [&](auto &&p){return key == p.first;});
    }
    std::pair<iterator, bool> emplace(auto &&key, T &&t) {
        auto it = find(key);
        if (it != base::end())  {
            return {it, false};
        }
        base::emplace_back(key, t);
        return {--this->end(), true};
    }
    T &operator[](auto &&key) {
        return emplace(std::move(key), T{}).first->second;
    }
    auto erase(const K &key) {
        auto it = find(key);
        if (it != base::end())  {
            // cannot move const keys, re-construct inplace
            for (auto next = it; ++next != this->end(); ++it) {
                it->~value_type();
                new (&*it) value_type{std::move(*next)};
            }
            base::pop_back();
            return 1;
        }
        return 0;
    }
};

// options:
// view or owning
template <bool Owning, bool Ordered>
struct json_raw {
    //using string_view = std::u8string_view;
    using string_type = std::conditional_t<Owning, std::string, std::string_view>;
    template <typename K, typename T>
    using map_type = std::conditional_t<Ordered, ordered_map<K,T>, ::std::map<K,T>>;
    static inline constexpr auto json_view = std::same_as<string_type, std::string_view>;
    using this_type = json_raw;

    using array = std::vector<this_type>;
    using object = map_type<string_type, this_type>;
    using simple_value = variant<string_type, int64_t, double
        //, bool, nullptr_t
    >;
    //using simple_value = std::variant<string_type>;
    using value_type = std::variant<simple_value, array, object>;

    value_type value;

    /*template <bool B1, bool B2>
    this_type &operator=(const json_raw<B1, B2> &rhs) {
        auto &self = *this;
        visit_any(rhs.value
            , [&](const simple_value &v) {
                value = v;
            }
            , [&](const array &v) {
                value = array{};
                for (auto &&k : v) {
                    push_back(k);
                }
            }
            , [&](const object &m) {
                value = object{};
                for (auto &&[k,v] : m) {
                    self[k] = v;
                }
            }
        );
        return self;
    }*/
    void push_back(auto &&v) {
        auto &a = std::get<array>(value);
        a.push_back(v);
    }
    auto operator<=>(const this_type &) const = default;
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
    operator vector<string_view>() const {
        auto &p = std::get<array>(value);
        vector<string_view> v;
        v.reserve(p.size());
        std::ranges::copy(p, std::back_inserter(v));
        return v;
    }*/
    operator std::string() const {
        return std::get<string_type>(std::get<simple_value>(value));
    }

    template <bool ToJson>
    static void replace_chars(std::string &s) {
        auto repl = [&](auto &&from, auto &&to) {
            if constexpr (ToJson) {
                replace_all(s, to, from);
            } else {
                replace_all(s, from, to);
            }
        };
        repl("\\n"sv, "\n"sv);
    }

    static void check_null(auto p) {
        if (!*p) {
            throw std::runtime_error{"unexpected eof"};
        }
    }
    static void eat_space(std::string_view &p) {
        while (p[0] && isspace(p[0])) {
            p.remove_prefix(1);
        }
    }
    static auto get_symbol(std::string_view &p) {
        eat_space(p);
        return p[0];
    }
    static void eat_symbol(std::string_view &p, auto c) {
        if (get_symbol(p) != c) {
            throw std::runtime_error{"unexpected '"s + c + "'"s};
        }
        p.remove_prefix(1);
    }
    static auto eat_string(std::string_view &p) {
        auto start = p.data();
        while (!(p[0] == '\"' && *(p.data()-1) != '\\')) {
            p.remove_prefix(1);
        }
        return std::string_view{start, p.data()};
    }
    static auto eat_string_quoted(std::string_view &p) {
        eat_symbol(p, '\"');
        if constexpr (!json_view) {
            std::string s(eat_string(p));
            replace_chars<false>(s);
            eat_symbol(p, '\"');
            return s;
        } else {
            auto s = eat_string(p);
            eat_symbol(p, '\"');
            return s;
        }
    }
    static simple_value eat_number(std::string_view &p) {
        auto endp = p.find_first_of(",}] "sv);
        auto end = p.data() + endp;
        int64_t i;
        auto [e,ec] = std::from_chars(p.data(), end, i);
        if (ec != std::errc{} || e != end) {
            double d;
            auto [e,ec] = std::from_chars(p.data(), end, i);
            if (ec != std::errc{} || e != end) {
                throw std::runtime_error{"bad number"};
            }
            p.remove_prefix(endp);
            return d;
        }
        p.remove_prefix(endp);
        return i;
    }

    template <typename T, auto start_sym, auto end_sym>
    static auto parse1(std::string_view &p, auto &&f) {
        eat_symbol(p, start_sym);
        T v;
        while (p[0] != end_sym) {
            f(v);
            if (get_symbol(p) == ',') {
                p.remove_prefix(1);
            }
        }
        eat_symbol(p, end_sym);
        return v;
    }
    static this_type parse1(std::string_view &p) {
        if (!p.empty())
        switch (get_symbol(p)) {
        case '{':
            return {parse1<object, '{', '}'>(p, [&](auto &&v) {
                auto key = eat_string_quoted(p);
                eat_symbol(p, ':');
                v.emplace(key, parse1(p));
            })};
        case '[':
            return {parse1<array, '[', ']'>(p, [&](auto &&v) {
                v.emplace_back(parse1(p));
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
    static this_type parse(std::string_view s) {
        return parse1(s);
    }

    static std::string dump(const value_type &value) {
        return visit(value
            , [](const simple_value &v) {
                return visit(v
                    , [](int64_t v){return std::format("{}",v);}
                    , [](double v){return std::format("{}",v);}
                    , [](const std::string &v){
                        if constexpr (!json_view) {
                            auto s = v;
                            replace_chars<true>(s);
                            return std::format("\"{}\"",s);
                        } else {
                            return std::format("\"{}\"",v);
                        }
                    }
                );
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
                    s += std::format("\"{}\":{},", k, dump(v.value));
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

using json = json_raw<true, false>;

auto operator""_json(const char *s, size_t len) {
    //return json_raw<false, true>::parse(s);
    return json::parse(s);
}

} // namespace crypto
