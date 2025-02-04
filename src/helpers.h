// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#undef small

#include <array>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <format>
using std::format;
#include <iostream>
#include <map>
#include <print>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <utility>
#include <vector>
#ifdef _MSC_VER
#include <__msvc_int128.hpp>
#endif

#ifndef FWD
#define FWD(x) std::forward<decltype(x)>(x)
#endif

namespace crypto {

namespace fs = std::filesystem;
using path = fs::path;
using std::string;
using std::string_view;
using std::variant;
using std::vector;
using namespace std::literals;

using i8 = int8_t;
using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

template <auto N>
using array = std::array<u8, N>;
template <auto N>
struct array_gost : array<N> {
};

template <typename... Types>
struct types {
    using variant_type = std::variant<Types...>;
};

template <typename T>
concept bytes_concept1 = requires (T t) {
    t.data();
    t.size();
};

struct bytes_concept {
    u8 *p{};
    size_t sz{};
    bytes_concept() = default;
    bytes_concept(u8 *p, size_t sz) : p{p}, sz{sz} {
    }
    template <typename T, auto N>
    bytes_concept(T (&d)[N]) : p{(u8*)d}, sz{sizeof(T) * N} {
    }
    template <auto N>
    bytes_concept(const char (&d)[N]) : p{(u8*)d}, sz{N - 1} {
    }
    bytes_concept(const std::string &s) {
        p = (u8 *)s.data();
        sz = s.size();
    }
    bytes_concept(std::string_view s) {
        p = (u8 *)s.data();
        sz = s.size();
    }
    template <auto N>
    bytes_concept(u8 (&s)[N]) {
        p = s;
        sz = N;
    }
    template <auto N>
    bytes_concept(const array<N> &s) {
        p = (u8 *)s.data();
        sz = N;
    }
    template <auto N> bytes_concept(const array_gost<N> &) = delete; // bytes are reversed here, so we can't view over them
    bytes_concept(std::span<u8> s) {
        p = s.data();
        sz = s.size();
    }
    bytes_concept(const std::vector<u8> &s) {
        p = (u8 *)s.data();
        sz = s.size();
    }
    bytes_concept(bytes_concept1 auto &&s) {
        p = (u8 *)s.data();
        sz = s.size();
    }
    auto begin() const { return p; }
    auto end() const { return p+sz; }
    auto data() const { return p; }
    auto size() const { return sz; }
    auto empty() const { return size() == 0; }
    auto subspan(size_t start, size_t sz = -1) const {
        if (sz == -1 || sz >= this->sz) {
            return bytes_concept{p + start, this->sz - start};
        }
        sz = std::min<size_t>(this->sz - start, sz);
        return bytes_concept{p + start, sz};
    }
    auto remove_prefix(size_t s) {
        p += s;
        sz -= s;
    }
    auto &operator[](int i) { return data()[i]; }
    auto operator[](int i) const { return data()[i]; }
    void operator+=(int i) { p += i; }
    /*bool operator==(const bytes_concept &rhs) const {
        if (sz != rhs.sz) {
            return false;
        }
        return memcmp(data(), rhs.data(), sz) == 0;
    }*/
    bool operator==(const bytes_concept &rhs) const {
        if (sz != rhs.size()) {
            return false;
        }
        return std::memcmp(data(), rhs.data(), size()) == 0;
    }
    auto operator<=>(const bytes_concept &rhs) const {
        if (sz != rhs.size()) {
            return sz <=> rhs.size();
        }
        return std::memcmp(data(), rhs.data(), size()) <=> 0;
    }
    bool contains(u8 c) const {
        return std::memchr(data(), c, sz);
    }

    template <auto N>
    operator array<N>() const {
        if (N < sz) {
            throw std::runtime_error{"bad array conversion"};
        }
        array<N> a{};
        std::memcpy(a.data() + sz - N, p, sz);
        return a;
    }
    template <auto N>
    operator array_gost<N>() const {
        if (N < sz) {
            throw std::runtime_error{"bad array conversion"};
        }
        array_gost<N> a{};
        std::memcpy(a.data() + sz - N, p, sz);
        return a;
    }
    /*template <typename T, auto N>
    operator T[N]() const {
        if (N != sz) {
            throw std::runtime_error{"bad array conversion"};
        }
        array<N> a;
        std::memcpy(a.data(), p, sz);
        return a;
    }*/
    operator std::string() const {
        std::string a{p,p+sz};
        return a;
    }
};

template <typename... Ts>
struct overload : Ts... {
    overload(Ts... ts) : Ts(FWD(ts))... {
    }
    using Ts::operator()...;
};

decltype(auto) visit(auto &&var, auto &&...f) {
    return ::std::visit(overload{FWD(f)...}, var);
}
decltype(auto) visit_any(auto &&var, auto &&...f) {
    return visit(FWD(var), overload{FWD(f)..., [](auto &&) {
                                    }});
}

inline auto print_buffer(bytes_concept buffer) {
    int i, buflen = (int)buffer.size(), bufidx;
    constexpr int LINE_LEN = 16;
    // maybe make this 2? but seems 3 is more readable
    constexpr int SPACE_LEN = 3; // addr | ':' | space
    int ADDR_LEN = std::max<int>(5, std::log2(buffer.size()) / 4);
    /* addr:   00..0F | chars...chars\0 */

    std::string out;
    auto print = [&](auto &&s) {
        out += s + "\n";
    };

    string space(SPACE_LEN, ' ');
    if (!buffer.data()) {
        print(format("{:0{}d}:{}NULL", 0, ADDR_LEN, space));
        return out;
    }

    size_t addr = 0;
    while (buflen > 0) {
        std::string line;
        line += format("{:0{}x}:{}", addr, ADDR_LEN, space);

        for (i = 0; i < LINE_LEN; i++) {
            if (i < buflen) {
                line += format("{:02x} ", buffer[i]);
            } else {
                line += format("   ", buffer[i]);
            }
        }
        line += "|  ";

        for (i = 0; i < LINE_LEN; i++) {
            if (i < buflen) {
                line += format("{:c}", 31 < buffer[i] && buffer[i] < 127 ? buffer[i] : '.');
            }
        }
        print(line);
        buffer += LINE_LEN;
        buflen -= LINE_LEN;
        addr += 0x10;
    }
    return out;
}
inline void print_buffer(auto &&name, auto &&buffer) {
    std::cout << name << "\n";
    std::cout << print_buffer(buffer) << "\n";
}

std::ostream &operator<<(std::ostream &o, const bytes_concept &b) {
    return o << print_buffer(b);
}

template<std::size_t N>
struct static_string {
    char p[N]{};
    constexpr static_string(char const(&pp)[N]) {
        std::ranges::copy(pp, p);
    }
    operator auto() const { return &p[0]; }
    operator string_view() const { return string_view{p, N-1}; }
    constexpr auto size() const { return N-1; }
    constexpr auto begin() const {return p;}
    constexpr auto end() const {return p+size();}
};
template<static_string s>
constexpr auto operator""_s() { return s; }

template <auto Bytes>
struct bigendian_unsigned {
    //struct bad_type {};
    using max_type = u64;
    using internal_type = std::conditional_t<
        Bytes == 1, u8,
        std::conditional_t<Bytes == 2, uint16_t,
                           std::conditional_t<Bytes <= 4, u32, std::conditional_t<Bytes <= 8, u64, bool>>>>;

    u8 data[Bytes]{};

    bigendian_unsigned() = default;
    bigendian_unsigned(int v) {
        *this = v;
    }
    template <typename E>
    bigendian_unsigned(E v) requires std::is_enum_v<E> {
        *this = std::to_underlying(v);
    }

    auto &operator+=(auto v) {
        u64 x = *this;
        x += v;
        *this = x;
        return *this;
    }
    void operator=(u32 v) requires (Bytes == 3) {
        *(u32*)data |= std::byteswap(v << 8);
    }
    void operator=(internal_type v) requires (Bytes != 3) {
        *(internal_type *)data = std::byteswap(v);
    }
    operator auto() const requires (Bytes == 3) { return std::byteswap(*(u32*)data) >> 8; }
    operator auto() const requires (Bytes != 3)//requires (!std::same_as<internal_type, bad_type>)
    {
        auto d = *(internal_type*)data;
        return std::byteswap(d);
    }
};
template <auto Bytes>
auto operator+(auto &&v, const bigendian_unsigned<Bytes> &l) {
    return v + (typename bigendian_unsigned<Bytes>::internal_type)l;
}
template <auto Bytes>
auto operator+(const bigendian_unsigned<Bytes> &l, auto &&v) {
    return v + (typename bigendian_unsigned<Bytes>::internal_type)l;
}

struct be_stream {
    struct reader {
        be_stream &s;

        template <typename E>
            requires std::is_enum_v<E>
        operator E() {
            auto v = *(std::underlying_type_t<E> *)s.p;
            s.step(sizeof(v));
            v = std::byteswap(v);
            return (E)v;
        }
        template <typename T>
        operator T&() const {
            auto &v = *(T *)s.p;
            s.step(sizeof(T));
            return v;
        }
        operator uint16_t() const {
            auto v = *(uint16_t *)s.p;
            s.step(sizeof(v));
            v = std::byteswap(v);
            return v;
        }
    };

    const u8 *p;
    size_t len;

    be_stream() = default;
    //be_stream(const u8 *p) : p{p} {}
    be_stream(const u8 *p, auto len) : p{p},len{len} {}
    be_stream(auto &&v) : be_stream{(const u8*)v.data(),v.size()} {}

    auto read() {
        return reader{*this};
    }
    auto substream(auto len) {
        be_stream s{p,len};
        step(len);
        return s;
    }
    void skip(auto len) {
        step(len);
    }
    void step(auto len) {
        p += len;
        this->len -= len;
    }
    bytes_concept span(auto len) {
        std::span<u8> s((u8*)p, len);
        step(len);
        return s;
    }
    explicit operator bool() { return len != 0; }
    //operator uint16_t() { return read(); }
    //operator auto() { return read(); }
};

auto byteswap(auto &&in) {
    auto sz = in.size();
    std::decay_t<decltype(in)> out;
    out.resize(sz);
    for (int i = 0; i < sz; ++i) {
        out[i] = in[sz - i - 1];
    }
    return out;
}

auto str2bytes(auto &&in) {
    std::vector<u8> s;
    bool first = true;
    for (auto &&c : in | std::views::reverse) {
        auto isdigit = c >= '0' && c <= '9';
        if (!(isdigit || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')) {
            continue;
        }
        c = toupper(c);
        auto d = c - (isdigit ? '0' : ('A' - 10));
        if (first) {
            s.push_back(d);
        } else {
            s.back() |= d << 4;
        }
        first = !first;
    }
    std::reverse(s.begin(), s.end());
    return s;
}
auto operator""_sb(const char *in, size_t len) {
    std::vector<u8> s{in, in + len};
    return str2bytes(s);
}
auto operator""_sw(const char *in, size_t len) {
    std::string s{in, in + len};
    return crypto::byteswap(str2bytes(s));
}

#ifdef _MSC_VER
using uint128_t = std::_Unsigned128;
#else
using uint128_t = unsigned __int128;
#endif

template <typename T>
concept data_and_size_members = requires (T v) {
    v.data();
    v.size();
};

template <typename T>
struct hash_traits {
    void update_fast_pre(const u8 *data, size_t length, u8 *dst, size_t dstsize, auto &blockpos, auto &&f) {
        auto p = data;
        while (length > 0) {
            if (blockpos == dstsize) {
                f();
                blockpos = 0;
            }
            auto to_copy = std::min(length, dstsize - blockpos);
            memcpy(dst + blockpos, p, to_copy);
            p += to_copy;
            blockpos += to_copy;
            length -= to_copy;
        }
    }
    void update_fast_post(const u8 *data, size_t length, u8 *dst, size_t dstsize, auto &blockpos, auto &&f) {
        auto p = data;
        while (length > 0) {
            auto to_copy = std::min(length, dstsize - blockpos);
            memcpy(dst + blockpos, p, to_copy);
            p += to_copy;
            blockpos += to_copy;
            length -= to_copy;
            if (blockpos == dstsize) {
                f();
                blockpos = 0;
            }
        }
    }
    void update(this auto &&obj, bytes_concept v, auto && ... v2) {
        obj.update(v.data(), v.size());
        (obj.update(v2),...);
    }
    // still not ready
    /*void update(this auto &&obj, const u8 *data, size_t size) {
        obj.update1(data, size);
    }*/
    static auto digest(std::initializer_list<bytes_concept> list) {
        T h;
        for (auto &&v : list) {
            h.update(v);
        }
        return h.digest();
    }
    static auto digest(data_and_size_members auto && ... v) {
        T h;
        (h.update(v),...);
        return h.digest();
    }
};

void replace_all(auto &&s, std::string_view from, std::string_view to) {
    auto oldlen = from.size(), newlen = to.size();
    size_t p{};
    while ((p = s.find(from, p)) != -1) {
        s.replace(p, oldlen, to);
        p += newlen;
    }
}

struct bitlen {
    size_t value;
    bitlen(size_t v) : value{v} {}
    operator auto() const {return (value + 8 - 1) / 8;}
};

void take_left_bits(auto &&v, bitlen len) {
    if (v.size() * 8 <= len.value) {
        return;
    }
    v.resize(len);
    int rshift = len.value % 8, lshift = 8 - rshift;
    if (rshift == 0) {
        return;
    }
    u8 rem{};
    for (auto &c : v) {
        auto &b = (u8&)c;
        u8 newrem = b << rshift;
        b >>= lshift;
        b |= rem;
        rem = newrem;
    }
}
auto expand_bytes(auto &&v, auto len) {
    auto vsz = v.size();
    auto diff = len - vsz;
    std::string vs(v.begin(), v.end());
    vs.resize(vsz + diff);
    memmove(vs.data() + diff, vs.data(), vsz);
    memset(vs.data(), 0, diff);
    return vs;
}

} // namespace crypto
