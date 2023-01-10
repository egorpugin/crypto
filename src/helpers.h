#pragma once

//#include <filesystem>
#if __has_include(<format>)
#include <format>
using std::format;
#elif __has_include(<format.h>)
#define FMT_HEADER_ONLY
#include <format.h>
using fmt::format;
#else
#define FMT_HEADER_ONLY
#include <fmt/format.h>
using fmt::format;
#endif
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#ifndef FWD
#define FWD(x) std::forward<decltype(x)>(x)
#endif

namespace crypto {

//namespace fs = std::filesystem;
//using path = fs::path;
using std::string;
using std::string_view;
using std::variant;
using std::vector;
using namespace std::literals;

template <auto N>
using array = std::array<uint8_t, N>;

template <typename T>
concept bytes_concept1 = requires (T t) {
    t.data();
    t.size();
};

struct bytes_concept {
    uint8_t *p;
    size_t sz;
    bytes_concept(uint8_t *p, size_t sz) : p{p}, sz{sz} {
    }
    bytes_concept(const std::string &s) {
        p = (uint8_t *)s.data();
        sz = s.size();
    }
    bytes_concept(std::string_view s) {
        p = (uint8_t *)s.data();
        sz = s.size();
    }
    template <auto N>
    bytes_concept(uint8_t (&s)[N]) {
        p = s;
        sz = N;
    }
    template <auto N>
    bytes_concept(const array<N> &s) {
        p = (uint8_t *)s.data();
        sz = N;
    }
    bytes_concept(std::span<uint8_t> s) {
        p = s.data();
        sz = s.size();
    }
    bytes_concept(const std::vector<uint8_t> &s) {
        p = (uint8_t *)s.data();
        sz = s.size();
    }
    bytes_concept(bytes_concept1 auto &&s) {
        p = (uint8_t *)s.data();
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
        return bytes_concept{p + start, this->sz - start - sz};
    }
    auto &operator[](int i) { return data()[i]; }
    auto operator[](int i) const { return data()[i]; }
    void operator+=(int i) { p += i; }
    bool operator==(const bytes_concept &rhs) const {
        if (sz != rhs.sz) {
            return false;
        }
        return memcmp(data(), rhs.data(), sz) == 0;
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

inline void print_buffer(bytes_concept buffer) {
    int i, buflen = (int)buffer.size(), bufidx;
    constexpr int LINE_LEN = 16;
    char line[(LINE_LEN * 4) + 3]; /* \t00..0F | chars...chars\0 */

    auto print = [](auto &&s) {
        std::cout << s << "\n";
    };

    if (!buffer.data()) {
        print("\tNULL");
        return;
    }

    while (buflen > 0) {
        bufidx = 0;
        snprintf(&line[bufidx], sizeof(line) - bufidx, "\t");
        bufidx++;

        for (i = 0; i < LINE_LEN; i++) {
            if (i < buflen) {
                snprintf(&line[bufidx], sizeof(line) - bufidx, "%02x ", buffer[i]);
            } else {
                snprintf(&line[bufidx], sizeof(line) - bufidx, "   ");
            }
            bufidx += 3;
        }
        snprintf(&line[bufidx], sizeof(line) - bufidx, "| ");
        bufidx++;

        for (i = 0; i < LINE_LEN; i++) {
            if (i < buflen) {
                snprintf(&line[bufidx], sizeof(line) - bufidx, "%c",
                          31 < buffer[i] && buffer[i] < 127 ? buffer[i] : '.');
                bufidx++;
            }
        }
        print(line);
        buffer += LINE_LEN;
        buflen -= LINE_LEN;
    }
}
inline void print_buffer(auto &&name, auto &&buffer) {
    std::cout << name << "\n";
    print_buffer(buffer);
}

template<std::size_t N>
struct static_string {
    char p[N]{};
    constexpr static_string(char const(&pp)[N]) {
        std::ranges::copy(pp, p);
    }
    operator auto() const { return &p[0]; }
    operator string_view() const { return string_view{p, N-1}; }
};
template<static_string s>
constexpr auto operator""_s() { return s; }

template <auto Bytes>
struct bigendian_unsigned {
    struct bad_type {};
    using max_type = uint64_t;
    using internal_type = std::conditional_t<
        Bytes == 1, uint8_t,
        std::conditional_t<Bytes == 2, uint16_t,
                           std::conditional_t<Bytes == 4, uint32_t, std::conditional_t<Bytes == 8, uint64_t, bool>>>>;

    uint8_t data[Bytes]{};

    bigendian_unsigned() = default;
    bigendian_unsigned(int v) {
        *this = v;
    }
    template <typename E>
    bigendian_unsigned(E v) requires std::is_enum_v<E> {
        *this = std::to_underlying(v);
    }

    auto &operator+=(auto v) {
        uint64_t x = *this;
        x += v;
        *this = x;
        return *this;
    }
    void operator=(uint32_t v) requires (Bytes == 3) {
        *(uint32_t*)data |= std::byteswap(v << 8);
    }
    void operator=(internal_type v) requires (Bytes != 3) {
        *(internal_type *)data = std::byteswap(v);
    }
    operator auto() const requires (Bytes == 3) { return std::byteswap(*(uint32_t*)data) >> 8; }
    operator auto() const requires !std::same_as<internal_type, bad_type> {
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
        operator E() requires(std::is_enum_v<E>) {
            auto v = *(std::underlying_type_t<E> *)s.p;
            s.step(sizeof(v));
            v = std::byteswap(v);
            return (E)v;
        }
        template <typename T>
        operator T&() {
            auto &v = *(T *)s.p;
            s.step(sizeof(T));
            return v;
        }
        operator uint16_t() {
            auto v = *(uint16_t *)s.p;
            s.step(sizeof(v));
            v = std::byteswap(v);
            return v;
        }
    };

    const uint8_t *p;
    size_t len;

    be_stream() = default;
    be_stream(const uint8_t *p) : p{p} {}
    be_stream(const uint8_t *p, auto len) : p{p},len{len} {}
    be_stream(auto &&v) : be_stream{(const uint8_t*)v.data(),v.size()} {}

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
        std::span<uint8_t> s((uint8_t*)p, len);
        step(len);
        return s;
    }
    explicit operator bool() { return len != 0; }
    //operator uint16_t() { return read(); }
    //operator auto() { return read(); }
};

} // namespace crypto
