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

template <typename T>
concept bytes_concept1 = requires (T t) {
    t.data();
    t.size();
};

struct bytes_concept {
    uint8_t *p;
    size_t sz;
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
    bytes_concept(const std::array<uint8_t, N> &s) {
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
    auto data() const { return p; }
    auto size() const { return sz; }
    auto &operator[](int i) { return data()[i]; }
    auto operator[](int i) const { return data()[i]; }
    void operator+=(int i) { p += i; }
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

}
