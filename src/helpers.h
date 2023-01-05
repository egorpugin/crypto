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

/*template <typename T>
concept bytes_concept = requires (T t) {
    t.data();
    t.size();
};*/

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
    auto data() const { return p; }
    auto size() const { return sz; }
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

}
