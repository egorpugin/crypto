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
