#pragma once

#include "linux.h"
#include "macos.h"
#include "win32.h"

namespace crypto {

// helpers?
auto read_file(const std::filesystem::path &fn) {
    if (!std::filesystem::exists(fn)) {
        throw std::runtime_error{ "file does not exist: " + fn.string() };
    }
    // better mmap?
    std::ifstream i{ fn, std::ios::binary };
    auto sz = std::filesystem::file_size(fn);
    std::string s(sz, 0);
    i.read(s.data(), sz);
    return s;
}
void write_file(const std::filesystem::path &fn, auto &&s) {
    std::ofstream o{ fn, std::ios::binary };
    if constexpr (requires {s.data(); }) {
        o.write((const char *)s.data(), s.size());
    } else {
        o << s;
    }
}

auto &default_io_context() {
    static executor ctx;
    return ctx;
}

}
