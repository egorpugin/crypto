// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#define DEFLATE_CORO 0
#if DEFLATE_CORO
#include "deflate_coro.h"
#else
#include "deflate.h"
#endif
#include "d:/dev/EzGz/ezgz.hpp"

#include <print>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>

// #define ASSERT(x) if (!(x)) throw std::runtime_error{"error"};
#define ASSERT(x)                                                                                                                                              \
    if (!(x))                                                                                                                                                  \
        std::cerr << "error" << "\n";                                                                                                                          \
    else                                                                                                                                                       \
        std::cerr << "ok" << "\n";

auto read_file(auto f) {
    std::filesystem::path p{f};
    std::ifstream ifile(p, std::ios::binary);
    auto sz = std::filesystem::file_size(p);
    std::string ss(sz, 0);
    ifile.read(ss.data(), sz);
    return ss;
}

auto ez_deflate(auto &&d) {
    std::span<const uint8_t> data((uint8_t *)d.data(), d.size());
    EzGz::IDeflateArchive s{data};
    auto v = s.readAll();
    std::string ss(v.data(), v.size());
    return ss;
}
#if DEFLATE_CORO
auto my_deflate(auto &&in, int n_parts = 1) {
    deflater_coro d;
    auto sz = in.size();
    d.decode((uint8_t *)in.data(), sz / 2);
    d.decode((uint8_t *)in.data() + sz / 2, sz - sz / 2);
    return d.out;
}
#else
auto my_deflate(auto &&in, int n_parts = 1) {
    deflate d;
    auto sz = in.size();
    d.decode((uint8_t *)in.data(), sz);
    return d.out;
}
#endif
auto cmp(auto &&defl, auto &&orig) {
    auto ss2 = read_file(defl);
    ASSERT(my_deflate(ss2) == ez_deflate(ss2));
    ASSERT(my_deflate(ss2) == read_file(orig));
    ASSERT(my_deflate(ss2, true) == read_file(orig));
}
auto cmp2(auto &&n) {
    std::cerr << n << "\n";
    std::string base = "d:/dev/wuffs/test/data/artificial-deflate/";
    cmp(base + n + ".deflate", base + n + ".deflate.decompressed");
}

void f() {
    auto ss = read_file("d:/dev/wow/softres_points/2.zip");
    auto defl = ss.substr(2);

    ASSERT(my_deflate(defl) == ez_deflate(defl));
    cmp("d:/dev/wuffs/test/data/romeo.txt.deflate", "d:/dev/wuffs/test/data/romeo.txt");
    cmp2("backref-crosses-blocks");
    cmp2("degenerate-huffman");
    cmp2("distance-32768");
    cmp2("huffman-primlen-9");
    cmp2("distance-code-31");

    int a = 5;
    a++;
}

int main() {
    try {
        f();
    } catch (std::exception &e) {
        std::cerr << e.what() << "\n";
    }
}
