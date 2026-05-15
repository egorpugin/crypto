// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2026 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "sha3.h"

// NIST.SP.800-185 (cSHAKE, KMAC, TupleHash, ParallelHash)

namespace crypto {

// limits are 2^2040 usually

template <auto ShakeType>
using shake_for_cshake = shake_base<ShakeType, 0b00, 2>;

consteval bool is_usual_cshake(auto FunctionName, auto CustomizationString) {
    return FunctionName.empty() && CustomizationString.empty();
}

template <auto ShakeType, auto FunctionName = ""_s, auto CustomizationString = ""_s>
using conditional_cshake = std::conditional_t<is_usual_cshake(FunctionName, CustomizationString), shake_base<ShakeType>, shake_for_cshake<ShakeType>>;

template <auto ShakeType, auto FunctionName = ""_s, auto CustomizationString = ""_s>
struct cshake_base : conditional_cshake<ShakeType, FunctionName, CustomizationString> {
    using base = conditional_cshake<ShakeType, FunctionName, CustomizationString>;
    static inline constexpr auto usual_shake = is_usual_cshake(FunctionName, CustomizationString);

    // usual shake if no args
    cshake_base() requires (usual_shake) = default;
    cshake_base() requires (!usual_shake) {
        bytepad([&]() {
            encode_string(FunctionName);
            encode_string(CustomizationString);
        });
    }

private:
    static auto len_size(auto &&size) {
        u8 size1{};
        auto sz = size;
        while (sz) {
            sz >>= 8;
            ++size1;
        }
        if (size1 == 0) size1 = 1;
        return size1;
    }
    auto update_size(auto &&size, u8 size1) {
        while (size1--) {
            u8 sz = *(((u8 *)&size) + size1);
            base::update(&sz, 1);
        }
    }
protected:
    auto left_encode(auto &&size) {
        auto size1 = len_size(size);
        base::update(&size1, sizeof(size1));
        update_size(size, size1);
    }
    auto right_encode(auto &&size) {
        auto size1 = len_size(size);
        update_size(size, size1);
        base::update(&size1, sizeof(size1));
    }
    auto encode_string(auto &&x) {
        left_encode(x.size() * 8);
        base::update(x);
    }
    auto bytepad(auto &&f) {
        left_encode(base::rate_bytes);
        f();
        if (base::blockpos) {
            array<base::rate_bytes> z{};
            base::update(z.data(), z.size() - base::blockpos);
        }
    }
};

template <auto ShakeType, auto FunctionName = ""_s, auto CustomizationString = ""_s> struct cshake;

template <auto FunctionName, auto CustomizationString>
struct cshake<128, FunctionName, CustomizationString> : cshake_base<128, FunctionName, CustomizationString> {};
template <auto FunctionName, auto CustomizationString>
struct cshake<256, FunctionName, CustomizationString> : cshake_base<256, FunctionName, CustomizationString> {};

constexpr auto kmac_function_id = "KMAC"_s;
constexpr auto tuple_hash_function_id = "TupleHash"_s;
constexpr auto parallel_hash_function_id = "ParallelHash"_s;

// some operations should not be available (i.e. misuse is possible atm?)
// kmac should not have base::squeeze and finalize
// also base for tuple_hash
template <auto ShakeType, auto FunctionName, auto CustomizationString = ""_s, bool XOF = false>
struct kmac_base : cshake_base<ShakeType, FunctionName, CustomizationString> {
    using base = cshake_base<ShakeType, FunctionName, CustomizationString>;
    static inline constexpr auto KMAC = FunctionName == kmac_function_id;
    static inline constexpr auto TupleHash = FunctionName == tuple_hash_function_id;
    static inline constexpr auto ParallelHash = FunctionName == parallel_hash_function_id;

    kmac_base() requires (TupleHash || ParallelHash) = default;
    kmac_base(bytes_concept key = {}) requires (KMAC) {
        base::bytepad([&]() {
            base::encode_string(key);
        });
    }
    template <auto Bits> requires (!XOF)
        auto digest() noexcept {
        finalize1<Bits>();
        array<Bits / 8> hash;
        base::squeeze(hash);
        return hash;
    }
    auto finalize() noexcept requires (XOF) {
        finalize1<0>();
    }
    void update(auto &&t) requires (KMAC) {
        base::update(t.data(), t.size());
    }
    void update(auto &&t, auto &&...args) requires (TupleHash) {
        base::encode_string(t);
        (base::encode_string(args), ...);
    }
    // block_size_bytes also can be up to 2^2040
    void update(auto &&data, size_t block_size_bytes) requires (ParallelHash) {
        auto n = divceil(data.size(), block_size_bytes);
        auto B = block_size_bytes;
        base::left_encode(B);
        auto p = data.data();
        auto end = p + data.size();
        while (p < end) {
            cshake<ShakeType> s;
            s.update(bytes_concept{p,std::min(B,(decltype(B))(end-p))});
            s.finalize();
            auto r = s.template squeeze<ShakeType * 2>();
            base::update(r.data(), r.size());
            p += B;
        }
        base::right_encode(n);
    }
private:
    template <auto Bits>
    auto finalize1() noexcept {
        base::right_encode(Bits);
        base::finalize();
    }
};

template <auto ShakeType, auto CustomizationString = ""_s> struct kmac;
template <auto ShakeType, auto CustomizationString = ""_s> struct kmac_xof;

template <auto CustomizationString>
struct kmac<128, CustomizationString> : kmac_base<128, kmac_function_id, CustomizationString> {
    using base = kmac_base<128, kmac_function_id, CustomizationString>;
    using base::base;
};
template <auto CustomizationString>
struct kmac<256, CustomizationString> : kmac_base<256, kmac_function_id, CustomizationString> {
    using base = kmac_base<256, kmac_function_id, CustomizationString>;
    using base::base;
};

template <auto CustomizationString>
struct kmac_xof<128, CustomizationString> : kmac_base<128, kmac_function_id, CustomizationString, true> {
    using base = kmac_base<128, kmac_function_id, CustomizationString, true>;
    using base::base;
};
template <auto CustomizationString>
struct kmac_xof<256, CustomizationString> : kmac_base<256, kmac_function_id, CustomizationString, true> {
    using base = kmac_base<256, kmac_function_id, CustomizationString, true>;
    using base::base;
};

template <auto ShakeType, auto CustomizationString = ""_s> struct tuple_hash;
template <auto ShakeType, auto CustomizationString = ""_s> struct tuple_hash_xof;

template <auto CustomizationString>
struct tuple_hash<128, CustomizationString> : kmac_base<128, tuple_hash_function_id, CustomizationString> {};
template <auto CustomizationString>
struct tuple_hash<256, CustomizationString> : kmac_base<256, tuple_hash_function_id, CustomizationString> {};

template <auto CustomizationString>
struct tuple_hash_xof<128, CustomizationString> : kmac_base<128, tuple_hash_function_id, CustomizationString, true> {};
template <auto CustomizationString>
struct tuple_hash_xof<256, CustomizationString> : kmac_base<256, tuple_hash_function_id, CustomizationString, true> {};

template <auto ShakeType, auto CustomizationString = ""_s> struct parallel_hash;
template <auto ShakeType, auto CustomizationString = ""_s> struct parallel_hash_xof;

template <auto CustomizationString>
struct parallel_hash<128, CustomizationString> : kmac_base<128, parallel_hash_function_id, CustomizationString> {};
template <auto CustomizationString>
struct parallel_hash<256, CustomizationString> : kmac_base<256, parallel_hash_function_id, CustomizationString> {};

template <auto CustomizationString>
struct parallel_hash_xof<128, CustomizationString> : kmac_base<128, parallel_hash_function_id, CustomizationString, true> {};
template <auto CustomizationString>
struct parallel_hash_xof<256, CustomizationString> : kmac_base<256, parallel_hash_function_id, CustomizationString, true> {};

} // namespace crypto
