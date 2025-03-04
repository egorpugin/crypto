#pragma once

namespace crypto {

template <auto k, auto n1, auto du, auto dv>
struct mlkem_base {
    static inline constexpr auto n = 256;
    static inline constexpr auto q = 3329;
    static inline constexpr auto n2 = 2;

    static inline constexpr auto privkey_size = k * 12 * 32;
    static inline constexpr auto pubkey_size = privkey_size + 32;
};

template <auto> struct mlkem;

template <> struct mlkem<512>  : mlkem_base<2,3,10,4> {};
template <> struct mlkem<768>  : mlkem_base<3,2,10,4> {};
template <> struct mlkem<1024> : mlkem_base<4,2,11,5> {};

}
