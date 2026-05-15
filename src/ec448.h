#pragma once

#include "ec25519_impl.h"
#include "random.h"

namespace crypto {

namespace ec::curve448 {

array_little<56> x448(bigint k, bigint u) {
    static auto p = []() {
        bigint two{2};
        return two.pow(448) - two.pow(224) - 1;
    }();
    constexpr auto a24 = 39081;
    bigint x_1 = u;
    bigint x_2 = 1;
    bigint z_2 = 0;
    bigint x_3 = u;
    bigint z_3 = 1;
    u8 swap = 0;

    //buf[0] &= 0xfc;
    //buf[55] |= 0x80;
    mpz_setbit(k, 447); // |= 0x80
    mpz_clrbit(k, 0); // &= 0xfc
    mpz_clrbit(k, 1);

    // not const time atm
    auto cond_swap = [&](auto &a, auto &b) {
        if (swap) {
            std::swap(a, b);
        }
    };

    for (int16_t t = 448 - 1; t >= 0; --t) {
        auto k_t = k.bit(t);
        swap ^= k_t;

        cond_swap(x_2, x_3);
        cond_swap(z_2, z_3);
        swap = k_t;

        auto A = (x_2 + z_2) % p;
        auto AA = A * A % p;
        auto B = (x_2 - z_2) % p;
        auto BB = B * B % p;
        auto E = AA - BB;
        auto C = x_3 + z_3;
        auto D = x_3 - z_3;
        auto DA = D * A % p;
        auto CB = C * B % p;
        x_3 = (DA + CB) * (DA + CB) % p;
        z_3 = x_1 * (DA - CB) * (DA - CB) % p;
        x_2 = AA * BB % p;
        z_2 = E * (AA + E * a24) % p;
    }

    cond_swap(x_2, x_3);
    cond_swap(z_2, z_3);

    // is it correct?
    auto res = x_2 * z_2.powm(p-2, p) % p;
    return res;
}

} // namespace ec::curve448

auto curve448_f(auto &&private_key) {
    static const unsigned char kBasePoint[56] = { 5 };
    return ec::curve448::x448(bytes_to_bigint(private_key, -1), bytes_to_bigint(kBasePoint, -1));
}

auto curve448_f(auto &&private_key, auto &&peer_public_key) {
    return ec::curve448::x448(bytes_to_bigint(private_key, -1), bytes_to_bigint(peer_public_key, -1));
}

// also x448 (x for x point only)
struct curve448 {
    static inline constexpr auto key_size = 56;
    using private_key_type = array<key_size>;
    using public_key_type = private_key_type;

    private_key_type private_key_;

    void private_key() { get_random_secure_bytes(private_key_); }
    auto public_key() {
        return curve448_f(private_key_);
    }
    auto public_key(auto &&out) {
        out = curve448_f(private_key_);
    }
    auto shared_secret(const public_key_type &peer_public_key) {
        return curve448_f(private_key_, peer_public_key);
    }
    auto shared_secret(auto &&peer_public_key) {
        if (peer_public_key.size() != sizeof(public_key_type)) {
            throw std::runtime_error{ "invalid pubk size" };
        }
        return curve448_f(private_key_, peer_public_key);
    }
};
using x448 = curve448;

}
