// parts are from https://github.com/itzmeanjan/ml-dsa
// MIT license

#pragma once

#include "sha3.h"

// TODO: SLH-DSA?

namespace crypto {

// Prime field arithmetic over Z_q s.t. q = 2^23 - 2^13 + 1
namespace ml_dsa_field {

// ML-DSA Prime Field Modulus
static constexpr uint32_t Q = (1u << 23) - (1u << 13) + 1u;

// Bit width of ML-DSA Prime Field Modulus ( = 23 )
static constexpr size_t Q_BIT_WIDTH = std::bit_width(Q);

// Precomputed Barrett Reduction Constant
//
// Note,
//
// k = ceil(log2(Q)) = 23
// r = floor((1 << 2k) / Q) = 8396807
//
// See https://www.nayuki.io/page/barrett-reduction-algorithm for more.
static constexpr uint32_t R = (1ull << (2 * Q_BIT_WIDTH)) / Q;

// ML-DSA Prime Field element e ∈ [0, Q), with arithmetic operations defined & implemented over it.
struct zq_t {
public:
    // Constructor(s)
    inline constexpr zq_t() = default;
    inline constexpr zq_t(const uint32_t val /* val ∈ [0, Q) */) { v = val; }
    static inline constexpr zq_t from_non_reduced(const uint32_t val /* val ∈ [0, 2^32) */) { return barrett_reduce(val); }

    // Accessor
    inline constexpr uint32_t raw() const { return this->v; }

    static inline constexpr zq_t zero() { return zq_t(0u); }
    static inline constexpr zq_t one() { return zq_t(1u); }

    // Modulo Addition
    inline constexpr zq_t operator+(const zq_t rhs) const { return reduce_once(this->v + rhs.v); }
    inline constexpr void operator+=(const zq_t rhs) { *this = *this + rhs; }

    // Modulo Negation and subtraction
    inline constexpr zq_t operator-() const { return Q - this->v; }
    inline constexpr zq_t operator-(const zq_t rhs) const { return *this + (-rhs); }
    inline constexpr void operator-=(const zq_t rhs) { *this = *this - rhs; }

    // Modulo Multiplication
    inline constexpr zq_t operator*(const zq_t rhs) const {
#ifdef __SIZEOF_INT128__
        __extension__ using uint128_t = unsigned __int128;

        const uint64_t t = static_cast<uint64_t>(this->v) * static_cast<uint64_t>(rhs.v); // (23+23) significant bits, from LSB
        const uint128_t tR = static_cast<uint128_t>(t) * static_cast<uint128_t>(R);       // (23+23+24) significant bits, from LSB

        const uint64_t res = static_cast<uint64_t>(tR >> 46); // 24 significant bits, from LSB
        const uint64_t resQ = res * static_cast<uint64_t>(Q); // (24+23) significant bits, from LSB

        const uint32_t reduced = reduce_once(static_cast<uint32_t>(t - resQ));
        return reduced;
#else
        const uint64_t t0 = static_cast<uint64_t>(this->v);
        const uint64_t t1 = static_cast<uint64_t>(rhs.v);
        const uint64_t t2 = t0 * t1;

        // operand 0
        const uint64_t t2_hi = t2 >> 32;
        const uint64_t t2_lo = t2 & 0xfffffffful;

        // operand 1
        constexpr uint64_t r_hi = 0ul;
        constexpr uint64_t r_lo = static_cast<uint64_t>(R);

        const uint64_t hi = t2_hi * r_hi;                 // high bits
        const uint64_t mid = t2_hi * r_lo + t2_lo * r_hi; // mid bits
        const uint64_t lo = t2_lo * r_lo;                 // low bits

        const uint64_t mid_hi = mid >> 32;          // high 32 -bits of mid
        const uint64_t mid_lo = mid & 0xfffffffful; // low 32 -bits of mid

        const uint64_t t3 = lo >> 32;
        const uint64_t t4 = t3 + mid_lo;
        const uint64_t carry = t4 >> 32;

        const uint64_t res_hi = hi + mid_hi + carry;
        const uint64_t res_lo = lo + (mid_lo << 32);

        // It must be the case that,
        //
        // if   t3 = t2 * R
        // then ((res_hi << 64) | res_lo) == t3
        //
        // Though result is 128 -bit, with two limbs ( such as res_hi and res_lo ),
        // representing lower & higher 64 -bits, only lower (23 + 23 + 24) -bits are
        // of significance.
        //
        // t0 -> 23 -bit number
        // t1 -> 23 -bit number
        // t2 -> (23 + 23) -bit number      | t2 = t0 * t1
        // R -> 24 -bit number
        // t3 -> (23 + 23 + 24) -bit number | t3 = t2 * R
        //
        // Now we can drop lower 46 -bits of 128 -bit result ( remember, which has
        // only 70 significant bits ) & keep 24 -bits of interest, in res, see
        // below.

        const uint64_t res = ((res_hi & 0x3ful) << 18) | (res_lo >> 46);
        const uint64_t t5 = res * static_cast<uint64_t>(Q);
        const uint32_t t6 = static_cast<uint32_t>(t2 - t5);

        const uint32_t t7 = reduce_once(t6);
        return zq_t(t7);
#endif
    }
    inline constexpr void operator*=(const zq_t rhs) { *this = *this * rhs; }

    // Modulo Exponentiation
    inline constexpr zq_t operator^(const size_t n) const {
        zq_t base = *this;

        const zq_t br[]{ zq_t(1), base };
        zq_t res = br[n & 0b1ul];

        const size_t zeros = std::countl_zero(n);
        const size_t till = 64ul - zeros;

        for (size_t i = 1; i < till; i++) {
            base = base * base;

            const zq_t br[]{ zq_t(1), base };
            res = res * br[(n >> i) & 0b1ul];
        }

        return res;
    }

    // Modulo multiplicative inverse and division
    inline constexpr zq_t inv() const { return *this ^ static_cast<size_t>(Q - 2); }
    inline constexpr zq_t operator/(const zq_t rhs) const { return *this * rhs.inv(); }

    // Comparison operations, see https://en.cppreference.com/w/cpp/language/default_comparisons
    inline constexpr auto operator<=>(const zq_t &) const = default;

    // Modulo left shift by `l` -bits
    inline constexpr zq_t operator<<(const size_t l) const { return zq_t(this->v << l); }

    // Generate a random field element
    /*static inline zq_t random(randomshake::randomshake_t<> &csprng) {
        uint32_t res = 0;
        csprng.generate(std::span(reinterpret_cast<uint8_t *>(&res), sizeof(res)));
        return zq_t::from_non_reduced(res);
    }*/

private:
    // Underlying value held in this type.
    //
    // Note, v is always kept in its canonical form i.e. v ∈ [0, Q).
    uint32_t v = 0u;

    // Given a 32 -bit unsigned integer value v, this routine can be used for
    // reducing it by modulo prime Q = 2^23 - 2^13 + 1, computing v' ∈ [0, Q),
    // without using division/ modulo division operator.
    //
    // ∀ v ∈ [0, 2^32), barrett_reduce(v) == (v % Q) - must hold !
    static inline constexpr uint32_t barrett_reduce(const uint32_t val) {
        constexpr uint32_t mask23 = (1u << 23) - 1u;
        constexpr uint32_t mask13 = (1u << 13) - 1u;
        constexpr uint32_t u23_max = mask23;

        const uint32_t hi = val >> 23;
        const uint32_t lo = val & mask23;

        const uint32_t t0 = (hi << 13) - hi;
        const uint32_t t1 = t0 + lo;
        const bool flg0 = t0 > (u23_max - lo);
        const uint32_t t2 = (0u - static_cast<uint32_t>(flg0)) & mask13;
        const uint32_t t3 = t1 + t2;
        const uint32_t t4 = t3 & mask23;

        const uint32_t t5 = reduce_once(t4);
        return t5;
    }

    // Given a 32 -bit unsigned integer `v` such that `v` ∈ [0, 2*Q), this routine can be invoked for reducing `v` modulo prime Q.
    static inline constexpr uint32_t reduce_once(const uint32_t val) {
        const uint32_t t0 = val - Q;
        const uint32_t t1 = 0u - (t0 >> 31);
        const uint32_t t2 = t1 & Q;
        const uint32_t t3 = t0 + t2;

        return t3;
    }
};

}

// Auxiliary functions used for extracting out high/ low order bits and making/ using hint bits.
namespace ml_dsa_reduction {

// Given an element of Z_q, this routine extracts out high and low order bits s.t.
//
// `r = hi * 2^D + lo (mod q)`
//
// This routine is used for compressing public key.
//
// See algorithm 35 of ML-DSA specification https://doi.org/10.6028/NIST.FIPS.204.
// This implementation collects some ideas from https://github.com/pq-crystals/dilithium/blob/3e9b9f1/ref/rounding.c#L5-L23.
template<size_t d>
static inline constexpr std::pair<ml_dsa_field::zq_t, ml_dsa_field::zq_t>
power2round(const ml_dsa_field::zq_t r) {
    constexpr uint32_t max = 1u << (d - 1);

    const uint32_t t1 = r.raw() + max - 1u;
    const uint32_t t2 = t1 >> d;
    const uint32_t t3 = t2 << d;

    const ml_dsa_field::zq_t hi{ t2 };
    const ml_dsa_field::zq_t lo = r - ml_dsa_field::zq_t{ t3 };

    return std::make_pair(hi, lo);
}

// Given an element of Z_q, this routine computes high and low order bits s.t.
//
// `r mod^+ q = r1 * alpha + r0 | -alpha/2 < r0 <= alpha/2`
//
// If r1 = (q - 1)/ alpha then r1 = 0; r0 = r0 - 1
//
// See algorithm 36 of ML-DSA specification https://doi.org/10.6028/NIST.FIPS.204.
template<uint32_t alpha>
static inline constexpr std::pair<ml_dsa_field::zq_t, ml_dsa_field::zq_t>
decompose(const ml_dsa_field::zq_t r) {
    constexpr uint32_t t0 = alpha >> 1;
    constexpr uint32_t t1 = ml_dsa_field::Q - 1u;

    const uint32_t t2 = r.raw() + t0 - 1u;
    const uint32_t t3 = t2 / alpha;
    const uint32_t t4 = t3 * alpha;

    const ml_dsa_field::zq_t r0 = r - ml_dsa_field::zq_t{ t4 };
    const ml_dsa_field::zq_t t5 = r - r0;

    const bool flg = !static_cast<bool>(t5.raw() ^ t1);
    const ml_dsa_field::zq_t br[]{ ml_dsa_field::zq_t(t5.raw() / alpha), ml_dsa_field::zq_t::zero() };

    const ml_dsa_field::zq_t r1 = br[flg];
    const ml_dsa_field::zq_t r0_ = r0 - ml_dsa_field::zq_t{ 1u * flg };

    return std::make_pair(r1, r0_);
}

// Given an element ∈ Z_q, this routine extracts out high order bits of r.
// See algorithm 37 of ML-DSA specification https://doi.org/10.6028/NIST.FIPS.204.
template<uint32_t alpha>
static inline constexpr ml_dsa_field::zq_t
highbits(const ml_dsa_field::zq_t r) {
    const auto s = decompose<alpha>(r);
    return s.first;
}

// Given an element ∈ Z_q, this routine extracts out low order bits of r.
// See algorithm 38 of ML-DSA specification https://doi.org/10.6028/NIST.FIPS.204.
template<uint32_t alpha>
static inline constexpr ml_dsa_field::zq_t
lowbits(const ml_dsa_field::zq_t r) {
    const auto s = decompose<alpha>(r);
    return s.second;
}

// This algorithm takes `r`, `z` ∈ Z_q, producing a 1 -bit hint `h` such that it allows one to compute the higher order
// bits of `r + z` just using `r` and `h`.
//
// This hint is essentially the “carry” caused by `z` in the addition. Note, `z` is small.
// See algorithm 39 of ML-DSA specification https://doi.org/10.6028/NIST.FIPS.204.
template<uint32_t alpha>
static inline constexpr ml_dsa_field::zq_t
make_hint(const ml_dsa_field::zq_t z, const ml_dsa_field::zq_t r) {
    const ml_dsa_field::zq_t r1 = highbits<alpha>(r);
    const ml_dsa_field::zq_t v1 = highbits<alpha>(r + z);

    return ml_dsa_field::zq_t{ static_cast<uint32_t>(r1 != v1) };
}

// 1 -bit hint ( read `h` ) is used to recover higher order bits of `r + z`.
// See algorithm 40 of ML-DSA algorithm https://doi.org/10.6028/NIST.FIPS.204.
template<uint32_t alpha>
static inline constexpr ml_dsa_field::zq_t
use_hint(const ml_dsa_field::zq_t h, const ml_dsa_field::zq_t r) {
    constexpr uint32_t m = (ml_dsa_field::Q - 1) / alpha;
    constexpr ml_dsa_field::zq_t t0{ alpha >> 1 };
    constexpr ml_dsa_field::zq_t t1 = ml_dsa_field::zq_t{ ml_dsa_field::Q } - t0;
    constexpr auto one = ml_dsa_field::zq_t::one();

    const auto s = decompose<alpha>(r);

    if ((h == one) && ((s.second > ml_dsa_field::zq_t::zero()) && (s.second < t1))) {
        const bool flg = s.first == ml_dsa_field::zq_t{ m - 1u };
        const ml_dsa_field::zq_t br[]{ s.first + one, ml_dsa_field::zq_t{ 0u } };

        return br[flg];
    } else if ((h == one) && (s.second >= t1)) {
        const bool flg = s.first == ml_dsa_field::zq_t{ 0u };
        const ml_dsa_field::zq_t br[]{ s.first - one, ml_dsa_field::zq_t{ m - 1 } };

        return br[flg];
    } else {
        return s.first;
    }
}

}

// Compile-time executable functions, ensuring that ML-DSA routines are always invoked with proper arguments.
namespace ml_dsa_params {

// Compile-time check to ensure that *s*ignificant *b*it *w*idth (sbw) of Z_q element doesn't cross maximum bit width of
// field prime q ( = 2^23 - 2^13 + 1 ).
consteval bool
check_sbw(const size_t sbw) {
    return sbw <= ml_dsa_field::Q_BIT_WIDTH;
}

// Compile-time check to ensure that eta ∈ {2, 4}, so that sampled secret key range stays short i.e. [-eta, eta].
consteval bool
check_eta(const uint32_t eta) {
    return (eta == 2u) || (eta == 4u);
}

// Compile-time check to ensure that starting nonce belongs to allowed set of values when uniform sampling polynomial
// coefficients in [-eta, eta].
consteval bool
check_nonce(const size_t nonce) {
    return (nonce == 0) || (nonce == 4) || (nonce == 5) || (nonce == 7);
}

// Compile-time check to ensure that gamma1 has recommended value.
consteval bool
check_gamma1(const uint32_t gamma1) {
    return (gamma1 == (1u << 17)) || (gamma1 == (1u << 19));
}

// Compile-time check to ensure that gamma2 has recommended value.
consteval bool
check_gamma2(const uint32_t gamma2) {
    return (gamma2 == ((ml_dsa_field::Q - 1) / 88)) || (gamma2 == ((ml_dsa_field::Q - 1) / 32));
}

// Compile-time check to ensure that tau is set to parameter recommended in ML-DSA specification.
consteval bool
check_tau(const uint32_t tau) {
    return (tau == 39) || (tau == 49) || (tau == 60);
}

// Compile-time check to ensure that number of bits to be dropped from a polynomial coefficient is supplied correctly.
consteval bool
check_d(const size_t d) {
    return d == 13;
}

// Compile-time check to ensure that operand matrices are having compatible dimension for matrix multiplication.
consteval bool
check_matrix_dim(const size_t a_cols, const size_t b_rows) {
    return !static_cast<bool>(a_cols ^ b_rows);
}

}

// Number Theoretic Transform for degree-255 polynomial
namespace ml_dsa_ntt {

static constexpr size_t LOG2N = 8;
static constexpr size_t N = 1 << LOG2N;

// First primitive 512 -th root of unity modulo q
static constexpr ml_dsa_field::zq_t zeta(1753);
static_assert((zeta ^ 512) == ml_dsa_field::zq_t::one(), "zeta must be 512th root of unity modulo Q");

// Multiplicative inverse of N over Z_q
static constexpr auto INV_N = ml_dsa_field::zq_t(N).inv();

// Given a 64 -bit unsigned integer, this routine extracts specified many contiguous bits from LSB ( least significant
// bits ) side & reverses their bit order, returning bit reversed `mbw` -bit wide number.
//
// See https://github.com/itzmeanjan/kyber/blob/3cd41a5/include/ntt.hpp#L74-L93 for source of inspiration.
template<size_t mbw>
static inline constexpr size_t
bit_rev(const size_t v)
    requires(mbw == LOG2N) {
    size_t v_rev = 0ul;

    for (size_t i = 0; i < mbw; i++) {
        const size_t bit = (v >> i) & 0b1;
        v_rev ^= bit << (mbw - 1ul - i);
    }

    return v_rev;
}

// Precomputed table of powers of zeta, used during polynomial evaluation.
static constexpr auto zeta_EXP = []() {
    std::array<ml_dsa_field::zq_t, N> res;

    for (size_t i = 0; i < N; i++) {
        res[i] = zeta ^ bit_rev<LOG2N>(i);
    }

    return res;
    }();

// Precomputed table of negated powers of zeta, used during polynomial interpolation.
static constexpr auto zeta_NEG_EXP = []() {
    std::array<ml_dsa_field::zq_t, N> res;

    for (size_t i = 0; i < N; i++) {
        res[i] = -zeta_EXP[i];
    }

    return res;
    }();

// Given a polynomial f with 256 coefficients over Z_q, this routine computes number theoretic transform using
// Cooley-Tukey algorithm, producing polynomial f' s.t. its coefficients are placed in bit-reversed order.
//
// Note, this routine mutates input i.e. it's an in-place NTT implementation.
//
// Implementation inspired from https://github.com/itzmeanjan/kyber/blob/3cd41a5/include/ntt.hpp#L95-L129.
// See algorithm 41 of ML-DSA standard https://doi.org/10.6028/NIST.FIPS.204.
static inline constexpr void
ntt(std::span<ml_dsa_field::zq_t, N> poly) {
#if (not defined __clang__) && (defined __GNUG__)
#pragma GCC unroll 8
#endif
    for (int64_t l = LOG2N - 1; l >= 0; l--) {
        const size_t len = 1ul << l;
        const size_t lenx2 = len << 1;
        const size_t k_beg = N >> (l + 1);

        for (size_t start = 0; start < poly.size(); start += lenx2) {
            const size_t k_now = k_beg + (start >> (l + 1));
            const ml_dsa_field::zq_t zeta_exp = zeta_EXP[k_now];

#if (not defined __clang__) && (defined __GNUG__)
#pragma GCC unroll 4
#pragma GCC ivdep
#endif
            for (size_t i = start; i < start + len; i++) {
                auto tmp = zeta_exp * poly[i + len];

                poly[i + len] = poly[i] - tmp;
                poly[i] += tmp;
            }
        }
    }
}

// Given a polynomial f with 256 coefficients over Z_q, s.t. its coefficients are placed in bit-reversed order, this
// routine computes inverse number theoretic transform using Gentleman-Sande algorithm, producing polynomial f' s.t. its
// coefficients are placed in standard order.
//
// Note, this routine mutates input i.e. it's an in-place iNTT implementation.
//
// Implementation inspired from https://github.com/itzmeanjan/kyber/blob/3cd41a5/include/ntt.hpp#L131-L172.
// See algorithm 42 of ML-DSA standard https://doi.org/10.6028/NIST.FIPS.204.
static inline constexpr void
intt(std::span<ml_dsa_field::zq_t, N> poly) {
#if (not defined __clang__) && (defined __GNUG__)
#pragma GCC unroll 8
#endif
    for (size_t l = 0; l < LOG2N; l++) {
        const size_t len = 1ul << l;
        const size_t lenx2 = len << 1;
        const size_t k_beg = (N >> l) - 1;

        for (size_t start = 0; start < poly.size(); start += lenx2) {
            const size_t k_now = k_beg - (start >> (l + 1));
            const ml_dsa_field::zq_t neg_zeta_exp = zeta_NEG_EXP[k_now];

#if (not defined __clang__) && (defined __GNUG__)
#pragma GCC unroll 4
#pragma GCC ivdep
#endif
            for (size_t i = start; i < start + len; i++) {
                const auto tmp = poly[i];

                poly[i] += poly[i + len];
                poly[i + len] = tmp - poly[i + len];
                poly[i + len] *= neg_zeta_exp;
            }
        }
    }

    for (size_t i = 0; i < poly.size(); i++) {
        poly[i] *= INV_N;
    }
}

}

// Bit packing/ unpacking -related utility functions
namespace ml_dsa_bit_packing {

// Given a degree-255 polynomial, where significant portion of each coefficient ∈ [0, 2^sbw), this
// routine serializes the polynomial to a byte array of length 32 * sbw -bytes.
//
// See algorithm 16 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
template<size_t sbw>
static inline constexpr void
encode(std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N> poly, std::span<uint8_t, (ml_dsa_ntt::N *sbw) / std::numeric_limits<uint8_t>::digits> arr)
    requires(ml_dsa_params::check_sbw(sbw)) {
    std::fill(arr.begin(), arr.end(), 0);

    if constexpr (sbw == 3) {
        constexpr size_t itr_cnt = poly.size() >> 3;
        constexpr uint32_t mask3 = 0b111u;
        constexpr uint32_t mask2 = mask3 >> 1;
        constexpr uint32_t mask1 = mask2 >> 1;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 3;
            const size_t boff = i * 3;

            arr[boff + 0] = (static_cast<uint8_t>(poly[poff + 2].raw() & mask2) << 6) | (static_cast<uint8_t>(poly[poff + 1].raw() & mask3) << 3) |
                (static_cast<uint8_t>(poly[poff + 0].raw() & mask3) << 0);
            arr[boff + 1] = (static_cast<uint8_t>(poly[poff + 5].raw() & mask1) << 7) | (static_cast<uint8_t>(poly[poff + 4].raw() & mask3) << 4) |
                (static_cast<uint8_t>(poly[poff + 3].raw() & mask3) << 1) | static_cast<uint8_t>((poly[poff + 2].raw() >> 2) & mask1);
            arr[boff + 2] = (static_cast<uint8_t>(poly[poff + 7].raw() & mask3) << 5) | (static_cast<uint8_t>(poly[poff + 6].raw() & mask3) << 2) |
                static_cast<uint8_t>((poly[poff + 5].raw() >> 1) & mask2);
        }
    } else if constexpr (sbw == 4) {
        constexpr size_t itr_cnt = poly.size() >> 1;
        constexpr uint32_t mask = 0b1111u;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t off = i << 1;
            const uint8_t byte = (static_cast<uint8_t>(poly[off + 1].raw() & mask) << 4) | (static_cast<uint8_t>(poly[off + 0].raw() & mask) << 0);

            arr[i] = byte;
        }
    } else if constexpr (sbw == 6) {
        constexpr size_t itr_cnt = poly.size() >> 2;
        constexpr uint32_t mask6 = 0b111111u;
        constexpr uint32_t mask4 = mask6 >> 2;
        constexpr uint32_t mask2 = mask4 >> 2;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 2;
            const size_t boff = i * 3;

            arr[boff + 0] = (static_cast<uint8_t>(poly[poff + 1].raw() & mask2) << 6) | (static_cast<uint8_t>(poly[poff + 0].raw() & mask6) << 0);
            arr[boff + 1] = (static_cast<uint8_t>(poly[poff + 2].raw() & mask4) << 4) | static_cast<uint8_t>((poly[poff + 1].raw() >> 2) & mask4);
            arr[boff + 2] = (static_cast<uint8_t>(poly[poff + 3].raw() & mask6) << 2) | static_cast<uint8_t>((poly[poff + 2].raw() >> 4) & mask2);
        }
    } else if constexpr (sbw == 10) {
        constexpr size_t itr_cnt = poly.size() >> 2;
        constexpr uint32_t mask6 = 0b111111u;
        constexpr uint32_t mask4 = mask6 >> 2;
        constexpr uint32_t mask2 = mask4 >> 2;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 2;
            const size_t boff = i * 5;

            arr[boff + 0] = static_cast<uint8_t>(poly[poff + 0].raw());
            arr[boff + 1] = static_cast<uint8_t>((poly[poff + 1].raw() & mask6) << 2) | static_cast<uint8_t>((poly[poff + 0].raw() >> 8) & mask2);
            arr[boff + 2] = static_cast<uint8_t>((poly[poff + 2].raw() & mask4) << 4) | static_cast<uint8_t>((poly[poff + 1].raw() >> 6) & mask4);
            arr[boff + 3] = static_cast<uint8_t>((poly[poff + 3].raw() & mask2) << 6) | static_cast<uint8_t>((poly[poff + 2].raw() >> 4) & mask6);
            arr[boff + 4] = static_cast<uint8_t>(poly[poff + 3].raw() >> 2);
        }
    } else if constexpr (sbw == 13) {
        constexpr size_t itr_cnt = poly.size() >> 3;
        constexpr uint32_t mask7 = 0b1111111u;
        constexpr uint32_t mask6 = mask7 >> 1;
        constexpr uint32_t mask5 = mask6 >> 1;
        constexpr uint32_t mask4 = mask5 >> 1;
        constexpr uint32_t mask3 = mask4 >> 1;
        constexpr uint32_t mask2 = mask3 >> 1;
        constexpr uint32_t mask1 = mask2 >> 1;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 3;
            const size_t boff = i * 13;

            arr[boff + 0] = static_cast<uint8_t>(poly[poff + 0].raw());
            arr[boff + 1] = static_cast<uint8_t>((poly[poff + 1].raw() & mask3) << 5) | static_cast<uint8_t>((poly[poff + 0].raw() >> 8) & mask5);
            arr[boff + 2] = static_cast<uint8_t>(poly[poff + 1].raw() >> 3);
            arr[boff + 3] = static_cast<uint8_t>((poly[poff + 2].raw() & mask6) << 2) | static_cast<uint8_t>((poly[poff + 1].raw() >> 11) & mask2);
            arr[boff + 4] = static_cast<uint8_t>((poly[poff + 3].raw() & mask1) << 7) | static_cast<uint8_t>((poly[poff + 2].raw() >> 6) & mask7);
            arr[boff + 5] = static_cast<uint8_t>(poly[poff + 3].raw() >> 1);
            arr[boff + 6] = static_cast<uint8_t>((poly[poff + 4].raw() & mask4) << 4) | static_cast<uint8_t>((poly[poff + 3].raw() >> 9) & mask4);
            arr[boff + 7] = static_cast<uint8_t>(poly[poff + 4].raw() >> 4);
            arr[boff + 8] = static_cast<uint8_t>((poly[poff + 5].raw() & mask7) << 1) | static_cast<uint8_t>((poly[poff + 4].raw() >> 12) & mask1);
            arr[boff + 9] = static_cast<uint8_t>((poly[poff + 6].raw() & mask2) << 6) | static_cast<uint8_t>((poly[poff + 5].raw() >> 7) & mask6);
            arr[boff + 10] = static_cast<uint8_t>(poly[poff + 6].raw() >> 2);
            arr[boff + 11] = static_cast<uint8_t>((poly[poff + 7].raw() & mask5) << 3) | static_cast<uint8_t>((poly[poff + 6].raw() >> 10) & mask3);
            arr[boff + 12] = static_cast<uint8_t>(poly[poff + 7].raw() >> 5);
        }
    } else if constexpr (sbw == 18) {
        constexpr size_t itr_cnt = poly.size() >> 2;
        constexpr uint32_t mask6 = 0b111111u;
        constexpr uint32_t mask4 = mask6 >> 2;
        constexpr uint32_t mask2 = mask4 >> 2;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 2;
            const size_t boff = i * 9;

            arr[boff + 0] = static_cast<uint8_t>(poly[poff + 0].raw());
            arr[boff + 1] = static_cast<uint8_t>(poly[poff + 0].raw() >> 8);
            arr[boff + 2] = static_cast<uint8_t>((poly[poff + 1].raw() & mask6) << 2) | static_cast<uint8_t>((poly[poff + 0].raw() >> 16) & mask2);
            arr[boff + 3] = static_cast<uint8_t>(poly[poff + 1].raw() >> 6);
            arr[boff + 4] = static_cast<uint8_t>((poly[poff + 2].raw() & mask4) << 4) | static_cast<uint8_t>((poly[poff + 1].raw() >> 14) & mask4);
            arr[boff + 5] = static_cast<uint8_t>(poly[poff + 2].raw() >> 4);
            arr[boff + 6] = static_cast<uint8_t>((poly[poff + 3].raw() & mask2) << 6) | static_cast<uint8_t>((poly[poff + 2].raw() >> 12) & mask6);
            arr[boff + 7] = static_cast<uint8_t>(poly[poff + 3].raw() >> 2);
            arr[boff + 8] = static_cast<uint8_t>(poly[poff + 3].raw() >> 10);
        }
    } else if constexpr (sbw == 20) {
        constexpr size_t itr_cnt = poly.size() >> 1;
        constexpr uint32_t mask4 = 0b1111u;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 1;
            const size_t boff = i * 5;

            arr[boff + 0] = static_cast<uint8_t>(poly[poff + 0].raw());
            arr[boff + 1] = static_cast<uint8_t>(poly[poff + 0].raw() >> 8);
            arr[boff + 2] = static_cast<uint8_t>((poly[poff + 1].raw() & mask4) << 4) | static_cast<uint8_t>((poly[poff + 0].raw() >> 16) & mask4);
            arr[boff + 3] = static_cast<uint8_t>(poly[poff + 1].raw() >> 4);
            arr[boff + 4] = static_cast<uint8_t>(poly[poff + 1].raw() >> 12);
        }
    } else {
        for (size_t i = 0; i < arr.size() * 8; i++) {
            const size_t pidx = i / sbw;
            const size_t poff = i % sbw;

            const size_t aidx = i >> 3;
            const size_t aoff = i & 7ul;

            const uint8_t bit = static_cast<uint8_t>((poly[pidx].raw() >> poff) & 0b1);
            arr[aidx] = arr[aidx] ^ (bit << aoff);
        }
    }
}

// Given a byte array of length 32 * sbw -bytes, this routine extracts out 256 coefficients of a degree-255
// polynomial s.t. significant portion of each coefficient ∈ [0, 2^sbw).
//
// This function reverses what `encode` does.
// See algorithm 18 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
template<size_t sbw>
static inline constexpr void
decode(std::span<const uint8_t, ml_dsa_ntt::N *sbw / 8> arr, std::span<ml_dsa_field::zq_t, ml_dsa_ntt::N> poly)
    requires(ml_dsa_params::check_sbw(sbw)) {
    std::fill(poly.begin(), poly.end(), ml_dsa_field::zq_t::zero());

    if constexpr (sbw == 3) {
        constexpr size_t itr_cnt = poly.size() >> 3;
        constexpr uint8_t mask3 = 0b111;
        constexpr uint8_t mask2 = mask3 >> 1;
        constexpr uint8_t mask1 = mask2 >> 1;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 3;
            const size_t boff = i * 3;

            poly[poff + 0] = static_cast<uint32_t>((arr[boff + 0] >> 0) & mask3);
            poly[poff + 1] = static_cast<uint32_t>((arr[boff + 0] >> 3) & mask3);
            poly[poff + 2] = static_cast<uint32_t>((arr[boff + 1] & mask1) << 2) | static_cast<uint32_t>(arr[boff + 0] >> 6);
            poly[poff + 3] = static_cast<uint32_t>((arr[boff + 1] >> 1) & mask3);
            poly[poff + 4] = static_cast<uint32_t>((arr[boff + 1] >> 4) & mask3);
            poly[poff + 5] = static_cast<uint32_t>((arr[boff + 2] & mask2) << 1) | static_cast<uint32_t>(arr[boff + 1] >> 7);
            poly[poff + 6] = static_cast<uint32_t>((arr[boff + 2] >> 2) & mask3);
            poly[poff + 7] = static_cast<uint32_t>(arr[boff + 2] >> 5);
        }
    } else if constexpr (sbw == 4) {
        constexpr size_t itr_cnt = poly.size() >> 1;
        constexpr uint8_t mask = 0b1111;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t off = i << 1;
            const uint8_t byte = arr[i];

            poly[off + 0] = static_cast<uint32_t>((byte >> 0) & mask);
            poly[off + 1] = static_cast<uint32_t>((byte >> 4) & mask);
        }
    } else if constexpr (sbw == 6) {
        constexpr size_t itr_cnt = poly.size() >> 2;
        constexpr uint8_t mask6 = 0b111111;
        constexpr uint8_t mask4 = mask6 >> 2;
        constexpr uint8_t mask2 = mask4 >> 2;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 2;
            const size_t boff = i * 3;

            poly[poff + 0] = static_cast<uint32_t>(arr[boff + 0] & mask6);
            poly[poff + 1] = static_cast<uint32_t>((arr[boff + 1] & mask4) << 2) | static_cast<uint32_t>(arr[boff + 0] >> 6);
            poly[poff + 2] = static_cast<uint32_t>((arr[boff + 2] & mask2) << 4) | static_cast<uint32_t>(arr[boff + 1] >> 4);
            poly[poff + 3] = static_cast<uint32_t>(arr[boff + 2] >> 2);
        }
    } else if constexpr (sbw == 10) {
        constexpr size_t itr_cnt = poly.size() >> 2;
        constexpr uint8_t mask6 = 0b111111;
        constexpr uint8_t mask4 = mask6 >> 2;
        constexpr uint8_t mask2 = mask4 >> 2;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 2;
            const size_t boff = i * 5;

            poly[poff + 0] = (static_cast<uint16_t>(arr[boff + 1] & mask2) << 8) | static_cast<uint16_t>(arr[boff + 0]);
            poly[poff + 1] = (static_cast<uint16_t>(arr[boff + 2] & mask4) << 6) | static_cast<uint16_t>(arr[boff + 1] >> 2);
            poly[poff + 2] = (static_cast<uint16_t>(arr[boff + 3] & mask6) << 4) | static_cast<uint16_t>(arr[boff + 2] >> 4);
            poly[poff + 3] = (static_cast<uint16_t>(arr[boff + 4]) << 2) | static_cast<uint16_t>(arr[boff + 3] >> 6);
        }
    } else if constexpr (sbw == 13) {
        constexpr size_t itr_cnt = poly.size() >> 3;
        constexpr uint8_t mask7 = 0b1111111;
        constexpr uint8_t mask6 = mask7 >> 1;
        constexpr uint8_t mask5 = mask6 >> 1;
        constexpr uint8_t mask4 = mask5 >> 1;
        constexpr uint8_t mask3 = mask4 >> 1;
        constexpr uint8_t mask2 = mask3 >> 1;
        constexpr uint8_t mask1 = mask2 >> 1;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 3;
            const size_t boff = i * 13;

            poly[poff + 0] = (static_cast<uint32_t>(arr[boff + 1] & mask5) << 8) | static_cast<uint32_t>(arr[boff + 0]);
            poly[poff + 1] = (static_cast<uint32_t>(arr[boff + 3] & mask2) << 11) | (static_cast<uint32_t>(arr[boff + 2]) << 3) | static_cast<uint32_t>(arr[boff + 1] >> 5);
            poly[poff + 2] = (static_cast<uint32_t>(arr[boff + 4] & mask7) << 6) | static_cast<uint32_t>(arr[boff + 3] >> 2);
            poly[poff + 3] = (static_cast<uint32_t>(arr[boff + 6] & mask4) << 9) | (static_cast<uint32_t>(arr[boff + 5]) << 1) | static_cast<uint32_t>(arr[boff + 4] >> 7);
            poly[poff + 4] = (static_cast<uint32_t>(arr[boff + 8] & mask1) << 12) | (static_cast<uint32_t>(arr[boff + 7]) << 4) | static_cast<uint32_t>(arr[boff + 6] >> 4);
            poly[poff + 5] = (static_cast<uint32_t>(arr[boff + 9] & mask6) << 7) | static_cast<uint32_t>(arr[boff + 8] >> 1);
            poly[poff + 6] = (static_cast<uint32_t>(arr[boff + 11] & mask3) << 10) | (static_cast<uint32_t>(arr[boff + 10]) << 2) | static_cast<uint32_t>(arr[boff + 9] >> 6);
            poly[poff + 7] = (static_cast<uint32_t>(arr[boff + 12]) << 5) | static_cast<uint32_t>(arr[boff + 11] >> 3);
        }
    } else if constexpr (sbw == 18) {
        constexpr size_t itr_cnt = poly.size() >> 2;
        constexpr uint8_t mask6 = 0b111111;
        constexpr uint8_t mask4 = mask6 >> 2;
        constexpr uint8_t mask2 = mask4 >> 2;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 2;
            const size_t boff = i * 9;

            poly[poff + 0] = (static_cast<uint32_t>(arr[boff + 2] & mask2) << 16) | (static_cast<uint32_t>(arr[boff + 1]) << 8) | static_cast<uint32_t>(arr[boff + 0]);
            poly[poff + 1] = (static_cast<uint32_t>(arr[boff + 4] & mask4) << 14) | (static_cast<uint32_t>(arr[boff + 3]) << 6) | static_cast<uint32_t>(arr[boff + 2] >> 2);
            poly[poff + 2] = (static_cast<uint32_t>(arr[boff + 6] & mask6) << 12) | (static_cast<uint32_t>(arr[boff + 5]) << 4) | static_cast<uint32_t>(arr[boff + 4] >> 4);
            poly[poff + 3] = (static_cast<uint32_t>(arr[boff + 8]) << 10) | (static_cast<uint32_t>(arr[boff + 7]) << 2) | static_cast<uint32_t>(arr[boff + 6] >> 6);
        }
    } else if constexpr (sbw == 20) {
        constexpr size_t itr_cnt = poly.size() >> 1;
        constexpr uint8_t mask4 = 0b1111;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 1;
            const size_t boff = i * 5;

            poly[poff + 0] = (static_cast<uint32_t>(arr[boff + 2] & mask4) << 16) | (static_cast<uint32_t>(arr[boff + 1]) << 8) | static_cast<uint32_t>(arr[boff + 0]);
            poly[poff + 1] = (static_cast<uint32_t>(arr[boff + 4]) << 12) | (static_cast<uint32_t>(arr[boff + 3]) << 4) | static_cast<uint32_t>(arr[boff + 2] >> 4);
        }
    } else {
        for (size_t i = 0; i < arr.size() * 8; i++) {
            const size_t aidx = i >> 3;
            const size_t aoff = i & 7ul;

            const size_t pidx = i / sbw;
            const size_t poff = i % sbw;

            const uint8_t bit = (arr[aidx] >> aoff) & 0b1;
            poly[pidx] = poly[pidx].raw() ^ static_cast<uint32_t>(bit) << poff;
        }
    }
}

// Given a vector of hint bits ( of dimension k x 1 ), this routine encodes hint bits into (omega + k) -bytes.
//
// See algorithm 20 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
template<size_t k, size_t omega>
static inline constexpr void
encode_hint_bits(std::span<const ml_dsa_field::zq_t, k *ml_dsa_ntt::N> h, std::span<uint8_t, omega + k> arr) {
    std::fill(arr.begin(), arr.end(), 0);

    constexpr auto zero = ml_dsa_field::zq_t::zero();
    size_t idx = 0;

    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;

        for (size_t j = 0; j < ml_dsa_ntt::N; j++) {
            const bool flg = h[off + j] != zero;
            const uint8_t br[]{ arr[idx], static_cast<uint8_t>(j) };

            arr[idx] = br[static_cast<size_t>(flg)];
            idx += 1ul * flg;
        }

        arr[omega + i] = idx;
    }
}

// Given a serialized byte array holding hint bits, this routine unpacks hint bits into a vector ( of dimension k x 1 )
// of degree-255 polynomials s.t. <= omega many hint bits are set.
//
// Returns boolean result denoting status of decoding of byte serialized hint bits.
// For example, say return value is true, it denotes that decoding has failed.
//
// See algorithm 21 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
template<size_t k, size_t omega>
static inline constexpr bool
decode_hint_bits(std::span<const uint8_t, omega + k> arr, std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> h) {
    std::fill(h.begin(), h.end(), ml_dsa_field::zq_t::zero());

    size_t idx = 0;
    bool failed = false;

    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;

        const bool flg0 = arr[omega + i] < idx;
        const bool flg1 = arr[omega + i] > omega;
        const bool flg2 = flg0 | flg1;

        failed |= flg2;

        const size_t till = arr[omega + i];
        for (size_t j = idx; !failed && (j < till); j++) {
            const bool flg0 = j > idx;
            const bool flg1 = flg0 & (arr[j] <= arr[j - flg0 * 1]);

            failed |= flg1;

            h[off + arr[j]] = ml_dsa_field::zq_t::one();
        }

        idx = arr[omega + i];
    }

    for (size_t i = idx; i < omega; i++) {
        const bool flg = arr[i] != 0;
        failed |= flg;
    }

    return failed;
}

}

// Degree-255 polynomial arithmetic
namespace ml_dsa_poly {

// Given a degree-255 polynomial, this routine extracts out high and low order bits from each coefficient.
template<size_t d>
static inline constexpr void
power2round(std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N> poly,
    std::span<ml_dsa_field::zq_t, ml_dsa_ntt::N> poly_hi,
    std::span<ml_dsa_field::zq_t, ml_dsa_ntt::N> poly_lo)
    requires(ml_dsa_params::check_d(d)) {
    for (size_t i = 0; i < poly.size(); i++) {
        const auto ext = ml_dsa_reduction::power2round<d>(poly[i]);

        poly_hi[i] = ext.first;
        poly_lo[i] = ext.second;
    }
}

// Given two degree-255 polynomials in NTT representation, this routine performs element-wise multiplication over Z_q.
static inline constexpr void
mul(std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N> polya, std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N> polyb, std::span<ml_dsa_field::zq_t, ml_dsa_ntt::N> polyc) {
#if (not defined __clang__) && (defined __GNUG__)
#pragma GCC unroll 16
#pragma GCC ivdep
#endif
    for (size_t i = 0; i < polya.size(); i++) {
        polyc[i] = polya[i] * polyb[i];
    }
}

// Given a degree-255 polynomial, which has all of its coefficients in [-x, x], this routine subtracts each coefficient
// from x, so that they stay in [0, 2x].
template<uint32_t x>
static inline constexpr void
sub_from_x(std::span<ml_dsa_field::zq_t, ml_dsa_ntt::N> poly) {
    constexpr ml_dsa_field::zq_t x_cap(x);

#if defined __clang__
#pragma clang loop unroll(enable) vectorize(enable) interleave(enable)
#endif
    for (size_t i = 0; i < poly.size(); i++) {
        poly[i] = x_cap - poly[i];
    }
}

// Given a degree-255 polynomial, this routine extracts out high order bits.
template<uint32_t alpha>
static inline constexpr void
highbits(std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N> src, std::span<ml_dsa_field::zq_t, ml_dsa_ntt::N> dst) {
    for (size_t i = 0; i < src.size(); i++) {
        dst[i] = ml_dsa_reduction::highbits<alpha>(src[i]);
    }
}

// Given a degree-255 polynomial, this routine extracts out low order bits.
template<uint32_t alpha>
static inline constexpr void
lowbits(std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N> src, std::span<ml_dsa_field::zq_t, ml_dsa_ntt::N> dst) {
    for (size_t i = 0; i < src.size(); i++) {
        dst[i] = ml_dsa_reduction::lowbits<alpha>(src[i]);
    }
}

// Computes infinity norm of a degree-255 polynomial.
//
// See section 2.3 of ML-DSA standard https://doi.org/10.6028/NIST.FIPS.204.
static inline constexpr ml_dsa_field::zq_t
infinity_norm(std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N> poly) {
    constexpr ml_dsa_field::zq_t qby2(ml_dsa_field::Q / 2);
    auto res = ml_dsa_field::zq_t::zero();

    for (size_t i = 0; i < poly.size(); i++) {
#ifdef __clang__
        if (poly[i] > qby2) {
            res = std::max(res, -poly[i]);
        } else {
            res = std::max(res, poly[i]);
        }
#else
        const bool flg = poly[i] > qby2;
        const ml_dsa_field::zq_t br[]{ poly[i], -poly[i] };

        res = std::max(res, br[flg]);
#endif
    }

    return res;
}

// Given two degree-255 polynomials, this routine computes hint bit for each coefficient.
template<uint32_t alpha>
static inline constexpr void
make_hint(std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N> polya,
    std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N> polyb,
    std::span<ml_dsa_field::zq_t, ml_dsa_ntt::N> polyc) {
    for (size_t i = 0; i < polya.size(); i++) {
        polyc[i] = ml_dsa_reduction::make_hint<alpha>(polya[i], polyb[i]);
    }
}

// Given a hint bit polynomial (of degree-255) and another degree-255 polynomial r with arbitrary coefficients ∈
// Z_q, this routine recovers high order bits of r + z s.t. hint bit was computed using `make_hint` routine and z is
// another degree-255 polynomial with small coefficients.
template<uint32_t alpha>
static inline constexpr void
use_hint(std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N> polyh,
    std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N> polyr,
    std::span<ml_dsa_field::zq_t, ml_dsa_ntt::N> polyrz) {
    for (size_t i = 0; i < polyh.size(); i++) {
        polyrz[i] = ml_dsa_reduction::use_hint<alpha>(polyh[i], polyr[i]);
    }
}

// Given a degree-255 polynomial, this routine counts number of coefficients having value 1.
// Note, following implementation makes an assumption, coefficieints of input polynomial must be either 0 or 1.
// In case, one invokes this function with arbitrary polynomial, expect wrong result.
static inline constexpr size_t
count_1s(std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N> poly) {
    return std::accumulate(poly.begin(), poly.end(), 0ul, [](auto acc, auto cur) -> auto { return acc + cur.raw(); });
}

// Given a degree-255 polynomial, this routine shifts each coefficient leftwards, by d bits.
template<size_t d>
static inline constexpr void
shl(std::span<ml_dsa_field::zq_t, ml_dsa_ntt::N> poly) {
    for (size_t i = 0; i < poly.size(); i++) {
        poly[i] = poly[i] << d;
    }
}

}

// Utility functions applied on vector of degree-255 polynomials
namespace ml_dsa_polyvec {

using const_poly_t = std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N>;
using poly_t = std::span<ml_dsa_field::zq_t, ml_dsa_ntt::N>;

// Applies NTT on a vector ( of dimension k x 1 ) of degree-255 polynomials.
template<size_t k>
static inline constexpr void
ntt(std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> vec) {
    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        ml_dsa_ntt::ntt(poly_t(vec.subspan(off, ml_dsa_ntt::N)));
    }
}

// Applies iNTT on a vector ( of dimension k x 1 ) of degree-255 polynomials.
template<size_t k>
static inline constexpr void
intt(std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> vec) {
    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        ml_dsa_ntt::intt(poly_t(vec.subspan(off, ml_dsa_ntt::N)));
    }
}

// Compresses vector ( of dimension k x 1 ) of degree-255 polynomials by extracting out high and low order bits.
template<size_t k, size_t d>
static inline constexpr void
power2round(std::span<const ml_dsa_field::zq_t, k *ml_dsa_ntt::N> poly,
    std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> poly_hi,
    std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> poly_lo)
    requires(ml_dsa_params::check_d(d)) {
    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        ml_dsa_poly::power2round<d>(const_poly_t(poly.subspan(off, ml_dsa_ntt::N)), poly_t(poly_hi.subspan(off, ml_dsa_ntt::N)), poly_t(poly_lo.subspan(off, ml_dsa_ntt::N)));
    }
}

// Given two matrices ( in NTT domain ) of compatible dimension, where each matrix element is a degree-255 polynomial
// over Z_q, this routine multiplies them, computing resulting matrix.
template<size_t a_rows, size_t a_cols, size_t b_rows, size_t b_cols>
static inline constexpr void
matrix_multiply(std::span<const ml_dsa_field::zq_t, a_rows *a_cols *ml_dsa_ntt::N> a,
    std::span<const ml_dsa_field::zq_t, b_rows *b_cols *ml_dsa_ntt::N> b,
    std::span<ml_dsa_field::zq_t, a_rows *b_cols *ml_dsa_ntt::N> c)
    requires(ml_dsa_params::check_matrix_dim(a_cols, b_rows)) {
    std::array<ml_dsa_field::zq_t, ml_dsa_ntt::N> tmp{};
    auto tmp_span = poly_t(tmp);

    for (size_t i = 0; i < a_rows; i++) {
        for (size_t j = 0; j < b_cols; j++) {
            const size_t coff = (i * b_cols + j) * ml_dsa_ntt::N;

            for (size_t k = 0; k < a_cols; k++) {
                const size_t aoff = (i * a_cols + k) * ml_dsa_ntt::N;
                const size_t boff = (k * b_cols + j) * ml_dsa_ntt::N;

                ml_dsa_poly::mul(const_poly_t(a.subspan(aoff, ml_dsa_ntt::N)), const_poly_t(b.subspan(boff, ml_dsa_ntt::N)), tmp_span);

                for (size_t l = 0; l < tmp_span.size(); l++) {
                    c[coff + l] += tmp_span[l];
                }
            }
        }
    }
}

// Given a vector ( of dimension k x 1 ) of degree-255 polynomials, this routine adds it to another polynomial vector of
// same dimension s.t. destination vector is mutated.
template<size_t k>
static inline constexpr void
add_to(std::span<const ml_dsa_field::zq_t, k *ml_dsa_ntt::N> src, std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> dst) {
    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;

        for (size_t l = 0; l < ml_dsa_ntt::N; l++) {
            dst[off + l] += src[off + l];
        }
    }
}

// Given a vector ( of dimension k x 1 ) of degree-255 polynomials, this routine negates each coefficient.
template<size_t k>
static inline constexpr void
neg(std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> vec) {
    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;

        for (size_t l = 0; l < ml_dsa_ntt::N; l++) {
            vec[off + l] = -vec[off + l];
        }
    }
}

// Given a vector ( of dimension k x 1 ) of degree-255 polynomials s.t. each coefficient ∈ [-x, x], this routine
// subtracts each coefficient from x so that coefficients now stay in [0, 2x].
template<size_t k, uint32_t x>
static inline constexpr void
sub_from_x(std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> vec) {
    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        ml_dsa_poly::sub_from_x<x>(poly_t(vec.subspan(off, ml_dsa_ntt::N)));
    }
}

// Given a vector ( of dimension k x 1 ) of degree-255 polynomials, this routine encodes each of those polynomials into
// 32 x sbw -bytes, writing to a (k x 32 x sbw) -bytes destination array.
template<size_t k, size_t sbw>
static inline constexpr void
encode(std::span<const ml_dsa_field::zq_t, k *ml_dsa_ntt::N> src, std::span<uint8_t, (k *sbw *ml_dsa_ntt::N) / std::numeric_limits<uint8_t>::digits> dst) {
    // Byte length of degree-255 polynomial after serialization
    constexpr size_t poly_blen = dst.size() / k;

    for (size_t i = 0; i < k; i++) {
        const size_t off0 = i * ml_dsa_ntt::N;
        const size_t off1 = i * poly_blen;

        ml_dsa_bit_packing::encode<sbw>(const_poly_t(src.subspan(off0, ml_dsa_ntt::N)), std::span<uint8_t, poly_blen>(dst.subspan(off1, poly_blen)));
    }
}

// Given a byte array of length (k x 32 x sbw) -bytes, this routine decodes them into k degree-255 polynomials, writing
// them to a column vector of dimension k x 1.
template<size_t k, size_t sbw>
static inline constexpr void
decode(std::span<const uint8_t, (k *sbw *ml_dsa_ntt::N) / std::numeric_limits<uint8_t>::digits> src, std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> dst) {
    // Byte length of degree-255 polynomial after serialization
    constexpr size_t poly_blen = src.size() / k;

    for (size_t i = 0; i < k; i++) {
        const size_t off0 = i * poly_blen;
        const size_t off1 = i * ml_dsa_ntt::N;

        ml_dsa_bit_packing::decode<sbw>(std::span<const uint8_t, poly_blen>(src.subspan(off0, poly_blen)), poly_t(dst.subspan(off1, ml_dsa_ntt::N)));
    }
}

// Given a vector (of dimension k x 1) of degree-255 polynomials, it extracts out high order bits from each coefficient.
template<size_t k, uint32_t alpha>
static inline constexpr void
highbits(std::span<const ml_dsa_field::zq_t, k *ml_dsa_ntt::N> src, std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> dst) {
    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        ml_dsa_poly::highbits<alpha>(const_poly_t(src.subspan(off, ml_dsa_ntt::N)), poly_t(dst.subspan(off, ml_dsa_ntt::N)));
    }
}

// Given a vector (of dimension k x 1) of degree-255 polynomials, it extracts out low order bits from each coefficient.
template<size_t k, uint32_t alpha>
static inline constexpr void
lowbits(std::span<const ml_dsa_field::zq_t, k *ml_dsa_ntt::N> src, std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> dst) {
    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        ml_dsa_poly::lowbits<alpha>(const_poly_t(src.subspan(off, ml_dsa_ntt::N)), poly_t(dst.subspan(off, ml_dsa_ntt::N)));
    }
}

// Given a vector ( of dimension k x 1 ) of degree-255 polynomials and one multiplier polynomial, this routine performs
// k pointwise polynomial multiplications when each of these polynomials are in their NTT representation.
template<size_t k>
static inline constexpr void
mul_by_poly(std::span<const ml_dsa_field::zq_t, ml_dsa_ntt::N> poly,
    std::span<const ml_dsa_field::zq_t, k *ml_dsa_ntt::N> src_vec,
    std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> dst_vec) {
    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        ml_dsa_poly::mul(poly, const_poly_t(src_vec.subspan(off, ml_dsa_ntt::N)), poly_t(dst_vec.subspan(off, ml_dsa_ntt::N)));
    }
}

// Computes infinity norm of a vector ( of dimension k x 1 ) of degree-255 polynomials.
template<size_t k>
static inline constexpr ml_dsa_field::zq_t
infinity_norm(std::span<const ml_dsa_field::zq_t, k *ml_dsa_ntt::N> vec) {
    auto res = ml_dsa_field::zq_t::zero();

    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        res = std::max(res, ml_dsa_poly::infinity_norm(const_poly_t(vec.subspan(off, ml_dsa_ntt::N))));
    }

    return res;
}

// Given two vectors (of dimension k x 1) of degree-255 polynomials, this routine computes hint bit for each
// coefficient, using `make_hint` routine.
template<size_t k, uint32_t alpha>
static inline constexpr void
make_hint(std::span<const ml_dsa_field::zq_t, k *ml_dsa_ntt::N> polya,
    std::span<const ml_dsa_field::zq_t, k *ml_dsa_ntt::N> polyb,
    std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> polyc) {
    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        ml_dsa_poly::make_hint<alpha>(
            const_poly_t(polya.subspan(off, ml_dsa_ntt::N)), const_poly_t(polyb.subspan(off, ml_dsa_ntt::N)), poly_t(polyc.subspan(off, ml_dsa_ntt::N)));
    }
}

// Recovers high order bits of a vector of degree-255 polynomials (i.e. r + z) s.t. hint bits (say h) and another
// polynomial vector (say r) are provided.
template<size_t k, uint32_t alpha>
static inline constexpr void
use_hint(std::span<const ml_dsa_field::zq_t, k *ml_dsa_ntt::N> polyh,
    std::span<const ml_dsa_field::zq_t, k *ml_dsa_ntt::N> polyr,
    std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> polyrz) {
    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        ml_dsa_poly::use_hint<alpha>(
            const_poly_t(polyh.subspan(off, ml_dsa_ntt::N)), const_poly_t(polyr.subspan(off, ml_dsa_ntt::N)), poly_t(polyrz.subspan(off, ml_dsa_ntt::N)));
    }
}

// Given a vector (of dimension k x 1) of degree-255 polynomials, it counts number of coefficients having value 1.
template<size_t k>
static inline constexpr size_t
count_1s(std::span<const ml_dsa_field::zq_t, k *ml_dsa_ntt::N> vec) {
    size_t cnt = 0;

    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        cnt += ml_dsa_poly::count_1s(const_poly_t(vec.subspan(off, ml_dsa_ntt::N)));
    }

    return cnt;
}

// Given a vector (of dimension k x 1) of degree-255 polynomials, it shifts each coefficient leftwards by d bits.
template<size_t k, size_t d>
static inline constexpr void
shl(std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> vec) {
    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        ml_dsa_poly::shl<d>(poly_t(vec.subspan(off, ml_dsa_ntt::N)));
    }
}

}

// Routines related to sampling of polynomials/ vector of polynomials
namespace ml_dsa_sampling {

using poly_t = std::span<ml_dsa_field::zq_t, ml_dsa_ntt::N>;

// Given a 32 -bytes uniform seed ρ, a k x l matrix is deterministically sampled ( using the method of rejection
// sampling ), where each coefficient is a degree-255 polynomial ∈ R_q.
//
// See algorithm 32 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
template<size_t k, size_t l>
static inline constexpr void
expand_a(std::span<const uint8_t, 32> rho, std::span<ml_dsa_field::zq_t, k *l *ml_dsa_ntt::N> mat) {
    std::array<uint8_t, rho.size() + 2> msg{};
    auto msg_span = std::span(msg);

    std::copy(rho.begin(), rho.end(), msg_span.begin());

    for (size_t i = 0; i < k; i++) {
        for (size_t j = 0; j < l; j++) {
            const size_t off = (i * l + j) * ml_dsa_ntt::N;

            msg[32] = static_cast<uint8_t>(j);
            msg[33] = static_cast<uint8_t>(i);

            shake<128> hasher;
            hasher.absorb(msg_span);
            hasher.finalize();

            std::array<uint8_t, shake<128>::rate / std::numeric_limits<uint8_t>::digits> buf{};
            auto buf_span = std::span(buf);

            size_t n = 0;
            while (n < ml_dsa_ntt::N) {
                hasher.squeeze(buf_span);

                for (size_t boff = 0; (boff < buf_span.size()) && (n < ml_dsa_ntt::N); boff += 3) {
                    const uint32_t t0 = static_cast<uint32_t>(buf_span[boff + 2] & 0b01111111);
                    const uint32_t t1 = static_cast<uint32_t>(buf_span[boff + 1]);
                    const uint32_t t2 = static_cast<uint32_t>(buf_span[boff + 0]);

                    const uint32_t t3 = (t0 << 16) ^ (t1 << 8) ^ (t2 << 0);
                    if (t3 < ml_dsa_field::Q) {
                        mat[off + n] = ml_dsa_field::zq_t(t3);
                        n++;
                    }
                }
            }
        }
    }
}

// Uniform rejection sampling k -many degree-255 polynomials s.t. each coefficient of those polynomials ∈ [-eta, eta].
//
// Sampling is performed deterministically, by seeding Shake256 Xof with 64 -bytes seed and two nonce bytes, whose
// starting value is provided ( see template parameter ). Consecutive nonces are computed by adding 1 to previous value.
//
// Note, sampled polynomial coefficients are kept in canonical form.
//
// See algorithm 33 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
template<uint32_t eta, size_t k, uint16_t nonce>
static inline constexpr void
expand_s(std::span<const uint8_t, 64> rho_prime, std::span<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> vec)
    requires(ml_dsa_params::check_eta(eta) && ml_dsa_params::check_nonce(nonce)) {
    constexpr auto eta_value = ml_dsa_field::zq_t(eta);

    std::array<uint8_t, rho_prime.size() + 2> msg{};
    auto msg_span = std::span(msg);

    std::copy(rho_prime.begin(), rho_prime.end(), msg_span.begin());

    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        const uint16_t new_nonce = nonce + static_cast<uint16_t>(i);

        msg[64] = static_cast<uint8_t>(new_nonce >> 0);
        msg[65] = static_cast<uint8_t>(new_nonce >> 8);

        shake<256> hasher;
        hasher.absorb(msg_span);
        hasher.finalize();

        std::array<uint8_t, shake<256>::rate / std::numeric_limits<uint8_t>::digits> buf{};
        auto buf_span = std::span(buf);

        size_t n = 0;
        while (n < ml_dsa_ntt::N) {
            hasher.squeeze(buf_span);

            for (size_t boff = 0; (boff < buf_span.size()) && (n < ml_dsa_ntt::N); boff++) {
                const uint8_t t0 = buf_span[boff] & 0x0f;
                const uint8_t t1 = buf_span[boff] >> 4;

                if constexpr (eta == 2u) {
                    const uint32_t t2 = static_cast<uint32_t>(t0 % 5);
                    const bool flg0 = t0 < 15;

                    vec[off + n] = eta_value - ml_dsa_field::zq_t(t2);
                    n += flg0 * 1;

                    const uint32_t t3 = static_cast<uint32_t>(t1 % 5);
                    const bool flg1 = (t1 < 15) & (n < ml_dsa_ntt::N);
                    const ml_dsa_field::zq_t br[]{ vec[off], eta_value - ml_dsa_field::zq_t(t3) };

                    vec[off + flg1 * n] = br[flg1];
                    n += flg1 * 1;
                } else {
                    const bool flg0 = t0 < 9;

                    vec[off + n] = eta_value - ml_dsa_field::zq_t(static_cast<uint32_t>(t0));
                    n += flg0 * 1;

                    const bool flg1 = (t1 < 9) & (n < ml_dsa_ntt::N);
                    const auto t2 = eta_value - ml_dsa_field::zq_t(static_cast<uint32_t>(t1));
                    const ml_dsa_field::zq_t br[]{ vec[off], t2 };

                    vec[off + flg1 * n] = br[flg1];
                    n += flg1 * 1;
                }
            }
        }
    }
}

// Given a 64 -bytes seed and 2 -bytes nonce, this routine does uniform sampling from output of Shake256 Xof, computing
// a l x 1 vector of degree-255 polynomials s.t. each coefficient ∈ [-(gamma1-1), gamma1].
//
// See algorithm 34 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
template<uint32_t gamma1, size_t l>
static inline constexpr void
expand_mask(std::span<const uint8_t, 64> seed, const uint16_t nonce, std::span<ml_dsa_field::zq_t, l *ml_dsa_ntt::N> vec)
    requires(ml_dsa_params::check_gamma1(gamma1)) {
    constexpr size_t gamma1_bitwidth = std::bit_width(gamma1);

    std::array<uint8_t, seed.size() + 2> msg{};
    std::array<uint8_t, (ml_dsa_ntt::N *gamma1_bitwidth) / std::numeric_limits<uint8_t>::digits> buf{};

    auto msg_span = std::span(msg);
    auto buf_span = std::span(buf);

    std::copy(seed.begin(), seed.end(), msg_span.begin());

    for (size_t i = 0; i < l; i++) {
        const size_t off = i * ml_dsa_ntt::N;
        const uint16_t new_nonce = nonce + static_cast<uint16_t>(i);

        msg[64] = static_cast<uint8_t>(new_nonce >> 0);
        msg[65] = static_cast<uint8_t>(new_nonce >> 8);

        shake<256> hasher;
        hasher.absorb(msg_span);
        hasher.finalize();
        hasher.squeeze(buf_span);

        ml_dsa_bit_packing::decode<gamma1_bitwidth>(buf_span, poly_t(vec.subspan(off, ml_dsa_ntt::N)));
        ml_dsa_poly::sub_from_x<gamma1>(poly_t(vec.subspan(off, ml_dsa_ntt::N)));
    }
}

// Given a (lambda/4) -bytes seed, this routine creates a degree-255 polynomial with tau -many coefficients set to +/- 1, while
// remaining (256 - tau) -many set to 0 s.t. lambda = bit-security level of the respective ML-DSA instantiation.
//
// See algorithm 29 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
template<uint32_t tau, size_t lambda>
static inline constexpr void
sample_in_ball(std::span<const uint8_t, (2 * lambda) / std::numeric_limits<uint8_t>::digits> seed, std::span<ml_dsa_field::zq_t, ml_dsa_ntt::N> poly)
    requires(ml_dsa_params::check_tau(tau)) {
    std::array<uint8_t, 8> tau_bits{};
    std::array<uint8_t, shake<256>::rate / std::numeric_limits<uint8_t>::digits> buf{};

    auto tau_bits_span = std::span(tau_bits);
    auto buf_span = std::span(buf);

    shake<256> hasher;
    hasher.absorb(seed);
    hasher.finalize();
    hasher.squeeze(tau_bits_span);

    constexpr size_t frm = ml_dsa_ntt::N - tau;
    size_t i = frm;

    while (i < ml_dsa_ntt::N) {
        hasher.squeeze(buf_span);

        for (size_t off = 0; (off < buf_span.size()) && (i < ml_dsa_ntt::N); off++) {
            const size_t tau_bit = i - frm;

            const size_t tau_byte_off = tau_bit >> 3;
            const size_t tau_bit_off = tau_bit & 7ul;

            const uint8_t s = (tau_bits_span[tau_byte_off] >> tau_bit_off) & 0b1;
            const bool s_ = static_cast<bool>(s);

            const auto tmp = buf_span[off];
            const bool flg = tmp <= static_cast<uint8_t>(i);

            const ml_dsa_field::zq_t br0[]{ poly[i], poly[tmp] };
            const ml_dsa_field::zq_t br1[]{ poly[tmp], ml_dsa_field::zq_t::one() - ml_dsa_field::zq_t(2u * s_) };

            poly[i] = br0[flg];
            poly[tmp] = br1[flg];

            i += 1ul * flg;
        }
    };
}

}

// ML-DSA FIPS 204
template<size_t k, size_t l, size_t d, uint32_t eta, uint32_t gamma1, uint32_t gamma2, uint32_t tau, uint32_t beta, size_t omega, size_t lambda>
struct ml_dsa_base {
    // Byte length of seed, required for key generation.
    static inline constexpr size_t KeygenSeedByteLen = 32;

    // Byte length of randomness, required for hedged signing.
    static inline constexpr size_t SigningSeedByteLen = 32;

    // Byte length of message representative, which is to be signed.
    static inline constexpr size_t MessageRepresentativeByteLen = 64;

    // Byte length of ML-DSA public key.
    static inline constexpr size_t PubKeyByteLen = 32 + k * 32 * (ml_dsa_field::Q_BIT_WIDTH - d);

    // Byte length of ML-DSA secret key.
    static inline constexpr size_t SecKeyByteLen = 32 + 32 + 64 + 32 * (std::bit_width(2 * eta) * (k + l) + k * d);

    // Byte length of ML-DSA signature.
    static inline constexpr size_t SigByteLen = ((2 * lambda) / std::numeric_limits<uint8_t>::digits) + (32 * l * std::bit_width(gamma1)) + (omega + k);

public:
    // Given seed, this routine generates a public key and secret key pair, using deterministic key generation algorithm.
    //
    // See algorithm 1 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
    static constexpr void keygen(std::span<const uint8_t, KeygenSeedByteLen> seed, std::span<uint8_t, PubKeyByteLen> pubkey, std::span<uint8_t, SecKeyByteLen> seckey) {
        constexpr std::array<uint8_t, 2> domain_separator{ k, l };

        std::array<uint8_t, 32 + 64 + 32> seed_hash{};
        auto seed_hash_span = std::span(seed_hash);

        shake<256> hasher;
        hasher.absorb(seed);
        hasher.absorb(domain_separator);
        hasher.finalize();
        hasher.squeeze(seed_hash_span);

        auto rho = seed_hash_span.template first<32>();
        auto rho_prime = seed_hash_span.template subspan<rho.size(), 64>();
        auto key = seed_hash_span.template last<32>();

        std::array<ml_dsa_field::zq_t, k *l *ml_dsa_ntt::N> A{};
        ml_dsa_sampling::expand_a<k, l>(rho, A);

        std::array<ml_dsa_field::zq_t, l *ml_dsa_ntt::N> s1{};
        std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> s2{};

        ml_dsa_sampling::expand_s<eta, l, 0>(rho_prime, s1);
        ml_dsa_sampling::expand_s<eta, k, l>(rho_prime, s2);

        std::array<ml_dsa_field::zq_t, l *ml_dsa_ntt::N> s1_prime{};

        std::copy(s1.begin(), s1.end(), s1_prime.begin());
        ml_dsa_polyvec::ntt<l>(s1_prime);

        std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> t{};

        ml_dsa_polyvec::matrix_multiply<k, l, l, 1>(A, s1_prime, t);
        ml_dsa_polyvec::intt<k>(t);
        ml_dsa_polyvec::add_to<k>(s2, t);

        std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> t1{};
        std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> t0{};

        ml_dsa_polyvec::power2round<k, d>(t, t1, t0);

        constexpr size_t t1_bw = std::bit_width(ml_dsa_field::Q) - d;
        std::array<uint8_t, 64> tr{};

        // Prepare public key
        constexpr size_t pkoff0 = 0;
        constexpr size_t pkoff1 = pkoff0 + rho.size();
        constexpr size_t pkoff2 = pubkey.size();

        std::copy(rho.begin(), rho.end(), pubkey.begin());
        ml_dsa_polyvec::encode<k, t1_bw>(t1, pubkey.template last<pkoff2 - pkoff1>());

        // Prepare secret key
        hasher = decltype(hasher){};
        hasher.absorb(pubkey);
        hasher.finalize();
        hasher.squeeze(tr);

        constexpr size_t eta_bw = std::bit_width(2 * eta);
        constexpr size_t s1_len = l * eta_bw * 32;
        constexpr size_t s2_len = k * eta_bw * 32;

        constexpr size_t skoff0 = 0;
        constexpr size_t skoff1 = skoff0 + rho.size();
        constexpr size_t skoff2 = skoff1 + key.size();
        constexpr size_t skoff3 = skoff2 + tr.size();
        constexpr size_t skoff4 = skoff3 + s1_len;
        constexpr size_t skoff5 = skoff4 + s2_len;
        constexpr size_t skoff6 = seckey.size();

        std::copy(rho.begin(), rho.end(), seckey.template subspan<skoff0, skoff1 - skoff0>().begin());
        std::copy(key.begin(), key.end(), seckey.template subspan<skoff1, skoff2 - skoff1>().begin());
        std::copy(tr.begin(), tr.end(), seckey.template subspan<skoff2, skoff3 - skoff2>().begin());

        ml_dsa_polyvec::sub_from_x<l, eta>(s1);
        ml_dsa_polyvec::sub_from_x<k, eta>(s2);

        ml_dsa_polyvec::encode<l, eta_bw>(s1, seckey.template subspan<skoff3, skoff4 - skoff3>());
        ml_dsa_polyvec::encode<k, eta_bw>(s2, seckey.template subspan<skoff4, skoff5 - skoff4>());

        constexpr uint32_t t0_rng = 1u << (d - 1);

        ml_dsa_polyvec::sub_from_x<k, t0_rng>(t0);
        ml_dsa_polyvec::encode<k, d>(t0, seckey.template subspan<skoff5, skoff6 - skoff5>());
    }
    // Given a ML-DSA secret key and 64 -bytes message representative, this routine computes a hedged/ deterministic signature.
    //
    // Notice, first parameter of this function, `rnd`, which lets you pass 32 -bytes randomness for generating default
    // "hedged" signature. In case you don't need randomized message signature, you can instead fill `rnd` with zeros, and
    // it'll generate a deterministic signature.
    //
    // Note, hedged signing is the default and recommended version.
    //
    // See algorithm 7 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
    static constexpr bool sign_internal(std::span<const uint8_t, SigningSeedByteLen> rnd,
        std::span<const uint8_t, SecKeyByteLen> seckey,
        std::span<const uint8_t, MessageRepresentativeByteLen> mu,
        std::span<uint8_t, SigByteLen> sig) {
        constexpr uint32_t t0_rng = 1u << (d - 1);

        constexpr size_t eta_bw = std::bit_width(2 * eta);
        constexpr size_t s1_len = l * eta_bw * 32;
        constexpr size_t s2_len = k * eta_bw * 32;

        constexpr size_t skoff0 = 0;
        constexpr size_t skoff1 = skoff0 + 32;
        constexpr size_t skoff2 = skoff1 + 32;
        constexpr size_t skoff3 = skoff2 + 64;
        constexpr size_t skoff4 = skoff3 + s1_len;
        constexpr size_t skoff5 = skoff4 + s2_len;

        auto rho = seckey.template subspan<skoff0, skoff1 - skoff0>();
        auto key = seckey.template subspan<skoff1, skoff2 - skoff1>();

        std::array<ml_dsa_field::zq_t, k *l *ml_dsa_ntt::N> A{};
        ml_dsa_sampling::expand_a<k, l>(rho, A);

        std::array<uint8_t, 64> rho_prime{};

        shake<256> hasher;
        hasher.absorb(key);
        hasher.absorb(rnd);
        hasher.absorb(mu);
        hasher.finalize();
        hasher.squeeze(rho_prime);

        std::array<ml_dsa_field::zq_t, l *ml_dsa_ntt::N> s1{};
        std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> s2{};
        std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> t0{};

        ml_dsa_polyvec::decode<l, eta_bw>(seckey.template subspan<skoff3, skoff4 - skoff3>(), s1);
        ml_dsa_polyvec::decode<k, eta_bw>(seckey.template subspan<skoff4, skoff5 - skoff4>(), s2);
        ml_dsa_polyvec::decode<k, d>(seckey.template subspan<skoff5, seckey.size() - skoff5>(), t0);

        ml_dsa_polyvec::sub_from_x<l, eta>(s1);
        ml_dsa_polyvec::sub_from_x<k, eta>(s2);
        ml_dsa_polyvec::sub_from_x<k, t0_rng>(t0);

        ml_dsa_polyvec::ntt<l>(s1);
        ml_dsa_polyvec::ntt<k>(s2);
        ml_dsa_polyvec::ntt<k>(t0);

        bool has_signed = false;
        uint16_t kappa = 0;

        std::array<ml_dsa_field::zq_t, l *ml_dsa_ntt::N> z{};
        std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> h{};

        std::array<uint8_t, (2 * lambda) / std::numeric_limits<uint8_t>::digits> c_tilda{};
        auto c_tilda_span = std::span(c_tilda);

        while (!has_signed) {
            std::array<ml_dsa_field::zq_t, l *ml_dsa_ntt::N> y{};
            std::array<ml_dsa_field::zq_t, l *ml_dsa_ntt::N> y_prime{};
            std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> w{};

            ml_dsa_sampling::expand_mask<gamma1, l>(rho_prime, kappa, y);

            std::copy(y.begin(), y.end(), y_prime.begin());

            ml_dsa_polyvec::ntt<l>(y_prime);
            ml_dsa_polyvec::matrix_multiply<k, l, l, 1>(A, y_prime, w);
            ml_dsa_polyvec::intt<k>(w);

            constexpr uint32_t alpha = gamma2 << 1;
            constexpr uint32_t m = (ml_dsa_field::Q - 1u) / alpha;
            constexpr size_t w1bw = std::bit_width(m - 1u);

            std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> w1{};
            std::array<uint8_t, k *w1bw * 32> w1_encoded{};

            ml_dsa_polyvec::highbits<k, alpha>(w, w1);
            ml_dsa_polyvec::encode<k, w1bw>(w1, w1_encoded);

            hasher = decltype(hasher){};
            hasher.absorb(mu);
            hasher.absorb(w1_encoded);
            hasher.finalize();
            hasher.squeeze(c_tilda_span);

            std::array<ml_dsa_field::zq_t, ml_dsa_ntt::N> c{};

            ml_dsa_sampling::sample_in_ball<tau, lambda>(c_tilda_span, c);
            ml_dsa_ntt::ntt(c);

            ml_dsa_polyvec::mul_by_poly<l>(c, s1, z);
            ml_dsa_polyvec::intt<l>(z);
            ml_dsa_polyvec::add_to<l>(y, z);

            std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> r0{};
            std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> r1{};

            ml_dsa_polyvec::mul_by_poly<k>(c, s2, r1);
            ml_dsa_polyvec::intt<k>(r1);
            ml_dsa_polyvec::neg<k>(r1);
            ml_dsa_polyvec::add_to<k>(w, r1);
            ml_dsa_polyvec::lowbits<k, alpha>(r1, r0);

            const ml_dsa_field::zq_t z_norm = ml_dsa_polyvec::infinity_norm<l>(z);
            const ml_dsa_field::zq_t r0_norm = ml_dsa_polyvec::infinity_norm<k>(r0);

            constexpr ml_dsa_field::zq_t bound0(gamma1 - beta);
            constexpr ml_dsa_field::zq_t bound1(gamma2 - beta);

            if ((z_norm >= ml_dsa_field::zq_t(gamma1 - beta)) || (r0_norm >= ml_dsa_field::zq_t(gamma2 - beta))) {
                has_signed = false;
            } else {
                std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> h0{};
                std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> h1{};

                ml_dsa_polyvec::mul_by_poly<k>(c, t0, h0);
                ml_dsa_polyvec::intt<k>(h0);

                std::copy(h0.begin(), h0.end(), h1.begin());

                ml_dsa_polyvec::neg<k>(h0);
                ml_dsa_polyvec::add_to<k>(h1, r1);
                ml_dsa_polyvec::make_hint<k, alpha>(h0, r1, h);

                const ml_dsa_field::zq_t ct0_norm = ml_dsa_polyvec::infinity_norm<k>(h1);
                const size_t count_1s = ml_dsa_polyvec::count_1s<k>(h);

                constexpr ml_dsa_field::zq_t bound2(gamma2);

                if ((ct0_norm >= ml_dsa_field::zq_t(gamma2)) || (count_1s > omega)) {
                    has_signed = false;
                } else {
                    has_signed = true;
                }
            }

            kappa += static_cast<uint16_t>(l);
        }

        constexpr size_t gamma1_bw = std::bit_width(gamma1);

        constexpr size_t sigoff0 = 0;
        constexpr size_t sigoff1 = sigoff0 + c_tilda_span.size();
        constexpr size_t sigoff2 = sigoff1 + (32 * l * gamma1_bw);
        constexpr size_t sigoff3 = sig.size();

        std::copy(c_tilda_span.begin(), c_tilda_span.end(), sig.template subspan<sigoff0, sigoff1 - sigoff0>().begin());

        ml_dsa_polyvec::sub_from_x<l, gamma1>(z);
        ml_dsa_polyvec::encode<l, gamma1_bw>(z, sig.template subspan<sigoff1, sigoff2 - sigoff1>());

        ml_dsa_bit_packing::encode_hint_bits<k, omega>(h, sig.template subspan<sigoff2, sigoff3 - sigoff2>());

        return has_signed;
    }
    // Given a ML-DSA secret key, message (can be empty too) and context (optional, but if given, length must be capped at 255 -bytes),
    // this routine computes a hedged/ deterministic signature.
    //
    // Notice, first parameter of this function, `rnd`, which lets you pass 32 -bytes randomness for generating default
    // "hedged" signature. In case you don't need randomized message signature, you can instead fill `rnd` with zeros, and
    // it'll generate a deterministic signature.
    //
    // Note, hedged signing is the default and recommended version.
    //
    // See algorithm 2 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
    static constexpr bool sign(std::span<const uint8_t, SigningSeedByteLen> rnd,
        std::span<const uint8_t, SecKeyByteLen> seckey,
        std::span<const uint8_t> msg,
        std::span<const uint8_t> ctx,
        std::span<uint8_t, SigByteLen> sig) {
        if (ctx.size() > std::numeric_limits<uint8_t>::max()) {
            return false;
        }

        constexpr size_t skoff0 = 0;
        constexpr size_t skoff1 = skoff0 + 32;
        constexpr size_t skoff2 = skoff1 + 32;
        constexpr size_t skoff3 = skoff2 + 64;

        auto tr = seckey.template subspan<skoff2, skoff3 - skoff2>();
        const std::array<uint8_t, 2> domain_separator{ 0, static_cast<uint8_t>(ctx.size()) };

        std::array<uint8_t, MessageRepresentativeByteLen> mu{};
        auto mu_span = std::span(mu);

        shake<256> hasher;
        hasher.absorb(tr);
        hasher.absorb(domain_separator);
        hasher.absorb(ctx);
        hasher.absorb(msg);
        hasher.finalize();
        hasher.squeeze(mu_span);

        return sign_internal(rnd, seckey, mu_span, sig);
    }
    // Given a ML-DSA public key, 64 -bytes message representative and serialized signature, this routine verifies validity of the signature,
    // returning boolean result, denoting status of signature verification. For example, say it returns true, it means signature is valid for
    // given message and public key.
    //
    // See algorithm 8 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
    static constexpr bool verify_internal(std::span<const uint8_t, PubKeyByteLen> pubkey, std::span<const uint8_t, MessageRepresentativeByteLen> mu, std::span<const uint8_t, SigByteLen> sig) {
        constexpr size_t t1_bw = std::bit_width(ml_dsa_field::Q) - d;
        constexpr size_t gamma1_bw = std::bit_width(gamma1);

        // Decode signature
        constexpr size_t sigoff0 = 0;
        constexpr size_t sigoff1 = sigoff0 + (2 * lambda) / std::numeric_limits<uint8_t>::digits;
        constexpr size_t sigoff2 = sigoff1 + (32 * l * gamma1_bw);
        constexpr size_t sigoff3 = sig.size();

        auto c_tilda = sig.template first<sigoff1 - sigoff0>();
        auto z_encoded = sig.template subspan<sigoff1, sigoff2 - sigoff1>();
        auto h_encoded = sig.template subspan<sigoff2, sigoff3 - sigoff2>();

        std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> h{};
        const bool has_failed = ml_dsa_bit_packing::decode_hint_bits<k, omega>(h_encoded, h);
        if (has_failed) {
            return false;
        }

        const size_t count_1s = ml_dsa_polyvec::count_1s<k>(h);
        if (count_1s > omega) {
            return false;
        }

        std::array<ml_dsa_field::zq_t, ml_dsa_ntt::N> c{};
        ml_dsa_sampling::sample_in_ball<tau, lambda>(c_tilda, c);
        ml_dsa_ntt::ntt(c);

        std::array<ml_dsa_field::zq_t, l *ml_dsa_ntt::N> z{};
        ml_dsa_polyvec::decode<l, gamma1_bw>(z_encoded, z);
        ml_dsa_polyvec::sub_from_x<l, gamma1>(z);

        const ml_dsa_field::zq_t z_norm = ml_dsa_polyvec::infinity_norm<l>(z);
        if (z_norm >= ml_dsa_field::zq_t(gamma1 - beta)) {
            return false;
        }

        // Decode public key
        constexpr size_t pkoff0 = 0;
        constexpr size_t pkoff1 = pkoff0 + 32;
        constexpr size_t pkoff2 = pubkey.size();

        auto rho = pubkey.template subspan<pkoff0, pkoff1 - pkoff0>();
        auto t1_encoded = pubkey.template subspan<pkoff1, pkoff2 - pkoff1>();

        std::array<ml_dsa_field::zq_t, k *l *ml_dsa_ntt::N> A{};
        std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> t1{};

        ml_dsa_sampling::expand_a<k, l>(rho, A);
        ml_dsa_polyvec::decode<k, t1_bw>(t1_encoded, t1);

        std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> w0{};
        std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> w1{};
        std::array<ml_dsa_field::zq_t, k *ml_dsa_ntt::N> w2{};

        ml_dsa_polyvec::ntt<l>(z);
        ml_dsa_polyvec::matrix_multiply<k, l, l, 1>(A, z, w0);

        ml_dsa_polyvec::shl<k, d>(t1);
        ml_dsa_polyvec::ntt<k>(t1);
        ml_dsa_polyvec::mul_by_poly<k>(c, t1, w2);
        ml_dsa_polyvec::neg<k>(w2);

        ml_dsa_polyvec::add_to<k>(w0, w2);
        ml_dsa_polyvec::intt<k>(w2);

        constexpr uint32_t alpha = gamma2 << 1;
        constexpr uint32_t m = (ml_dsa_field::Q - 1u) / alpha;
        constexpr size_t w1bw = std::bit_width(m - 1u);

        ml_dsa_polyvec::use_hint<k, alpha>(h, w2, w1);

        std::array<uint8_t, k *w1bw * 32> w1_encoded{};
        ml_dsa_polyvec::encode<k, w1bw>(w1, w1_encoded);

        std::array<uint8_t, c_tilda.size()> c_tilda_prime{};

        shake<256> hasher;
        hasher.absorb(mu);
        hasher.absorb(w1_encoded);
        hasher.finalize();
        hasher.squeeze(c_tilda_prime);

        return std::equal(c_tilda.begin(), c_tilda.end(), c_tilda_prime.begin());
    }
    // Given a ML-DSA public key, message (can be empty too), context (optional, but if given, length must be capped at 255 -bytes)
    // and serialized signature, this routine verifies validity of the signature, returning boolean result, denoting status
    // of signature verification. For example, say it returns true, it means signature is valid for given message and public key.
    //
    // See algorithm 3 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
    static constexpr bool verify(std::span<const uint8_t, PubKeyByteLen> pubkey, std::span<const uint8_t> msg, std::span<const uint8_t> ctx, std::span<const uint8_t, SigByteLen> sig) {
        if (ctx.size() > std::numeric_limits<uint8_t>::max()) {
            return false;
        }

        std::array<uint8_t, 64> mu{};
        std::array<uint8_t, 64> tr{};

        shake<256> hasher;
        hasher.absorb(pubkey);
        hasher.finalize();
        hasher.squeeze(tr);

        const std::array<uint8_t, 2> domain_separator{ 0, static_cast<uint8_t>(ctx.size()) };

        hasher = decltype(hasher){};
        hasher.absorb(tr);
        hasher.absorb(domain_separator);
        hasher.absorb(ctx);
        hasher.absorb(msg);
        hasher.finalize();
        hasher.squeeze(mu);

        return verify_internal(pubkey, mu, sig);
    }

public:
    using private_key_type = array<SecKeyByteLen>;
    using public_key_type = array<PubKeyByteLen>;

    private_key_type private_key_;
    public_key_type public_key_;

    void keygen(std::span<const uint8_t, KeygenSeedByteLen> seed) {
        keygen(seed, bytes_concept{public_key_}, bytes_concept{private_key_});
    }
};

// use some common values (d and beta)
template<size_t k, size_t l, uint32_t eta, uint32_t gamma1, uint32_t gamma2, uint32_t tau, size_t omega, size_t lambda>
struct ml_dsa_base2 : ml_dsa_base<k,l,13,eta,gamma1,gamma2,tau,tau*eta,omega,lambda> {};

template <auto>
struct ml_dsa;

// See table 1 of ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204
template <>
struct ml_dsa<44> : ml_dsa_base2<4, 4, 2, 1u << 17, (ml_dsa_field::Q - 1) / 88, 39, 80, 128> {};
template <>
struct ml_dsa<65> : ml_dsa_base2<6, 5, 4, 1u << 19, (ml_dsa_field::Q - 1) / 32, 49, 55, 192> {};
template <>
struct ml_dsa<87> : ml_dsa_base2<8, 7, 2, 1u << 19, (ml_dsa_field::Q - 1) / 32, 60, 75, 256> {};

} // namespace crypto
