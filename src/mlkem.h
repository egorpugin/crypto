// parts are from https://github.com/itzmeanjan/ml-kem
// MPL-2.0 license

#pragma once

#include "random.h"
#include "sha3.h"

namespace crypto {

namespace ml_kem_field {

// Ml_kem Prime Field Modulus ( = 3329 )
inline constexpr uint32_t Q = (1u << 8) * 13 + 1;

// Bit width of Ml_kem Prime Field Modulus ( = 12 )
inline constexpr size_t Q_BIT_WIDTH = std::bit_width(Q);

// Precomputed Barrett Reduction Constant
//
// Note,
//
// k = ceil(log2(Q)) = 12,
// r = floor((1 << 2k) / Q) = 5039
//
// See https://www.nayuki.io/page/barrett-reduction-algorithm.
inline constexpr uint32_t R = (1u << (2 * Q_BIT_WIDTH)) / Q;

// Prime field Zq | q = 3329, with arithmetic operations defined over it.
//
// Collects inspiration from https://github.com/itzmeanjan/dilithium/blob/3fe6ab61/include/field.hpp.
struct zq_t {
private:
    // Underlying value held in this type.
    //
    // Note, v is always kept in its canonical form i.e. v ∈ [0, Q).
    uint32_t v = 0u;

    // Given a 32 -bit unsigned integer `v` such that `v` ∈ [0, 2*Q), this routine can be invoked for reducing `v` modulo prime Q.
    static constexpr uint32_t reduce_once(const uint32_t v) {
        const uint32_t t0 = v - Q;
        const uint32_t t1 = -(t0 >> 31);
        const uint32_t t2 = Q & t1;
        const uint32_t t3 = t0 + t2;

        return t3;
    }

    // Given a 32 -bit unsigned integer `v` such that `v` ∈ [0, Q*Q), this routine can be invoked for reducing `v` modulo Q, using
    // barrett reduction technique, following algorithm description @ https://www.nayuki.io/page/barrett-reduction-algorithm.
    static constexpr uint32_t barrett_reduce(const uint32_t v) {
        const uint64_t t0 = static_cast<uint64_t>(v) * static_cast<uint64_t>(R);
        const uint32_t t1 = static_cast<uint32_t>(t0 >> (2 * Q_BIT_WIDTH));
        const uint32_t t2 = t1 * Q;
        const uint32_t t = v - t2;

        return reduce_once(t);
    }

public:
    // Constructor(s)
    constexpr zq_t() = default;
    constexpr zq_t(const uint16_t a /* Expects a ∈ [0, Q) */) {
        this->v = a;
    }
    static constexpr zq_t from_non_reduced(const uint16_t a /* Doesn't expect that a ∈ [0, Q) */) {
        return barrett_reduce(a);
    }

    // Returns canonical value held under Zq type. Returned value must ∈ [0, Q).
    constexpr uint32_t raw() const {
        return this->v;
    }

    static constexpr zq_t zero() {
        return zq_t(0u);
    }
    static constexpr zq_t one() {
        return zq_t(1u);
    }

    // Modulo addition of two Zq elements.
    constexpr zq_t operator+(const zq_t &rhs) const {
        return reduce_once(this->v + rhs.v);
    }
    constexpr void operator+=(const zq_t &rhs) {
        *this = *this + rhs;
    }

    // Modulo negation of a Zq element.
    constexpr zq_t operator-() const {
        return zq_t(Q - this->v);
    }

    // Modulo subtraction of one Zq element from another one.
    constexpr zq_t operator-(const zq_t &rhs) const {
        return *this + (-rhs);
    }
    constexpr void operator-=(const zq_t &rhs) {
        *this = *this - rhs;
    }

    // Modulo multiplication of two Zq elements.
    constexpr zq_t operator*(const zq_t &rhs) const {
        return barrett_reduce(this->v * rhs.v);
    }
    constexpr void operator*=(const zq_t &rhs) {
        *this = *this * rhs;
    }

    // Modulo exponentiation of Zq element.
    // Taken from https://github.com/itzmeanjan/dilithium/blob/3fe6ab61/include/field.hpp#L144-L167.
    constexpr zq_t operator^(const size_t n) const {
        zq_t base = *this;

        const zq_t br[]{zq_t(1), base};
        zq_t res = br[n & 0b1ul];

        const size_t zeros = std::countl_zero(n);
        const size_t till = 64ul - zeros;

        for (size_t i = 1; i < till; i++) {
            base = base * base;

            const zq_t br[]{zq_t(1), base};
            res = res * br[(n >> i) & 0b1ul];
        }
        return res;
    }

    // Multiplicative inverse of Zq element. Also division of one Zq element by another one.
    // Note, if Zq element is 0, we can't compute multiplicative inverse and 0 is returned.
    constexpr zq_t inv() const {
        return *this ^ static_cast<size_t>((Q - 2));
    }
    constexpr zq_t operator/(const zq_t &rhs) const {
        return *this * rhs.inv();
    }

    constexpr auto operator<=>(const zq_t &) const = default;

    // Samples a random Zq element, using pseudo random number generator.
    /*template<size_t bit_security_level>
    static zq_t random(randomshake::randomshake_t<bit_security_level>& csprng)
    {
      uint16_t res = 0;
      csprng.generate(std::span(reinterpret_cast<uint8_t*>(&res), sizeof(res)));

      return zq_t::from_non_reduced(static_cast<uint32_t>(res));
    }*/
};

} // namespace ml_kem_field

namespace ml_kem_ntt {

inline constexpr size_t LOG2N = 8;
inline constexpr size_t N = 1 << LOG2N;

// First primitive 256-th root of unity modulo q | q = 3329
//
// Meaning, 17 ** 256 == 1 mod q
inline constexpr auto zeta = ml_kem_field::zq_t(17);
static_assert((zeta ^ N) == ml_kem_field::zq_t::one(), "zeta must be 256th root of unity modulo Q");

// Multiplicative inverse of N/2 over Z_q | q = 3329 and N = 256
//
// Meaning (N/ 2) * INV_N = 1 mod q
inline constexpr auto INV_N = ml_kem_field::zq_t(N / 2).inv();

// Given a 64 -bit unsigned integer, this routine extracts specified many contiguous bits from ( least significant bits ) LSB side
// and reverses their bit order, returning bit reversed `mbw` -bit wide number.
//
// See https://github.com/itzmeanjan/falcon/blob/45b0593/include/ntt.hpp#L30-L38 for source of inspiration.
template <size_t mbw>
constexpr size_t bit_rev(const size_t v) {
    size_t v_rev = 0ul;

    for (size_t i = 0; i < mbw; i++) {
        const size_t bit = (v >> i) & 0b1;
        v_rev ^= bit << (mbw - 1ul - i);
    }

    return v_rev;
}

// Compile-time computed constants ( powers of zeta ), used for polynomial evaluation i.e. computation of NTT form.
inline constexpr std::array<ml_kem_field::zq_t, N / 2> NTT_ZETA_EXP = []() -> auto {
    std::array<ml_kem_field::zq_t, N / 2> res{};

    for (size_t i = 0; i < res.size(); i++) {
        res[i] = zeta ^ bit_rev<LOG2N - 1>(i);
    }

    return res;
}();

// Compile-time computed constants ( negated powers of zeta ), used for polynomial interpolation i.e. computation of iNTT form.
inline constexpr std::array<ml_kem_field::zq_t, N / 2> INTT_ZETA_EXP = []() -> auto {
    std::array<ml_kem_field::zq_t, N / 2> res{};

    for (size_t i = 0; i < res.size(); i++) {
        res[i] = -NTT_ZETA_EXP[i];
    }

    return res;
}();

// Compile-time computed constants ( powers of zeta ), used when multiplying two degree-255 polynomials in NTT domain.
inline constexpr std::array<ml_kem_field::zq_t, N / 2> POLY_MUL_ZETA_EXP = []() -> auto {
    std::array<ml_kem_field::zq_t, N / 2> res{};

    for (size_t i = 0; i < res.size(); i++) {
        res[i] = zeta ^ ((bit_rev<LOG2N - 1>(i) << 1) ^ 1);
    }

    return res;
}();

// Given a polynomial f with 256 coefficients over F_q | q = 3329, this routine computes number theoretic transform
// using Cooley-Tukey algorithm, producing polynomial f' s.t. its coefficients are placed in bit-reversed order.
//
// Note, this routine mutates input i.e. it's an in-place NTT implementation.
//
// Implementation inspired from https://github.com/itzmeanjan/falcon/blob/45b0593/include/ntt.hpp#L69-L144.
// See algorithm 9 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
constexpr void ntt(std::span<ml_kem_field::zq_t, N> poly) {
    for (size_t l = LOG2N - 1; l >= 1; l--) {
        const size_t len = 1ul << l;
        const size_t lenx2 = len << 1;
        const size_t k_beg = N >> (l + 1);

        for (size_t start = 0; start < poly.size(); start += lenx2) {
            const size_t k_now = k_beg + (start >> (l + 1));
            // Looking up precomputed constant, though it can be computed using
            //
            // zeta ^ bit_rev<LOG2N - 1>(k_now)
            //
            // This is how these constants are generated !
            const ml_kem_field::zq_t zeta_exp = NTT_ZETA_EXP[k_now];

            for (size_t i = start; i < start + len; i++) {
                auto tmp = zeta_exp;
                tmp *= poly[i + len];

                poly[i + len] = poly[i] - tmp;
                poly[i] += tmp;
            }
        }
    }
}

// Given a polynomial f with 256 coefficients over F_q | q = 3329, s.t. its coefficients are placed in bit-reversed order,
// this routine computes inverse number theoretic transform using Gentleman-Sande algorithm, producing polynomial f' s.t.
// its coefficients are placed in standard order.
//
// Note, this routine mutates input i.e. it's an in-place iNTT implementation.
//
// Implementation inspired from https://github.com/itzmeanjan/falcon/blob/45b0593/include/ntt.hpp#L146-L224.
// See algorithm 10 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
constexpr void intt(std::span<ml_kem_field::zq_t, N> poly) {
    for (size_t l = 1; l < LOG2N; l++) {
        const size_t len = 1ul << l;
        const size_t lenx2 = len << 1;
        const size_t k_beg = (N >> l) - 1;

        for (size_t start = 0; start < poly.size(); start += lenx2) {
            const size_t k_now = k_beg - (start >> (l + 1));
            // Looking up precomputed constant, though it can be computed using
            //
            // -(zeta ^ bit_rev<LOG2N - 1>(k_now))
            //
            // Or simpler
            //
            // -NTT_ZETA_EXP[k_now]
            const ml_kem_field::zq_t neg_zeta_exp = INTT_ZETA_EXP[k_now];

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

// Given two degree-1 polynomials, this routine computes resulting degree-1 polynomial h.
// See algorithm 12 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
constexpr void basemul(std::span<const ml_kem_field::zq_t, 2> f, std::span<const ml_kem_field::zq_t, 2> g, std::span<ml_kem_field::zq_t, 2> h,
                       const ml_kem_field::zq_t zeta) {
    ml_kem_field::zq_t f0 = f[0];
    ml_kem_field::zq_t f1 = f[1];

    f0 *= g[0];
    f1 *= g[1];
    f1 *= zeta;
    f1 += f0;

    h[0] = f1;

    ml_kem_field::zq_t g0 = g[0];
    ml_kem_field::zq_t g1 = g[1];

    g1 *= f[0];
    g0 *= f[1];
    g1 += g0;

    h[1] = g1;
}

// Given two degree-255 polynomials in NTT form, this routine performs 128
// base case multiplications for 128 pairs of degree-1 polynomials s.t.
//
// f = (f0ˆ + f1ˆX, f2ˆ + f3ˆX, ..., f254ˆ + f255ˆX)
// g = (g0ˆ + g1ˆX, g2ˆ + g3ˆX, ..., g254ˆ + g255ˆX)
//
// h = f ◦ g
//
// See algorithm 11 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
constexpr void polymul(std::span<const ml_kem_field::zq_t, N> f, std::span<const ml_kem_field::zq_t, N> g, std::span<ml_kem_field::zq_t, N> h) {
    using poly_t = std::span<const ml_kem_field::zq_t, 2>;
    using mut_poly_t = std::span<ml_kem_field::zq_t, 2>;

    for (size_t i = 0; i < f.size() / 2; i++) {
        const size_t off = i * 2;
        basemul(poly_t(f.subspan(off, 2)), poly_t(g.subspan(off, 2)), mut_poly_t(h.subspan(off, 2)), POLY_MUL_ZETA_EXP[i]);
    }
}

} // namespace ml_kem_ntt

// Holds compile-time executable functions, ensuring that functions are invoked with proper arguments.
namespace ml_kem_params {

// Compile-time check to ensure that number of bits ( read `d` ) to consider during
// polynomial coefficient compression/ decompression is within tolerable bounds.
//
// See "Compression and Decompression" section on page 21 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
consteval bool check_d(const size_t d) {
    return d < ml_kem_field::Q_BIT_WIDTH;
}

// Compile-time check to ensure that functions requiring `η` as parameter are invoked with proper argument.
consteval bool check_eta(const size_t eta) {
    return (eta == 2) || (eta == 3);
}

// Compile-time check to ensure that functions requiring `k` as parameter are invoked with proper argument.
consteval bool check_k(const size_t k) {
    return (k == 2) || (k == 3) || (k == 4);
}

// Compile-time check to ensure that polynomial to byte array encoding ( and decoding ) routines are invoked with proper params.
consteval bool check_l(const size_t l) {
    return (l == 1) || (l == 4) || (l == 5) || (l == 10) || (l == 11) || (l == 12);
}

// Compile-time check to ensure that operand matrices are having compatible dimension for matrix multiplication.
consteval bool check_matrix_dim(const size_t a_cols, const size_t b_rows) {
    return !static_cast<bool>(a_cols ^ b_rows);
}

// Compile-time check to ensure that both K-PKE, ML-KEM key generation routine is invoked with proper parameter set.
//
// See table 2 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
consteval bool check_keygen_params(const size_t k, const size_t eta1) {
    bool flg0 = (k == 2) && (eta1 == 3);
    bool flg1 = (k == 3) && (eta1 == 2);
    bool flg2 = (k == 4) && (eta1 == 2);

    return flg0 || flg1 || flg2;
}

// Compile-time check to ensure that K-PKE encryption routine is invoked with proper parameter set.
//
// See table 2 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
consteval bool check_encrypt_params(const size_t k, const size_t η1, const size_t η2, const size_t du, const size_t dv) {
    bool flg0 = (k == 2) && (η1 == 3) && (η2 == 2) && (du == 10) && (dv == 4);
    bool flg1 = (k == 3) && (η1 == 2) && (η2 == 2) && (du == 10) && (dv == 4);
    bool flg2 = (k == 4) && (η1 == 2) && (η2 == 2) && (du == 11) && (dv == 5);

    return flg0 || flg1 || flg2;
}

// Compile-time check to ensure that K-PKE decryption routine is invoked with proper parameter set.
//
// See table 2 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
consteval bool check_decrypt_params(const size_t k, const size_t du, const size_t dv) {
    bool flg0 = (k == 2) && (du == 10) && (dv == 4);
    bool flg1 = (k == 3) && (du == 10) && (dv == 4);
    bool flg2 = (k == 4) && (du == 11) && (dv == 5);

    return flg0 || flg1 || flg2;
}

// Compile-time check to ensure that ML-KEM encapsulation routine is invoked with proper parameter set.
//
// See table 2 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
consteval bool check_encap_params(const size_t k, const size_t η1, const size_t η2, const size_t du, const size_t dv) {
    return check_encrypt_params(k, η1, η2, du, dv);
}

// Compile-time check to ensure that ML-KEM encapsulation routine is invoked with proper parameter set.
//
// See table 2 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
consteval bool check_decap_params(const size_t k, const size_t η1, const size_t η2, const size_t du, const size_t dv) {
    return check_encap_params(k, η1, η2, du, dv);
}

} // namespace ml_kem_params

namespace ml_kem_utils {

// Uniform sampling in R_q | q = 3329.
//
// Given a byte stream, this routine *deterministically* samples a degree 255 polynomial in NTT representation.
// If the byte stream is statistically close to uniform random byte stream, produced polynomial coefficients are also
// statiscally close to randomly sampled elements of R_q.
//
// See algorithm 7 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
constexpr void sample_ntt(auto &hasher, std::span<ml_kem_field::zq_t, ml_kem_ntt::N> poly) {
    constexpr size_t n = poly.size();

    size_t coeff_idx = 0;
    array<std::decay_t<decltype(hasher)>::rate / std::numeric_limits<uint8_t>::digits> buf{};

    while (coeff_idx < n) {
        hasher.squeeze(buf);

        for (size_t off = 0; (off < buf.size()) && (coeff_idx < n); off += 3) {
            const uint16_t d1 = (static_cast<uint16_t>(buf[off + 1] & 0x0f) << 8) | static_cast<uint16_t>(buf[off + 0]);
            const uint16_t d2 = (static_cast<uint16_t>(buf[off + 2]) << 4) | (static_cast<uint16_t>(buf[off + 1] >> 4));

            if (d1 < ml_kem_field::Q) {
                poly[coeff_idx] = ml_kem_field::zq_t(d1);
                coeff_idx++;
            }

            if ((d2 < ml_kem_field::Q) && (coeff_idx < n)) {
                poly[coeff_idx] = ml_kem_field::zq_t(d2);
                coeff_idx++;
            }
        }
    }
}

// Generate public matrix A ( consists of degree-255 polynomials ) in NTT domain, by sampling from a XOF ( read SHAKE128 ),
// which is seeded with 32 -bytes key and two nonces ( each of 1 -byte ).
//
// See step (3-7) of algorithm 13 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
template <size_t k, bool transpose>
constexpr void generate_matrix(std::span<ml_kem_field::zq_t, k * k * ml_kem_ntt::N> mat, std::span<const uint8_t, 32> rho)
    requires(ml_kem_params::check_k(k))
{
    array<rho.size() + 2> xof_in{};
    std::copy(rho.begin(), rho.end(), xof_in.begin());

    for (size_t i = 0; i < k; i++) {
        for (size_t j = 0; j < k; j++) {
            const size_t off = (i * k + j) * ml_kem_ntt::N;

            if constexpr (transpose) {
                xof_in[32] = static_cast<uint8_t>(i);
                xof_in[33] = static_cast<uint8_t>(j);
            } else {
                xof_in[32] = static_cast<uint8_t>(j);
                xof_in[33] = static_cast<uint8_t>(i);
            }

            shake<128> hasher;
            hasher.update(xof_in);
            hasher.finalize();

            using poly_t = std::span<ml_kem_field::zq_t, mat.size() / (k * k)>;
            sample_ntt(hasher, poly_t(mat.subspan(off, ml_kem_ntt::N)));
        }
    }
}

// Centered Binomial Distribution.
// A degree 255 polynomial deterministically sampled from `64 * eta` -bytes output of a pseudorandom function ( PRF ).
//
// See algorithm 8 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
template <size_t eta>
constexpr void sample_poly_cbd(std::span<const uint8_t, 64 * eta> prf, std::span<ml_kem_field::zq_t, ml_kem_ntt::N> poly)
    requires(ml_kem_params::check_eta(eta))
{
    if constexpr (eta == 2) {
        static_assert(eta == 2, "η must be 2 !");

        constexpr size_t till = 64 * eta;
        constexpr uint8_t mask8 = 0b01010101;
        constexpr uint8_t mask2 = 0b11;

        for (size_t i = 0; i < till; i++) {
            const size_t poff = i << 1;
            const uint8_t word = prf[i];

            const uint8_t t0 = (word >> 0) & mask8;
            const uint8_t t1 = (word >> 1) & mask8;
            const uint8_t t2 = t0 + t1;

            poly[poff + 0] = ml_kem_field::zq_t((t2 >> 0) & mask2) - ml_kem_field::zq_t((t2 >> 2) & mask2);
            poly[poff + 1] = ml_kem_field::zq_t((t2 >> 4) & mask2) - ml_kem_field::zq_t((t2 >> 6) & mask2);
        }
    } else {
        static_assert(eta == 3, "η must be 3 !");

        constexpr size_t till = 64;
        constexpr uint32_t mask24 = 0b001001001001001001001001u;
        constexpr uint32_t mask3 = 0b111u;

        for (size_t i = 0; i < till; i++) {
            const size_t boff = i * 3;
            const size_t poff = i << 2;

            const uint32_t word =
                (static_cast<uint32_t>(prf[boff + 2]) << 16) | (static_cast<uint32_t>(prf[boff + 1]) << 8) | static_cast<uint32_t>(prf[boff + 0]);

            const uint32_t t0 = (word >> 0) & mask24;
            const uint32_t t1 = (word >> 1) & mask24;
            const uint32_t t2 = (word >> 2) & mask24;
            const uint32_t t3 = t0 + t1 + t2;

            poly[poff + 0] = ml_kem_field::zq_t((t3 >> 0) & mask3) - ml_kem_field::zq_t((t3 >> 3) & mask3);
            poly[poff + 1] = ml_kem_field::zq_t((t3 >> 6) & mask3) - ml_kem_field::zq_t((t3 >> 9) & mask3);
            poly[poff + 2] = ml_kem_field::zq_t((t3 >> 12) & mask3) - ml_kem_field::zq_t((t3 >> 15) & mask3);
            poly[poff + 3] = ml_kem_field::zq_t((t3 >> 18) & mask3) - ml_kem_field::zq_t((t3 >> 21) & mask3);
        }
    }
}

// Sample a polynomial vector from Bη, following step (8-11) of algorithm 13 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
template <size_t k, size_t eta>
constexpr void generate_vector(std::span<ml_kem_field::zq_t, k * ml_kem_ntt::N> vec, std::span<const uint8_t, 32> sigma, const uint8_t nonce)
    requires((k == 1) || ml_kem_params::check_k(k))
{
    array<64 * eta> prf_out{};
    array<sigma.size() + 1> prf_in{};
    std::copy(sigma.begin(), sigma.end(), prf_in.begin());

    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_kem_ntt::N;

        prf_in[32] = nonce + static_cast<uint8_t>(i);

        shake<256> hasher;
        hasher.update(prf_in);
        hasher.finalize();
        hasher.squeeze(prf_out);

        using poly_t = std::span<ml_kem_field::zq_t, vec.size() / k>;
        ml_kem_utils::sample_poly_cbd<eta>(prf_out, poly_t(vec.subspan(off, ml_kem_ntt::N)));
    }
}

} // namespace ml_kem_utils

namespace ml_kem_utils {

// Given a degree-255 polynomial, where significant portion of each ( total 256 of them ) coefficient ∈ [0, 2^l),
// this routine serializes the polynomial to a byte array of length 32 * l -bytes.
//
// See algorithm 5 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
template <size_t l>
constexpr void encode(std::span<const ml_kem_field::zq_t, ml_kem_ntt::N> poly, std::span<uint8_t, 32 * l> arr)
    requires(ml_kem_params::check_l(l))
{
    std::fill(arr.begin(), arr.end(), 0);

    if constexpr (l == 1) {
        constexpr size_t itr_cnt = ml_kem_ntt::N >> 3;
        constexpr uint32_t one = 0b1u;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t off = i << 3;
            arr[i] = (static_cast<uint8_t>(poly[off + 7].raw() & one) << 7) | (static_cast<uint8_t>(poly[off + 6].raw() & one) << 6) |
                     (static_cast<uint8_t>(poly[off + 5].raw() & one) << 5) | (static_cast<uint8_t>(poly[off + 4].raw() & one) << 4) |
                     (static_cast<uint8_t>(poly[off + 3].raw() & one) << 3) | (static_cast<uint8_t>(poly[off + 2].raw() & one) << 2) |
                     (static_cast<uint8_t>(poly[off + 1].raw() & one) << 1) | (static_cast<uint8_t>(poly[off + 0].raw() & one) << 0);
        }
    } else if constexpr (l == 4) {
        constexpr size_t itr_cnt = ml_kem_ntt::N >> 1;
        constexpr uint32_t msk = 0b1111u;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t off = i << 1;
            arr[i] = (static_cast<uint8_t>(poly[off + 1].raw() & msk) << 4) | static_cast<uint8_t>(poly[off + 0].raw() & msk);
        }
    } else if constexpr (l == 5) {
        constexpr size_t itr_cnt = ml_kem_ntt::N >> 3;
        constexpr uint32_t mask5 = 0b11111u;
        constexpr uint32_t mask4 = 0b1111u;
        constexpr uint32_t mask3 = 0b111u;
        constexpr uint32_t mask2 = 0b11u;
        constexpr uint32_t mask1 = 0b1u;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 3;
            const size_t boff = i * 5;

            const auto t0 = poly[poff + 0].raw();
            const auto t1 = poly[poff + 1].raw();
            const auto t2 = poly[poff + 2].raw();
            const auto t3 = poly[poff + 3].raw();
            const auto t4 = poly[poff + 4].raw();
            const auto t5 = poly[poff + 5].raw();
            const auto t6 = poly[poff + 6].raw();
            const auto t7 = poly[poff + 7].raw();

            arr[boff + 0] = (static_cast<uint8_t>(t1 & mask3) << 5) | (static_cast<uint8_t>(t0 & mask5) << 0);
            arr[boff + 1] = (static_cast<uint8_t>(t3 & mask1) << 7) | (static_cast<uint8_t>(t2 & mask5) << 2) | static_cast<uint8_t>((t1 >> 3) & mask2);
            arr[boff + 2] = (static_cast<uint8_t>(t4 & mask4) << 4) | static_cast<uint8_t>((t3 >> 1) & mask4);
            arr[boff + 3] = (static_cast<uint8_t>(t6 & mask2) << 6) | (static_cast<uint8_t>(t5 & mask5) << 1) | static_cast<uint8_t>((t4 >> 4) & mask1);
            arr[boff + 4] = (static_cast<uint8_t>(t7 & mask5) << 3) | static_cast<uint8_t>((t6 >> 2) & mask3);
        }
    } else if constexpr (l == 10) {
        constexpr size_t itr_cnt = ml_kem_ntt::N >> 2;
        constexpr uint32_t mask6 = 0b111111u;
        constexpr uint32_t mask4 = 0b1111u;
        constexpr uint32_t mask2 = 0b11u;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 2;
            const size_t boff = i * 5;

            const auto t0 = poly[poff + 0].raw();
            const auto t1 = poly[poff + 1].raw();
            const auto t2 = poly[poff + 2].raw();
            const auto t3 = poly[poff + 3].raw();

            arr[boff + 0] = static_cast<uint8_t>(t0);
            arr[boff + 1] = static_cast<uint8_t>((t1 & mask6) << 2) | static_cast<uint8_t>((t0 >> 8) & mask2);
            arr[boff + 2] = static_cast<uint8_t>((t2 & mask4) << 4) | static_cast<uint8_t>((t1 >> 6) & mask4);
            arr[boff + 3] = static_cast<uint8_t>((t3 & mask2) << 6) | static_cast<uint8_t>((t2 >> 4) & mask6);
            arr[boff + 4] = static_cast<uint8_t>(t3 >> 2);
        }
    } else if constexpr (l == 11) {
        constexpr size_t itr_cnt = ml_kem_ntt::N >> 3;
        constexpr uint32_t mask8 = 0b11111111u;
        constexpr uint32_t mask7 = 0b1111111u;
        constexpr uint32_t mask6 = 0b111111u;
        constexpr uint32_t mask5 = 0b11111u;
        constexpr uint32_t mask4 = 0b1111u;
        constexpr uint32_t mask3 = 0b111u;
        constexpr uint32_t mask2 = 0b11u;
        constexpr uint32_t mask1 = 0b1u;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 3;
            const size_t boff = i * 11;

            const auto t0 = poly[poff + 0].raw();
            const auto t1 = poly[poff + 1].raw();
            const auto t2 = poly[poff + 2].raw();
            const auto t3 = poly[poff + 3].raw();
            const auto t4 = poly[poff + 4].raw();
            const auto t5 = poly[poff + 5].raw();
            const auto t6 = poly[poff + 6].raw();
            const auto t7 = poly[poff + 7].raw();

            arr[boff + 0] = static_cast<uint8_t>(t0 & mask8);
            arr[boff + 1] = static_cast<uint8_t>((t1 & mask5) << 3) | static_cast<uint8_t>((t0 >> 8) & mask3);
            arr[boff + 2] = static_cast<uint8_t>((t2 & mask2) << 6) | static_cast<uint8_t>((t1 >> 5) & mask6);
            arr[boff + 3] = static_cast<uint8_t>((t2 >> 2) & mask8);
            arr[boff + 4] = static_cast<uint8_t>((t3 & mask7) << 1) | static_cast<uint8_t>((t2 >> 10) & mask1);
            arr[boff + 5] = static_cast<uint8_t>((t4 & mask4) << 4) | static_cast<uint8_t>((t3 >> 7) & mask4);
            arr[boff + 6] = static_cast<uint8_t>((t5 & mask1) << 7) | static_cast<uint8_t>((t4 >> 4) & mask7);
            arr[boff + 7] = static_cast<uint8_t>((t5 >> 1) & mask8);
            arr[boff + 8] = static_cast<uint8_t>((t6 & mask6) << 2) | static_cast<uint8_t>((t5 >> 9) & mask2);
            arr[boff + 9] = static_cast<uint8_t>((t7 & mask3) << 5) | static_cast<uint8_t>((t6 >> 6) & mask5);
            arr[boff + 10] = static_cast<uint8_t>((t7 >> 3) & mask8);
        }
    } else {
        static_assert(l == 12, "l must be equal to 12 !");

        constexpr size_t itr_cnt = ml_kem_ntt::N >> 1;
        constexpr uint32_t mask4 = 0b1111u;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 1;
            const size_t boff = i * 3;

            const auto t0 = poly[poff + 0].raw();
            const auto t1 = poly[poff + 1].raw();

            arr[boff + 0] = static_cast<uint8_t>(t0);
            arr[boff + 1] = static_cast<uint8_t>((t1 & mask4) << 4) | static_cast<uint8_t>((t0 >> 8) & mask4);
            arr[boff + 2] = static_cast<uint8_t>(t1 >> 4);
        }
    }
}

// Given a byte array of length 32 * l -bytes this routine deserializes it to a polynomial of degree 255 s.t. significant
// portion of each ( total 256 of them ) coefficient ∈ [0, 2^l).
//
// See algorithm 6 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
template <size_t l>
constexpr void decode(std::span<const uint8_t, 32 * l> arr, std::span<ml_kem_field::zq_t, ml_kem_ntt::N> poly)
    requires(ml_kem_params::check_l(l))
{
    if constexpr (l == 1) {
        constexpr size_t itr_cnt = ml_kem_ntt::N >> 3;
        constexpr uint8_t one = 0b1;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t off = i << 3;
            const uint8_t byte = arr[i];

            poly[off + 0] = ml_kem_field::zq_t((byte >> 0) & one);
            poly[off + 1] = ml_kem_field::zq_t((byte >> 1) & one);
            poly[off + 2] = ml_kem_field::zq_t((byte >> 2) & one);
            poly[off + 3] = ml_kem_field::zq_t((byte >> 3) & one);
            poly[off + 4] = ml_kem_field::zq_t((byte >> 4) & one);
            poly[off + 5] = ml_kem_field::zq_t((byte >> 5) & one);
            poly[off + 6] = ml_kem_field::zq_t((byte >> 6) & one);
            poly[off + 7] = ml_kem_field::zq_t((byte >> 7) & one);
        }
    } else if constexpr (l == 4) {
        constexpr size_t itr_cnt = ml_kem_ntt::N >> 1;
        constexpr uint8_t mask = 0b1111;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t off = i << 1;
            const uint8_t byte = arr[i];

            poly[off + 0] = ml_kem_field::zq_t((byte >> 0) & mask);
            poly[off + 1] = ml_kem_field::zq_t((byte >> 4) & mask);
        }
    } else if constexpr (l == 5) {
        constexpr size_t itr_cnt = ml_kem_ntt::N >> 3;
        constexpr uint8_t mask5 = 0b11111;
        constexpr uint8_t mask4 = 0b1111;
        constexpr uint8_t mask3 = 0b111;
        constexpr uint8_t mask2 = 0b11;
        constexpr uint8_t mask1 = 0b1;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 3;
            const size_t boff = i * 5;

            const auto t0 = static_cast<uint16_t>(arr[boff + 0] & mask5);
            const auto t1 = static_cast<uint16_t>((arr[boff + 1] & mask2) << 3) | static_cast<uint16_t>((arr[boff + 0] >> 5) & mask3);
            const auto t2 = static_cast<uint16_t>((arr[boff + 1] >> 2) & mask5);
            const auto t3 = static_cast<uint16_t>((arr[boff + 2] & mask4) << 1) | static_cast<uint16_t>((arr[boff + 1] >> 7) & mask1);
            const auto t4 = static_cast<uint16_t>((arr[boff + 3] & mask1) << 4) | static_cast<uint16_t>((arr[boff + 2] >> 4) & mask4);
            const auto t5 = static_cast<uint16_t>((arr[boff + 3] >> 1) & mask5);
            const auto t6 = static_cast<uint16_t>((arr[boff + 4] & mask3) << 2) | static_cast<uint16_t>((arr[boff + 3] >> 6) & mask2);
            const auto t7 = static_cast<uint16_t>((arr[boff + 4] >> 3) & mask5);

            poly[poff + 0] = ml_kem_field::zq_t(t0);
            poly[poff + 1] = ml_kem_field::zq_t(t1);
            poly[poff + 2] = ml_kem_field::zq_t(t2);
            poly[poff + 3] = ml_kem_field::zq_t(t3);
            poly[poff + 4] = ml_kem_field::zq_t(t4);
            poly[poff + 5] = ml_kem_field::zq_t(t5);
            poly[poff + 6] = ml_kem_field::zq_t(t6);
            poly[poff + 7] = ml_kem_field::zq_t(t7);
        }
    } else if constexpr (l == 10) {
        constexpr size_t itr_cnt = ml_kem_ntt::N >> 2;
        constexpr uint8_t mask6 = 0b111111;
        constexpr uint8_t mask4 = 0b1111;
        constexpr uint8_t mask2 = 0b11;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 2;
            const size_t boff = i * 5;

            const auto t0 = (static_cast<uint16_t>(arr[boff + 1] & mask2) << 8) | static_cast<uint16_t>(arr[boff + 0]);
            const auto t1 = (static_cast<uint16_t>(arr[boff + 2] & mask4) << 6) | static_cast<uint16_t>(arr[boff + 1] >> 2);
            const auto t2 = (static_cast<uint16_t>(arr[boff + 3] & mask6) << 4) | static_cast<uint16_t>(arr[boff + 2] >> 4);
            const auto t3 = (static_cast<uint16_t>(arr[boff + 4]) << 2) | static_cast<uint16_t>(arr[boff + 3] >> 6);

            poly[poff + 0] = ml_kem_field::zq_t(t0);
            poly[poff + 1] = ml_kem_field::zq_t(t1);
            poly[poff + 2] = ml_kem_field::zq_t(t2);
            poly[poff + 3] = ml_kem_field::zq_t(t3);
        }
    } else if constexpr (l == 11) {
        constexpr size_t itr_cnt = ml_kem_ntt::N >> 3;
        constexpr uint8_t mask7 = 0b1111111;
        constexpr uint8_t mask6 = 0b111111;
        constexpr uint8_t mask5 = 0b11111;
        constexpr uint8_t mask4 = 0b1111;
        constexpr uint8_t mask3 = 0b111;
        constexpr uint8_t mask2 = 0b11;
        constexpr uint8_t mask1 = 0b1;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 3;
            const size_t boff = i * 11;

            const auto t0 = (static_cast<uint16_t>(arr[boff + 1] & mask3) << 8) | static_cast<uint16_t>(arr[boff + 0]);
            const auto t1 = (static_cast<uint16_t>(arr[boff + 2] & mask6) << 5) | static_cast<uint16_t>(arr[boff + 1] >> 3);
            const auto t2 =
                (static_cast<uint16_t>(arr[boff + 4] & mask1) << 10) | (static_cast<uint16_t>(arr[boff + 3]) << 2) | static_cast<uint16_t>(arr[boff + 2] >> 6);
            const auto t3 = (static_cast<uint16_t>(arr[boff + 5] & mask4) << 7) | static_cast<uint16_t>(arr[boff + 4] >> 1);
            const auto t4 = (static_cast<uint16_t>(arr[boff + 6] & mask7) << 4) | static_cast<uint16_t>(arr[boff + 5] >> 4);
            const auto t5 =
                (static_cast<uint16_t>(arr[boff + 8] & mask2) << 9) | (static_cast<uint16_t>(arr[boff + 7]) << 1) | static_cast<uint16_t>(arr[boff + 6] >> 7);
            const auto t6 = (static_cast<uint16_t>(arr[boff + 9] & mask5) << 6) | static_cast<uint16_t>(arr[boff + 8] >> 2);
            const auto t7 = (static_cast<uint16_t>(arr[boff + 10]) << 3) | static_cast<uint16_t>(arr[boff + 9] >> 5);

            poly[poff + 0] = ml_kem_field::zq_t(t0);
            poly[poff + 1] = ml_kem_field::zq_t(t1);
            poly[poff + 2] = ml_kem_field::zq_t(t2);
            poly[poff + 3] = ml_kem_field::zq_t(t3);
            poly[poff + 4] = ml_kem_field::zq_t(t4);
            poly[poff + 5] = ml_kem_field::zq_t(t5);
            poly[poff + 6] = ml_kem_field::zq_t(t6);
            poly[poff + 7] = ml_kem_field::zq_t(t7);
        }
    } else {
        static_assert(l == 12, "l must be equal to 12 !");

        constexpr size_t itr_cnt = ml_kem_ntt::N >> 1;
        constexpr uint8_t mask4 = 0b1111;

        for (size_t i = 0; i < itr_cnt; i++) {
            const size_t poff = i << 1;
            const size_t boff = i * 3;

            const auto t0 = (static_cast<uint16_t>(arr[boff + 1] & mask4) << 8) | static_cast<uint16_t>(arr[boff + 0]);
            const auto t1 = (static_cast<uint16_t>(arr[boff + 2]) << 4) | static_cast<uint16_t>(arr[boff + 1] >> 4);

            // Read line (786-792) of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
            poly[poff + 0] = ml_kem_field::zq_t::from_non_reduced(t0);
            poly[poff + 1] = ml_kem_field::zq_t::from_non_reduced(t1);
        }
    }
}

} // namespace ml_kem_utils

namespace ml_kem_utils {

// Given an element x ∈ Z_q | q = 3329, this routine compresses it by discarding some low-order bits, computing y ∈ [0, 2^d) | d < round(log2(q)).
//
// See formula 4.7 on page 21 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
// Following implementation collects inspiration from https://github.com/FiloSottile/mlkem768/blob/cffbfb96/mlkem768.go#L395-L425.
template <size_t d>
constexpr ml_kem_field::zq_t compress(const ml_kem_field::zq_t x)
    requires(ml_kem_params::check_d(d))
{
    constexpr uint16_t mask = (1u << d) - 1;

    const auto dividend = x.raw() << d;
    const auto quotient0 = static_cast<uint32_t>((static_cast<uint64_t>(dividend) * ml_kem_field::R) >> (ml_kem_field::Q_BIT_WIDTH * 2));
    const auto remainder = dividend - quotient0 * ml_kem_field::Q;

    const auto quotient1 = quotient0 + ((((ml_kem_field::Q / 2) - remainder) >> 31) & 1);
    const auto quotient2 = quotient1 + (((ml_kem_field::Q + (ml_kem_field::Q / 2) - remainder) >> 31) & 1);

    return ml_kem_field::zq_t(static_cast<uint16_t>(quotient2) & mask);
}

// Given an element x ∈ [0, 2^d) | d < round(log2(q)), this routine decompresses it back to y ∈ Z_q | q = 3329.
//
// See formula 4.8 on page 21 of ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
template <size_t d>
constexpr ml_kem_field::zq_t decompress(const ml_kem_field::zq_t x)
    requires(ml_kem_params::check_d(d))
{
    constexpr uint32_t t0 = 1u << d;
    constexpr uint32_t t1 = t0 >> 1;

    const uint32_t t2 = ml_kem_field::Q * x.raw();
    const uint32_t t3 = t2 + t1;
    const uint16_t t4 = static_cast<uint16_t>(t3 >> d);

    return ml_kem_field::zq_t(t4);
}

// Utility function to compress each of 256 coefficients of a degree-255 polynomial while mutating the input.
template <size_t d>
constexpr void poly_compress(std::span<ml_kem_field::zq_t, ml_kem_ntt::N> poly)
    requires(ml_kem_params::check_d(d))
{
    for (size_t i = 0; i < poly.size(); i++) {
        poly[i] = compress<d>(poly[i]);
    }
}

// Utility function to decompress each of 256 coefficients of a degree-255 polynomial while mutating the input.
template <size_t d>
constexpr void poly_decompress(std::span<ml_kem_field::zq_t, ml_kem_ntt::N> poly)
    requires(ml_kem_params::check_d(d))
{
    for (size_t i = 0; i < poly.size(); i++) {
        poly[i] = decompress<d>(poly[i]);
    }
}

} // namespace ml_kem_utils

namespace ml_kem_utils {

// Given two matrices ( in NTT domain ) of compatible dimension, where each matrix element is a degree-255 polynomial over Z_q | q = 3329,
// this routine multiplies them, computing a resulting matrix.
template <size_t a_rows, size_t a_cols, size_t b_rows, size_t b_cols>
constexpr void matrix_multiply(std::span<const ml_kem_field::zq_t, a_rows * a_cols * ml_kem_ntt::N> a,
                               std::span<const ml_kem_field::zq_t, b_rows * b_cols * ml_kem_ntt::N> b,
                               std::span<ml_kem_field::zq_t, a_rows * b_cols * ml_kem_ntt::N> c)
    requires(ml_kem_params::check_matrix_dim(a_cols, b_rows))
{
    using poly_t = std::span<const ml_kem_field::zq_t, ml_kem_ntt::N>;

    std::array<ml_kem_field::zq_t, ml_kem_ntt::N> tmp{};
    auto tmp_span = std::span(tmp);

    for (size_t i = 0; i < a_rows; i++) {
        for (size_t j = 0; j < b_cols; j++) {
            const size_t coff = (i * b_cols + j) * ml_kem_ntt::N;

            for (size_t k = 0; k < a_cols; k++) {
                const size_t aoff = (i * a_cols + k) * ml_kem_ntt::N;
                const size_t boff = (k * b_cols + j) * ml_kem_ntt::N;

                ml_kem_ntt::polymul(poly_t(a.subspan(aoff, ml_kem_ntt::N)), poly_t(b.subspan(boff, ml_kem_ntt::N)), tmp_span);

                for (size_t l = 0; l < ml_kem_ntt::N; l++) {
                    c[coff + l] += tmp[l];
                }
            }
        }
    }
}

// Given a vector ( of dimension `k x 1` ) of degree-255 polynomials ( where polynomial coefficients are in non-NTT form ),
// this routine applies in-place polynomial NTT over `k` polynomials.
template <size_t k>
constexpr void poly_vec_ntt(std::span<ml_kem_field::zq_t, k * ml_kem_ntt::N> vec)
    requires((k == 1) || ml_kem_params::check_k(k))
{
    using poly_t = std::span<ml_kem_field::zq_t, ml_kem_ntt::N>;

    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_kem_ntt::N;
        ml_kem_ntt::ntt(poly_t(vec.subspan(off, ml_kem_ntt::N)));
    }
}

// Given a vector ( of dimension `k x 1` ) of degree-255 polynomials ( where polynomial coefficients are in NTT form i.e.
// they are placed in bit-reversed order ), this routine applies in-place polynomial iNTT over those `k` polynomials.
template <size_t k>
constexpr void poly_vec_intt(std::span<ml_kem_field::zq_t, k * ml_kem_ntt::N> vec)
    requires((k == 1) || ml_kem_params::check_k(k))
{
    using poly_t = std::span<ml_kem_field::zq_t, ml_kem_ntt::N>;

    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_kem_ntt::N;
        ml_kem_ntt::intt(poly_t(vec.subspan(off, ml_kem_ntt::N)));
    }
}

// Given a vector ( of dimension `k x 1` ) of degree-255 polynomials, this routine adds it to another polynomial vector of same dimension.
template <size_t k>
constexpr void poly_vec_add_to(std::span<const ml_kem_field::zq_t, k * ml_kem_ntt::N> src, std::span<ml_kem_field::zq_t, k * ml_kem_ntt::N> dst)
    requires((k == 1) || ml_kem_params::check_k(k))
{
    constexpr size_t cnt = k * ml_kem_ntt::N;

    for (size_t i = 0; i < cnt; i++) {
        dst[i] += src[i];
    }
}

// Given a vector ( of dimension `k x 1` ) of degree-255 polynomials, this routine subtracts it to another polynomial vector of same dimension.
template <size_t k>
constexpr void poly_vec_sub_from(std::span<const ml_kem_field::zq_t, k * ml_kem_ntt::N> src, std::span<ml_kem_field::zq_t, k * ml_kem_ntt::N> dst)
    requires((k == 1) || ml_kem_params::check_k(k))
{
    constexpr size_t cnt = k * ml_kem_ntt::N;

    for (size_t i = 0; i < cnt; i++) {
        dst[i] -= src[i];
    }
}

// Given a vector ( of dimension `k x 1` ) of degree-255 polynomials, this routine encodes each of those polynomials into 32 x l -bytes,
// writing to a (k x 32 x l) -bytes destination array.
template <size_t k, size_t l>
constexpr void poly_vec_encode(std::span<const ml_kem_field::zq_t, k * ml_kem_ntt::N> src, std::span<uint8_t, k * 32 * l> dst)
    requires(ml_kem_params::check_k(k))
{
    using poly_t = std::span<const ml_kem_field::zq_t, src.size() / k>;
    using serialized_t = std::span<uint8_t, dst.size() / k>;

    for (size_t i = 0; i < k; i++) {
        const size_t off0 = i * ml_kem_ntt::N;
        const size_t off1 = i * l * 32;

        ml_kem_utils::encode<l>(poly_t(src.subspan(off0, ml_kem_ntt::N)), serialized_t(dst.subspan(off1, 32 * l)));
    }
}

// Given a byte array of length (k x 32 x l) -bytes, this routine decodes them into k degree-255 polynomials, writing them to a
// column vector of dimension `k x 1`.
template <size_t k, size_t l>
constexpr void poly_vec_decode(std::span<const uint8_t, k * 32 * l> src, std::span<ml_kem_field::zq_t, k * ml_kem_ntt::N> dst)
    requires(ml_kem_params::check_k(k))
{
    using serialized_t = std::span<const uint8_t, src.size() / k>;
    using poly_t = std::span<ml_kem_field::zq_t, dst.size() / k>;

    for (size_t i = 0; i < k; i++) {
        const size_t off0 = i * l * 32;
        const size_t off1 = i * ml_kem_ntt::N;

        ml_kem_utils::decode<l>(serialized_t(src.subspan(off0, 32 * l)), poly_t(dst.subspan(off1, ml_kem_ntt::N)));
    }
}

// Given a vector ( of dimension `k x 1` ) of degree-255 polynomials, each of k * 256 coefficients are compressed, while mutating input.
template <size_t k, size_t d>
constexpr void poly_vec_compress(std::span<ml_kem_field::zq_t, k * ml_kem_ntt::N> vec)
    requires(ml_kem_params::check_k(k))
{
    using poly_t = std::span<ml_kem_field::zq_t, vec.size() / k>;

    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_kem_ntt::N;
        ml_kem_utils::poly_compress<d>(poly_t(vec.subspan(off, ml_kem_ntt::N)));
    }
}

// Given a vector ( of dimension `k x 1` ) of degree-255 polynomials, each of k * 256 coefficients are decompressed, while mutating input.
template <size_t k, size_t d>
constexpr void poly_vec_decompress(std::span<ml_kem_field::zq_t, k * ml_kem_ntt::N> vec)
    requires(ml_kem_params::check_k(k))
{
    using poly_t = std::span<ml_kem_field::zq_t, vec.size() / k>;

    for (size_t i = 0; i < k; i++) {
        const size_t off = i * ml_kem_ntt::N;
        ml_kem_utils::poly_decompress<d>(poly_t(vec.subspan(off, ml_kem_ntt::N)));
    }
}

} // namespace ml_kem_utils

// Constant-time comparison and selection of unsigned integer values.
namespace subtle {

// Given two unsigned integers x, y of type operandT ( of bitwidth 8, 16, 32 or
// 64 ), this routine returns true ( if x == y ) or false ( in case x != y )
// testing equality of two values.
//
// We represent truth value using maximum number that can be represented using
// returnT i.e. all bits of returnT are set to one. While for false value, we
// set all bits of returnT to zero.
template <typename operandT, typename returnT>
static inline constexpr returnT ct_eq(const operandT x, const operandT y)
    requires(std::is_unsigned_v<operandT> && std::is_unsigned_v<returnT>)
{
    const operandT a = x ^ y;
    const operandT b = a | (-a);
    const operandT c = b >> ((sizeof(operandT) * 8) - 1); // select only MSB
    const returnT d = static_cast<returnT>(c);
    const returnT e = d - static_cast<returnT>(1);

    return e;
}

// Given a branch value br ( of type branchT ) holding either truth or false
// value and two unsigned integers x, y ( of bitwidth 8, 16, 32 or 64 ), this
// routine selects x if br is truth value or it returns y.
//
// Branch value br can have either of two values
//
// - truth value is represented using all bits of type branchT set to 1
// - false value is represented using all bits of type branchT set to 0
//
// If br takes any other value, this is an undefined behaviour !
template <typename branchT, typename operandT>
static inline constexpr operandT ct_select(const branchT br, const operandT x, const operandT y)
    requires(std::is_unsigned_v<branchT> && std::is_unsigned_v<operandT>)
{
    const branchT z = br >> ((sizeof(branchT) * 8) - 1); // select MSB
    const operandT w = -static_cast<operandT>(z);        // bw(br) = bw(x) = bw(y)
    const operandT selected = (x & w) | (y & (~w));      // br ? x : y

    return selected;
}

} // namespace subtle

namespace ml_kem_utils {

// Given two byte arrays of equal length, this routine can be used for comparing them in constant-time,
// producing truth value (0xffffffff) in case of equality, otherwise it returns false value (0x00000000).
template <size_t n>
constexpr uint32_t ct_memcmp(std::span<const uint8_t, n> bytes0, std::span<const uint8_t, n> bytes1) {
    uint32_t flag = -1u;
    for (size_t i = 0; i < n; i++) {
        flag &= subtle::ct_eq<uint8_t, uint32_t>(bytes0[i], bytes1[i]);
    }

    return flag;
}

// Given a branch value, taking either 0x00000000 (false value) or 0xffffffff (truth value), this routine can be used for conditionally
// copying bytes from either `source0` byte array (in case branch holds truth value) or `source1` byte array (if branch holds false value)
// to `sink` byte array, all in constant-time.
//
// In simple words, `sink = cond ? source0 ? source1`
template <size_t n>
constexpr void ct_cond_memcpy(const uint32_t cond, std::span<uint8_t, n> sink, std::span<const uint8_t, n> source0, std::span<const uint8_t, n> source1) {
    for (size_t i = 0; i < n; i++) {
        sink[i] = subtle::ct_select(cond, source0[i], source1[i]);
    }
}

} // namespace ml_kem_utils

template <auto k, auto eta1, auto du, auto dv>
struct mlkem_base {
    static inline constexpr auto n = 256;
    static inline constexpr auto q = 3329;
    static inline constexpr auto eta2 = 2;

    static inline constexpr auto pke_privkey_size = k * 12 * 32;
    static inline constexpr auto pke_pubkey_size = pke_privkey_size + 32;

    static inline constexpr auto pke_cipher_text_len = 32 * (k * du + dv);
    static inline constexpr auto kem_cipher_text_len = pke_cipher_text_len;
    static inline constexpr auto shared_secret_byte_len = 32;
    static inline constexpr auto message_size = 32;

    static inline constexpr auto kem_privkey_size = pke_privkey_size + pke_pubkey_size + 32 + 32;
    static inline constexpr auto kem_pubkey_size = pke_pubkey_size;

    static inline constexpr auto privkey_size = kem_privkey_size;
    static inline constexpr auto pubkey_size = kem_pubkey_size;

    using private_key_type = array<privkey_size>;
    using public_key_type = array<pubkey_size>;

    private_key_type private_key_;
    public_key_type public_key_;

    void private_key() {
        array<32> d, z;
        get_random_secure_bytes(d);
        get_random_secure_bytes(z);
        ml_kem_geygen(d, z);
    }
    // ML-KEM key generation algorithm, generating byte serialized public key and secret key, given 32 -bytes seed `d` and `z`.
    // See algorithm 16 defined in ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
    constexpr void ml_kem_geygen(auto &&d, // used in CPA-PKE
                                 auto &&z  // used in CCA-KEM
    ) {
        std::span pubkey{public_key_};
        std::span seckey{private_key_};

        constexpr size_t seckey_offset_kpke_skey = k * 12 * 32;
        constexpr size_t seckey_offset_kpke_pkey = seckey_offset_kpke_skey + pubkey.size();
        constexpr size_t seckey_offset_z = seckey_offset_kpke_pkey + 32;

        auto kpke_skey_in_seckey = seckey.template subspan<0, seckey_offset_kpke_skey>();
        auto kpke_pkey_in_seckey = seckey.template subspan<seckey_offset_kpke_skey, seckey_offset_kpke_pkey - seckey_offset_kpke_skey>();
        auto kpke_pkey_digest_in_seckey = seckey.template subspan<seckey_offset_kpke_pkey, seckey_offset_z - seckey_offset_kpke_pkey>();
        auto z_in_seckey = seckey.template subspan<seckey_offset_z, seckey.size() - seckey_offset_z>();

        k_pke_geygen(d, kpke_pkey_in_seckey, kpke_skey_in_seckey);
        std::copy(kpke_pkey_in_seckey.begin(), kpke_pkey_in_seckey.end(), pubkey.begin());
        std::copy(z.begin(), z.end(), z_in_seckey.begin());

        sha3<256> hasher;
        hasher.update(pubkey);
        auto r = hasher.digest();
        memcpy(kpke_pkey_digest_in_seckey.data(), r.data(), r.size());
    }
    static void k_pke_geygen(auto &&d, auto &&pubkey, auto &&seckey) {
        array<64> g_out{};
        memcpy(g_out.data(), d.data(), d.size());
        g_out[d.size()] = k;
        std::span g{g_out};

        sha3<512> h512;
        h512.update(g.subspan(0, d.size() + 1));
        g_out = h512.digest();

        const auto rho = g.subspan<0, 32>();
        const auto sigma = g.subspan<rho.size(), 32>();

        std::array<ml_kem_field::zq_t, k * k * ml_kem_ntt::N> A_prime{};
        ml_kem_utils::generate_matrix<k, false>(A_prime, rho);

        uint8_t N = 0;

        std::array<ml_kem_field::zq_t, k * ml_kem_ntt::N> s{};
        ml_kem_utils::generate_vector<k, eta1>(s, sigma, N);
        N += k;

        std::array<ml_kem_field::zq_t, k * ml_kem_ntt::N> e{};
        ml_kem_utils::generate_vector<k, eta1>(e, sigma, N);
        N += k;

        ml_kem_utils::poly_vec_ntt<k>(s);
        ml_kem_utils::poly_vec_ntt<k>(e);

        std::array<ml_kem_field::zq_t, k * ml_kem_ntt::N> t_prime{};

        ml_kem_utils::matrix_multiply<k, k, k, 1>(A_prime, s, t_prime);
        ml_kem_utils::poly_vec_add_to<k>(e, t_prime);

        constexpr size_t pubkey_offset = k * 12 * 32;
        auto encoded_t_prime_in_pubkey = pubkey.template subspan<0, pubkey_offset>();
        auto rho_in_pubkey = pubkey.template subspan<pubkey_offset, 32>();

        ml_kem_utils::poly_vec_encode<k, 12>(t_prime, encoded_t_prime_in_pubkey);
        std::copy(rho.begin(), rho.end(), rho_in_pubkey.begin());
        ml_kem_utils::poly_vec_encode<k, 12>(s, seckey);
    }

    // Given seed `m` and a ML-KEM-512 public key, this routine computes a ML-KEM-512 cipher text and a fixed size shared secret.
    // If, input ML-KEM-512 public key is malformed, encapsulation will fail, returning false.
    [[nodiscard("If public key is malformed, encapsulation fails")]] constexpr bool
    encapsulate(std::span<const uint8_t, 32> m, std::span<uint8_t, pke_cipher_text_len> cipher, std::span<uint8_t, shared_secret_byte_len> shared_secret) {
        return ml_kem_encapsulate(m, std::span{public_key_}, cipher, shared_secret);
    }

    // Given ML-KEM public key and 32 -bytes seed ( used for deriving 32 -bytes message & 32 -bytes random coin ), this routine computes
    // ML-KEM cipher text which can be shared with recipient party ( owning corresponding secret key ) over insecure channel.
    //
    // It also computes a fixed length 32 -bytes shared secret, which can be used for fast symmetric key encryption between these
    // two participating entities. Alternatively they might choose to derive longer keys from this shared secret. Other side of
    // communication should also be able to generate same 32 -byte shared secret, after successful decryption of cipher text.
    //
    // If invalid ML-KEM public key is input, this function execution will fail, returning false.
    //
    // See algorithm 17 defined in ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
    [[nodiscard("Use result, it might fail because of malformed input public key")]] constexpr bool
    ml_kem_encapsulate(std::span<const uint8_t, 32> m, std::span<const uint8_t, kem_pubkey_size> pubkey, std::span<uint8_t, pke_cipher_text_len> cipher,
                       std::span<uint8_t, shared_secret_byte_len> shared_secret) {
        array<m.size() + sha3<256>::digest_size_bytes> g_in{};
        array<sha3<512>::digest_size_bytes> g_out{};

        auto g_in_span = std::span(g_in);
        auto g_in_span0 = g_in_span.template first<m.size()>();
        auto g_in_span1 = g_in_span.template last<sha3<256>::digest_size_bytes>();

        auto g_out_span = std::span(g_out);
        auto g_out_span0 = g_out_span.template first<shared_secret.size()>();
        auto g_out_span1 = g_out_span.template last<g_out_span.size() - g_out_span0.size()>();

        std::copy(m.begin(), m.end(), g_in_span0.begin());

        sha3<256> h256;
        h256.update(pubkey);
        auto dgst1 = h256.digest();
        memcpy(g_in_span1.data(), dgst1.data(), dgst1.size());

        sha3<512> h512;
        h512.update(g_in_span);
        auto dgst2 = h512.digest();
        memcpy(g_out_span.data(), dgst2.data(), dgst2.size());

        const auto has_mod_check_passed = k_pke_encrypt(pubkey, m, g_out_span1, cipher);
        if (!has_mod_check_passed) {
            // Got an invalid public key
            return has_mod_check_passed;
        }

        std::copy(g_out_span0.begin(), g_out_span0.end(), shared_secret.begin());
        return true;
    }

    // Given a *valid* K-PKE public key, 32 -bytes message ( to be encrypted ) and 32 -bytes random coin
    // ( from where all randomness is deterministically sampled ), this routine encrypts message using
    // K-PKE encryption algorithm, computing compressed cipher text.
    //
    // If modulus check, as described in point (2) of section 7.2 of ML-KEM standard, fails, it returns false.
    //
    // See algorithm 14 of K-PKE specification https://doi.org/10.6028/NIST.FIPS.203.
    [[nodiscard("Use result of modulus check on public key")]] constexpr bool k_pke_encrypt(std::span<const uint8_t, kem_pubkey_size> pubkey,
                                                                                            std::span<const uint8_t, 32> msg,
                                                                                            std::span<const uint8_t, 32> rcoin,
                                                                                            std::span<uint8_t, kem_cipher_text_len> ctxt) {
        constexpr size_t pkoff = k * 12 * 32;
        auto encoded_t_prime_in_pubkey = pubkey.template subspan<0, pkoff>();
        auto rho = pubkey.template subspan<pkoff, 32>();

        std::array<ml_kem_field::zq_t, k * ml_kem_ntt::N> t_prime{};
        array<encoded_t_prime_in_pubkey.size()> encoded_tprime{};

        ml_kem_utils::poly_vec_decode<k, 12>(encoded_t_prime_in_pubkey, t_prime);
        ml_kem_utils::poly_vec_encode<k, 12>(t_prime, encoded_tprime);

        using encoded_pkey_t = std::span<const uint8_t, encoded_t_prime_in_pubkey.size()>;
        const auto are_equal = ml_kem_utils::ct_memcmp(encoded_pkey_t(encoded_t_prime_in_pubkey), encoded_pkey_t(encoded_tprime));
        if (!are_equal) {
            // Got an invalid public key
            return false;
        }

        std::array<ml_kem_field::zq_t, k * k * ml_kem_ntt::N> A_prime{};
        ml_kem_utils::generate_matrix<k, true>(A_prime, rho);

        uint8_t N = 0;

        std::array<ml_kem_field::zq_t, k * ml_kem_ntt::N> r{};
        ml_kem_utils::generate_vector<k, eta1>(r, rcoin, N);
        N += k;

        std::array<ml_kem_field::zq_t, k * ml_kem_ntt::N> e1{};
        ml_kem_utils::generate_vector<k, eta2>(e1, rcoin, N);
        N += k;

        std::array<ml_kem_field::zq_t, ml_kem_ntt::N> e2{};
        ml_kem_utils::generate_vector<1, eta2>(e2, rcoin, N);

        ml_kem_utils::poly_vec_ntt<k>(r);

        std::array<ml_kem_field::zq_t, k * ml_kem_ntt::N> u{};

        ml_kem_utils::matrix_multiply<k, k, k, 1>(A_prime, r, u);
        ml_kem_utils::poly_vec_intt<k>(u);
        ml_kem_utils::poly_vec_add_to<k>(e1, u);

        std::array<ml_kem_field::zq_t, ml_kem_ntt::N> v{};

        ml_kem_utils::matrix_multiply<1, k, k, 1>(t_prime, r, v);
        ml_kem_utils::poly_vec_intt<1>(v);
        ml_kem_utils::poly_vec_add_to<1>(e2, v);

        std::array<ml_kem_field::zq_t, ml_kem_ntt::N> m{};
        ml_kem_utils::decode<1>(msg, m);
        ml_kem_utils::poly_decompress<1>(m);
        ml_kem_utils::poly_vec_add_to<1>(m, v);

        constexpr size_t ctxt_offset = k * du * 32;
        auto polyvec_u_in_ctxt = ctxt.template first<ctxt_offset>();
        auto poly_v_in_ctxt = ctxt.template last<dv * 32>();

        ml_kem_utils::poly_vec_compress<k, du>(u);
        ml_kem_utils::poly_vec_encode<k, du>(u, polyvec_u_in_ctxt);

        ml_kem_utils::poly_compress<dv>(v);
        ml_kem_utils::encode<dv>(v, poly_v_in_ctxt);

        return true;
    }

    // Given a ML-KEM-512 secret key and a cipher text, this routine computes a fixed size shared secret.
    constexpr void decapsulate(std::span<const uint8_t, kem_cipher_text_len> cipher, std::span<uint8_t, shared_secret_byte_len> shared_secret) {
        ml_kem_decapsulate(std::span{private_key_}, cipher, shared_secret);
    }

    // Given ML-KEM secret key and cipher text, this routine recovers 32 -bytes plain text which was encrypted by sender,
    // using ML-KEM public key, associated with this secret key.
    //
    // Recovered 32 -bytes plain text is used for deriving a 32 -bytes shared secret key, which can now be
    // used for encrypting communication between two participating parties, using fast symmetric key algorithms.
    //
    // See algorithm 18 defined in ML-KEM specification https://doi.org/10.6028/NIST.FIPS.203.
    constexpr void ml_kem_decapsulate(std::span<const uint8_t, kem_privkey_size> seckey, std::span<const uint8_t, kem_cipher_text_len> cipher,
                                      std::span<uint8_t, 32> shared_secret) {
        constexpr size_t sklen = k * 12 * 32;
        constexpr size_t pklen = k * 12 * 32 + 32;
        constexpr size_t ctlen = cipher.size();

        constexpr size_t skoff0 = sklen;
        constexpr size_t skoff1 = skoff0 + pklen;
        constexpr size_t skoff2 = skoff1 + 32;

        auto pke_sk = seckey.template subspan<0, skoff0>();
        auto pubkey = seckey.template subspan<skoff0, skoff1 - skoff0>();
        auto h = seckey.template subspan<skoff1, skoff2 - skoff1>();
        auto z = seckey.template subspan<skoff2, seckey.size() - skoff2>();

        array<32 + h.size()> g_in{};
        array<shared_secret.size() + 32> g_out{};
        array<shared_secret.size()> j_out{};
        array<cipher.size()> c_prime{};

        auto g_in_span = std::span(g_in);
        auto g_in_span0 = g_in_span.template first<32>();
        auto g_in_span1 = g_in_span.template last<h.size()>();

        auto g_out_span = std::span(g_out);
        auto g_out_span0 = g_out_span.template first<shared_secret.size()>();
        auto g_out_span1 = g_out_span.template last<32>();

        k_pke_decrypt(pke_sk, cipher, g_in_span0);
        std::copy(h.begin(), h.end(), g_in_span1.begin());

        sha3<512> h512;
        h512.absorb(g_in_span);
        auto dgst1 = h512.digest();
        memcpy(g_out_span.data(), dgst1.data(), dgst1.size());

        shake<256> xof256;
        xof256.absorb(z);
        xof256.absorb(cipher);
        xof256.finalize();
        xof256.squeeze(j_out);

        // Explicitly ignore return value, because public key, held as part of secret key is *assumed* to be valid.
        (void)k_pke_encrypt(pubkey, g_in_span0, g_out_span1, c_prime);

        // line 9-12 of algorithm 17, in constant-time
        using kdf_t = std::span<const uint8_t, shared_secret.size()>;
        const uint32_t cond = ml_kem_utils::ct_memcmp(cipher, std::span<const uint8_t, ctlen>(c_prime));
        ml_kem_utils::ct_cond_memcpy(cond, shared_secret, kdf_t(g_out_span0), kdf_t(z));
    }

    // Given K-PKE secret key and cipher text, this routine recovers 32 -bytes plain text which
    // was encrypted using K-PKE public key i.e. associated with this secret key.
    //
    // See algorithm 15 defined in K-PKE specification https://doi.org/10.6028/NIST.FIPS.203.
    constexpr void k_pke_decrypt(std::span<const uint8_t, pke_privkey_size> seckey, std::span<const uint8_t, pke_cipher_text_len> ctxt,
                                 std::span<uint8_t, 32> ptxt) {
        constexpr size_t ctxt_offset = k * du * 32;
        auto polyvec_u_in_ctxt = ctxt.template subspan<0, ctxt_offset>();
        auto poly_v_in_ctxt = ctxt.template subspan<ctxt_offset, dv * 32>();

        std::array<ml_kem_field::zq_t, k * ml_kem_ntt::N> u{};
        std::array<ml_kem_field::zq_t, ml_kem_ntt::N> v{};

        ml_kem_utils::poly_vec_decode<k, du>(polyvec_u_in_ctxt, u);
        ml_kem_utils::poly_vec_decompress<k, du>(u);

        ml_kem_utils::decode<dv>(poly_v_in_ctxt, v);
        ml_kem_utils::poly_decompress<dv>(v);

        std::array<ml_kem_field::zq_t, k * ml_kem_ntt::N> s_prime{};
        ml_kem_utils::poly_vec_decode<k, 12>(seckey, s_prime);

        ml_kem_utils::poly_vec_ntt<k>(u);

        std::array<ml_kem_field::zq_t, ml_kem_ntt::N> t{};

        ml_kem_utils::matrix_multiply<1, k, k, 1>(s_prime, u, t);
        ml_kem_utils::poly_vec_intt<1>(t);
        ml_kem_utils::poly_vec_sub_from<1>(t, v);

        ml_kem_utils::poly_compress<1>(v);
        ml_kem_utils::encode<1>(v, ptxt);
    }
};

template <auto>
struct mlkem;

template <>
struct mlkem<512> : mlkem_base<2, 3, 10, 4> {};
template <>
struct mlkem<768> : mlkem_base<3, 2, 10, 4> {};
template <>
struct mlkem<1024> : mlkem_base<4, 2, 11, 5> {};

} // namespace crypto
