#pragma once

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>

namespace crypto {

struct sha2_data {
    static inline constexpr uint32_t K256[] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
            0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
            0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
            0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
            0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
            0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
            0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
            0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
            0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    };
    static inline constexpr uint64_t K512[] = {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
            0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
            0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
            0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
            0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
            0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    };
};

struct sha2_params {
    struct s {
        int r1,r2,sh;
    };
    struct S {
        int r1,r2,r3;
    };

    int rounds;
    int chunk_size_bits;
    s s[2];
    S S[2];

    constexpr auto chunk_size_bytes() const { return chunk_size_bits / 8; }
};
constexpr sha2_params sha256_params {
    64, 512,
    {{7,18,3},{17,19,10}},
    {{2,13,22},{6,11,25}},
};
constexpr sha2_params sha512_params {
    80, 1024,
    {{1,8,7},{19,61,6}},
    {{28,34,39},{14,18,41}},
};

template <typename State, auto K, auto Params>
struct sha2_base {
    void update(const uint8_t *data, size_t length) {
        for (size_t i = 0 ; i < length ; i++) {
            m_data[m_blocklen++] = data[i];
            if (m_blocklen == Params.chunk_size_bytes()) {
                transform();
                // end of the block
                m_bitlen += Params.chunk_size_bits;
                m_blocklen = 0;
            }
        }
    }

protected:
    uint8_t m_data[Params.chunk_size_bytes()];
    uint32_t m_blocklen{};
    uint64_t m_bitlen{};
    std::array<State, 8> h;

    static State choose(State e, State f, State g) {
        return (e & f) ^ (~e & g);
    }
    static State majority(State a, State b, State c) {
        return (a & (b | c)) | (b & c);
    }
    template <auto P>
    static auto s(State x) {
        using std::rotr;
        return rotr(x, P.r1) ^ rotr(x, P.r2) ^ (x >> P.sh);
    }
    template <auto P>
    static auto S(State x) {
        using std::rotr;
        return rotr(x, P.r1) ^ rotr(x, P.r2) ^ rotr(x, P.r3);
    }
    void transform() {
        State w[Params.rounds];
        for (uint8_t i = 0, j = 0; i < 16; ++i, j += sizeof(State)) {
            if constexpr (sizeof(State) == 4) {
                w[i] = (m_data[j] << 24) | (m_data[j + 1] << 16) | (m_data[j + 2] << 8) | (m_data[j + 3] << 0);
            } else {
                w[i] = 0
                       | ((uint64_t)m_data[j + 0] << 56)
                       | ((uint64_t)m_data[j + 1] << 48)
                       | ((uint64_t)m_data[j + 2] << 40)
                       | ((uint64_t)m_data[j + 3] << 32)
                       | ((uint64_t)m_data[j + 4] << 24)
                       | ((uint64_t)m_data[j + 5] << 16)
                       | ((uint64_t)m_data[j + 6] << 8)
                       | ((uint64_t)m_data[j + 7] << 0)
                       ;
            }
        }
        for (uint8_t k = 16; k < Params.rounds; ++k) {
            w[k] = s<Params.s[1]>(w[k - 2]) + w[k - 7] + s<Params.s[0]>(w[k - 15]) + w[k - 16];
        }
        auto state = h;
        for (uint8_t i = 0; i < Params.rounds; ++i) {
            auto maj = majority(state[0], state[1], state[2]);
            auto ch = choose(state[4], state[5], state[6]);
            auto sum = w[i] + K[i] + state[7] + ch + S<Params.S[1]>(state[4]);

            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = state[3] + sum;
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = S<Params.S[0]>(state[0]) + maj + sum;
        }
        auto sz = h.size();
        for (uint8_t i = 0; i < sz; ++i) {
            h[i] += state[i];
        }
    }
    void pad() {
        uint64_t i = m_blocklen;
        constexpr auto padding_size = Params.chunk_size_bytes();
        constexpr auto bigint_size = padding_size / 8;
        constexpr auto padding_minus_bigint = padding_size - bigint_size;
        uint8_t end = m_blocklen < padding_minus_bigint ? padding_minus_bigint : padding_size;

        m_data[i++] = 0x80; // Append a bit 1
        while (i < end) {
            m_data[i++] = 0x00; // Pad with zeros
        }
        if (m_blocklen >= padding_minus_bigint) {
            transform();
            memset(m_data, 0, padding_minus_bigint);
        }

        // Append to the padding the total message's length in bits and transform.
        m_bitlen += m_blocklen * 8;
        for (int i = 0; i < bigint_size - sizeof(m_bitlen); ++i) {
            m_data[padding_size - i - 1] = m_bitlen >> (i * 8);
        }
        for (int i = 8; i < sizeof(m_bitlen) + 8; ++i) {
            m_data[padding_size - i - 1] = 0;
        }
        transform();
    }
    void revert(uint8_t *hash, int len) {
        for (uint8_t i = 0; i < len; i++) {
            *(State*)(hash + i * sizeof(State)) = std::byteswap(h[i]);
        }
        /*for (uint8_t i = 0; i < sizeof(State); i++) {
            for(uint8_t j = 0; j < len; j++) {
                hash[i + (j * sizeof(State))] = (h[j] >> (sizeof(State) * 8 - 8 - i * 8)) & 0xff;
            }
        }*/
    }
};

template <auto Bits>
struct sha2;

template <>
struct sha2<224> : sha2_base<uint32_t,sha2_data::K256,sha256_params> {
    sha2() {
        h = {
                0xc1059ed8,
                0x367cd507,
                0x3070dd17,
                0xf70e5939,
                0xffc00b31,
                0x68581511,
                0x64f98fa7,
                0xbefa4fa4,
        };
    }
    auto digest() {
        std::array<uint8_t, 28> hash;
        pad();
        revert(hash.data(), 7);
        return hash;
    }
};
template <>
struct sha2<256> : sha2_base<uint32_t,sha2_data::K256,sha256_params> {
    sha2() {
        h = {
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
        };
    }
    auto digest() {
        std::array<uint8_t, 32> hash;
        pad();
        revert(hash.data(), 8);
        return hash;
    }
};
template <>
struct sha2<384> : sha2_base<uint64_t,sha2_data::K512,sha512_params> {
    sha2() {
        h = {
                0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
                0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
        };
    }
    auto digest() {
        std::array<uint8_t, 48> hash;
        pad();
        revert(hash.data(), 6);
        return hash;
    }
};
template <>
struct sha2<512> : sha2_base<uint64_t,sha2_data::K512,sha512_params> {
    sha2() {
        h = {
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
        };
    }
    auto digest() {
        std::array<uint8_t, 64> hash;
        pad();
        revert(hash.data(), 8);
        return hash;
    }
};

} // namespace crypto
