#include "aes.h"
#include "bigint.h"
#include "sha2.h"

#include <array>
#include <iostream>
#include <iomanip>
#include <span>
#include <sstream>

void test_aes() {
    using namespace crypto;

    unsigned char plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                           0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    unsigned char right[] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                             0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};

    auto cmp = [](auto &&left, auto &&right) {
        auto r = memcmp(left, right, 16);
        static int x{};
        x += r;
        //std::cout << r << "\n";
    };

    //using v4u = unsigned __attribute__ ((vector_size (16)));
    using v4u = std::array<unsigned char,16>;
    //using v4u = unsigned char[16];
    int n = 10000000;
    //while (n--)
    {
        {
            //v4u out, out2;
            unsigned char out[16], out2[16];
            aes_ecb<256> aes{key};
            aes.encrypt(plain, out);
            cmp(right, &out);
            aes.decrypt(out, out2);
            cmp(plain, &out2);
        }
        {
            v4u out, out2;
            v4u iv{}, iv2{};
            aes_cbc<256> aes{key};
            aes.encrypt(plain, iv, out);
            cmp(right, &out);
            aes.decrypt(out, iv2, out2);
            cmp(plain, &out2);
        }
        {
            v4u out, out2;
            v4u iv{}, iv2{};
            aes_cfb<256> aes{key};
            aes.encrypt(plain, iv, out);
            aes.decrypt(out, iv2, out2);
            cmp(plain, &out2);
        }
    }
}

void test_sha2() {
    using namespace crypto;

    auto to_string = [](auto &&sha) {
        auto digest = sha.digest();
        std::span<uint8_t> d{(uint8_t*)digest.data(), digest.size() * sizeof(typename std::decay_t<decltype(digest)>::value_type)};
        std::stringstream s;
        s << std::setfill('0') << std::hex;
        for (auto &&v : d) {
            s << std::setw(2) << (unsigned int)v;
        }
        //printf("%s\n", s.str().c_str());
        //std::cout << s.str() << "\n";
        return s.str();
    };
    auto to_string2 = [&](auto &&sha, auto &&s, std::string s2) {
        sha.update(s);
        auto r = to_string(sha) == s2;
        printf("%s\n", r ? "ok" : "false");
    };

    {
        sha2<224> sha;
        to_string2(sha, "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    }
    {
        sha2<256> sha;
        to_string2(sha, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
    {
        sha2<384> sha;
        to_string2(sha, "", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    }
    {
        sha2<512> sha;
        to_string2(sha, "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }
    {
        sha2<512,224> sha;
        to_string2(sha, "", "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
    }
    {
        sha2<512,256> sha;
        to_string2(sha, "", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
    }
    {
        sha2<512> sha;
        to_string2(sha, "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    }
    {
        sha2<224> sha;
        to_string2(sha, "The quick brown fox jumps over the lazy dog", "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525");
    }
    {
        sha2<224> sha;
        to_string2(sha, "The quick brown fox jumps over the lazy dog.", "619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c");
    }
    {
        sha2<224> sha;
        to_string2(sha, "111111111111111111111111111111111111111111111111111111111111111", "00ef5dfeea3023e818bace072aa850098a0f8e852f9b444c14ddb55c");
    }
    {
        sha2<224> sha;
        to_string2(sha,
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111"
                , "394c13be14f7b0d8c3fb5a8588d2710657040ad6efd1c6b9eafccae1");
    }
    {
        sha2<224> sha;
        to_string2(sha,
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111"
                   "11111111111111111111111111111111111111111111111111111111111111111"
                , "32063579e2f475efdea66d4384f75a96df64247e363c7ad8eb640a25");
    }
}

#include <gmp.h>
#include <gmpxx.h>

int main() {
    mpz_class a, b, c;
    a = "100000000000000000000054645645645645600000000000000000000";
    b = "20000000034534534500838393935684563456345340000000000";
    c = a + b;
    c = a * b;

    {
        bigint bn2{0xFFFFFFFFFFFFFFFFull};
        bn2 <<= 65;
    }
    {
        bigint bn2{0xFFFFFFFFFFFFFFFFull};
        bn2 <<= 1;
    }
    {
        bigint bn2{0xFFFFFFFFFFFFFFFFull};
        bn2 <<= 129;
    }
    {
        bigint bn2{0xFFFFFFFFFFFFFFFFull};
        bn2 <<= 128;
    }
    {
        bigint bn1;
        bn1 += 0xFFFFFFFFFFFFFFFFull;
        bigint bn2;
        bn2 += 0xFFFFFFFFFFFFFFFFull;
        bn2 <<= 64;
        bn2 += 1u;
        bn1 += bn2;
    }
    {
        bigint bn1;
        bn1 += 0xFFFFFFFFFFFFFFFFull;
        bigint bn2;
        bn2 += 0xFFFFFFFFFFFFFFFFull;
        bn2 <<= 64;
        bn1 += bn2;
        bn1 += 1u;
    }
    {
        bigint bn;
        std::cout << bn << "\n";
        std::cout << (bn += 1000u) << "\n";
        std::cout << bn + 1u << "\n";
        bn += 0xFFFFFFFFFFFFFFFFu;
        bn += 0xFFFFFFFFFFFFFFFFu;
        bn += 0xFFFFFFFFFFFFFFFFu;
        bn += 0xFFFFFFFFFFFFFFFFu;
        bn += 0xFFFFFFFFFFFFFFFFu;
        //bn *= 0xFFFFFFFFFFFFFFFFu;
    }
}
