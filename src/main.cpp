#include "aes.h"
#include "sha2.h"

#include <array>
#include <iostream>
#include <iomanip>
#include <span>
#include <sstream>

int main() {
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

    auto to_string = [](auto &&digest) {
        std::span<uint8_t> d{(uint8_t*)digest.data(), digest.size() * sizeof(typename std::decay_t<decltype(digest)>::value_type)};
        std::stringstream s;
        s << std::setfill('0') << std::hex;
        for (auto &&v : d) {
            s << std::setw(2) << (unsigned int)v;
        }
        std::cout << s.str() << "\n";
        return s.str();
    };

    {
        sha2<224> sha;
        sha.update(0,0);
        to_string(sha.digest());
    }
    {
        sha2<256> sha;
        sha.update(0,0);
        to_string(sha.digest());
    }
    {
        sha2<384> sha;
        sha.update(0,0);
        to_string(sha.digest());
    }
    {
        sha2<512> sha;
        sha.update(0,0);
        to_string(sha.digest());
    }
    {
        sha2<512,224> sha;
        sha.update(0,0);
        to_string(sha.digest());
    }
    {
        /*sha2<512,256> sha;
        sha.update(0,0);
        to_string(sha.digest());*/
    }
    {
        sha2<512> sha;
        sha.update((uint8_t*)"abc",3);
        to_string(sha.digest());
    }
}
