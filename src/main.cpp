#include "aes.h"

#include <iostream>

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
        std::cout << r << "\n";
    };

    {
        unsigned char out[16], out2[16];
        aes_ecb<256> aes{key};
        aes.encrypt(plain, out);
        cmp(right, &out);
        aes.decrypt(out, out2);
        cmp(plain, &out2);
    }
    {
        typedef unsigned v4si __attribute__ ((vector_size (16)));
        v4si out, out2;
        v4si iv{}, iv2{};
        aes_cbc<256> aes{key};
        aes.encrypt(plain, iv, out);
        cmp(right, &out);
        aes.decrypt(out, iv2, out2);
        cmp(plain, &out2);
    }
    {
        typedef unsigned v4si __attribute__ ((vector_size (16)));
        v4si out, out2;
        v4si iv{}, iv2{};
        aes_cfb<256> aes{key};
        aes.encrypt(plain, iv, out);
        aes.decrypt(out, iv2, out2);
        cmp(plain, &out2);
    }
}
