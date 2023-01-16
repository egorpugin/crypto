#include "aes.h"
#include "bigint.h"
#include "sha2.h"
#include "sha3.h"
#include "sm4.h"
#include "tls.h"
#include "random.h"
#include "ec.h"
#include "hmac.h"
#include "chacha20.h"
#include "asn1.h"
#include "streebog.h"
#include "kuznyechik.h"

#include <array>
#include <iostream>
#include <iomanip>
#include <span>
#include <sstream>

auto to_string_raw = [](auto &&d) {
    std::stringstream s;
    s << std::setfill('0') << std::hex;
    for (auto &&v : d) {
        s << std::setw(2) << (unsigned int)v;
    }
    // printf("%s\n", s.str().c_str());
    std::cerr << s.str() << "\n";
    return s.str();
};
auto to_string = [](auto &&sha) {
    auto digest = sha.digest();
    std::span<uint8_t> d{(uint8_t *) digest.data(),
                         digest.size() * sizeof(typename std::decay_t<decltype(digest)>::value_type)};
    return to_string_raw(d);
};
auto to_string2 = [](auto &&sha, std::string s, std::string s2) {
    sha.update(s);
    auto r = to_string(sha) == s2;
    printf("%s\n", r ? "ok" : "false");
};
auto cmp_base = [](auto &&left, auto &&right) {
    auto r = left == right;
    static int total, success;
    static struct stats {
        ~stats() {
            std::cerr << "\ntotal:  " << total << "\n"
                << "passed: " << success << "\n"
                << "failed: " << total - success << "\n"
                ;
        }
    } __;
    ++total;
    success += !!r;
    if (!r) {
        std::cerr << "false" << "\n";
    }
};
auto cmp_l = [](auto &&left, auto &&right) {
    return cmp_base(memcmp(left, right, 16), 0);
};

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
            cmp_l(right, &out);
            aes.decrypt(out, out2);
            cmp_l(plain, &out2);
        }
        {
            v4u out, out2;
            v4u iv{}, iv2{};
            aes_cbc<256> aes{key};
            aes.encrypt(plain, iv, out);
            cmp_l(right, &out);
            aes.decrypt(out, iv2, out2);
            cmp_l(plain, &out2);
        }
        {
            v4u out, out2;
            v4u iv{}, iv2{};
            aes_cfb<256> aes{key};
            aes.encrypt(plain, iv, out);
            aes.decrypt(out, iv2, out2);
            cmp_l(plain, &out2);
        }
    }
}

void test_sha2() {
    using namespace crypto;
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

void test_sha3() {
    using namespace crypto;
    {
        sha3<224> sha;
        to_string2(sha, "", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    }
    {
        sha3<256> sha;
        to_string2(sha, "", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    }
    {
        sha3<384> sha;
        to_string2(sha, "", "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    }
    {
        sha3<512> sha;
        to_string2(sha, "", "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    }
    {
        shake<128,256> sha;
        to_string2(sha, "", "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    }
    {
        shake<256,512> sha;
        to_string2(sha, "", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
    }
    {
        shake<256,5120> sha;
        to_string2(sha, "", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea203bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f5a1aaa96d313eacc890936c173cdcd0fab882c45755feb3aed96d477ff96390bf9a66d1368b208e21f7c10d04a3dbd4e360633e5db4b602601c14cea737db3dcf722632cc77851cbdde2aaf0a33a07b373445df490cc8fc1e4160ff118378f11f0477de055a81a9eda57a4a2cfb0c83929d310912f729ec6cfa36c6ac6a75837143045d791cc85eff5b21932f23861bcf23a52b5da67eaf7baae0f5fb1369db78f3ac45f8c4ac5671d85735cdddb09d2b1e34a1fc066ff4a162cb263d6541274ae2fcc865f618abe27c124cd8b074ccd516301b91875824d09958f341ef274bdab0bae316339894304e35877b0c28a9b1fd166c796b9cc258a064a8f57e27f2a5b8d548a728c9444ecb879adc19de0c1b8587de3e73e15d3ce2db7c9fa7b58ffc0e87251773faf3e8f3e3cf1d4dfa723afd4da9097cb3c866acbefab2c4e85e1918990ff93e0656b5f75b08729c60e6a9d7352b9efd2e33e3d1ba6e6d89edfa671266ece6be7bb5ac948b737e41590abe138ce1869c08680162f08863d174e77");
    }

    auto fox = [](auto &&sha, auto &&h1, auto &&h2) {
        using type = std::decay_t<decltype(sha)>;
        to_string2(type{}, "The quick brown fox jumps over the lazy dog", h1);
        to_string2(type{}, "The quick brown fox jumps over the lazy dog.", h2);
    };
    {
        sha3<224> sha;
        fox(sha,
            "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795",
            "2d0708903833afabdd232a20201176e8b58c5be8a6fe74265ac54db0"
            );
    }
    {
        sha3<256> sha;
        fox(sha,
            "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
            "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d"
        );
    }
    {
        sha3<384> sha;
        fox(sha,
            "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41",
            "1a34d81695b622df178bc74df7124fe12fac0f64ba5250b78b99c1273d4b080168e10652894ecad5f1f4d5b965437fb9"
        );
    }
    {
        sha3<512> sha;
        fox(sha,
            "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450",
            "18f4f4bd419603f95538837003d9d254c26c23765565162247483f65c50303597bc9ce4d289f21d1c2f1f458828e33dc442100331b35e7eb031b5d38ba6460f8"
        );
    }
    {
        shake<128,256> sha;
        fox(sha,
            "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e",
            "634069e6b13c3af64c57f05babf5911b6acf1d309b9624fc92b0c0bd9f27f538"
        );
    }
    {
        shake<128,2560> sha;
        fox(sha,
            "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66eb5585ec6f86021cacf272c798bcf97d368b886b18fec3a571f096086a523717a3732d50db2b0b7998b4117ae66a761ccf1847a1616f4c07d5178d0d965f9feba351420f8bfb6f5ab9a0cb102568eabf3dfa4e22279f8082dce8143eb78235a1a54914ab71abb07f2f3648468370b9fbb071e074f1c030a4030225f40c39480339f3dc71d0f04f71326de1381674cc89e259e219927fae8ea2799a03da862a55afafe670957a2af3318d919d0a3358f3b891236d6a8e8d19999d1076b529968faefbd880d77bb300829dca87e9c8e4c28e0800ff37490a5bd8c36c0b0bdb2701a5d58d03378b9dbd384389e3ef0fd4003b08998fd3f32fe1a0810fc0eccaad94bca8dd83b34559c333f0b16dfc2896ed87b30ba14c81f87cd8b4bb6317db89b0e",
            "634069e6b13c3af64c57f05babf5911b6acf1d309b9624fc92b0c0bd9f27f5386331af1672c94b194ce623030744b31e848b7309ee7182c4319a1f67f8644d2034039832313286eb06af2e3fa8d3caa89c72638f9d1b26151d904ed006bd9ae7688f99f57d4195c5cee9eb51508c49169df4c5ee6588e458a69fdc78782155550ef567e503b355d906417cb85e30e7156e53af8be5b0858955c46e21e6fa777b7e351c8dba47949f33b00deef231afc3b861aaf543a8a3db940f8309d1facd1f684ac021c61432dba58fa4a2a5148fd0edc6e6987d9783850e3f7c517986d87525f6e9856987e669ef38e0b3b7996c8777d657d4aac1885b8f2cfeed70e645c869f32d31945565cb2a7d981958d393f8005dbffb0c00dfccc8f0d6111729f3a64e69d2fd4399de6c11635a6ae46daa3e918d473c4e0b2bb974c1ac3939773067"
        );
    }

    {
        sha3<224> sha;
        to_string2(sha,
                   "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
                   "f81f0a8291418a13fca7c85017e3e9c94a92c868ce7c6d103b05f480");
    }
    {
        sha3<224> sha;
        to_string2(sha,
                   "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
                   "8bcb6461eaaa339930d73868863c40861f18598560160ce1d69709a0");
    }
}

void test_sm4() {
    using namespace crypto;

    uint8_t tv_plain[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                          0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t tv_key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    {
        sm4_encrypt enc{tv_key};
        enc.encrypt(tv_plain);

        uint8_t tv_cipher[] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
                               0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};
        cmp_l(tv_cipher, tv_plain);

        sm4_decrypt dec{tv_key};
        dec.decrypt(tv_plain);
        cmp_l(tv_key, tv_plain);
    }
    {
        sm4_encrypt enc{tv_key};
        for (int i = 0; i < 1000000; i++) {
            enc.encrypt(tv_plain);
        }
        uint8_t tv_cipher[] = {0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
                               0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66};
        cmp_l(tv_cipher, tv_plain);

        sm4_decrypt dec{tv_key};
        for (int i = 0; i < 1000000; i++) {
            dec.decrypt(tv_plain);
        }
        cmp_l(tv_key, tv_plain);
    }
}

void test_ec() {
    using namespace crypto;

    //std::cout << std::hex;

    {
        auto m = "0x00542d46e7b3daac8aeb81e533873aabd6d74bb710"_bi;
        {
            ec::parameters<string_view> p{
                .p = "0xc1c627e1638fdc8e24299bb041e4e23af4bb5427"sv,
                .a = "0xc1c627e1638fdc8e24299bb041e4e23af4bb5424"sv,
                .b = "0x877a6d84155a1de374b72d9f9d93b36bb563b2ab"sv,
                .G{
                    "0x010aff82b3ac72569ae645af3b527be133442131"sv,
                    "0x46b8ec1e6d71e5ecb549614887d57a287df573cc"sv,
                }
            };
            auto c = p.curve();
            auto r = m * c.G;
            cmp_base(r.x, "0x41da1a8f74ff8d3f1ce20ef3e9d8865c96014fe3"_bi);
            cmp_base(r.y, "0x73ca143c9badedf2d9d3c7573307115ccfe04f13"_bi);
        }
        {
            ec::weierstrass c{
                "0xdfd7e09d5092e7a5d24fd2fec423f7012430ae9a",
                "0x01914dc5f39d6da3b1fa841fdc891674fa439bd4",
                "0xdfd7e09d5092e7a5d24fd2fec423f7012430ae9d"
            };
            ec::ec_field_point p{
                c,
                "0x70ee7b94f7d52ed6b1a1d3201e2d85d3b82a9810",
                "0x0b23823cd6dc3df20979373e5662f7083f6aa56f"
            };
            auto r = m * p;
            cmp_base(r.x, "0xb616c81e21d66dd84906468475654cf7d6f2058a"_bi);
            cmp_base(r.y, "0x7338bd2600ad645b093a67f4651de9edc625295c"_bi);
        }
    }

    // gost 34.10
    {
        // example 1
        {
            ec::weierstrass c{
                "0x7",
                "0x5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e",
                "0x8000000000000000000000000000000000000000000000000000000000000431"
            };
            ec::ec_field_point p{
                c,
                "2",
                "0x8e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8"
            };
            auto m = "55441196065363246126355624130324183196576709222340016572108097750006097525544"_bi;
            auto r = m * p;
            cmp_base(r.x, "57520216126176808443631405023338071176630104906313632182896741342206604859403"_bi);
            cmp_base(r.y, "17614944419213781543809391949654080031942662045363639260709847859438286763994"_bi);
            //std::cout << r.y << "\n";
        }
        // gost 34.10 example 2
        {
            ec::weierstrass c{
                "0x7",
                "0x1cff0806a31116da29d8cfa54e57eb748bc5f377e49400fdd788b649eca1ac4361834013b2ad7322480a89ca58e0cf74bc9e540c2add6897fad0a3084f302adc",
                "0x4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15df1d852741af4704a0458047e80e4546d35b8336fac224dd81664bbf528be6373"
            };
            ec::ec_field_point p{
                c,
                "0x24d19cc64572ee30f396bf6ebbfd7a6c5213b3b3d7057cc825f91093a68cd762fd60611262cd838dc6b60aa7eee804e28bc849977fac33b4b530f1b120248a9a",
                "0x2bb312a43bd2ce6e0d020613c857acddcfbf061e91e5f2c3f32447c259f39b2c83ab156d77f1496bf7eb3351e1ee4e43dc1a18b91b24640b6dbb92cb1add371e"
            };
            auto m = "610081804136373098219538153239847583006845519069531562982388135354890606301782255383608393423372379057665527595116827307025046458837440766121180466875860 "_bi;
            auto r = m * p;
            cmp_base(r.x, "0x115dc5bc96760c7b48598d8ab9e740d4c4a85a65be33c1815b5c320c854621dd5a515856d13314af69bc5b924c8b4ddff75c45415c1d9dd9dd33612cd530efe1"_bi);
            cmp_base(r.y, "0x37c7c90cd40b0f5621dc3ac1b751cfa0e2634fa0503b3d52639f5d7fb72afd61ea199441d943ffe7f0c70a2759a3cdb84c114e1f9339fdf27f35eca93677beec"_bi);
        }
    }
}

void test_hmac() {
    using namespace crypto;

    auto f = [](auto h, auto &&r1, auto &&r2) {
        auto key = "key"sv;
        auto fox = "The quick brown fox jumps over the lazy dog"sv;
        cmp_base(to_string_raw(hmac<decltype(h)>(key, fox)), r1);
        cmp_base(to_string_raw(hmac<decltype(h)>(fox, fox)), r2);
    };

    f(sha2<256>{},
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"s,
        "05ef8d2632d4140db730878ffb03a0bd9b32de06fb74df0471bde777cba1eff7"s
    );
    f(sha2<512>{},
        "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"s,
        "ed9bb695a3ccfe82fea7055e79fad7d225f5cc9c9b7b1808fc7121237a47903f59d8fad228c5710c487541db2bbecb09891b96b87c8718759ca4aa302cc72598"s
    );
}

void test_chacha20() {
    using namespace crypto;

    uint8_t key[32]{};
    uint32_t counter{1};
    uint8_t nonce[12]{};

    using byte = uint8_t;

    byte plaintext_1[127]{};
    byte out1[127]{};
    byte out2[127]{};

    chacha20(key, counter, nonce, plaintext_1, out1, 127);
    chacha20(key, counter, nonce, out1, out2, 127);
    cmp_l(plaintext_1,out2);
}

void test_asn1() {
    using namespace crypto;

    mmap_file<uint8_t> f{"d:/dev/crypto/_.gosuslugi.ru.der"};
    asn1 a{f};
    //a.parse();

    //rsaEncryption (PKCS #1)
    auto rsaEncryption = make_oid<1,2,840,113549,1,1,1>();

    auto pka = a.get<asn1_oid>(x509::main,x509::certificate,x509::subject_public_key_info,x509::public_key_algorithm,0);
    if (pka != rsaEncryption) {
        throw std::runtime_error{"unknown x509::public_key_algorithm"};
    }
    auto pk = a.get<asn1_bit_string>(x509::main,x509::certificate,x509::subject_public_key_info,x509::subject_public_key);
    {
    int a = 5;
    a++;
    }
}

void test_streebog() {
    using namespace crypto;

    {
    streebog stb;

    //---------------------
    static const unsigned char test_string[63] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32};

    stb.init(256);
    stb.update(test_string, sizeof test_string);
    stb.completion();
    streebog::vect hash = {0x9d, 0x15, 0x1e, 0xef, 0xd8, 0x59, 0x0b, 0x89, 0xda, 0xa6, 0xba,
                           0x6c, 0xb7, 0x4a, 0xf9, 0x27, 0x5d, 0xd0, 0x51, 0x02, 0x6b, 0xb1,
                           0x49, 0xa4, 0x52, 0xfd, 0x84, 0xe5, 0xe5, 0x7b, 0x55, 0x00};
    cmp_base(hash, stb.hash);
    // stb.HashPrint();
    }

    {
    streebog stb;
    const char str[] = "test";
    uint8_t *buffer = (uint8_t *)malloc(strlen(str));
    memcpy(buffer, str, strlen(str));
    stb.init(256);
    stb.update(buffer, strlen(str));
    stb.completion();
    streebog::vect hash = {0x12, 0xa5, 0x08, 0x38, 0x19, 0x1b, 0x55, 0x04, 0xf1, 0xe5, 0xf2,
                           0xfd, 0x07, 0x87, 0x14, 0xcf, 0x6b, 0x59, 0x2b, 0x9d, 0x29, 0xaf,
                           0x99, 0xd0, 0xb1, 0x0d, 0x8d, 0x02, 0x88, 0x1c, 0x38, 0x57};
    cmp_base(hash, stb.hash);
    // printf("GOST 34.11-2012 \"Stribog\"\nString: %s\n", str);
    // stb.HashPrint();
    }

    {
    streebog stb;

    FILE *file;
    uint8_t *buffer_file;
    size_t len;
    stb.init(256);
    if ((file = fopen("1.txt", "rb")) != NULL) {
            buffer_file = (uint8_t *)malloc((size_t)4096);
            while ((len = fread(buffer_file, (size_t)1, (size_t)4096, file)))
                stb.update(buffer_file, len);
            free(buffer_file);
            stb.completion();
            fclose(file);
            streebog::vect hash = {0x12, 0xa5, 0x08, 0x38, 0x19, 0x1b, 0x55, 0x04, 0xf1, 0xe5, 0xf2,
                                   0xfd, 0x07, 0x87, 0x14, 0xcf, 0x6b, 0x59, 0x2b, 0x9d, 0x29, 0xaf,
                                   0x99, 0xd0, 0xb1, 0x0d, 0x8d, 0x02, 0x88, 0x1c, 0x38, 0x57};
            cmp_base(hash, stb.hash);
            // printf("GOST 34.11-2012 \"Stribog\"\nFile name: %s\n", "1.txt");
            // stb.HashPrint();
    } else
            printf("File error: %s\n", "1.txt");
    }
}

void test_kuznechik() {
    using namespace crypto;

    kuznechik::key_type key1{0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd,
                             0xcc, 0xbb, 0xaa, 0x99, 0x88, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45,
                             0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe};

    kuznechik::vect encrypt_test_string{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                                        0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    kuznechik::vect decrypt_test_string{0xcd, 0xed, 0xd4, 0xb9, 0x42, 0x8d, 0x46, 0x5a,
                                        0x30, 0x24, 0xbc, 0xbe, 0x90, 0x9d, 0x67, 0x7f};

    kuznechik k;
    k.expand_key(key1);
    cmp_base(decrypt_test_string, k.encrypt(encrypt_test_string));
    cmp_base(encrypt_test_string, k.decrypt(decrypt_test_string));
}

void test_tls() {
    using namespace crypto;

    auto run = [](auto &&url) {
        //std::cout << "connecting to " << url << "\n";
        try {
            http_client t{url};
            t.run();
            //std::cout << "ok" << "\n\n";
            cmp_base(0, 0);
        } catch (std::exception &e) {
            std::cout << "connecting to " << url << "\n";
            std::cerr << e.what() << "\n\n";
            cmp_base(0, 1);
        }
    };

    //run("91.244.183.22"); // https://infotecs.ru/stand_tls/
    //run("tlsgost-512.cryptopro.ru"); // https://www.cryptopro.ru/products/csp/tc26tls

    //run("software-network.org");
    //run("letsencrypt.org");
    //run("example.com");
    //run("google.com");
    //run("gosuslugi.ru"); // does not support tls13
    //run("sberbank.ru"); // does not support tls13
    //run("nalog.gov.ru");
    //run("github.com");
    //run("gmail.com");
    //run("youtube.com");
    //run("twitch.tv");
    //run("tls13.akamai.io");
    //run("tls13.1d.pw");
    //run("localhost");
}

int main() {
    //test_aes();
    //test_sha2();
    //test_sha3();
    //test_sm4();
    //test_ec();
    //test_hmac();
    //test_chacha20();
    //test_asn1();
    //test_streebog();
    //test_kuznechik();
    test_tls();
}
