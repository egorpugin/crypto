// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#include "aes.h"
#include "argon2.h"
#include "bigint.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"
#include "blake2.h"
#include "blake3.h"
#include "sm4.h"
#include "tls.h"
#include "random.h"
#include "ec.h"
#include "hmac.h"
#include "chacha20.h"
#include "asn1.h"
#include "streebog.h"
#include "grasshopper.h"
#include "magma.h"
#include "mmap.h"
#include "scrypt.h"
#include "jwt.h"
#include "rsa.h"
#include "pki.h"

#include <array>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <print>
#include <span>
#include <sstream>

#define LOG_TEST() std::print("{} ... ", __FUNCTION__);scoped_timer ____timer;

static int total, success;
static struct stats {
    ~stats() {
        std::cerr << "\ntotal:  " << total << "\n"
            << "passed: " << success << "\n"
            << "failed: " << total - success << "\n"
            ;
    }
} __;

struct timer {
    using clock = std::chrono::high_resolution_clock;

    clock::time_point tp{clock::now()};
    int total{::total};
    int success{::success};

    void end() {
        auto diff = clock::now() - tp;
        auto ok = ::total - total == ::success - success;
        std::println("{} in {:.4f}", ok ? "ok" : "errored", std::chrono::duration_cast<std::chrono::duration<float>>(diff).count());
    }
};
struct scoped_timer {
    timer t;
    ~scoped_timer() {
        t.end();
    }
};

auto to_string_raw = [](auto &&d) {
    std::stringstream s;
    s << std::setfill('0') << std::hex;
    for (auto &&v : d) {
        s << std::setw(2) << (unsigned int)v;
    }
    // printf("%s\n", s.str().c_str());
    //std::cerr << s.str() << "\n";
    return s.str();
};
auto to_string2 = [](auto &&sha, std::string s, std::string s2) {
    sha.update(s);
    auto digest = sha.digest();
    //std::span<uint8_t> d{(uint8_t *) digest.data(),
                         //digest.size() * sizeof(typename std::decay_t<decltype(digest)>::value_type)};
    //auto res = to_string_raw(d);
    auto res = to_string_raw(digest);
    auto r = res == s2;
    ++total;
    success += !!r;
    //printf("%s\n", r ? "ok" : "false");
    if (!r) {
        printf("\n");
        printf("input: %s\n", s.c_str());
        printf("expected: %s\n", s2.c_str());
        printf("result: %s\n", res.c_str());
        printf("\n");
        crypto::print_buffer("expected:", s2);
        crypto::print_buffer("result:", res);
    }
};
auto cmp_bool = [](auto &&left, auto &&right) {
    auto r = left == right;
    ++total;
    success += !!r;
    if (!r) {
        std::cerr << "false" << "\n";
    }
    return r;
};
auto cmp_base = [](auto &&left, auto &&right) {
    return cmp_bool(left == right, true);
};
auto cmp_bytes = [](crypto::bytes_concept left, crypto::bytes_concept right) {
    auto r = cmp_base(left,right);
    if (!r) {
        std::cout << "bytes not equal" << "\n";
        std::cout << "left:" << "\n";
        std::cout << left;
        std::cout << "right:" << "\n";
        std::cout << right;
    }
    return r;
};
auto cmp_hash_bytes = [](auto &&sha, crypto::bytes_concept s, crypto::bytes_concept right) {
    sha.update(s);
    return cmp_bytes(sha.digest(), right);
};
auto cmp_l = [](auto &&left, auto &&right) {
    return cmp_base(memcmp(left, right, 16), 0);
};
auto fox = [](auto &&sha, auto &&h1, auto &&h2) {
    using type = std::decay_t<decltype(sha)>;
    to_string2(type{}, "The quick brown fox jumps over the lazy dog", h1);
    to_string2(type{}, "The quick brown fox jumps over the lazy dog.", h2);
};

auto read_file(const std::filesystem::path &fn) {
    if (!std::filesystem::exists(fn)) {
        throw std::runtime_error{"file does not exist: " + fn.string()};
    }
    // better mmap
    std::ifstream i{fn, std::ios::binary};
    auto sz = std::filesystem::file_size(fn);
    std::string s(sz, 0);
    i.read(s.data(), sz);
    return s;
}
void write_file(const std::filesystem::path &fn, auto &&s) {
    std::ofstream o{fn, std::ios::binary};
    o << s;
}

void test_aes() {
    LOG_TEST();

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

void test_sha1() {
    LOG_TEST();

    using namespace crypto;
    {
        sha1 sha;
        to_string2(sha, "", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }
    {
        sha1 sha;
        to_string2(sha, "The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
    }
    {
        sha1 sha;
        to_string2(sha, "The quick brown fox jumps over the lazy dog.", "408d94384216f890ff7a0c3528e8bed1e0b01621");
    }
    {
        sha1 sha;
        to_string2(sha, "The quick brown fox jumps over the lazy cog", "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3");
    }
    {
        sha1 sha;
        to_string2(sha, "123", "40bd001563085fc35165329ea1ff5c5ecbdbbeef");
    }
    {
        sha1 sha;
        to_string2(sha, "plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd", "65426b585154667542717027635463617226672a");
    }
}

void test_sha2() {
    LOG_TEST();

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
    {
        sha2<224> sha;
        to_string2(sha,
                   "message"
                , "ff51ddfabb180148583ba6ac23483acd2d049e7c4fdba6a891419320");
    }
    {
        sha2<512> sha;
        to_string2(sha,
                   "message"
                , "f8daf57a3347cc4d6b9d575b31fe6077e2cb487f60a96233c08cb479dbf31538cc915ec6d48bdbaa96ddc1a16db4f4f96f37276cfcb3510b8246241770d5952c");
    }
}

void test_sha3() {
    LOG_TEST();

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
        sha3<256> sha;
        cmp_hash_bytes(sha,
            "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc0469070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc0469070dd",
            "62ddcbb514fffa979c28304ebd7cc7319d7882bd988007fa28826582ef224aba"_sb);
    }
    {
        sha3<256> sha;
        cmp_hash_bytes(sha,
            "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc0469070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc0469070dd.",
            "e036d52be9b804b3d43da8ea23ab5713cbe59f1f519081010eeea16f6b6efeee"_sb);
    }
    {
        sha3<256> sha;
        cmp_hash_bytes(sha,
            "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc0469070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc0469070dd..",
            "52c2cdabcf0a5f0620e61471fd38760f4dfd09d776da87a0674fe791dede43a9"_sb);
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
    {
        sha3<512> sha;
        to_string2(sha,
                   std::string(0x48, '1'),
                   "631ce1bbf408fa13586f949526b77e8d529a6b89782bf7e156ef7749b66ba5080ac565b15f54e1c01ed65e10cb110aa2622df5d801837630fd2661970632abf5");
    }
    {
        sha3<512> sha;
        to_string2(sha,
                   std::string(0x49, '1'),
                   "cd45f9f16c23b3330fffbaefae37d072b34a5fc05954fda6419fedea03da27393ca7056ef2e25c78e3e787cd95b92d63c2389109553025d15935478fd773ba09");
    }
}

void test_blake2() {
    LOG_TEST();

    using namespace crypto;
    {
        blake2s<224> sha;
        to_string2(sha, "", "1fa1291e65248b37b3433475b2a0dd63d54a11ecc4e3e034e7bc1ef4");
    }
    {
        blake2s<256> b;
        to_string2(b, "", "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    }
    {
        blake2b<384> sha;
        to_string2(sha, "", "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100");
    }
    {
        blake2b<512> sha;
        to_string2(sha, "", "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    }
    {
        blake2s<256> sha;
        to_string2(sha, "abc", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    }
    {
        blake2b<512> sha;
        to_string2(sha, "abc", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    }
    {
        blake2b<512> sha{"1"sv};
        to_string2(sha, "abc", "8dcc70edeec8341bf056873cceea93b05a3f2e7b43aed334fa3de25be04780fcba0a642ef96576ca109a177c3cb51c5642299d26db1f64cc29f5377175a12db2");
    }
    {
        blake2b<512> sha{"abc"sv};
        to_string2(sha, "abc", "17de517e1278d00ac7a6bcf048881aa9a972e6b5cef843d3c61d3e252068a2f526c999f45cd96b172509d085b59170e388f845750c812781df582be3fc4a1972");
    }
    {
        blake2b<512> sha{"69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"sv};
        to_string2(sha,
            "17de517e1278d00ac7a6bcf048881aa9a972e6b5cef843d3c61d3e252068a2f526c999f45cd96b172509d085b59170e388f845750c812781df582be3fc4a1972"
            "17de517e1278d00ac7a6bcf048881aa9a972e6b5cef843d3c61d3e252068a2f526c999f45cd96b172509d085b59170e388f845750c812781df582be3fc4a1972"
            "."
            , "552225b32c7f991578114e624e2484275c96d966090ff90fbf56a3e4773f6d7d4d7865d3d27b7dd6f8e75849800474eeee7c7b747613dbea488548c283f7aa25");
    }
    {
        blake2b<512> sha;
        to_string2(sha, "The quick brown fox jumps over the lazy dog", "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918");
    }
    {
        blake2b<512> sha;
        to_string2(sha, "The quick brown fox jumps over the lazy dof", "ab6b007747d8068c02e25a6008db8a77c218d94f3b40d2291a7dc8a62090a744c082ea27af01521a102e42f480a31e9844053f456b4b41e8aa78bbe5c12957bb");
    }
    {
        blake2b<512> sha;
        to_string2(sha,
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            , "5ab06c925a13d6b9c991d4c2e5ee346bf1befb9b028be3ddf9b39d8fe0e92dc1f4fba7f78aa60a1f18d995e95bb5aabd6faca300e64cdce3352941872e96961f");
    }
    {
        blake2b<512> sha;
        to_string2(sha,
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            "."
            , "00756c07368f4c98176ae5d6b96e321704b8be4b9a2aa298700d4b4e0c0ca6c344f848b389ef3dfdde460e50e85ab649b82f9902cf4453e6c54ea58857fe76d4");
    }
    {
        blake2b<512> sha;
        to_string2(sha,
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            , "dbf11e82f88c5886b76afeb072c0304d27207e5168512cf27628edbb638f272cf05c04d1d85ee4e99dcc7e1f3cb1bcb972d722dabcd6624d613dcba434dbafd0");
    }
    {
        blake2b<512> sha;
        to_string2(sha,
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            "."
            , "c93a777c384d3186824ad214090cecfed185f0f9a618d696c5fea2dc63096643f87eac776f4c95a2b456f21aa225a092c46807c91b8656a79941af7d4cd82668");
    }
}

void test_blake3() {
    LOG_TEST();

    using namespace crypto;

    auto check = [](auto &&in, auto &&out) {
        blake3 b;
        b.update(in);
        cmp_bytes(b.digest(out.size()), out);
    };
    check("", R"(af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262)"_sb);
    check("", R"(af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e0)"_sb);
    check("", R"(af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a)"_sb);
    check("", R"(af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26)"_sb);
    check("IETF", R"(83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2)"_sb);
    check("83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2", R"(9471e2d3a751a5944aed95dc8a8eb1d9411d95cc61cdac6cdb892cd0dc098b48)"_sb);
    check("83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2.", R"(8258a13bc461c981030004b00afe2a91a25a578763ed5e5e42bdb6deecf29eaf)"_sb);
    check("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        R"(dba5865c0d91b17958e4d2cac98c338f85cbbda07b71a020ab16c391b5e7af4bffc423a6a9a445b3eb803bc061a5099d1e0dd83954760e34f899217488ede68a5b)"_sb);
    check("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        R"(e967136f1e3bf4f9106fe5b0345d37f7114edaa4e0df9ae2a1264dc42b8af4e3708144602b1243cbf5c5d2dd8c85a351b4650123e9b8a15f89e3f7d5784fe9f609)"_sb);
    check("83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e29471e2d3a751a5944aed95dc8a8eb1d9411d95cc61cdac6cdb892cd0dc098b48",
        R"(0d4fe4332d952c162479d5ce5548f2be1d27fd48f58e1793f33c3190d35dcedc)"_sb);
    check("83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e29471e2d3a751a5944aed95dc8a8eb1d9411d95cc61cdac6cdb892cd0dc098b48.",
        R"(435c6b135d9cabcbe817208379b1209e558ff707538e762851d5d366e47178e8)"_sb);
    check("83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e29471e2d3a751a5944aed95dc8a8eb1d9411d95cc61cdac6cdb892cd0dc098b48.",
        R"(435c6b135d9cabcbe817208379b1209e558ff707538e762851d5d366e47178e88e83caadfa61a060fedff5e094f30afca958110d0927566499b68e87d757f00688)"_sb);
    check(std::string(1, 0xaa), R"(f12dd093073bfad8ba6656e7e620378cc33cb4e2ab1f0b443b2898d03d1a9b46)"_sb);
    check(std::string(1024, 0xaa) + std::string(1024, 0xbb), R"(e79d2838915accd3b21bb0ba76b5edf8dc08d3d78d0db65b713f0f37ec58c346)"_sb);
    check(std::string(1024, 0xaa) + std::string(1024, 0xbb), R"(e79d2838915accd3b21bb0ba76b5edf8dc08d3d78d0db65b713f0f37ec58c34623d15d1e2d97c52cfb08f73a675c3d1d67bac5110d25703000ea9b6f5fc6ae9210)"_sb);
    check(std::string(4096, 0), R"(b6fb73fc46938c981e2b0b4b1ef282adcfc89854d01bfe3972fdc4785b41b2c7)"_sb);
    // hash traits
    cmp_bytes(blake3::digest({std::string(1024, 0xaa), std::string(1024, 0xbb)}), R"(e79d2838915accd3b21bb0ba76b5edf8dc08d3d78d0db65b713f0f37ec58c346)"_sb);
    cmp_bytes(blake3::digest(std::string(1024, 0xaa), std::string(1024, 0xbb)), R"(e79d2838915accd3b21bb0ba76b5edf8dc08d3d78d0db65b713f0f37ec58c346)"_sb);

    auto check_a = [](int na, auto &&res) {
        blake3 b;
        b.update(std::string(na, 'a'));
        cmp_bytes(b.digest(res.size()), res);
    };
    check_a(1024, R"(5a1c9e5d85d9898297037e8e24f69bb0e604a84c91c3b3ef4784a374812900d9)"_sb);
    check_a(1024, R"(5a1c9e5d85d9898297037e8e24f69bb0e604a84c91c3b3ef4784a374812900d9ecf50f8ed1faefc98c45d05db0c5e4e81eb5d5f3be89b5b12f96c199c61d7cbbc9)"_sb);
    check_a(2048, R"(11654ac17d073b0905429320fee0a34776cb5f10a9767287c70b627fc4f45539)"_sb);
    check_a(2048, R"(11654ac17d073b0905429320fee0a34776cb5f10a9767287c70b627fc4f455397e56bd45802b2a744cf5f7ff1169523c8d5be419747ad281c8a4cc440619a77a6c)"_sb);
    check_a(3072, R"(452f43e13d923a9ee495b3640e4dc681d6224586a9d1252b9d837d13438c92b5)"_sb);
    check_a(3072, R"(452f43e13d923a9ee495b3640e4dc681d6224586a9d1252b9d837d13438c92b5d2b18a46ef11cbd7973487dc71073890ad9ec0ff66add8ea4d4a83e1bc860944fb)"_sb);
    check_a(3072 * 2, R"(f01bbb4825647ad9814caf217d165e6b2e8a84a562fb4e157d0a2e51701f1f39)"_sb);
    check_a(3072 * 2, R"(f01bbb4825647ad9814caf217d165e6b2e8a84a562fb4e157d0a2e51701f1f391210340984e04d780b47652feabe707e301c4e0be160433fcf73fcd3700f364978)"_sb);
    check_a(3072 * 3, R"(805fed622390360e88f8785f648b4b8e2bb6871151e5bb104172d40841d9abc5)"_sb);
    check_a(3072 * 3, R"(805fed622390360e88f8785f648b4b8e2bb6871151e5bb104172d40841d9abc5a38bd070929a2ecc1e409bde1d23c2e69f11a232aeea28bb742fdb793b9330976c)"_sb);
    check_a(7168, R"(1437b23514e7a19dd5d4f48fb6fd4f38e2a9853a16532c6cc341c43c7680dad3)"_sb);
    check_a(7168, R"(1437b23514e7a19dd5d4f48fb6fd4f38e2a9853a16532c6cc341c43c7680dad38d91e07016c4678624dae3112a32663823fc36355e9f828ce4fb0918213599b1e4)"_sb);
    check_a(1024 * 15, R"(e598de4a1995abce47b1a8384cdff5b9822caa202662b47f5e3ba1eb7b3ac8c3dd80cc5d52c92f0948f557561e245208e5b92184d5f5668f4b699942eb92bc6ddf)"_sb);
    check_a(1024 * 16, R"(d2613fb519aa95cd328f55dd4551c848920c2209cdcf0debc02500d2ad8964076a3b341441904fc2e6ebb045517ec87a4f78121a3bb8af00611348c27667141c98)"_sb);

    // keyed
    {
        auto key = R"(0123456789ABCDEF0123456789ABCDEF)"s;
        blake3 b{key};
        b.update("");
        cmp_bytes(b.digest(65), R"(5491091c17191a894372e9f3b8867284eae6221b8030b3632677beae6f9ebe021e380f86faee6a34f802b637d2080e04465138bd0b18c802ec01eb0be8f9498e3d)"_sb);
    }
    // derive
    {
        auto key = R"(0123456789ABCDEF0123456789ABCDEF)"s;
        cmp_bytes(blake3::derive_key("", key, 65),
            R"(f575d579019891a95d9af9cb575e72efcd00cd1df66ae933917f46b890e15c3c8bf19d85e4f71adf61ec161cff147cceed112b70423d3ba5e3dcf8653567487ccd)"_sb);
    }

    auto check_all = [](auto &&msg, auto &&out1, auto &&out2, auto &&out3, auto &&out4) {
        auto key = R"(0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF)"_sb;
        auto key_derive = R"(qwerty)"s;
        auto outlen = 65;
        {
            blake3 b{};
            b.update(msg);
            cmp_bytes(b.digest(outlen), out1);
        }
        {
            blake3 b{key};
            b.update(msg);
            cmp_bytes(b.digest(outlen), out2);
        }
        cmp_bytes(blake3::derive_key(key_derive, msg, outlen), out3);
        cmp_bytes(blake3::derive_key(msg, msg, outlen), out4);
    };
    check_all("",
        R"(af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26)"_sb,
        R"(e69ae626ef8cb2dfc63d9603c9b9e35f670b47484085a417f926345f03afc586641b8e5bdd74d74baf5114de958bcd09fb8f7d0944d9d4dbc20b501ea4df600d81)"_sb,
        R"(f9fa26ec9bd90186cfcbadb18c742318887b4869826013409d09bfdffd581b0dce7631f45e746ede6bcc255f403fd69174f902b0f912ed968d980fe8add9b11f13)"_sb,
        R"(741011989511e0d6b52532320d9edb6c0def0ab7e832b99bcc1259591ce2d75b701d666214c39da11895511954dcc5a5c17e030a4db02e7fb04c0e3230283515c8)"_sb
    );
    check_all("test123",
        R"(e3428f2c4089c278544c4827529dee5c82cdb368dbf6013e576d5ddc179c2bec2bdd6946dcf05d4e829825d38fd2f1072db09120922d98df7f065a911bb3fbda32)"_sb,
        R"(d15c5596d85069c359d15a430136aa5479f9a79480f9ad93b04e37107c69e062ffb53b3132664fc7f6b389344e845653bedaf46deb35cbec5ce98208085eee7991)"_sb,
        R"(9d8b48d9f7bf97a2d3218877e5023e42954f954a8179e7a9718c46298c33e555f9684e5469b5ea62269c07c05312100238641be887da4e1a0917644506e4c6256a)"_sb,
        R"(e5fcee1bb3cde9f038ee32d985c17bd052dd8e6eba23856f73761f1e7ecf80e5071ebdf27ddc2beeffbaf116ec7b7fbfa27bb04cab0f3ff7ddaf05cc0110ed4e37)"_sb
    );
    check_all(std::string(1024, 'a'),
        R"(5a1c9e5d85d9898297037e8e24f69bb0e604a84c91c3b3ef4784a374812900d9ecf50f8ed1faefc98c45d05db0c5e4e81eb5d5f3be89b5b12f96c199c61d7cbbc9)"_sb,
        R"(82fe4001f46d18a731b2361b966f70c5b9f848b9447119882df09cdf48dbec3bc8394159bba068442b88e664bd127b818cccb03517763322fcd44e59ed30e3f73f)"_sb,
        R"(401c1d24951f14eef6c8cf2ad6993221edc8559fb9f56c06cf66c64b43abc1754a0269745176b79598b5e8cb2cc32d921229a62e2fa62c629e15ea7d56f1fe9a51)"_sb,
        R"(cc6d9942e33fa7f78601bb8b9697eddb92458cb77ffaccd19717a929adea788cd3e8d01e7c322591a344f24e53f53c5a70f1af1159545520530c9f64e2864682b1)"_sb
    );
    check_all(std::string(1025, 'a'),
        R"(c59d2e12583df14d951e757a42f1734d355c8c5b1db6b6a33ab2bfabeed40c7d26d5461cf30b142e78fa6227457c866765146a9f3a589f9459041011c018a88a70)"_sb,
        R"(e0fb3171de8423d93db31554929cc382b6c39357acf99e96f5e8d03a7c2fe2fdc26bc0fcb0e2222af7702bcfe5be5ad75751fd85f8806c9a15baca1211b642d7c5)"_sb,
        R"(b730131c95e0d8089907d9e98aa2944e4b4bb2b7d9622b5f8d135d4d0ffbf2c2ea2d74f981e26ffd4e0ac170a757afcefe542035bec79eaa310b10f675512e37eb)"_sb,
        R"(9e38623637339ab770c326b1f87c31c148c19d39782843c29910cee7fab7ac2ac2560389ece68195c2a14ebb5f0ed321390fa26c405e497296b39b94c53168ac9e)"_sb
    );
    check_all(std::string(2048, 'a'),
        R"(11654ac17d073b0905429320fee0a34776cb5f10a9767287c70b627fc4f455397e56bd45802b2a744cf5f7ff1169523c8d5be419747ad281c8a4cc440619a77a6c)"_sb,
        R"(6627a0d2200b5bb56e3921e03813128f060533debaf633deb3f3a3891a650ae92c501da5fb5ca5e99ca1f20cd7b01f3ce13da5997d4958145cd583b31c9c61aa32)"_sb,
        R"(f95d0c930f4eab036ba4e7dce7ccd9c26f8bdcd3515d6f14aa5a188d46e57402042ca431a8c7820c1c861d159356948c3ec100bad75b6358dae552240f1a26d126)"_sb,
        R"(220ddce7808d29d37b1353d4ef18c10d85d8eee6db3678a80ce1031c0cce313c6400d49224e04ed8e83b02ee052d21700bfaf956dc833a3949ecf2f6d090db46d9)"_sb
    );
    check_all(std::string(3072, 'a'),
        R"(452f43e13d923a9ee495b3640e4dc681d6224586a9d1252b9d837d13438c92b5d2b18a46ef11cbd7973487dc71073890ad9ec0ff66add8ea4d4a83e1bc860944fb)"_sb,
        R"(ec7ac93013d9536bea9424f086403ebf9927e724a27390fced378d722c50e5c5ebaa5a4084a948ffeed6b511e8825200152c19a68b5199bdbe3ceb09469c0235dd)"_sb,
        R"(07d71ce58b3d2fd750864b5a91d4aa403510f91bb21130ae9acafb3f19398550b9ee595c877b2626f6f62fbe72c2b2676b2a0aba071dde8bf8a04a7167c290ee7d)"_sb,
        R"(7607c3bdad2cd543a7ee4e52e93428051f699454f3e4620846b855a7105bb93a3aae8feff2f8f98c248281194de6b61e8243ba05ebeff763d9692e3a5f6b96bfc6)"_sb
    );
    check_all(std::string(4096, 'a'),
        R"(cf657d3fd42311a258afdf3b5261c256983e3deb2bb38980cb0e754db903d549ae329a6635596c535f2f443c2eee918d3fd202c8e0dda89e8756135de6e8fb9ac4)"_sb,
        R"(fcf2b82c77c14a1411a07bd1c663e99674f5d7c36aa02f1757a244708b56f9840a3b995dbb59369270f50ae0715d7abdfe0213e9c69f897f473eda57ce3ecf7826)"_sb,
        R"(e9ab7701a0b920f5ac4d2a897226554f7b396041113ac13548a07415db18cad3b540bf1b60baef6c720f2becaf523c34f4c47d6f0b6e7a42300df8e72b78a314c0)"_sb,
        R"(a4e8b185965d7336aac1033c2d33a3c255fa9d389f3c08de7a3bb5e8542a510c63a8eb3be239492f4e9842bff211713ddfc2361ba60c08a3574059605ab8837d80)"_sb
    );
}

void test_sm3() {
    LOG_TEST();

    using namespace crypto;

    auto sm3t = [](auto &&l, auto &&r) {
        sm3 sm;
        cmp_hash_bytes(sm, l, r);
    };

    sm3t("", "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B"_sb);
    sm3t("abc", "66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0"_sb);
    sm3t(R"(61626364 61626364 61626364 61626364 61626364 61626364 61626364 61626364
            61626364 61626364 61626364 61626364 61626364 61626364 61626364 61626364)"_sb,
            "debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732"_sb);

    cmp_bytes(hmac<sm3>("TestSecret", "Hello World"), "9d91da552268ddf11b9f69662773a66c6375b250336dfb9293e7e2611c36d79f"_sb);
}

void test_sm4() {
    LOG_TEST();

    using namespace crypto;

    auto tv_key = "0123456789ABCDEFFEDCBA9876543210"_sb;
    auto tv_plain = "0123456789abcdeffedcba9876543210"_sb;

    {
        sm4_encrypt enc{tv_key};
        auto res = enc.encrypt(tv_plain);

        uint8_t tv_cipher[] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
                               0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};
        cmp_bytes(tv_cipher, res);

        sm4_decrypt dec{tv_key};
        res = dec.decrypt(res);
        cmp_bytes(res, tv_plain);
    }
    {
        sm4_encrypt enc{tv_key};
        auto res = enc.encrypt(tv_plain);
        for (int i = 0; i < 1000000-1; i++) {
            res = enc.encrypt(res);
        }
        uint8_t tv_cipher[] = {0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
                               0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66};
        cmp_bytes(tv_cipher, res);

        sm4_decrypt dec{tv_key};
        for (int i = 0; i < 1000000; i++) {
            res = dec.decrypt(res);
        }
        cmp_bytes(res, tv_plain);
    }
    {
        gcm<sm4_encrypt> g{"0123456789ABCDEFFEDCBA9876543210"_sb};
        auto out = g.encrypt_and_tag(
            "00001234567800000000ABCD"_sb,
            "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA"_sb,
            "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"_sb);
        cmp_bytes(out,
                  R"(17F399F08C67D5EE19D0DC9969C4BB7D
                            5FD46FD3756489069157B282BB200735
                            D82710CA5C22F0CCFA7CBF93D496AC15
                            A56834CBCF98C397B4024A2691233B8D
83DE3541E4C2B58177E065A9BF7B62EC)"_sb);
    }
}

void test_ec() {
    LOG_TEST();

    using namespace crypto;

    // std::cout << std::hex;

    // simple
    {
        {
            ec::parameters<string_view, ec::weierstrass_prime_field> p{.p = "751"sv,
                                          .a = "-1"sv,
                                          .b = "188"sv,
                                          .G{
                                              "0"sv,
                                              "376"sv,
                                          }};
            auto c = p.curve();
            auto m = "386"_bi;
            auto r = m * c.G;
            cmp_base(r.x, "676"_bi);
            cmp_base(r.y, "558"_bi);
        }
        {
            ec::parameters<string_view, ec::weierstrass_prime_field> p{.p = "211"sv,
                                          .a = "0"sv,
                                          .b = "-4"sv,
                                          .G{
                                              "2"sv,
                                              "2"sv,
                                          }};
            auto c = p.curve();
            {
                auto m = "1"_bi;
                auto r = m * c.G;
                cmp_base(r.x, "2"_bi);
                cmp_base(r.y, "2"_bi);
            }
            {
                auto m = "121"_bi;
                auto r = m * c.G;
                cmp_base(r.x, "115"_bi);
                cmp_base(r.y, "48"_bi);
            }
            {
                auto m = "203"_bi;
                auto r = m * c.G;
                cmp_base(r.x, "130"_bi);
                cmp_base(r.y, "203"_bi);
            }
        }
    }

    //
    {
        auto m = "0x00542d46e7b3daac8aeb81e533873aabd6d74bb710"_bi;
        {
            ec::parameters<string_view, ec::weierstrass_prime_field> p{
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
            ec::weierstrass_prime_field c{
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
            ec::weierstrass_prime_field c{
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
        }
        // gost 34.10 example 2
        {
            ec::weierstrass_prime_field c{
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
        //
        {
            auto pubs = "350208a00f0a78c15ef3faa68feefb0ec804cd9eae9cfa0b4f4b8e3351563ae957aa47e08a421e8373e5b7d1947b46f62c0db53b55ffaffe48dafba7d68ac5a2"_sb;
            auto pubc = "f52612c43cbc122e897929919339e1b9221de15ea8553a836439bdbe10842aeaf605f689bef098b3726446cbe63bb7aab240d8a7d5590f009633d9ac464c5949"_sb;
            auto shared = "cd9fe19836b50edbe35dee4e0d6fc3d8e8b08533af1a47a2f16ee02444f5c4b5"_sb;

            using curve = ec::gost::r34102012::ec256a;
            curve s,c;
            s.private_key_ = bytes_concept{"316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb};
            c.private_key_ = bytes_concept{"30bd7301f388a808c3362b415692c1638e3b90d254803ef8c1e3401d328f5887"_sb};

            auto check_pub = [](auto &&c, auto &&v) {
                curve::public_key_type pub;
                c.public_key(pub);
                cmp_bytes(pub, v);
            };
            check_pub(s,pubs);
            check_pub(c,pubc);

            auto check_shared = [&](auto &&c, bytes_concept v) {
                auto sc = c.shared_secret(v);
                cmp_bytes(sc, shared);
            };
            check_shared(s,pubc);
            check_shared(c,pubs);
        }
        //
        {
            ec::weierstrass_prime_field c{
                "0x7",
                "0x5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e",
                "0x8000000000000000000000000000000000000000000000000000000000000431"
            };
            ec::ec_field_point P{
                c,
                "2",
                "0x8e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8"
            };
            auto m = "0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"_bi;
            auto q = m;
            auto d = "0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28"_bi; // private key
            auto Q = d * P; // pubkey
            auto xq = "0x7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B"_bi;
            auto yq = "0x26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA"_bi;
            cmp_base(Q.x, xq);
            cmp_base(Q.y, yq);

            using curve_t = ec::gost::r34102012::curve<256, "0x8000000000000000000000000000000000000000000000000000000000000431"_s,
                                   "0x7"_s,
                                   "0x5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e"_s,

                                   "0x2"_s,
                                   "0x8e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8"_s,

                                   "0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"_s, "1"_s>;

            curve_t ec;
            ec.private_key_ = d;
            auto pubk = ec.public_key();
            cmp_base(bytes_to_bigint(pubk.x), xq);
            cmp_base(bytes_to_bigint(pubk.y), yq);

            {
                auto e = "0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5"_bi;
                auto k = "0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3"_bi;
                auto r = "0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493"_bi;
                auto s = "0x1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40"_bi;

                // sign
                auto c = k * P;
                auto r2 = c.x % q;
                cmp_base(c.x, r);

                auto s2 = (r2 * d + k * e) % q;
                cmp_base(s2, s);

                // verify
                auto v = e.invert(q);
                cmp_base(v, "0x271A4EE429F84EBC423E388964555BB29D3BA53C7BF945E5FAC8F381706354C2"_bi);

                auto z1 = (s * v) % q;
                auto z2 = (-r * v) % q;
                cmp_base(z1, "0x5358F8FFB38F7C09ABC782A2DF2A3927DA4077D07205F763682F3A76C9019B4F"_bi);
                cmp_base(z2, "0x3221B4FBBF6D101074EC14AFAC2D4F7EFAC4CF9FEC1ED11BAE336D27D527665"_bi);

                auto C = z1 * P + z2 * Q;
                cmp_base(C.x % q, r);
            }

            auto h = streebog<256>::digest("test");
            auto sig = ec.sign(h);
            cmp_base(ec.verify(h, bytes_concept{&pubk,sizeof(pubk)}, sig), true);
        }
        // all non twisted edwards
        {
            auto h = streebog<256>::digest("some data");
            auto h2 = streebog<512>::digest("some data");
            cmp_bytes(h, "fb163564090e52332bd401f9218d62f7b1ad1e0d85988cd55663e8b7875a1875"_sb);
            cmp_bytes(h2, "aefa48f59945d65352797c3aa872357019716ad218ee19f76161df4815313f1d1d66449a82bfed36d95e1e229231fd877123f29f16547091afc7aa2a7caa8392"_sb);

            auto check = [](auto c, auto &&h, auto &&pk, auto &&pubkx, auto &&pubky, auto &&sig) {
                c.private_key_ = bytes_concept{pk};
                auto pubk = c.public_key();
                cmp_bytes(pubk.x, pubkx);
                cmp_bytes(pubk.y, pubky);
                cmp_base(c.verify(h, bytes_concept{&pubk,sizeof(pubk)}, sig), true);
                // random sign & verify
                cmp_base(c.verify(h, bytes_concept{&pubk,sizeof(pubk)}, c.sign(h)), true);
            };

            check(ec::gost::r34102012::ec256a{}, h,
                "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                "350208a00f0a78c15ef3faa68feefb0ec804cd9eae9cfa0b4f4b8e3351563ae9"_sb,
                "57aa47e08a421e8373e5b7d1947b46f62c0db53b55ffaffe48dafba7d68ac5a2"_sb,
                "08c7296c628619b747fce05f5ea0060251deea450491c0a55cdd8441a7455ec715a590da47a0be9caaf4963ee90a0f97220fa9fb8de46bb16f4937f00257e6b9"_sb
            );
            check(ec::gost::r34102012::ec256b{}, h,
                "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                "bf4e76550b73dfe435fef49742327274422b37fa5ab6554ccfa8727de2bf08e7"_sb,
                "4aa5bd0f69072dbc8ced84c2c5873f92fe491bd1f0115d3efd7af5108b920bf8"_sb,
                "4c495c83477eeb1d650ba8b1621f0b2c01ab797d3d95837316dd935154b4bbb515e6197fef15b818a0a64f836abb43f6f70582c922a95c9a957eb791e34e78a9"_sb
            );
            check(ec::gost::r34102012::ec256c{}, h,
                "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                "3af74bc0bcbf01e58e7676c9eb56a553ff10dccf600818e8e83423a7c1183c57"_sb,
                "d54a1bc1b7fc30f987c99a41cd39e6ecefb177439f98aa09505febedd14db609"_sb,
                "1a47b37a0338ec053ce5abb7f133557921c306fd235aab21b5d2bfa67d7f65ef760a19e3eae46d5ec06c56a54d4e695a167ea18cf827571d0c86a894b159e17e"_sb
            );
            check(ec::gost::r34102012::ec256d{}, h,
                "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                "d92e0b13cd506dfba87399b6472ae1c682ad82ad0c2288e9d76e99b0693b5a6e"_sb,
                "df072de75411b32cc935cba3a5079692cb3dd7aeaf8e938c3c2b2b2951c30195"_sb,
                "4620f84a48eaee14e4e0b63853d9ff18e65af3000f4917e30ea4fb9d506587d1886426b909a417e99357edcca35ac4aad7fa85f4b5e7c975e8b5428af640704a"_sb
            );

            check(ec::gost::r34102012::ec512a{}, h2,
                "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                "d6274e275a12898de87b835dd2b7a583f993d6a605d7ed869ae65d7350f9b85af8b14ed153e8982176ebf432a936b5de2a8aca197718be183fd115758082d1ac"_sb,
                "67a861c5cbafc99f2597d9773beba6cb2e335aa59e8270909071ba83720c3630d15cbfc252d487e3a8a9aab16de15f039ced3a6a631a8d5cd91db1b14f329fcd"_sb,
                "e197c18f669222262265c574d5911c3e9c3336fde1c0164c6eaa94f66615a8e7ace78bfb17c17ac2fa515b758e4020f07d38e87b138895069412a78aec225e211029974df95bd7d8b66e7bd8b2274a2a3096b818c6aec62375141c0a6a0c3f60c40462bd98a90f04b5da2353ead54622870a0df24a99e8d44b146c428ff6fd45"_sb
            );
            check(ec::gost::r34102012::ec512b{}, h2,
                "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                "2017a304d30b67873bd0811ba8a4a798a9fa2f340012f96a9c2a3377f26bec485f76c278abdb27a8a7770afcc4273423de784250703863883df3820ca5bb4d31"_sb,
                "ce809ced666b746e3af53676c4e0c65f3ff0f1e7025e72b2d6790680efc3a1b98e9938ad31c2c77dcb563ef575d88f5c5f9af281b31eb83a57fe361f2ae09e03"_sb,
                "06ba0869ecbb5a49f1a28efe0b73a09d0e770b2abf9e449a5e2f51a3fd215b2250b1092661e4ac0f1f09cd7ab88c47fcd2b85106d195b414c8da39526bf475895773e1be05c872bb4fd022e74dfbd1fe5bc4e0088b1aac9f792455761f3586358626c82f107beda04526e5fce497c1160a0db9b1567e92095c377f739eac188e"_sb
            );
            check(ec::gost::r34102012::ec512c{}, h2,
                "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                "cacff08b72c04b5e88342221f68cb188a4cd7792336fff33d9c08187564073862b4d0b7caa1321bb068a122966d39a23032cd6d2fa530fd8fa841643a8dcb26b"_sb,
                "c2fd9d0bb8ed53c889ab26abf4c111bfdc110f212eb42238312bf6e4f562023ca9b873c88a2f2a81aaa67f9ad201da5ddc6b16844ef63c06f1c5ceedba4476a2"_sb,
                "357666b68a3b336a091a642064c2472fd7e80b63c92ccb7c3c927b284ea345f113ebd280afd3c16e27f831309af4325437756cd4094e092b42ab88f032aea8420364fe74f5cbba0d9d9230417de9d988462136368533b5cd84d7eb0d9fecd09b1e0cf75d86ddd53c7f2427079946e151f5d74d2887d93a4a3ddfba2e31ba27aa"_sb
            );
        }
    }

    {
        ec::secp256r1 c{bytes_concept{"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"_sb}};
        auto pubkey = c.public_key();
        cmp_bytes(pubkey.x, "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"_sb);
        cmp_bytes(pubkey.y, "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"_sb);
    }
}

void test_ecdsa() {
    LOG_TEST();

    using namespace crypto;

    // sign & verify
    // rfc6979
    {
        const auto message1 = "sample"s;
        const auto message2 = "test"s;

        auto check = [](auto c_in, auto hash, auto &&msg, auto &&pk, auto &&r_in, auto &&s_in) {
            auto h = decltype(hash)::digest(msg);

            decltype(c_in) c{bytes_concept{pk}};
            auto pubkey = c.public_key();

            auto [r,s] = c.sign_deterministic<decltype(hash)>(h);
            cmp_bytes(r, r_in);
            cmp_bytes(s, s_in);

            cmp_base(c.verify(h, bytes_concept{&pubkey,sizeof(pubkey)}, r, s), true);
        };

        {
            // curve K-163 ansit163k1
            bitlen qlen{163};
            bigint q{"0x4000000000000000000020108A2E0CC0D99F8A5EF"};
            auto h1 = sha256::digest(message1);
            auto hs = ec::prepare_hash_for_signature(h1, q, qlen);
            hmac_drbg<sha256> d{
                expand_bytes("9A 4D 67 92 29 5A 7F 73 0F C3 F2 B4 9C BC 0F 62 E8 62 27 2F"_sb, qlen),
                hs, {}};
            auto res = d.digest({}, qlen);
            cmp_bytes(res, "4982D236F3FFC758838CA6F5E9FEA455106AF3B2B"_sb);
            cmp_bool(bytes_to_bigint(res) > q, true);
            res = d.digest({}, qlen);
            cmp_bytes(res, "63863C30451DADF4944DF4877B740D4F160A8B6AB"_sb);
            cmp_bool(bytes_to_bigint(res) > q, true);
            res = d.digest({}, qlen);
            cmp_bytes(res, "23AF4074C90A02B3FE61D286D5C87F425E6BDD81B"_sb);
            cmp_bool(bytes_to_bigint(res) < q, true);
        }

        /*
        *
        using ansit163k1 = sect<163, "0x800000000000000000000000000000000000000c9"_s, // x^163 + x^7 + x^6 + x^3 + 1
                               "0x000000000000000000000000000000000000000001"_s,
                               "0x000000000000000000000000000000000000000001"_s,

                               "0x02fe13c0537bbc11acaa07d793de4e6d5e5c94eee8"_s,
                               "0x0289070fb05d38ff58321f2e800536d538ccdaa3d9"_s,
                               "0x04000000000000000000020108a2e0cc0d99f8a5ef"_s, "2"_s>;

        check(ec::ansit163k1{}, sha256{}, message1,
            "09A4D6792295A7F730FC3F2B49CBC0F62E862272F"_sb,
            //"9A4D6792295A7F730FC3F2B49CBC0F62E862272F"_sb,
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"_sb,
            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"_sb
        );*/

        {
            //auto h = sha256::digest(message1);
            //bigint hb = bytes_to_bigint(h);
            //if (hb > q) {
            //    hb = hb - q;
            //}
            //auto hh = hb.to_string();
            //hmac_drbg<sha256> d{"00 9A 4D 67 92 29 5A 7F 73 0F C3 F2 B4 9C BC 0F 62 E8 62 27 2F"_sb, hh, {}};
            //d.digest();
            //auto h = sha256::digest(message1);
            //std::string hs(h.begin(), h.end());
            //take_left_bits(hs, qlen);
            //cmp_bytes(hs,
            //    "00 9A 4D 67 92 29 5A 7F 73 0F C3 F2 B4 9C BC 0F 62 E8 62 27 2F"_sb
            //);
        }

        auto check_big = [&](auto c, auto &&msg, auto &&pk, auto &&rs) {
            int i{};
            auto f = [&](auto h) {
                if (rs.size() <= i) {
                    return;
                }
                check(c, h, msg,
                    pk,
                    rs[i+0],
                    rs[i+1]
                );
                i += 2;
            };
            f(sha1{});
            f(sha2<224>{});
            f(sha2<256>{});
            f(sha2<384>{});
            f(sha2<512>{});
        };

        check_big(ec::secp256r1{}, message1, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"_sb,
            std::vector{
                "61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32"_sb,"6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB"_sb,
                "53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F"_sb,"B9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C"_sb,
                "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"_sb,"F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"_sb,
                "0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719"_sb,"4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954"_sb,
                "8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00"_sb,"2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE"_sb,
            }
        );
        check_big(ec::secp384r1{}, message1, "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5"_sb,
            std::vector{
                "EC748D839243D6FBEF4FC5C4859A7DFFD7F3ABDDF72014540C16D73309834FA37B9BA002899F6FDA3A4A9386790D4EB2"_sb,"A3BCFA947BEEF4732BF247AC17F71676CB31A847B9FF0CBC9C9ED4C1A5B3FACF26F49CA031D4857570CCB5CA4424A443"_sb,
                "42356E76B55A6D9B4631C865445DBE54E056D3B3431766D0509244793C3F9366450F76EE3DE43F5A125333A6BE060122"_sb,"9DA0C81787064021E78DF658F2FBB0B042BF304665DB721F077A4298B095E4834C082C03D83028EFBF93A3C23940CA8D"_sb,
                "21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD"_sb,"F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0"_sb,
                "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46"_sb,"99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8"_sb,
                "ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799CFE30F35CC900056D7C99CD7882433709"_sb,"512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112DC7CC3EF3446DEFCEB01A45C2667FDD5"_sb,
            }
        );
        check_big(ec::secp521r1{}, message1, "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"_sb,
            std::vector{
                "0343B6EC45728975EA5CBA6659BBB6062A5FF89EEA58BE3C80B619F322C87910FE092F7D45BB0F8EEE01ED3F20BABEC079D202AE677B243AB40B5431D497C55D75D"_sb,
                "0E7B0E675A9B24413D448B8CC119D2BF7B2D2DF032741C096634D6D65D0DBE3D5694625FB9E8104D3B842C1B0E2D0B98BEA19341E8676AEF66AE4EBA3D5475D5D16"_sb,
                "1776331CFCDF927D666E032E00CF776187BC9FDD8E69D0DABB4109FFE1B5E2A30715F4CC923A4A5E94D2503E9ACFED92857B7F31D7152E0F8C00C15FF3D87E2ED2E"_sb,
                "050CB5265417FE2320BBB5A122B8E1A32BD699089851128E360E620A30C7E17BA41A666AF126CE100E5799B153B60528D5300D08489CA9178FB610A2006C254B41F"_sb,
                "1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7"_sb,
                "04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC"_sb,
                "1EA842A0E17D2DE4F92C15315C63DDF72685C18195C2BB95E572B9C5136CA4B4B576AD712A52BE9730627D16054BA40CC0B8D3FF035B12AE75168397F5D50C67451"_sb,
                "1F21A3CEE066E1961025FB048BD5FE2B7924D0CD797BABE0A83B66F1E35EEAF5FDE143FA85DC394A7DEE766523393784484BDF3E00114A1C857CDE1AA203DB65D61"_sb,
                "0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA"_sb,
                "0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A"_sb,
            }
        );

        check_big(ec::secp256r1{}, message2, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"_sb,
            std::vector{
                "0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89"_sb,
                "01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1"_sb,
                "C37EDB6F0AE79D47C3C27E962FA269BB4F441770357E114EE511F662EC34A692"_sb,
                "C820053A05791E521FCAAD6042D40AEA1D6B1A540138558F47D0719800E18F2D"_sb,
                "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"_sb,
                "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"_sb,
                "83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6"_sb,
                "8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C"_sb,
                "461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04"_sb,
                "39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55"_sb,
            }
        );
        check_big(ec::secp384r1{}, message2, "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5"_sb,
            std::vector{
                "4BC35D3A50EF4E30576F58CD96CE6BF638025EE624004A1F7789A8B8E43D0678ACD9D29876DAF46638645F7F404B11C7"_sb,
                "D5A6326C494ED3FF614703878961C0FDE7B2C278F9A65FD8C4B7186201A2991695BA1C84541327E966FA7B50F7382282"_sb,
                "E8C9D0B6EA72A0E7837FEA1D14A1A9557F29FAA45D3E7EE888FC5BF954B5E62464A9A817C47FF78B8C11066B24080E72"_sb,
                "07041D4A7A0379AC7232FF72E6F77B6DDB8F09B16CCE0EC3286B2BD43FA8C6141C53EA5ABEF0D8231077A04540A96B66"_sb,
                "6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559F918EEDAF2293BE5B475CC8F0188636B"_sb,
                "2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D51AB373F9845C0514EEFB14024787265"_sb,
                "8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB"_sb,
                "DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5"_sb,
                "A0D5D090C9980FAF3C2CE57B7AE951D31977DD11C775D314AF55F76C676447D06FB6495CD21B4B6E340FC236584FB277"_sb,
                "976984E59B4C77B0E8E4460DCA3D9F20E07B9BB1F63BEEFAF576F6B2E8B224634A2092CD3792E0159AD9CEE37659C736"_sb,
            }
        );
        check_big(ec::secp521r1{}, message2, "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"_sb,
            std::vector{
                "13BAD9F29ABE20DE37EBEB823C252CA0F63361284015A3BF430A46AAA80B87B0693F0694BD88AFE4E661FC33B094CD3B7963BED5A727ED8BD6A3A202ABE009D0367"_sb,
                "1E9BB81FF7944CA409AD138DBBEE228E1AFCC0C890FC78EC8604639CB0DBDC90F717A99EAD9D272855D00162EE9527567DD6A92CBD629805C0445282BBC916797FF"_sb,
                "1C7ED902E123E6815546065A2C4AF977B22AA8EADDB68B2C1110E7EA44D42086BFE4A34B67DDC0E17E96536E358219B23A706C6A6E16BA77B65E1C595D43CAE17FB"_sb,
                "177336676304FCB343CE028B38E7B4FBA76C1C1B277DA18CAD2A8478B2A9A9F5BEC0F3BA04F35DB3E4263569EC6AADE8C92746E4C82F8299AE1B8F1739F8FD519A4"_sb,
                "00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D8071042EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656AA8"_sb,
                "0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694E86"_sb,
                "14BEE21A18B6D8B3C93FAB08D43E739707953244FDBE924FA926D76669E7AC8C89DF62ED8975C2D8397A65A49DCC09F6B0AC62272741924D479354D74FF6075578C"_sb,
                "133330865C067A0EAF72362A65E2D7BC4E461E8C8995C3B6226A21BD1AA78F0ED94FE536A0DCA35534F0CD1510C41525D163FE9D74D134881E35141ED5E8E95B979"_sb,
                "13E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47EE6D"_sb,
                "1FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4DCE3"_sb,
            }
        );
    }
}

void test_hmac() {
    LOG_TEST();

    using namespace crypto;

    auto f = [](auto h, auto &&r1, auto &&r2) {
        auto key = "key"sv;
        auto fox = "The quick brown fox jumps over the lazy dog"sv;
        cmp_base(to_string_raw(hmac<decltype(h)>(key, fox)), r1);
        cmp_base(to_string_raw(hmac<decltype(h)>(fox, fox)), r2);
    };

    f(sha1{},
        "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"s,
        "84997448f7991149b3e28fbe31314836e7cbb0cd"s
    );
    f(sha2<256>{},
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"s,
        "05ef8d2632d4140db730878ffb03a0bd9b32de06fb74df0471bde777cba1eff7"s
    );
    f(sha2<512>{},
        "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"s,
        "ed9bb695a3ccfe82fea7055e79fad7d225f5cc9c9b7b1808fc7121237a47903f59d8fad228c5710c487541db2bbecb09891b96b87c8718759ca4aa302cc72598"s
    );
    f(sha3<256>{},
        "8c6e0683409427f8931711b10ca92a506eb1fafa48fadd66d76126f47ac2c333"s,
        "e2f178144221853d60f7e9ddaf13ea57c6bddd54d9bd18b175fc59278f491a63"s
    );
}

void test_pbkdf2() {
    LOG_TEST();

    using namespace crypto;

    auto pass = "123"s;
    auto salt = "0"s;

    auto cmp = [](auto &&x, auto &&y) {
        return cmp_bytes(x, y);
    };

    cmp(pbkdf2<sha256>(pass, salt, 1000, 33), "4ff53b205602ea576b8a6bd69fb594a0a98a91299f14810092a23d925decca4208"_sb);
    cmp(pbkdf2<sha256>(pass, salt, 1000, 34), "4ff53b205602ea576b8a6bd69fb594a0a98a91299f14810092a23d925decca420882"_sb);
    cmp(pbkdf2<sha256>(pass, salt, 1000), "4ff53b205602ea576b8a6bd69fb594a0a98a91299f14810092a23d925decca42"_sb);
    cmp(pbkdf2<sha256>(pass, salt, 1000, 64), "4ff53b205602ea576b8a6bd69fb594a0a98a91299f14810092a23d925decca420882b3fc2a7336de94bcb473ea3d3e3155b8657bc512f349cb6141c116edda9d"_sb);
    cmp(pbkdf2<sha2<512>>(pass, salt, 1000), "2e18d9ea31a4e2c02321ea3f05a143f3b1b9952a947905a7393a7ba37e1150d01a0130b2754cc30427ade14fccf09b43b5a842f6898638c558e4487c84c8249a"_sb);
    cmp(pbkdf2<sha2<224>>(pass, salt, 1000), "e4e398e3022aa476b04abafc41b1725a00b4fec831ac4602269c758e"_sb);
    cmp(pbkdf2<sha2<384>>(pass, salt, 1000), "6bec9cbb3d01f590f321835e273a2f38f2778676a9e2b925bbdc3183132eadaad551cb9e1087666c2d13a1596ee61f61"_sb);

    cmp(pbkdf2<sha2<512>>(pass, salt, 999), "3b90da3da8c6180af0717d31f618e4572af386108afef6ec31c71be4298c38693153489141454ef0f2b4e794ee7b4ed2d9873bfbc3696e5f8acf384cfd0f7428"_sb);
    cmp(pbkdf2<sha256>(pass, salt, 1), "7426ee6b7a29c894a4b6953c8ed5df1a73e809de6a3f1e22e3379f95dce75a33"_sb);

    cmp(pbkdf2<sha1>(pass, salt, 1), "aea972ef0d1b000f8e379a2627d4e76ab3741c72"_sb);
    cmp(pbkdf2<sha1>(pass, salt, 998), "3ffed4bae693ca5c3fbf8eddb6977a6013467168"_sb);

    // collision, should be the same
    cmp(
        pbkdf2<sha1>("plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd"s,
            "A009C1A485912C6AE630D3E744240B04"_sb, 1000, 16),
        pbkdf2<sha1>("eBkXQTfuBqp'cTcar&g*"s,
            "A009C1A485912C6AE630D3E744240B04"_sb, 1000, 16)
    );

    cmp(pbkdf2<sha3<256>>("password"s, "salt"s, 4096), "778b6e237a0f49621549ff70d218d2080756b9fb38d71b5d7ef447fa2254af61"_sb);

    cmp(pbkdf2<sha3<256>>(pass, salt, 1), "c6c9bd558a9bc83a1d585e430194fcb6ae24a463082e7a61369e9213303fd450"_sb);
    cmp(pbkdf2<sha3<512>>(pass, salt, 1000), "34cbcad0f754e6f95f1a11fa5bc24da5378a1dda9fd94961c7413644d22a8ab083837fe831c48128a89ac63840ca11967121a08a83d92f21ed1347615c68ce85"_sb);
    cmp(pbkdf2<sha3<224>>(pass, salt, 1000), "596463961932a5247ade2d34673ca5d53f18664396ab7f9d827d86ca"_sb);
    cmp(pbkdf2<sha3<384>>(pass, salt, 1000), "430c8d81549ec45a3497c6ee4585c58740a07accf291a72e30c2234c329accd0dcb572cc586eb2c30f0b74e8859018de"_sb);

    cmp(pbkdf2<sha256>("passwd"s, "salt"s, 1, 64), R"(
   55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05
   f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc
   49 ca 9c cc f1 79 b6 45 99 16 64 b3 9d 77 ef 31
   7c 71 b8 45 b1 e3 0b d5 09 11 20 41 d3 a1 97 83
)"_sb);
    cmp(pbkdf2<sha256>("Password"s, "NaCl"s, 80000, 64), R"(
   4d dc d8 f6 0b 98 be 21 83 0c ee 5e f2 27 01 f9
   64 1a 44 18 d0 4c 04 14 ae ff 08 87 6b 34 ab 56
   a1 d4 25 a1 22 58 33 54 9a db 84 1b 51 c9 b3 17
   6a 27 2b de bb a1 d0 78 47 8f 62 b3 97 f3 3c 8d
)"_sb);
}

void test_scrypt() {
    LOG_TEST();

    using namespace crypto;

    //scoped_timer st;

    {
        auto in = R"(
           f7 ce 0b 65 3d 2d 72 a4 10 8c f5 ab e9 12 ff dd
           77 76 16 db bb 27 a7 0e 82 04 f3 ae 2d 0f 6f ad
           89 f6 8f 48 11 d1 e8 7b cc 3b d7 40 0a 9f fd 29
           09 4f 01 84 63 95 74 f3 9a e5 a1 31 52 17 bc d7

           89 49 91 44 72 13 bb 22 6c 25 b5 4d a8 63 70 fb
           cd 98 43 80 37 46 66 bb 8f fc b5 bf 40 c2 54 b0
           67 d2 7c 51 ce 4a d5 fe d8 29 c9 0b 50 5a 57 1b
           7f 4d 1c ad 6a 52 3c da 77 0e 67 bc ea af 7e 89
)"_sb;
        uint64_t out[16];
        scryptBlockMix(in.data(), (uint8_t*)out, 1);

        cmp_bytes(out, R"(
           a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05
           04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29
           b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba
           e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81

           20 ed c9 75 32 38 81 a8 05 40 f6 4c 16 2d cd 3c
           21 07 7c fe 5f 8d 5f e2 b1 a4 16 8f 95 36 78 b7
           7d 3b 3d 80 3b 60 e4 ab 92 09 96 e5 9b 4d 53 b6
           5d 2a 22 58 77 d5 ed f5 84 2c b9 f1 4e ef e4 25
)"_sb);
    }
    {
        auto in = R"(
           f7 ce 0b 65 3d 2d 72 a4 10 8c f5 ab e9 12 ff dd
           77 76 16 db bb 27 a7 0e 82 04 f3 ae 2d 0f 6f ad
           89 f6 8f 48 11 d1 e8 7b cc 3b d7 40 0a 9f fd 29
           09 4f 01 84 63 95 74 f3 9a e5 a1 31 52 17 bc d7
           89 49 91 44 72 13 bb 22 6c 25 b5 4d a8 63 70 fb
           cd 98 43 80 37 46 66 bb 8f fc b5 bf 40 c2 54 b0
           67 d2 7c 51 ce 4a d5 fe d8 29 c9 0b 50 5a 57 1b
           7f 4d 1c ad 6a 52 3c da 77 0e 67 bc ea af 7e 89
)"_sb;
        uint64_t out[16];
        scryptROMix(in, out, 1, 16);

        cmp_bytes(out, R"(
            79 cc c1 93 62 9d eb ca 04 7f 0b 70 60 4b f6 b6
            2c e3 dd 4a 96 26 e3 55 fa fc 61 98 e6 ea 2b 46
            d5 84 13 67 3b 99 b0 29 d6 65 c3 57 60 1f b4 26
            a0 b2 f4 bb a2 00 ee 9f 0a 43 d1 9b 57 1a 9c 71
            ef 11 42 e6 5d 5a 26 6f dd ca 83 2c e5 9f aa 7c
            ac 0b 9c f1 be 2b ff ca 30 0d 01 ee 38 76 19 c4
            ae 12 fd 44 38 f2 03 a0 e4 e1 c4 7e c3 14 86 1f
            4e 90 87 cb 33 39 6a 68 73 e8 f9 d2 53 9a 4b 8e
)"_sb);
    }

    auto scr = [](auto &&...args) {
        return scrypt(args...);
        //return scrypt2()(args...);
    };

    {
        cmp_bytes(scr(""s, ""s, 16, 1, 1, 64), R"(
       77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
       f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
       fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
       e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06
    )"_sb);
        cmp_bytes(scr("password"s, "NaCl"s, 1024, 8, 16, 64), R"(
       fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
       7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
       2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
       c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40
    )"_sb);
        cmp_bytes(scr("pleaseletmein"s, "SodiumChloride"s, 16384, 8, 1, 64), R"(
       70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
       fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
       d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
       e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87
    )"_sb);
        // very long in debug mode, 1 GB of mem
#ifdef NDEBUG
        {
            //scoped_timer t;
            cmp_bytes(scr("pleaseletmein"s, "SodiumChloride"s, 1048576, 8, 1, 64), R"(
           21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81
           ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47
           8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3
           37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4
            )"_sb);
        }
        {
            //scoped_timer t;
            cmp_bytes(scr("Rabbit"s, "Mouse"s, 1048576, 8, 1, 32), R"(
                E277EA2CACB23EDAFC039D229B79DC13ECEDB601D99B182A9FEDBA1E2BFB4F58
            )"_sb);
        }
#endif

        auto test = [&](int N, int r, int p, auto &&res) {
            cmp_bytes(scr("password"s, "ce3b79848f2a254df1d60e1a3146165a"_sb, N, r, p, 16), res);
        };
        test(8192, 5, 1, "a19e1c5ce6e0da022c64a7205da125dc"_sb);
        test(8192, 6, 1, "c9060cb775114c0688df86e9990c62ab"_sb);
        test(8192, 7, 1, "424e439dafcc0fc438469241e9d6bdf8"_sb);
        test(8192, 8, 1, "18f3116479374acd05755a1bf43a3af2"_sb);
        test(4096, 16, 1, "485d55c1267e1afa60349fe28c4aa2d9"_sb);
        test(4096, 32, 1, "a43d75bb3b899852c8297fe2cd3b9681"_sb);
        test(2, 64, 64, "a1c68ee1a41bc4e8dcfdc3fa93700426"_sb);
        test(2, 64, 128, "b58b8ec24738af168b4e24de079102f1"_sb);
        test(2, 63, 128, "61de26be0f6609462bf66d88dece2d3c"_sb);
        test(4, 19, 17, "b21fc99ae1dd4067c2d2b906af62518e"_sb);
    }
}

void test_argon2() {
    LOG_TEST();

    using namespace crypto;

    // from rfc
    auto pass = R"(
        01 01 01 01 01 01 01 01
        01 01 01 01 01 01 01 01
        01 01 01 01 01 01 01 01
        01 01 01 01 01 01 01 01
)"_sb;
    auto salt = R"(
        02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
)"_sb;
    auto key = R"(
        03 03 03 03 03 03 03 03
)"_sb;
    auto associated_data = R"(
        04 04 04 04 04 04 04 04 04 04 04 04
)"_sb;
    {
        argon2 a{
            .password = pass,
            .salt = salt,
            .key = key,
            .associated_data = associated_data,
            .taglen = 32,
            .p = 4,
            .m = 32,
            .t = 3,
            .y = argon2::argon2d
        };
        cmp_bytes(a(), R"(
            51 2b 39 1b 6f 11 62 97
            53 71 d3 09 19 73 42 94
            f8 68 e3 be 39 84 f3 c1
            a1 3a 4d b9 fa be 4a cb
    )"_sb);
    }
    {
        argon2 a{
            .password = pass,
            .salt = salt,
            .key = key,
            .associated_data = associated_data,
            .taglen = 32,
            .p = 4,
            .m = 32,
            .t = 3,
            .y = argon2::argon2i
        };
        cmp_bytes(a(), R"(
            c8 14 d9 d1 dc 7f 37 aa
            13 f0 d7 7f 24 94 bd a1
            c8 de 6b 01 6d d3 88 d2
            99 52 a4 c4 67 2b 6c e8
    )"_sb);
    }
    {
        argon2 a{
            .password = pass,
            .salt = salt,
            .key = key,
            .associated_data = associated_data,
            .taglen = 32,
            .p = 4,
            .m = 32,
            .t = 3,
            .y = argon2::argon2id
        };
        cmp_bytes(a(), R"(
            0d 64 0d f5 8d 78 76 6c
            08 c0 37 a3 4a 8b 53 c9
            d0 1e f0 45 2d 75 b6 5e
            b5 25 20 e9 6b 01 e6 59
    )"_sb);
    }
    // https://github.com/randombit/botan/blob/master/src/tests/data/argon2.vec
    {
    auto pass = R"(
70617373
)"_sb;
    auto salt = R"(
6161616161616161
)"_sb;
        argon2 a{
            .password = pass,
            .salt = salt,
            .taglen = 4,
            .p = 1,
            .m = 8,
            .t = 1,
            .y = argon2::argon2id
        };
        cmp_bytes(a(), R"(
7953c074
    )"_sb);
    }
    {
    auto pass = R"(
70617373
)"_sb;
    auto salt = R"(
6161616161616161
)"_sb;
        argon2 a{
            .password = pass,
            .salt = salt,
            .taglen = 5,
            .p = 1,
            .m = 8,
            .t = 1,
            .y = argon2::argon2id
        };
        cmp_bytes(a(), R"(
6d6fc6afe9
    )"_sb);
    }
    {
        argon2 a{
            .password = pass,
            .salt = salt,
            .key = key,
            .associated_data = associated_data,
            .taglen = 64,
            .p = 16,
            .m = 256,
            .t = 10,
            .y = argon2::argon2id
        };
        cmp_bytes(a(), R"(
f73b80dd42a7669e98aa98c58007b022055a0c0024d6b9064119b9d3ecba2476e4dcf4e444ba59762960a16660fff039ea80448a1f1e9b35814a05e311f52426
    )"_sb);
    }
    {
        argon2 a{
            .password = pass,
            .salt = salt,
            .key = key,
            .associated_data = associated_data,
            .taglen = 64,
            .p = 64,
            .m = 4096,
            .t = 32,
            .y = argon2::argon2id
        };
        cmp_bytes(a(), R"(
f76f7ac4e23bae5c3d1797f5d8a7b40222f770f0b6d339d8b5d4c168a2dfb512838b2bd5f110397e1c15267f782f0067d8ef567a7556470cd13af4dedf1d585d
    )"_sb);
    }
    // custom
    {
        argon2 a{
            .password = pass,
            .salt = salt,
            .key = key,
            .associated_data = associated_data,
            .taglen = 64,
            .p = 1,
            .m = 4096,
            .t = 32,
            .y = argon2::argon2id
        };
        cmp_bytes(a(), R"(
e5 e7 84 a7 19 f2 2b 70 e9 ac 5f 2e 87 57 31 81
b0 99 ff 9e fd 7c 16 0c 85 e3 bc 9e 5e fe d2 50
6e c1 9b b8 87 f5 43 24 ae 0c be 28 e4 5c 2b 5e
db 8f 1d c8 3f f3 f0 00 22 05 76 c5 4f 3b ed a4
    )"_sb);
    }
    {
        argon2 a{
            .password = pass,
            .salt = salt,
            .key = key,
            .associated_data = associated_data,
            .taglen = 64,
            .p = 10,
            .m = 4096,
            .t = 32,
            .y = argon2::argon2id
        };
        cmp_bytes(a(), R"(
12 73 12 13 2f 2a 9a 5d df f4 07 c7 59 a4 1a a5
20 1a 2c 25 92 c1 46 c9 98 24 ac 91 e0 06 c6 59
e6 40 c7 91 80 e8 ed eb 36 e0 44 d7 88 e4 fa af
69 1b 0f d4 35 a8 81 d2 ed fd cb 57 e0 bc 10 53
    )"_sb);
    }
}

void test_chacha20() {
    LOG_TEST();

    using namespace crypto;

    {
        auto in = R"(
   7e 87 9a 21 4f 3e c9 86 7c a9 40 e6 41 71 8f 26
   ba ee 55 5b 8c 61 c1 b5 0d f8 46 11 6d cd 3b 1d
   ee 24 f3 19 df 9b 3d 85 14 12 1e 4b 5a c5 aa 32
   76 02 1d 29 09 c7 48 29 ed eb c6 8d b8 b8 c2 5e
)"_sb;
        uint32_t out[16];
        salsa_block((uint32_t*)in.data(), out, 8);

        cmp_bytes(out, R"(
   a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05
   04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29
   b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba
   e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81
)"_sb);
    }

    {
        auto key = R"(
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
)"_sb;
        auto nonce = R"(
00 00 00 00 00 00 00 00 00 00 00 00
)"_sb;
        auto data = R"(
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
)"_sb;
        {
            chacha20 c(key.data(), nonce.data(), 0);
            cmp_bytes(c.block, R"(
76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37
6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86
)"_sb);
        }
        {
            chacha20 c(key.data(), nonce.data(), 1);
            cmp_bytes(c.block, R"(
9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d
cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed
29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5
31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f
)"_sb);
        }
        {
        auto key = R"(
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
)"_sb;
            chacha20 c(key.data(), nonce.data(), 1);
            cmp_bytes(c.block, R"(
3a eb 52 24 ec f8 49 92 9b 9d 82 8d b1 ce d4 dd
83 20 25 e8 01 8b 81 60 b8 22 84 f3 c9 49 aa 5a
8e ca 00 bb b4 a7 3b da d1 92 b5 c4 2f 73 f2 fd
4e 27 36 44 c8 b3 61 25 a6 4a dd eb 00 6c 13 a0
)"_sb);
        }
        {
        auto key = R"(
00 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
)"_sb;
            chacha20 c(key.data(), nonce.data(), 2);
            cmp_bytes(c.block, R"(
72 d5 4d fb f1 2e c4 4b 36 26 92 df 94 13 7f 32
8f ea 8d a7 39 90 26 5e c1 bb be a1 ae 9a f0 ca
13 b2 5a a2 6c b4 a6 48 cb 9b 9d 1b e6 5b 2c 09
24 a6 6c 54 d5 45 ec 1b 73 74 f4 87 2e 99 f0 96
)"_sb);
        }
        {
        auto nonce = R"(
00 00 00 00 00 00 00 00 00 00 00 02
)"_sb;
            chacha20 c(key.data(), nonce.data(), 0);
            cmp_bytes(c.block, R"(
c2 c6 4d 37 8c d5 36 37 4a e2 04 b9 ef 93 3f cd
1a 8b 22 88 b3 df a4 96 72 ab 76 5b 54 ee 27 c7
8a 97 0e 0e 95 5c 14 f3 a8 8e 74 1b 97 c2 86 f7
5f 8f c2 99 e8 14 83 62 fa 19 8a 39 53 1b ed 6d
)"_sb);
        }
        {
            chacha20 c(key.data(), nonce.data(), 0);
            auto out = data;
            c.cipher(data.data(), out.data(), data.size());
            cmp_bytes(out, R"(
76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37
6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86
)"_sb);
        }
        {
        auto key = R"(
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
)"_sb;
        auto nonce = R"(
00 00 00 00 00 00 00 00 00 00 00 02
)"_sb;
        auto data = R"(
41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74
6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e
64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72
69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69
63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72
20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46
20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20
6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73
74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69
74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74
20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69
76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72
65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74
72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20
73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75
64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e
74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69
6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20
77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63
74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61
74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e
79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c
20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65
73 73 65 64 20 74 6f
)"_sb;
            chacha20 c(key.data(), nonce.data(), 1);
            auto out = data;
            c.cipher(data.data(), out.data(), data.size());
            cmp_bytes(out, R"(
a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70
41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec
2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05
0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d
40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e
20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50
42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c
68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a
d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66
42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d
c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28
e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b
08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f
a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c
cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84
a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b
c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0
8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f
58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62
be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6
98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85
14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab
7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd
c4 fd 80 6c 22 f2 21
)"_sb);
        }
        {
        auto key = R"(
1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0
47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
)"_sb;
        auto nonce = R"(
00 00 00 00 00 00 00 00 00 00 00 02
)"_sb;
        auto data = R"(
27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61
6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f
76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64
20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77
61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77
65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65
73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20
72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e
)"_sb;
            chacha20 c(key.data(), nonce.data(), 42);
            auto out = data;
            c.cipher(data.data(), out.data(), data.size());
            cmp_bytes(out, R"(
62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df
5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf
16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71
fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb
f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6
1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77
04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1
87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1
)"_sb);
        }
    }
}

void test_chacha20_aead() {
    LOG_TEST();

    using namespace crypto;

    {
        auto text = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
                         "sunscreen would be it."s;
        auto aad = "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7"_sb;
        auto nonce = "07 00 00 00 40 41 42 43 44 45 46 47"_sb;
        array<32> K = (bytes_concept)"80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"_sb;

        //auto onetimekey = poly1305_key_gen((uint8_t *)K.c_str(), (uint8_t *)nonce.c_str());

        chacha20_poly1305_aead cp{K};
        auto out = cp.encrypt_and_tag(nonce, text, aad);

        cmp_bytes(out,
                  R"(
d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36
92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58
fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
61 16

1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91
    )"_sb);
    }
    // dec
    {
        array<32> K =
            (bytes_concept) R"(
1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0
47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
)"_sb;
        auto text = R"(
64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd
5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2
4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0
bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf
33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81
14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55
97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38
36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4
b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9
90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e
af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a
0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a
0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e
ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10
49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30
30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29
a6 ad 5c b4 02 2b 02 70 9b

ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38
)"_sb;
        // last line is tag
        auto nonce = "00 00 00 00 01 02 03 04 05 06 07 08"_sb;
        auto aad = "f3 33 88 86 00 00 00 00 00 00 4e 91"_sb;

        chacha20_poly1305_aead cp{K};
        auto out = cp.decrypt_with_tag(nonce, (bytes_concept)text, aad);
        cmp_bytes(out,
        R"(
49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20
61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65
6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20
6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d
6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65
20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63
65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64
20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65
6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e
20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72
69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65
72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72
65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61
6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65
6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20
2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67
72 65 73 73 2e 2f e2 80 9d
)"_sb);
    }
}

void test_asn1() {
    LOG_TEST();

    using namespace crypto;

    mmap_file<uint8_t> f{"d:/dev/crypto/_.gosuslugi.ru.der"};
    asn1 a{bytes_concept{f}};
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

void test_x509() {
    LOG_TEST();

    using namespace crypto;

    x509_storage ss;
    ss.load_pem(mmap_file<char>{"roots.pem"}, true);
    ss.load_der(mmap_file<char>{"infotecsCA.der"}, true);

    auto data1 = read_file("test1.der");
    auto data2 = read_file("test2.der");

    x509_storage s;
    s.add(data1);
    s.add(data2);
    cmp_bool(s.verify(ss), true);

    x509_storage s2;
    auto data3 = read_file("infotecs.der");
    s2.add(data3);
    cmp_bool(s2.verify(ss), true);
}

void test_pki() {
    LOG_TEST();

    using namespace crypto;

    public_key_infrastructure p{".sw/pki"};
    gost_sig<ec::gost::r34102001::ec256a, oid::gost_r34102001_param_set_a, streebog<256>> gs256, gs256_child;
    gost_sig<ec::gost::r34102012::ec512c, oid::gost_3410_12_512_param_set_c, streebog<512>> gs512;
    auto &&[cakey,casubj] = p.make_ca("ca256", gs256, cert_request{.subject = {.common_name = "localhost CA 256", .country = "RU"}});
    p.make_cert("ca256_child", casubj, gs256, gs256_child, cert_request{.subject = {.common_name = "localhost", .country = "RU"}});
    p.make_ca("ca512", gs512, cert_request{.subject = {.common_name = "localhost CA 512", .country = "RU"}});
}

void test_streebog() {
    LOG_TEST();

    using namespace crypto;

    {
        streebog<256> stb;
        to_string2(stb, "", "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb");
    }
    {
        streebog<512> stb;
        to_string2(stb, "", "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a");
    }
    {
        streebog<256> stb;
        fox(stb,
            "3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4",
            "36816a824dcbe7d6171aa58500741f2ea2757ae2e1784ab72c5c3c6c198d71da");
    }
    {
        streebog<512> stb;
        fox(stb,
            "d2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b97e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe",
            "fe0c42f267d921f940faa72bd9fcf84f9f1bd7e9d055e9816e4c2ace1ec83be82d2957cd59b86e123d8f5adee80b3ca08a017599a9fc1a14d940cf87c77df070");
    }
}

void test_grasshopper() {
    LOG_TEST();

    using namespace crypto;

    auto f = [](auto &&key, auto &&enc, auto &&dec) {
        grasshopper k;
        k.expand_key(bytes_concept{key});
        cmp_base(bytes_concept{dec}, k.encrypt(bytes_concept{enc}));
        cmp_base(bytes_concept{enc}, k.decrypt(bytes_concept{dec}));
        cmp_base(bytes_concept{enc}, k.decrypt(k.encrypt(bytes_concept{enc})));
    };

    f("88 99AABB CC DD EE FF 00 11 22 33 44 55 66 77 FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF "_sb,
      "11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88"_sb, "7f679d90bebc24305a468d42b9d4edcd"_sb);
    f("0000000000000000000000000000000000000000000000000000000000000000"_sb, "00000000000000000000000000000000"_sb,
      "98CC6B54DBCF7BD2F0800C1FAB0677EF"_sb);
    f("ef cd ab 89 67 45 23 01 10 32 54 76 98 ba dc fe 77 66 55 44 33 22 11 00 ff ee dd cc bb aa 99 88"_sb,
        "88 99 aa bb cc dd ee ff 00 77 66 55 44 33 22 11"_sb,
      "B2135B9C8EDA608E3D16385C396CB98B"_sb);
    f("77 66 55 44 33 22 11 00 ff ee dd      cc bb aa 99 88 ef cd ab 89 67 45 23 01 10 32 54 76 98 ba dc fe      "_sb,
        "88 99 aa bb cc dd ee ff 00 77 66 55 44 33 22 11"_sb,
      "DF4B256B59D499A552B77EF74C590B8B"_sb);
}

void test_mgm() {
    LOG_TEST();

    using namespace crypto;

    {
        auto K = "88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF"_sb;
        auto nonce = "11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88"_sb;
        auto A = "02 02 02 02 02 02 02 02 01 01 01 01 01 01 01 01         04 04 04 04 04 04 04 04 03 03 03 03 03 03 03 03 EA 05 05 05 05 05 05 05 05 "_sb;
        auto P = "11 22 33 44 55 66 77 00 FF EE DD CC BBAA99 88        00 11 22 33 44 55 66 77 88 99AABB CC EE FF 0A 11 22 33 44 55 66 77 88 99AABB CC EE            FF0A00 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 AA BB CC "_sb;
        auto E = "A9 75 7B 81 47 95 6E 90 55 B8 A3 3D E8 9F 42 FC 80 75 D2 21 2B F9 FD 5B D3 F7 06 9A AD C1 6B 39 49 7A B1 59 15 A6 BA 85 93 6B 5D 0E A9 F6 85 1C C6 0C 14 D4 D3 F8 83 D0 AB 94 42 06 95 C7 6D EB 2C 75 52"_sb;

        mgm<grasshopper> m{K};
        auto [enc,tag] = m.encrypt(nonce, P, A);
        cmp_base(enc, bytes_concept{E});
        cmp_base(tag, bytes_concept{"CF 5D 65 6F 40 C3 4F 5C 46 E8 BB 0E 29 FC DB 4C"_sb});
        cmp_base(P, bytes_concept{m.decrypt(nonce, E, A, tag)});
    }

    {
        auto K = "99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF 88"_sb;
        auto nonce = "11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88"_sb;
        auto A = "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01"_sb;
        auto P = ""_sb;
        auto E = ""_sb;

        mgm<grasshopper> m{K};
        auto [enc, tag] = m.encrypt(nonce, P, A);
        cmp_base(enc, bytes_concept{E});
        cmp_base(tag, bytes_concept{"79 01 E9 EA 20 85 CD 24 7E D2 49 69 5F 9F 8A 85"_sb});
        cmp_base(P, bytes_concept{m.decrypt(nonce, E, A, tag)});
    }
}

void test_gost() {
    LOG_TEST();

    using namespace crypto;

    // hmac
    cmp_bytes(hmac<streebog<256>>(
                  "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"_sb,
                  "01 26 bd b8 78 00 af 21 43 41 45 65 63 78 01 00"_sb),
              "a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34 01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9"_sb);
    cmp_bytes(
        hmac<streebog<512>>(
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"_sb,
            "01 26 bd b8 78 00 af 21 43 41 45 65 63 78 01 00"_sb),
        "a5 9b ab 22 ec ae 19 c6 5f bd e6 e5 f4 e9 f5 d8 54 9d 31 f0 37 f9 df 9b 90 55 00 e1 71 92 3a 77 3d 5f 15 30 f2 ed 7e 96 4c b2 ee dc 29 e9 ad 2f 3a fe 93 b2 81 4f 79 f5 00 0f fc 03 66 c2 51 e6"_sb);

    cmp_bytes(gost::kdf<streebog<256>>(
        "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"_sb,
        "26 bd b8 78"_sb,
        "af 21 43 41 45 65 63 78"_sb
        ),
              "a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34 01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9"_sb);
}

void test_tls() {
    LOG_TEST();

    using namespace crypto;

    auto &tcs = x509_storage::trusted_storage();
    tcs.load_pem(mmap_file<char>{"roots.pem"}, true);
    tcs.load_der(mmap_file<char>{"infotecsCA.der"}, true);
#ifdef _WIN32
    auto load_certs = [&](auto &&store) {
        for (auto &&s : win32::enum_certificate_store(store)) {
            tcs.load_der(s, true);
        }
    };
    load_certs("CA");
    load_certs("ROOT");
#endif

    auto run0 = [](auto &&t, auto &&url) {
        //std::cout << "connecting to " << url << "\n";
        try {
            t.follow_location = false;
            t.run();
#ifndef CI_TESTS
            std::cout << "connecting to " << url << "\n";
            std::cout << "ok" << "\n";
#endif
            cmp_base(0, 0);
        } catch (std::exception &e) {
            std::cout << "connecting to " << url << "\n";
            std::cerr << e.what() << "\n";
            cmp_base(0, 1);
        }
    };
    auto run = [&](auto &&url) {
        http_client t{url};
        run0(t, url);
    };
    auto run_with_params = [&](auto &&url, auto suite, auto kex) {
        http_client t{url};
        t.tls_layer.force_suite = suite;
        t.tls_layer.force_kex = (decltype(t.tls_layer.force_kex))kex;
#ifndef CI_TESTS
        std::println("suite 0x{:X}, kex 0x{:X}", (int)suite, (int)kex);
#endif
        run0(t, url);
    };

    //int n = 50;
    //while (n--)
        //run_with_params("91.244.183.22:15082", 0, parameters::supported_groups::GC512B);
    //run("github.com");

    // aliexpress.ru
    //run_with_params("https://aliexpress.ru/", tls13::CipherSuite::TLS_SM4_GCM_SM3, parameters::supported_groups::curveSM2);

    //run_with_params("127.0.0.1:11111", tls13::CipherSuite::TLS_SM4_GCM_SM3, parameters::supported_groups::curveSM2);
    //return;

    for (auto s : {
        tls13::CipherSuite::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L,
        tls13::CipherSuite::TLS_GOSTR341112_256_WITH_MAGMA_MGM_L,
        tls13::CipherSuite::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S,
        tls13::CipherSuite::TLS_GOSTR341112_256_WITH_MAGMA_MGM_S,
    }) {
        for (auto k : {
            parameters::supported_groups::GC256A,
            parameters::supported_groups::GC256B,
            parameters::supported_groups::GC256C,
            parameters::supported_groups::GC256D,
            parameters::supported_groups::GC512A,
            parameters::supported_groups::GC512B,
            parameters::supported_groups::GC512C,
        }) {
#ifndef CI_TESTS
            //run_with_params("127.0.0.1:443", s, k);
#endif
        }
        // does not support 1.3 yet
        //run_with_params("https://tlsgost-256.cryptopro.ru:2443", s, parameters::supported_groups::GC256A);
        //run_with_params("https://tlsgost-256.cryptopro.ru:3443", s, parameters::supported_groups::GC256B);
        //run_with_params("https://tlsgost-256.cryptopro.ru:4443", s, parameters::supported_groups::GC256C);
        //run_with_params("https://tlsgost-512.cryptopro.ru", s, parameters::supported_groups::GC512A);
        //run_with_params("https://tlsgost-512.cryptopro.ru:1443", s, parameters::supported_groups::GC512B);
    }
    //return;
    //
    //
    ////
    ////// https://infotecs.ru/stand_tls/
    //
    for (auto s : {
        tls13::CipherSuite::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L,
        tls13::CipherSuite::TLS_GOSTR341112_256_WITH_MAGMA_MGM_L,
        tls13::CipherSuite::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S,
        tls13::CipherSuite::TLS_GOSTR341112_256_WITH_MAGMA_MGM_S,
    }) {
        run_with_params("91.244.183.22:15002", s, parameters::supported_groups::GC256A);
        run_with_params("91.244.183.22:15012", s, parameters::supported_groups::GC256B);
        run_with_params("91.244.183.22:15022", s, parameters::supported_groups::GC256C);
        run_with_params("91.244.183.22:15032", s, parameters::supported_groups::GC256D);
        run_with_params("91.244.183.22:15072", s, parameters::supported_groups::GC512A);
        run_with_params("91.244.183.22:15082", s, parameters::supported_groups::GC512B);
        run_with_params("91.244.183.22:15092", s, parameters::supported_groups::GC512C);

        //run_with_params("91.244.183.22:15083", s, parameters::supported_groups::GC512B); // this server or their suite does not work well
        //run_with_params("91.244.183.22:15081", s, parameters::supported_groups::GC512B); // this server or their suite does not work well
    }

    run_with_params("aliexpress.ru", tls13::CipherSuite::TLS_SM4_GCM_SM3, parameters::supported_groups::curveSM2);

    run("software-network.org");
    run("letsencrypt.org");
    run("example.com");
#ifdef CI_TESTS
    run("google.com"); // causes hangs
#endif
    run("nalog.gov.ru");
    run("github.com");
    run("gmail.com");
#ifdef CI_TESTS
    run("youtube.com");
    run("twitch.tv");
#endif
    run("tls13.akamai.io");
    // this one sends some cryptic headers and expect something from us
    // X-TLS-ClientRandom-Challenge: try="0xDEADDEADDEADC0DE0[0...]-in-Random"
    //run("tls13.1d.pw");
    //run("127.0.0.1:11111");

    // some other tests
    run("https://www.reuters.com/");
    run("https://edition.cnn.com/");
    run("https://www.cloudflare.com/");
    run("gosuslugi.ru");
    //
    //// does not support tls13
    //run("https://www.globaltimes.cn/");
    //run("https://www.gov.cn/");
    //run("https://english.news.cn/");
    //run("sberbank.ru");
    //run("gost.cryptopro.ru");
    //// requires RFC 5746(Renegotiation Indication)
    //run("tlsgost-512.cryptopro.ru"); // https://www.cryptopro.ru/products/csp/tc26tls
    // return tls 1.0/1.1
    //run("https://tlsgost-512.cryptopro.ru");
    //run("https://tlsgost-512.cryptopro.ru:1443");
}

void test_jwt() {
    LOG_TEST();

    using namespace crypto;
    using namespace crypto::rsa;

    auto check = [](auto &&h, auto &&payload, auto &&res, bool verify_only, auto &&...args) {
        jwt x{payload};
        x.sign(h, args...);
        if (!verify_only && !cmp_base(x, res)) {
            std::println("{}", (std::string)x);
        }
        if (!cmp_base(x.verify(h, args...), true)) {
            std::println("{}", (std::string)x);
        }
    };
    auto check_hs256 = [&](auto &&payload, auto &&secret, auto &&res) {
        check(jwt::hs<256>{}, payload, res, false, secret);
    };
    auto check_rs256 = [&](auto &&payload, auto &&pkey, auto &&pubkey, auto &&res) {
        jwt x{payload};
        jwt::rs<256> h{};
        x.sign(h, pkey);
        if (!cmp_base(x, res)) {
            std::println("{}", (std::string)x);
        }
        if (!cmp_base(x.verify(h, pubkey), true)) {
            std::println("{}", (std::string)x);
        }
    };
    auto check_ps512 = [&](auto &&payload, auto &&pkey, auto &&pubkey, auto &&res) {
        jwt x{payload};
        jwt::ps<512> h{};
        x.sign(h, pkey);
        if (!cmp_base(x.verify(h, pubkey), true)) {
            std::println("{}", (std::string)x);
        }
    };
    auto verify_ps512 = [&](auto &&payload, auto &&pkey, auto &&pubkey, auto &&res) {
        jwt x{payload};
        jwt::ps<512> h{};
        if (!cmp_base(x.verify(h, pubkey), true)) {
            std::println("{}", (std::string)x);
        }
    };

    check_hs256(
        R"({"sub":"1234567890","name": "John Doe" ,"iat": 1516239022})"_json, "000",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.kH64lXJbz0NS5uG8NaoQjxmi-zgSgA-U1UCe5Plkzhw"_jwt
    );
    check_hs256(
        R"( { "sub" : "1234567890" , "name":"John Doe","iat":1516239022 })"_json, "0000",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABtGopfXew_rfoHUtAlV58GLAMWmdhsecKxVlDTuZAE"_jwt
    );
    check_hs256(
        R"({"loggedInAs":"admin","iat":1422779638} )"_json, "secretkey",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjI3Nzk2MzgsImxvZ2dlZEluQXMiOiJhZG1pbiJ9.bHroWl3rTXUTNjwZQ_N8w2YRYs6x1ZWkEMckM53_D9E"_jwt
    );

    auto pks = read_file("jwtRS256.key");
    auto pubs = read_file("jwtRS256.key.pub");

    auto pk = private_key::load_from_string_container(pks);
    auto pubk = public_key::load_from_string_container(pubs);

    check_rs256(
        R"({"loggedInAs":"admin","iat":1422779638} )"_json, pk, pubk,
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjI3Nzk2MzgsImxvZ2dlZEluQXMiOiJhZG1pbiJ9.VJkvpYvlELE2Hrnz6JKGZuoWshycW3HNdrgV8KOoIKatI64KYBs-a1wK6JUaTY1bkViEh_YrdrKKb3iDU_nJYkRZHIfNmM7J_sQeE04zUpit4ketxWzGk2daF10gRaO8nefH7b9bvMYLMyiqq4kOaaCVhTgTFHm73iu42Tl_ybqRVp5ArWzru2MYQrdCxK2X3qJ5mPx9GgHBtjjBSQkT6Np-XZphdEYXj7juOxeX6oE6FAl749PlYQXjWU23UaHDwIDzM8vfk9gPmQeuA1PQ7UMZ-MWrhC-ym7_cA4zq4USn-YmFSOsf_A96kSMlh9xiL2FlgE1C6DvrjGoyVl025w"_jwt
    );
    check_rs256(
        R"({"sub":"1234567890","name": "John Doe" ,"iat": 1516239022})"_json, pk, pubk,
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.MmNFMRvbzG6eb9kYkHXRMwOiEbkDBMXIQOk0Vrnipt4GL39Vz-y5YayzgfUOE_-xZdQGWYQWhxGnBIBQDRqkIBR1UMzL_adWd4FgpdMxaGdXScWupTj8_chBPsCzYvvImqm0b5buLHSs7FwXUVrMeEodpN3lyeuu8RV7vwTiitV3HwuQdm9z5TcOSPJjYw0tv1qNfoKscNiJK4-1VGl00rbneKevRKtlmuz8ddLMW7el-IoY9mwZyEkFpL5BsWZUiYN_64PgTmGYuBN7qU32PgWX9QAgwn6YjgwaY43pyet65jUwC7-bx2QnL6lBeja3rACuk3ph0PWNUZHZgNXbrg"_jwt
    );

    // salt is different every time, but verify will work
    check_ps512(
        R"({"loggedInAs":"admin","iat":1422779638} )"_json, pk, pubk,
        ""_jwt
    );
    check_ps512(
        R"({"sub":"1234567890","name": "John Doe" ,"iat": 1516239022})"_json, pk, pubk,
        ""_jwt
    );
    verify_ps512(
        R"(eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjI3Nzk2MzgsImxvZ2dlZEluQXMiOiJhZG1pbiJ9.V0xxUc58hL2QGsrKdeAWRCFqZULhYg98lNrHkMVqo8nB1No88-VHmti1EIVvZSV2fxMGNXbu0xNZ4qUMy8x43JieP4uvWGggX5KZTZn_dRpqtZKfC7o6pt5F2lwetnQjp9bhsYGqbOoQ9MLchRKg4oDtCYIl03yE4oiJuRQR-FobKHW-M61vkXGGvcnTL3AUyvyLgFRXYzzYPAy3JIhmLjy4IqQ8s4Vrz9sRiGw6zUpl3YSk0gq7KUdxR6DTtk5HF-WSHwNKtvmpgEFfuxHJm0amH3RQwvx-vwUjGTEogpOleeaYTUvWgzv-D9DHB5lW6uQbs2P7xf0ZWJ_wnHU2Dg)", pk, pubk,
        ""_jwt
    );
}

auto test_all() {
    test_aes();
    test_sha1();
    test_sha2();
    test_sha3();
    test_blake2();
    test_blake3();
    test_sm3();
    test_sm4();
    test_ec();
    test_ecdsa();
    test_hmac();
    test_pbkdf2();
    /*test_chacha20();
    test_chacha20_aead();
    test_scrypt();
    test_argon2();
    test_asn1();
    test_x509();
    test_pki();
    test_streebog();
    test_grasshopper();
    test_mgm();
    test_gost();*/

    test_tls();
    test_jwt();
    return success != total;
}

#ifdef CI_TESTS
int main() {
    return test_all();
}
#endif

#ifndef CI_TESTS
int main() {
    //test_aes();
    //test_sha1();
    //test_sha2();
    //test_sha3();
    //test_blake2();
    //test_blake3();
    //test_sm3();
    //test_sm4();
    //test_ec();
    //test_ecdsa();
    //test_hmac();
    //test_pbkdf2();
    //test_chacha20();
    //test_chacha20_aead();
    //test_scrypt();
    //test_argon2();
    //test_asn1();
    //test_x509();
    //test_pki();
    //test_streebog();
    //test_grasshopper();
    //test_mgm();
    //test_gost();
    //
    //test_tls();
    test_jwt();
}
#endif
