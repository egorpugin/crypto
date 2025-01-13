#include "aes.h"
#include "bigint.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"
#include "blake2.h"
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

#include <array>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <print>
#include <span>
#include <sstream>

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

    void end() {
        auto diff = clock::now() - tp;
        std::println("time of the last op: {}", std::chrono::duration_cast<std::chrono::duration<float>>(diff).count());
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
    printf("%s\n", r ? "ok" : "false");
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
auto cmp_base = [](auto &&left, auto &&right) {
    auto r = left == right;
    ++total;
    success += !!r;
    if (!r) {
        std::cerr << "false" << "\n";
    }
    return r;
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

void test_sha1() {
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
}

void test_blake2() {
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

void test_sm3() {
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
}

void test_sm4() {
    using namespace crypto;

    auto tv_key = "0123456789ABCDEFFEDCBA9876543210"_sb;
    auto tv_plain = "0123456789abcdeffedcba9876543210"_sb;

    {
        sm4_encrypt enc{tv_key};
        enc.encrypt(tv_plain);

        uint8_t tv_cipher[] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
                               0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};
        cmp_bytes(tv_cipher, tv_plain);

        sm4_decrypt dec{tv_key};
        dec.decrypt(tv_plain);
        cmp_bytes(tv_key, tv_plain);
    }
    {
        sm4_encrypt enc{tv_key};
        for (int i = 0; i < 1000000; i++) {
            enc.encrypt(tv_plain);
        }
        uint8_t tv_cipher[] = {0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
                               0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66};
        cmp_bytes(tv_cipher, tv_plain);

        sm4_decrypt dec{tv_key};
        for (int i = 0; i < 1000000; i++) {
            dec.decrypt(tv_plain);
        }
        cmp_bytes(tv_key, tv_plain);
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
    using namespace crypto;

    // std::cout << std::hex;

    // simple
    {
        {
            ec::parameters<string_view, ec::weierstrass> p{.p = "751"sv,
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
            ec::parameters<string_view, ec::weierstrass> p{.p = "211"sv,
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
            ec::parameters<string_view, ec::weierstrass> p{
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
    using namespace crypto;

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
    {
        cmp_bytes(scrypt(""s, ""s, 16, 1, 1, 64), R"(
       77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
       f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
       fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
       e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06
    )"_sb);
        cmp_bytes(scrypt("password"s, "NaCl"s, 1024, 8, 16, 64), R"(
       fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
       7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
       2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
       c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40
    )"_sb);
        cmp_bytes(scrypt("pleaseletmein"s, "SodiumChloride"s, 16384, 8, 1, 64), R"(
       70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
       fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
       d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
       e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87
    )"_sb);
        // very long in debug mode, 1 GB of mem
        /*{
            scoped_timer t;
            cmp_bytes(scrypt("pleaseletmein"s, "SodiumChloride"s, 1048576, 8, 1, 64), R"(
           21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81
           ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47
           8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3
           37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4
            )"_sb);
        }
        {
            scoped_timer t;
            cmp_bytes(scrypt("Rabbit"s, "Mouse"s, 1048576, 8, 1, 32), R"(
                E277EA2CACB23EDAFC039D229B79DC13ECEDB601D99B182A9FEDBA1E2BFB4F58
            )"_sb);
        }*/

        auto test = [](int N, int r, int p, auto &&res) {
            cmp_bytes(scrypt("password"s, "ce3b79848f2a254df1d60e1a3146165a"_sb, N, r, p, 16), res);
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

void test_chacha20() {
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

    {
        uint8_t key[32]{};
        uint32_t counter{1};
        uint8_t nonce[12]{};

        using byte = uint8_t;

        byte plaintext_1[127]{};
        byte out1[127]{};
        byte out2[127]{};

        //chacha20(key, counter, nonce, plaintext_1, out1, 127);
        //chacha20(key, counter, nonce, out1, out2, 127);
        cmp_l(plaintext_1, out2);

        auto K = "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"_sb;
        auto nonce_one = "00 00 00 00 00 01 02 03 04 05 06 07"_sb;
        /*auto onetimekey = poly1305_key_gen((uint8_t *)K.c_str(), (uint8_t *)nonce_one.c_str());
        cmp_bytes(onetimekey,
                  "8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71 a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46"_sb);*/
    }
}

void test_chacha20_aead() {
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
    using namespace crypto;

    auto run = [](auto &&url) {
        //std::cout << "connecting to " << url << "\n";
        try {
            http_client t{url};
            t.run();
            std::cout << "connecting to " << url << "\n";
            std::cout << "ok" << "\n\n";
            cmp_base(0, 0);
        } catch (std::exception &e) {
            std::cout << "connecting to " << url << "\n";
            std::cerr << e.what() << "\n\n";
            cmp_base(0, 1);
        }
    };

    //
    // run("pugin.goststand.ru:1443");
    // run("pugin.goststand.ru:2443"); // magma
    // run("pugin.goststand.ru:3443");
    // run("pugin.goststand.ru:4443"); // magma
    ////
    ////// https://infotecs.ru/stand_tls/
    // run("91.244.183.22:15002");
    // run("91.244.183.22:15012");
    // run("91.244.183.22:15022");
    // run("91.244.183.22:15032");
    // run("91.244.183.22:15072");
    // run("91.244.183.22:15082");
    // run("91.244.183.22:15092");
    ////
    //
    run("infotecs.ru");
    run("software-network.org");
    run("letsencrypt.org");
    run("example.com");
    run("google.com");
    run("nalog.gov.ru");
    run("github.com");
    run("gmail.com");
    run("youtube.com");
    run("twitch.tv");
    run("tls13.akamai.io");
    run("tls13.1d.pw");
    //run("127.0.0.1:11111");

    // some other tests
    run("https://www.reuters.com/");
    run("https://edition.cnn.com/");
    run("https://www.cloudflare.com/");
    //
    //// does not support tls13
    // run("https://www.globaltimes.cn/");
    // run("https://www.gov.cn/");
    // run("https://english.news.cn/");
    // run("sberbank.ru");
    // run("gosuslugi.ru");
    // run("gost.cryptopro.ru");
    //// requires RFC 5746(Renegotiation Indication)
    // run("tlsgost-512.cryptopro.ru"); // https://www.cryptopro.ru/products/csp/tc26tls
}

int main() {
    //test_aes();
    //test_sha1();
    //test_sha2();
    //test_sha3();
    //test_blake2();
    //test_sm3();
    //test_sm4();
    //test_ec();
    //test_hmac();
    //test_pbkdf2();
    test_chacha20();
    //test_scrypt();
    test_chacha20_aead();
    //test_asn1();
    //test_streebog();
    //test_grasshopper();
    //test_mgm();
    //test_gost();
    //
    //test_tls();
}
