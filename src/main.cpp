// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#include "aes.h"
#include "argon2.h"
#include "asn1.h"
#include "bigint.h"
#include "blake2.h"
#include "blake3.h"
#include "chacha20.h"
#include "ec.h"
#include "grasshopper.h"
#include "hmac.h"
#include "hpke.h"
#include "jwt.h"
#include "magma.h"
#include "mlkem.h"
#include "mldsa.h"
#include "mmap.h"
#include "pki.h"
#include "random.h"
#include "rsa.h"
#include "scrypt.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"
#include "sm4.h"
#include "streebog.h"
#include "tls.h"
#include "dns.h"
#include "http.h"
#include "email.h"
#include "ed25519.h"
#include "ed448.h"
#include "ssh2.h"

// TODO: dns - doh dot (port 853)?

#define LOG_TEST()                                                                                                                                             \
    std::print("{} ... ", __FUNCTION__);                                                                                                                       \
    std::flush(std::cout);                                                                                                                                     \
    scoped_timer ____timer;

#define SRCLOC std::source_location loc = std::source_location::current()

static int total, success;
static struct stats {
    ~stats() {
        std::print(R"(
total:  {}
passed: {}
failed: {}
)",
                   total, success, total - success);
    }
} __;

struct timer {
    using clock = std::chrono::high_resolution_clock;

    clock::time_point tp{clock::now()};
    int total{::total};
    int success{::success};

    void end() {
        auto diff = clock::now() - tp;
        auto ok = ::total - total == ::success - success && std::uncaught_exceptions() == 0;
        std::println("{} in {:.4f} ({} of {} tests passed)", ok ? "ok" : "errored",
            std::chrono::duration_cast<std::chrono::duration<float>>(diff).count(),
            ::success - success, ::total - total
        );
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
    // std::println(s.str());
    return s.str();
};
auto to_string2 = [](auto &&sha, std::string s, std::string s2) {
    sha.update(s);
    auto digest = sha.digest();
    // std::span<uint8_t> d{(uint8_t *) digest.data(),
    // digest.size() * sizeof(typename std::decay_t<decltype(digest)>::value_type)};
    // auto res = to_string_raw(d);
    auto res = to_string_raw(digest);
    auto r = res == s2;
    ++total;
    success += !!r;
    // printf("%s\n", r ? "ok" : "false");
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
auto cmp_bool = [](auto &&left, bool right = true, SRCLOC) {
    auto r = left == right;
    ++total;
    success += !!r;
    if (!r) {
        std::println("test failed on the line {}", loc.line());
    }
    return r;
};
auto cmp_base = [](auto &&left, auto &&right, SRCLOC) {
    return cmp_bool(left == right, true, loc);
};
auto cmp_bytes = [](crypto::bytes_concept left, crypto::bytes_concept right, bool with_xor = false, SRCLOC) {
    auto r = cmp_base(left, right, loc);
    if (!r) {
        std::cout << "bytes not equal" << "\n";
        std::cout << "left:" << "\n";
        std::cout << left;
        std::cout << "right:" << "\n";
        std::cout << right;
        if (with_xor) {
            std::cout << "xored:" << "\n";
            auto sz = std::min(left.size(), right.size());
            for (int i = 0; i < sz; ++i) {
                right[i] ^= left[i];
            }
            std::cout << right;
        }
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
    if constexpr (requires {s.data();}) {
        o.write((const char *)s.data(), s.size());
    } else {
        o << s;
    }
}
auto cacert_pem() {
    auto name = "roots.pem";
    if (!std::filesystem::exists(name)) {
        crypto::http_client t{"https://curl.se/ca/cacert.pem"};
        t.tls_layer.ignore_server_certificate_check = true;
        t.run(
            // crypto::default_io_context()
        );
        write_file(name, t.m.body);
    }
    auto &tcs = crypto::x509_storage::trusted_storage();
    tcs.load_pem(read_file(name), true);
    return name;
}
auto infotecs_ca() {
    auto name = "infotecsCA.der";
    /*if (!std::filesystem::exists(name)) {
        crypto::http_client t{"http://testcert.infotecs.ru/CA.der"};
        t.run(default_io_context());
        write_file(name, t.m.body);
    }*/
    return name;
}
void load_system_certs() {
    using namespace crypto;

    auto &tcs = x509_storage::trusted_storage();
    tcs.load_pem(read_file(cacert_pem()), true);
    tcs.load_der(read_file(infotecs_ca()), true);
#ifdef _WIN32
    auto load_certs = [&](auto &&store) {
        for (auto &&s : win32::enum_certificate_store(store)) {
            tcs.load_der(s, true);
        }
    };
    load_certs("CA");
    load_certs("ROOT");
#endif
}

void test_aes() {
    LOG_TEST();

    using namespace crypto;

    unsigned char plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    unsigned char right[] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};

    // using v4u = unsigned __attribute__ ((vector_size (16)));
    using v4u = std::array<unsigned char, 16>;
    // using v4u = unsigned char[16];
    //int n = 10000000;
    // while (n--)
    {
        {
            // v4u out, out2;
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
    {
        sha1 sha;
        to_string2(sha, std::string(64, 'a'), "0098ba824b5c16427bd7a1122a5a442a25ec644d");
    }
    {
        sha1 sha;
        to_string2(sha, std::string(65, 'a'), "11655326c708d70319be2610e8a57d9a5b959d3b");
    }
    {
        sha1 sha;
        to_string2(sha, std::string(585, 'a'), "0eb45e04b2491c518efaf14a5735dbf0241ad7d8");
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
        sha2<512, 224> sha;
        to_string2(sha, "", "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
    }
    {
        sha2<512, 256> sha;
        to_string2(sha, "", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
    }
    {
        sha2<512> sha;
        to_string2(sha, "abc",
                   "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
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
                   "1111111111111111111111111111111111111111111111111111111111111111",
                   "394c13be14f7b0d8c3fb5a8588d2710657040ad6efd1c6b9eafccae1");
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
                   "11111111111111111111111111111111111111111111111111111111111111111",
                   "32063579e2f475efdea66d4384f75a96df64247e363c7ad8eb640a25");
    }
    {
        sha2<224> sha;
        to_string2(sha, "message", "ff51ddfabb180148583ba6ac23483acd2d049e7c4fdba6a891419320");
    }
    {
        sha2<512> sha;
        to_string2(sha, "message",
                   "f8daf57a3347cc4d6b9d575b31fe6077e2cb487f60a96233c08cb479dbf31538cc915ec6d48bdbaa96ddc1a16db4f4f96f37276cfcb3510b8246241770d5952c");
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
        cmp_hash_bytes(
            sha, "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc0469070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc0469070dd",
            "62ddcbb514fffa979c28304ebd7cc7319d7882bd988007fa28826582ef224aba"_sb);
    }
    {
        sha3<256> sha;
        cmp_hash_bytes(
            sha, "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc0469070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc0469070dd.",
            "e036d52be9b804b3d43da8ea23ab5713cbe59f1f519081010eeea16f6b6efeee"_sb);
    }
    {
        sha3<256> sha;
        cmp_hash_bytes(
            sha, "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc0469070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc0469070dd..",
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
        sha3<224> sha;
        fox(sha, "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795", "2d0708903833afabdd232a20201176e8b58c5be8a6fe74265ac54db0");
    }
    {
        sha3<256> sha;
        fox(sha, "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04", "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d");
    }
    {
        sha3<384> sha;
        fox(sha, "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41",
            "1a34d81695b622df178bc74df7124fe12fac0f64ba5250b78b99c1273d4b080168e10652894ecad5f1f4d5b965437fb9");
    }
    {
        sha3<512> sha;
        fox(sha, "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450",
            "18f4f4bd419603f95538837003d9d254c26c23765565162247483f65c50303597bc9ce4d289f21d1c2f1f458828e33dc442100331b35e7eb031b5d38ba6460f8");
    }
    {
        sha3<224> sha;
        to_string2(
            sha,
            "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "f81f0a8291418a13fca7c85017e3e9c94a92c868ce7c6d103b05f480");
    }
    {
        sha3<224> sha;
        to_string2(
            sha,
            "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "8bcb6461eaaa339930d73868863c40861f18598560160ce1d69709a0");
    }
    {
        sha3<512> sha;
        to_string2(sha, std::string(0x48, '1'),
                   "631ce1bbf408fa13586f949526b77e8d529a6b89782bf7e156ef7749b66ba5080ac565b15f54e1c01ed65e10cb110aa2622df5d801837630fd2661970632abf5");
    }
    {
        sha3<512> sha;
        to_string2(sha, std::string(0x49, '1'),
                   "cd45f9f16c23b3330fffbaefae37d072b34a5fc05954fda6419fedea03da27393ca7056ef2e25c78e3e787cd95b92d63c2389109553025d15935478fd773ba09");
    }

    // shake
    {
        shake<128> s;
        s.finalize();
        cmp_bytes(s.squeeze<8>(), "7f"_sb);
        cmp_bytes(s.squeeze<8>(), "9c"_sb);
        cmp_bytes(s.squeeze<16>(), "2ba4"_sb);
        cmp_bytes(s.squeeze<256 - 32>(), "e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"_sb);
        cmp_bytes(s.squeeze<256>(), "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2"_sb);
    }
    {
        shake<128> s;
        s.update("The quick brown fox jumps over the lazy dog"sv);
        s.finalize();
        cmp_bytes(
            s.squeeze<2560>(),
            "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66eb5585ec6f86021cacf272c798bcf97d368b886b18fec3a571f096086a523717a3732d50db2b0b7998b4117ae66a761ccf1847a1616f4c07d5178d0d965f9feba351420f8bfb6f5ab9a0cb102568eabf3dfa4e22279f8082dce8143eb78235a1a54914ab71abb07f2f3648468370b9fbb071e074f1c030a4030225f40c39480339f3dc71d0f04f71326de1381674cc89e259e219927fae8ea2799a03da862a55afafe670957a2af3318d919d0a3358f3b891236d6a8e8d19999d1076b529968faefbd880d77bb300829dca87e9c8e4c28e0800ff37490a5bd8c36c0b0bdb2701a5d58d03378b9dbd384389e3ef0fd4003b08998fd3f32fe1a0810fc0eccaad94bca8dd83b34559c333f0b16dfc2896ed87b30ba14c81f87cd8b4bb6317db89b0e"_sb);
    }
    {
        shake<128> s;
        s.update("The quick brown fox jumps over the lazy dog."sv);
        s.finalize();
        cmp_bytes(
            s.squeeze<2560>(),
            "634069e6b13c3af64c57f05babf5911b6acf1d309b9624fc92b0c0bd9f27f5386331af1672c94b194ce623030744b31e848b7309ee7182c4319a1f67f8644d2034039832313286eb06af2e3fa8d3caa89c72638f9d1b26151d904ed006bd9ae7688f99f57d4195c5cee9eb51508c49169df4c5ee6588e458a69fdc78782155550ef567e503b355d906417cb85e30e7156e53af8be5b0858955c46e21e6fa777b7e351c8dba47949f33b00deef231afc3b861aaf543a8a3db940f8309d1facd1f684ac021c61432dba58fa4a2a5148fd0edc6e6987d9783850e3f7c517986d87525f6e9856987e669ef38e0b3b7996c8777d657d4aac1885b8f2cfeed70e645c869f32d31945565cb2a7d981958d393f8005dbffb0c00dfccc8f0d6111729f3a64e69d2fd4399de6c11635a6ae46daa3e918d473c4e0b2bb974c1ac3939773067"_sb);
    }
    {
        shake<256> s;
        s.finalize();
        cmp_bytes(s.squeeze<512>(),
                  "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"_sb);
    }
    {
        shake<256> s;
        s.finalize();
        cmp_bytes(
            s.squeeze<5120>(),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea203bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f5a1aaa96d313eacc890936c173cdcd0fab882c45755feb3aed96d477ff96390bf9a66d1368b208e21f7c10d04a3dbd4e360633e5db4b602601c14cea737db3dcf722632cc77851cbdde2aaf0a33a07b373445df490cc8fc1e4160ff118378f11f0477de055a81a9eda57a4a2cfb0c83929d310912f729ec6cfa36c6ac6a75837143045d791cc85eff5b21932f23861bcf23a52b5da67eaf7baae0f5fb1369db78f3ac45f8c4ac5671d85735cdddb09d2b1e34a1fc066ff4a162cb263d6541274ae2fcc865f618abe27c124cd8b074ccd516301b91875824d09958f341ef274bdab0bae316339894304e35877b0c28a9b1fd166c796b9cc258a064a8f57e27f2a5b8d548a728c9444ecb879adc19de0c1b8587de3e73e15d3ce2db7c9fa7b58ffc0e87251773faf3e8f3e3cf1d4dfa723afd4da9097cb3c866acbefab2c4e85e1918990ff93e0656b5f75b08729c60e6a9d7352b9efd2e33e3d1ba6e6d89edfa671266ece6be7bb5ac948b737e41590abe138ce1869c08680162f08863d174e77"_sb);
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
        to_string2(sha, "abc",
                   "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    }
    {
        blake2b<512> sha{"1"sv};
        to_string2(sha, "abc",
                   "8dcc70edeec8341bf056873cceea93b05a3f2e7b43aed334fa3de25be04780fcba0a642ef96576ca109a177c3cb51c5642299d26db1f64cc29f5377175a12db2");
    }
    {
        blake2b<512> sha{"abc"sv};
        to_string2(sha, "abc",
                   "17de517e1278d00ac7a6bcf048881aa9a972e6b5cef843d3c61d3e252068a2f526c999f45cd96b172509d085b59170e388f845750c812781df582be3fc4a1972");
    }
    {
        blake2b<512> sha{"69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"sv};
        to_string2(sha,
                   "17de517e1278d00ac7a6bcf048881aa9a972e6b5cef843d3c61d3e252068a2f526c999f45cd96b172509d085b59170e388f845750c812781df582be3fc4a1972"
                   "17de517e1278d00ac7a6bcf048881aa9a972e6b5cef843d3c61d3e252068a2f526c999f45cd96b172509d085b59170e388f845750c812781df582be3fc4a1972"
                   ".",
                   "552225b32c7f991578114e624e2484275c96d966090ff90fbf56a3e4773f6d7d4d7865d3d27b7dd6f8e75849800474eeee7c7b747613dbea488548c283f7aa25");
    }
    {
        blake2b<512> sha;
        to_string2(sha, "The quick brown fox jumps over the lazy dog",
                   "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918");
    }
    {
        blake2b<512> sha;
        to_string2(sha, "The quick brown fox jumps over the lazy dof",
                   "ab6b007747d8068c02e25a6008db8a77c218d94f3b40d2291a7dc8a62090a744c082ea27af01521a102e42f480a31e9844053f456b4b41e8aa78bbe5c12957bb");
    }
    {
        blake2b<512> sha;
        to_string2(sha, "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
                   "5ab06c925a13d6b9c991d4c2e5ee346bf1befb9b028be3ddf9b39d8fe0e92dc1f4fba7f78aa60a1f18d995e95bb5aabd6faca300e64cdce3352941872e96961f");
    }
    {
        blake2b<512> sha;
        to_string2(sha,
                   "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
                   ".",
                   "00756c07368f4c98176ae5d6b96e321704b8be4b9a2aa298700d4b4e0c0ca6c344f848b389ef3dfdde460e50e85ab649b82f9902cf4453e6c54ea58857fe76d4");
    }
    {
        blake2b<512> sha;
        to_string2(sha,
                   "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
                   "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
                   "dbf11e82f88c5886b76afeb072c0304d27207e5168512cf27628edbb638f272cf05c04d1d85ee4e99dcc7e1f3cb1bcb972d722dabcd6624d613dcba434dbafd0");
    }
    {
        blake2b<512> sha;
        to_string2(sha,
                   "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
                   "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
                   ".",
                   "c93a777c384d3186824ad214090cecfed185f0f9a618d696c5fea2dc63096643f87eac776f4c95a2b456f21aa225a092c46807c91b8656a79941af7d4cd82668");
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
    check(std::string(1024, 0xaa) + std::string(1024, 0xbb),
          R"(e79d2838915accd3b21bb0ba76b5edf8dc08d3d78d0db65b713f0f37ec58c34623d15d1e2d97c52cfb08f73a675c3d1d67bac5110d25703000ea9b6f5fc6ae9210)"_sb);
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
    check_a(3072 * 2,
            R"(f01bbb4825647ad9814caf217d165e6b2e8a84a562fb4e157d0a2e51701f1f391210340984e04d780b47652feabe707e301c4e0be160433fcf73fcd3700f364978)"_sb);
    check_a(3072 * 3, R"(805fed622390360e88f8785f648b4b8e2bb6871151e5bb104172d40841d9abc5)"_sb);
    check_a(3072 * 3,
            R"(805fed622390360e88f8785f648b4b8e2bb6871151e5bb104172d40841d9abc5a38bd070929a2ecc1e409bde1d23c2e69f11a232aeea28bb742fdb793b9330976c)"_sb);
    check_a(7168, R"(1437b23514e7a19dd5d4f48fb6fd4f38e2a9853a16532c6cc341c43c7680dad3)"_sb);
    check_a(7168, R"(1437b23514e7a19dd5d4f48fb6fd4f38e2a9853a16532c6cc341c43c7680dad38d91e07016c4678624dae3112a32663823fc36355e9f828ce4fb0918213599b1e4)"_sb);
    check_a(1024 * 15,
            R"(e598de4a1995abce47b1a8384cdff5b9822caa202662b47f5e3ba1eb7b3ac8c3dd80cc5d52c92f0948f557561e245208e5b92184d5f5668f4b699942eb92bc6ddf)"_sb);
    check_a(1024 * 16,
            R"(d2613fb519aa95cd328f55dd4551c848920c2209cdcf0debc02500d2ad8964076a3b341441904fc2e6ebb045517ec87a4f78121a3bb8af00611348c27667141c98)"_sb);

    // keyed
    {
        auto key = R"(0123456789ABCDEF0123456789ABCDEF)"s;
        blake3 b{key};
        b.update("");
        cmp_bytes(b.digest(65),
                  R"(5491091c17191a894372e9f3b8867284eae6221b8030b3632677beae6f9ebe021e380f86faee6a34f802b637d2080e04465138bd0b18c802ec01eb0be8f9498e3d)"_sb);
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
    check_all("", R"(af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26)"_sb,
              R"(e69ae626ef8cb2dfc63d9603c9b9e35f670b47484085a417f926345f03afc586641b8e5bdd74d74baf5114de958bcd09fb8f7d0944d9d4dbc20b501ea4df600d81)"_sb,
              R"(f9fa26ec9bd90186cfcbadb18c742318887b4869826013409d09bfdffd581b0dce7631f45e746ede6bcc255f403fd69174f902b0f912ed968d980fe8add9b11f13)"_sb,
              R"(741011989511e0d6b52532320d9edb6c0def0ab7e832b99bcc1259591ce2d75b701d666214c39da11895511954dcc5a5c17e030a4db02e7fb04c0e3230283515c8)"_sb);
    check_all("test123",
              R"(e3428f2c4089c278544c4827529dee5c82cdb368dbf6013e576d5ddc179c2bec2bdd6946dcf05d4e829825d38fd2f1072db09120922d98df7f065a911bb3fbda32)"_sb,
              R"(d15c5596d85069c359d15a430136aa5479f9a79480f9ad93b04e37107c69e062ffb53b3132664fc7f6b389344e845653bedaf46deb35cbec5ce98208085eee7991)"_sb,
              R"(9d8b48d9f7bf97a2d3218877e5023e42954f954a8179e7a9718c46298c33e555f9684e5469b5ea62269c07c05312100238641be887da4e1a0917644506e4c6256a)"_sb,
              R"(e5fcee1bb3cde9f038ee32d985c17bd052dd8e6eba23856f73761f1e7ecf80e5071ebdf27ddc2beeffbaf116ec7b7fbfa27bb04cab0f3ff7ddaf05cc0110ed4e37)"_sb);
    check_all(std::string(1024, 'a'),
              R"(5a1c9e5d85d9898297037e8e24f69bb0e604a84c91c3b3ef4784a374812900d9ecf50f8ed1faefc98c45d05db0c5e4e81eb5d5f3be89b5b12f96c199c61d7cbbc9)"_sb,
              R"(82fe4001f46d18a731b2361b966f70c5b9f848b9447119882df09cdf48dbec3bc8394159bba068442b88e664bd127b818cccb03517763322fcd44e59ed30e3f73f)"_sb,
              R"(401c1d24951f14eef6c8cf2ad6993221edc8559fb9f56c06cf66c64b43abc1754a0269745176b79598b5e8cb2cc32d921229a62e2fa62c629e15ea7d56f1fe9a51)"_sb,
              R"(cc6d9942e33fa7f78601bb8b9697eddb92458cb77ffaccd19717a929adea788cd3e8d01e7c322591a344f24e53f53c5a70f1af1159545520530c9f64e2864682b1)"_sb);
    check_all(std::string(1025, 'a'),
              R"(c59d2e12583df14d951e757a42f1734d355c8c5b1db6b6a33ab2bfabeed40c7d26d5461cf30b142e78fa6227457c866765146a9f3a589f9459041011c018a88a70)"_sb,
              R"(e0fb3171de8423d93db31554929cc382b6c39357acf99e96f5e8d03a7c2fe2fdc26bc0fcb0e2222af7702bcfe5be5ad75751fd85f8806c9a15baca1211b642d7c5)"_sb,
              R"(b730131c95e0d8089907d9e98aa2944e4b4bb2b7d9622b5f8d135d4d0ffbf2c2ea2d74f981e26ffd4e0ac170a757afcefe542035bec79eaa310b10f675512e37eb)"_sb,
              R"(9e38623637339ab770c326b1f87c31c148c19d39782843c29910cee7fab7ac2ac2560389ece68195c2a14ebb5f0ed321390fa26c405e497296b39b94c53168ac9e)"_sb);
    check_all(std::string(2048, 'a'),
              R"(11654ac17d073b0905429320fee0a34776cb5f10a9767287c70b627fc4f455397e56bd45802b2a744cf5f7ff1169523c8d5be419747ad281c8a4cc440619a77a6c)"_sb,
              R"(6627a0d2200b5bb56e3921e03813128f060533debaf633deb3f3a3891a650ae92c501da5fb5ca5e99ca1f20cd7b01f3ce13da5997d4958145cd583b31c9c61aa32)"_sb,
              R"(f95d0c930f4eab036ba4e7dce7ccd9c26f8bdcd3515d6f14aa5a188d46e57402042ca431a8c7820c1c861d159356948c3ec100bad75b6358dae552240f1a26d126)"_sb,
              R"(220ddce7808d29d37b1353d4ef18c10d85d8eee6db3678a80ce1031c0cce313c6400d49224e04ed8e83b02ee052d21700bfaf956dc833a3949ecf2f6d090db46d9)"_sb);
    check_all(std::string(3072, 'a'),
              R"(452f43e13d923a9ee495b3640e4dc681d6224586a9d1252b9d837d13438c92b5d2b18a46ef11cbd7973487dc71073890ad9ec0ff66add8ea4d4a83e1bc860944fb)"_sb,
              R"(ec7ac93013d9536bea9424f086403ebf9927e724a27390fced378d722c50e5c5ebaa5a4084a948ffeed6b511e8825200152c19a68b5199bdbe3ceb09469c0235dd)"_sb,
              R"(07d71ce58b3d2fd750864b5a91d4aa403510f91bb21130ae9acafb3f19398550b9ee595c877b2626f6f62fbe72c2b2676b2a0aba071dde8bf8a04a7167c290ee7d)"_sb,
              R"(7607c3bdad2cd543a7ee4e52e93428051f699454f3e4620846b855a7105bb93a3aae8feff2f8f98c248281194de6b61e8243ba05ebeff763d9692e3a5f6b96bfc6)"_sb);
    check_all(std::string(4096, 'a'),
              R"(cf657d3fd42311a258afdf3b5261c256983e3deb2bb38980cb0e754db903d549ae329a6635596c535f2f443c2eee918d3fd202c8e0dda89e8756135de6e8fb9ac4)"_sb,
              R"(fcf2b82c77c14a1411a07bd1c663e99674f5d7c36aa02f1757a244708b56f9840a3b995dbb59369270f50ae0715d7abdfe0213e9c69f897f473eda57ce3ecf7826)"_sb,
              R"(e9ab7701a0b920f5ac4d2a897226554f7b396041113ac13548a07415db18cad3b540bf1b60baef6c720f2becaf523c34f4c47d6f0b6e7a42300df8e72b78a314c0)"_sb,
              R"(a4e8b185965d7336aac1033c2d33a3c255fa9d389f3c08de7a3bb5e8542a510c63a8eb3be239492f4e9842bff211713ddfc2361ba60c08a3574059605ab8837d80)"_sb);
}

void test_sm3() {
    LOG_TEST();

    using namespace crypto;

    {
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

    // sm2 sig
    {
        constexpr auto bits = 256;
        using test_curve = ec::sm2_base<bits, "0x 8542D69E 4C044F18 E8B92435 BF6FF7DE 45728391 5C45517D 722EDB8B 08F1DFC3"_s,
                         "0x 787968B4 FA32C3FD 2417842E 73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498"_s,
                         "0x 63E4C6D3 B23B0C84 9CF84241 484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A"_s,

                         "0x 421DEBD6 1B62EAB6 746434EB C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D"_s,
                         "0x 0680512B CBB42C07 D47349D2 153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2"_s,
                         "0x 8542D69E 4C044F18 E8B92435 BF6FF7DD 29772063 0485628D 5AE74EE7 C32E79B7"_s, "1"_s>;

        auto m = "message digest"sv;

        test_curve ec;
        ec.private_key_ = bytes_concept{"128B2FA8 BD433C6C 068C8D80 3DFF7979 2A519A55 171B1B65 0C23661D 15897263"_sb};
        auto pubk = ec.public_key();
        cmp_bytes(pubk.x, "0AE4C779 8AA0F119 471BEE11 825BE462 02BB79E2 A5844495 E97C04FF 4DF2548A"_sb);
        cmp_bytes(pubk.y, "7C0240F8 8F1CD4E1 6352A73C 17B7F16F 07353E53 A176D684 A9FE0C6B B798E857"_sb);

        auto id_a = "ALICE123@YAHOO.COM"sv;

        auto za = ec.za<sm3>(id_a, pubk);
        cmp_bytes(za, "F4A38489 E32B45B6 F876E3AC 2168CA39 2362DC8F 23459C1D 1146FC3D BFB7BC9A"_sb);

        sm3 hv;
        hv.update(za);
        hv.update(m);
        auto mh = hv.digest();
        cmp_bytes(mh, "B524F552 CD82B8B0 28476E00 5C377FB1 9A87E6FC 682D48BB 5D42E3D9 B9EFFE76"_sb);

        // values k,r,s from rfc example
        {
            auto q = bigint{test_curve::parameters.order};
            auto e = bytes_to_bigint(test_curve::hash<sm3>(id_a, m, pubk));
            bigint k = "0x 6CB28D99 385C175C 94F94E93 4817663F C176D925 DD72B727 260DBAAE 1FB2F96F"sv;
            auto x1 = (k * test_curve::parameters.curve().G).x;
            auto r = (e + x1) % q;
            auto da = bytes_to_bigint(ec.private_key_);
            auto s = (da + 1).invert(q) * (k - r * da) % q;
            auto rs = r.to_string(bitlen{bits});
            auto ss = s.to_string(bitlen{bits});
            cmp_bytes(rs, "40F1EC59 F793D9F4 9E09DCEF 49130D41 94F79FB1 EED2CAA5 5BACDB49 C4E755D1"_sb);
            cmp_bytes(ss, "6FC6DAC3 2C5D5CF1 0C77DFB2 0F7C2EB6 67A45787 2FB09EC5 6327A67E C7DEEBE7"_sb);
            cmp_bool(ec.verify<sm3>(id_a, m, pubk, rs, ss), true);
        }

        auto [r,s] = ec.sign<sm3>(id_a, m);
        cmp_bool(ec.verify<sm3>(id_a, m, pubk, r, s), true);
    }
}

void test_sm4() {
    LOG_TEST();

    using namespace crypto;

    auto tv_key = "0123456789ABCDEFFEDCBA9876543210"_sb;
    auto tv_plain = "0123456789abcdeffedcba9876543210"_sb;

    {
        sm4_encrypt enc{tv_key};
        auto res = enc.encrypt(tv_plain);

        uint8_t tv_cipher[] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};
        cmp_bytes(tv_cipher, res);

        sm4_decrypt dec{tv_key};
        res = dec.decrypt(res);
        cmp_bytes(res, tv_plain);
    }
    {
        sm4_encrypt enc{tv_key};
        auto res = enc.encrypt(tv_plain);
        for (int i = 0; i < 1000000 - 1; i++) {
            res = enc.encrypt(res);
        }
        uint8_t tv_cipher[] = {0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f, 0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66};
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
            ec::parameters<string_view, ec::weierstrass_prime_field> p{.p = "0xc1c627e1638fdc8e24299bb041e4e23af4bb5427"sv,
                                                                       .a = "0xc1c627e1638fdc8e24299bb041e4e23af4bb5424"sv,
                                                                       .b = "0x877a6d84155a1de374b72d9f9d93b36bb563b2ab"sv,
                                                                       .G{
                                                                           "0x010aff82b3ac72569ae645af3b527be133442131"sv,
                                                                           "0x46b8ec1e6d71e5ecb549614887d57a287df573cc"sv,
                                                                       }};
            auto c = p.curve();
            auto r = m * c.G;
            cmp_base(r.x, "0x41da1a8f74ff8d3f1ce20ef3e9d8865c96014fe3"_bi);
            cmp_base(r.y, "0x73ca143c9badedf2d9d3c7573307115ccfe04f13"_bi);
        }
        {
            ec::weierstrass_prime_field c{"0xdfd7e09d5092e7a5d24fd2fec423f7012430ae9a", "0x01914dc5f39d6da3b1fa841fdc891674fa439bd4",
                                          "0xdfd7e09d5092e7a5d24fd2fec423f7012430ae9d"};
            ec::ec_field_point p{c, "0x70ee7b94f7d52ed6b1a1d3201e2d85d3b82a9810", "0x0b23823cd6dc3df20979373e5662f7083f6aa56f"};
            auto r = m * p;
            cmp_base(r.x, "0xb616c81e21d66dd84906468475654cf7d6f2058a"_bi);
            cmp_base(r.y, "0x7338bd2600ad645b093a67f4651de9edc625295c"_bi);
        }
    }

    // gost 34.10
    {
        // example 1
        {
            ec::weierstrass_prime_field c{"0x7", "0x5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e",
                                          "0x8000000000000000000000000000000000000000000000000000000000000431"};
            ec::ec_field_point p{c, "2", "0x8e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8"};
            auto m = "55441196065363246126355624130324183196576709222340016572108097750006097525544"_bi;
            auto r = m * p;
            cmp_base(r.x, "57520216126176808443631405023338071176630104906313632182896741342206604859403"_bi);
            cmp_base(r.y, "17614944419213781543809391949654080031942662045363639260709847859438286763994"_bi);
        }
        // gost 34.10 example 2
        {
            ec::weierstrass_prime_field c{
                "0x7", "0x1cff0806a31116da29d8cfa54e57eb748bc5f377e49400fdd788b649eca1ac4361834013b2ad7322480a89ca58e0cf74bc9e540c2add6897fad0a3084f302adc",
                "0x4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15df1d852741af4704a0458047e80e4546d35b8336fac224dd81664bbf528be6373"};
            ec::ec_field_point p{
                c, "0x24d19cc64572ee30f396bf6ebbfd7a6c5213b3b3d7057cc825f91093a68cd762fd60611262cd838dc6b60aa7eee804e28bc849977fac33b4b530f1b120248a9a",
                "0x2bb312a43bd2ce6e0d020613c857acddcfbf061e91e5f2c3f32447c259f39b2c83ab156d77f1496bf7eb3351e1ee4e43dc1a18b91b24640b6dbb92cb1add371e"};
            auto m =
                "610081804136373098219538153239847583006845519069531562982388135354890606301782255383608393423372379057665527595116827307025046458837440766121180466875860 "_bi;
            auto r = m * p;
            cmp_base(r.x,
                     "0x115dc5bc96760c7b48598d8ab9e740d4c4a85a65be33c1815b5c320c854621dd5a515856d13314af69bc5b924c8b4ddff75c45415c1d9dd9dd33612cd530efe1"_bi);
            cmp_base(r.y,
                     "0x37c7c90cd40b0f5621dc3ac1b751cfa0e2634fa0503b3d52639f5d7fb72afd61ea199441d943ffe7f0c70a2759a3cdb84c114e1f9339fdf27f35eca93677beec"_bi);
        }
        //
        {
            auto pubs = "350208a00f0a78c15ef3faa68feefb0ec804cd9eae9cfa0b4f4b8e3351563ae957aa47e08a421e8373e5b7d1947b46f62c0db53b55ffaffe48dafba7d68ac5a2"_sb;
            auto pubc = "f52612c43cbc122e897929919339e1b9221de15ea8553a836439bdbe10842aeaf605f689bef098b3726446cbe63bb7aab240d8a7d5590f009633d9ac464c5949"_sb;
            auto shared = "cd9fe19836b50edbe35dee4e0d6fc3d8e8b08533af1a47a2f16ee02444f5c4b5"_sb;

            using curve = ec::gost::r34102012::ec256a;
            curve s, c;
            s.private_key_ = bytes_concept{"316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb};
            c.private_key_ = bytes_concept{"30bd7301f388a808c3362b415692c1638e3b90d254803ef8c1e3401d328f5887"_sb};

            auto check_pub = [](auto &&c, auto &&v) {
                curve::public_key_type pub;
                c.public_key(pub);
                cmp_bytes(pub, v);
            };
            check_pub(s, pubs);
            check_pub(c, pubc);

            auto check_shared = [&](auto &&c, bytes_concept v) {
                auto sc = c.shared_secret(v);
                cmp_bytes(sc, shared);
            };
            check_shared(s, pubc);
            check_shared(c, pubs);
        }
        //
        {
            ec::weierstrass_prime_field c{"0x7", "0x5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e",
                                          "0x8000000000000000000000000000000000000000000000000000000000000431"};
            ec::ec_field_point P{c, "2", "0x8e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8"};
            auto m = "0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"_bi;
            auto q = m;
            auto d = "0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28"_bi; // private key
            auto Q = d * P;                                                                   // pubkey
            auto xq = "0x7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B"_bi;
            auto yq = "0x26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA"_bi;
            cmp_base(Q.x, xq);
            cmp_base(Q.y, yq);

            using curve_t = ec::gost::r34102012::curve<256, "0x8000000000000000000000000000000000000000000000000000000000000431"_s, "0x7"_s,
                                                       "0x5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e"_s,

                                                       "0x2"_s, "0x8e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8"_s,

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
            cmp_base(ec.verify(h, bytes_concept{&pubk, sizeof(pubk)}, sig), true);
        }
        // all non twisted edwards
        {
            auto h = streebog<256>::digest("some data");
            auto h2 = streebog<512>::digest("some data");
            cmp_bytes(h, "fb163564090e52332bd401f9218d62f7b1ad1e0d85988cd55663e8b7875a1875"_sb);
            cmp_bytes(h2,
                      "aefa48f59945d65352797c3aa872357019716ad218ee19f76161df4815313f1d1d66449a82bfed36d95e1e229231fd877123f29f16547091afc7aa2a7caa8392"_sb);

            auto check = [](auto c, auto &&h, auto &&pk, auto &&pubkx, auto &&pubky, auto &&sig) {
                c.private_key_ = bytes_concept{pk};
                auto pubk = c.public_key();
                cmp_bytes(pubk.x, pubkx);
                cmp_bytes(pubk.y, pubky);
                cmp_base(c.verify(h, bytes_concept{&pubk, sizeof(pubk)}, sig), true);
                // random sign & verify
                cmp_base(c.verify(h, bytes_concept{&pubk, sizeof(pubk)}, c.sign(h)), true);
            };

            check(ec::gost::r34102012::ec256a{}, h, "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                  "350208a00f0a78c15ef3faa68feefb0ec804cd9eae9cfa0b4f4b8e3351563ae9"_sb, "57aa47e08a421e8373e5b7d1947b46f62c0db53b55ffaffe48dafba7d68ac5a2"_sb,
                  "08c7296c628619b747fce05f5ea0060251deea450491c0a55cdd8441a7455ec715a590da47a0be9caaf4963ee90a0f97220fa9fb8de46bb16f4937f00257e6b9"_sb);
            check(ec::gost::r34102012::ec256b{}, h, "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                  "bf4e76550b73dfe435fef49742327274422b37fa5ab6554ccfa8727de2bf08e7"_sb, "4aa5bd0f69072dbc8ced84c2c5873f92fe491bd1f0115d3efd7af5108b920bf8"_sb,
                  "4c495c83477eeb1d650ba8b1621f0b2c01ab797d3d95837316dd935154b4bbb515e6197fef15b818a0a64f836abb43f6f70582c922a95c9a957eb791e34e78a9"_sb);
            check(ec::gost::r34102012::ec256c{}, h, "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                  "3af74bc0bcbf01e58e7676c9eb56a553ff10dccf600818e8e83423a7c1183c57"_sb, "d54a1bc1b7fc30f987c99a41cd39e6ecefb177439f98aa09505febedd14db609"_sb,
                  "1a47b37a0338ec053ce5abb7f133557921c306fd235aab21b5d2bfa67d7f65ef760a19e3eae46d5ec06c56a54d4e695a167ea18cf827571d0c86a894b159e17e"_sb);
            check(ec::gost::r34102012::ec256d{}, h, "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                  "d92e0b13cd506dfba87399b6472ae1c682ad82ad0c2288e9d76e99b0693b5a6e"_sb, "df072de75411b32cc935cba3a5079692cb3dd7aeaf8e938c3c2b2b2951c30195"_sb,
                  "4620f84a48eaee14e4e0b63853d9ff18e65af3000f4917e30ea4fb9d506587d1886426b909a417e99357edcca35ac4aad7fa85f4b5e7c975e8b5428af640704a"_sb);

            check(
                ec::gost::r34102012::ec512a{}, h2, "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                "d6274e275a12898de87b835dd2b7a583f993d6a605d7ed869ae65d7350f9b85af8b14ed153e8982176ebf432a936b5de2a8aca197718be183fd115758082d1ac"_sb,
                "67a861c5cbafc99f2597d9773beba6cb2e335aa59e8270909071ba83720c3630d15cbfc252d487e3a8a9aab16de15f039ced3a6a631a8d5cd91db1b14f329fcd"_sb,
                "e197c18f669222262265c574d5911c3e9c3336fde1c0164c6eaa94f66615a8e7ace78bfb17c17ac2fa515b758e4020f07d38e87b138895069412a78aec225e211029974df95bd7d8b66e7bd8b2274a2a3096b818c6aec62375141c0a6a0c3f60c40462bd98a90f04b5da2353ead54622870a0df24a99e8d44b146c428ff6fd45"_sb);
            check(
                ec::gost::r34102012::ec512b{}, h2, "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                "2017a304d30b67873bd0811ba8a4a798a9fa2f340012f96a9c2a3377f26bec485f76c278abdb27a8a7770afcc4273423de784250703863883df3820ca5bb4d31"_sb,
                "ce809ced666b746e3af53676c4e0c65f3ff0f1e7025e72b2d6790680efc3a1b98e9938ad31c2c77dcb563ef575d88f5c5f9af281b31eb83a57fe361f2ae09e03"_sb,
                "06ba0869ecbb5a49f1a28efe0b73a09d0e770b2abf9e449a5e2f51a3fd215b2250b1092661e4ac0f1f09cd7ab88c47fcd2b85106d195b414c8da39526bf475895773e1be05c872bb4fd022e74dfbd1fe5bc4e0088b1aac9f792455761f3586358626c82f107beda04526e5fce497c1160a0db9b1567e92095c377f739eac188e"_sb);
            check(
                ec::gost::r34102012::ec512c{}, h2, "316ac7252683fdf9f6dfb272183a0a98ea732a200822a45b97a4468342371fe9"_sb,
                "cacff08b72c04b5e88342221f68cb188a4cd7792336fff33d9c08187564073862b4d0b7caa1321bb068a122966d39a23032cd6d2fa530fd8fa841643a8dcb26b"_sb,
                "c2fd9d0bb8ed53c889ab26abf4c111bfdc110f212eb42238312bf6e4f562023ca9b873c88a2f2a81aaa67f9ad201da5ddc6b16844ef63c06f1c5ceedba4476a2"_sb,
                "357666b68a3b336a091a642064c2472fd7e80b63c92ccb7c3c927b284ea345f113ebd280afd3c16e27f831309af4325437756cd4094e092b42ab88f032aea8420364fe74f5cbba0d9d9230417de9d988462136368533b5cd84d7eb0d9fecd09b1e0cf75d86ddd53c7f2427079946e151f5d74d2887d93a4a3ddfba2e31ba27aa"_sb);
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

    // ed25519
    {
        auto check_ed25519 = [](bytes_concept priv, auto &&in_pubk, auto &&msg, auto &&in_sig) {
            ed25519 ed;
            ed.private_key_ = priv;
            auto pubk = ed.public_key();
            cmp_bytes(pubk, in_pubk);
            auto sig = ed.sign(msg);
            cmp_bytes(sig, in_sig);
            cmp_base(ed.verify(pubk, msg, sig), true);
        };
        check_ed25519(R"(
   9d61b19deffd5a60ba844af492ec2cc4
   4449c5697b326919703bac031cae7f60
)"_sb, R"(
   d75a980182b10ab7d54bfed3c964073a
   0ee172f3daa62325af021a68f707511a
)"_sb, ""sv, R"(
   e5564300c360ac729086e2cc806e828a
   84877f1eb8e5d974d873e06522490155
   5fb8821590a33bacc61e39701cf9b46b
   d25bf5f0595bbe24655141438e7a100b
)"_sb);
        check_ed25519(R"(
   4ccd089b28ff96da9db6c346ec114e0f
   5b8a319f35aba624da8cf6ed4fb8a6fb
)"_sb, R"(
   3d4017c3e843895a92b70aa74d1b7ebc
   9c982ccf2ec4968cc0cd55f12af4660c
)"_sb, "72"_sb, R"(
   92a009a9f0d4cab8720e820b5f642540
   a2b27b5416503f8fb3762223ebdb69da
   085ac1e43e15996e458f3613d0f11d8c
   387b2eaeb4302aeeb00d291612bb0c00
)"_sb);
        check_ed25519(R"(
   c5aa8df43f9f837bedb7442f31dcb7b1
   66d38535076f094b85ce3a2e0b4458f7
)"_sb, R"(
   fc51cd8e6218a1a38da47ed00230f058
   0816ed13ba3303ac5deb911548908025
)"_sb, "af82"_sb, R"(
   6291d657deec24024827e69c3abe01a3
   0ce548a284743a445e3680d7db5ac3ac
   18ff9b538d16f290ae67f760984dc659
   4a7c15e9716ed28dc027beceea1ec40a
)"_sb);
        check_ed25519(R"(
   f5e5767cf153319517630f226876b86c
   8160cc583bc013744c6bf255f5cc0ee5
)"_sb, R"(
   278117fc144c72340f67d0f2316e8386
   ceffbf2b2428c9c51fef7c597f1d426e
)"_sb,
    R"(
   08b8b2b733424243760fe426a4b54908
   632110a66c2f6591eabd3345e3e4eb98
   fa6e264bf09efe12ee50f8f54e9f77b1
   e355f6c50544e23fb1433ddf73be84d8
   79de7c0046dc4996d9e773f4bc9efe57
   38829adb26c81b37c93a1b270b20329d
   658675fc6ea534e0810a4432826bf58c
   941efb65d57a338bbd2e26640f89ffbc
   1a858efcb8550ee3a5e1998bd177e93a
   7363c344fe6b199ee5d02e82d522c4fe
   ba15452f80288a821a579116ec6dad2b
   3b310da903401aa62100ab5d1a36553e
   06203b33890cc9b832f79ef80560ccb9
   a39ce767967ed628c6ad573cb116dbef
   efd75499da96bd68a8a97b928a8bbc10
   3b6621fcde2beca1231d206be6cd9ec7
   aff6f6c94fcd7204ed3455c68c83f4a4
   1da4af2b74ef5c53f1d8ac70bdcb7ed1
   85ce81bd84359d44254d95629e9855a9
   4a7c1958d1f8ada5d0532ed8a5aa3fb2
   d17ba70eb6248e594e1a2297acbbb39d
   502f1a8c6eb6f1ce22b3de1a1f40cc24
   554119a831a9aad6079cad88425de6bd
   e1a9187ebb6092cf67bf2b13fd65f270
   88d78b7e883c8759d2c4f5c65adb7553
   878ad575f9fad878e80a0c9ba63bcbcc
   2732e69485bbc9c90bfbd62481d9089b
   eccf80cfe2df16a2cf65bd92dd597b07
   07e0917af48bbb75fed413d238f5555a
   7a569d80c3414a8d0859dc65a46128ba
   b27af87a71314f318c782b23ebfe808b
   82b0ce26401d2e22f04d83d1255dc51a
   ddd3b75a2b1ae0784504df543af8969b
   e3ea7082ff7fc9888c144da2af58429e
   c96031dbcad3dad9af0dcbaaaf268cb8
   fcffead94f3c7ca495e056a9b47acdb7
   51fb73e666c6c655ade8297297d07ad1
   ba5e43f1bca32301651339e22904cc8c
   42f58c30c04aafdb038dda0847dd988d
   cda6f3bfd15c4b4c4525004aa06eeff8
   ca61783aacec57fb3d1f92b0fe2fd1a8
   5f6724517b65e614ad6808d6f6ee34df
   f7310fdc82aebfd904b01e1dc54b2927
   094b2db68d6f903b68401adebf5a7e08
   d78ff4ef5d63653a65040cf9bfd4aca7
   984a74d37145986780fc0b16ac451649
   de6188a7dbdf191f64b5fc5e2ab47b57
   f7f7276cd419c17a3ca8e1b939ae49e4
   88acba6b965610b5480109c8b17b80e1
   b7b750dfc7598d5d5011fd2dcc5600a3
   2ef5b52a1ecc820e308aa342721aac09
   43bf6686b64b2579376504ccc493d97e
   6aed3fb0f9cd71a43dd497f01f17c0e2
   cb3797aa2a2f256656168e6c496afc5f
   b93246f6b1116398a346f1a641f3b041
   e989f7914f90cc2c7fff357876e506b5
   0d334ba77c225bc307ba537152f3f161
   0e4eafe595f6d9d90d11faa933a15ef1
   369546868a7f3a45a96768d40fd9d034
   12c091c6315cf4fde7cb68606937380d
   b2eaaa707b4c4185c32eddcdd306705e
   4dc1ffc872eeee475a64dfac86aba41c
   0618983f8741c5ef68d3a101e8a3b8ca
   c60c905c15fc910840b94c00a0b9d0
)"_sb, R"(
   0aab4c900501b3e24d7cdf4663326a3a
   87df5e4843b2cbdb67cbf6e460fec350
   aa5371b1508f9f4528ecea23c436d94b
   5e8fcd4f681e30a6ac00a9704a188a03
)"_sb);
        check_ed25519(R"(
   833fe62409237b9d62ec77587520911e
   9a759cec1d19755b7da901b96dca3d42
)"_sb, R"(
   ec172b93ad5e563bf4932c70e1245034
   c35467ef2efd4d64ebf819683467e2bf
)"_sb, sha512::digest("abc"sv), R"(
   dc2a4459e7369633a52b1bf277839a00
   201009a3efbf3ecb69bea2186c26b589
   09351fc9ac90b3ecfdfbc7c66431e030
   3dca179c138ac17ad9bef1177331a704
)"_sb);

        auto check_ed25519_ctx = [](bytes_concept priv, auto &&in_pubk, auto &&msg, auto &&ctx, auto &&in_sig) {
            ed25519 ed;
            ed.private_key_ = priv;
            auto pubk = ed.public_key();
            cmp_bytes(pubk, in_pubk);
            auto sig = ed.sign(msg, ctx);
            cmp_bytes(sig, in_sig);
            cmp_base(ed.verify(pubk, msg, ctx, sig), true);
        };
        auto check_ed25519_ctx1 = [&](auto &&msg, auto &&ctx, auto &&in_sig) {
            check_ed25519_ctx(R"(
   0305334e381af78f141cb666f6199f57
   bc3495335a256a95bd2a55bf546663f6
)"_sb, R"(
   dfc9425e4f968f7f0c29f0259cf5f9ae
   d6851c2bb4ad8bfb860cfee0ab248292
)"_sb, msg, ctx, in_sig);
        };
        check_ed25519_ctx1(
            "f726936d19c800494e3fdaff20b276a8"_sb, "foo"sv, R"(
   55a4cc2f70a54e04288c5f4cd1e45a7b
   b520b36292911876cada7323198dd87a
   8b36950b95130022907a7fb7c4e9b2d5
   f6cca685a587b4b21f4b888e4e7edb0d
)"_sb);
        check_ed25519_ctx1(
            "f726936d19c800494e3fdaff20b276a8"_sb, "bar"sv, R"(
   fc60d5872fc46b3aa69f8b5b4351d580
   8f92bcc044606db097abab6dbcb1aee3
   216c48e8b3b66431b5b186d1d28f8ee1
   5a5ca2df6668346291c2043d4eb3e90d
)"_sb);
        check_ed25519_ctx1(
            "508e9e6882b979fea900f62adceaca35"_sb, "foo"sv, R"(
   8b70c1cc8310e1de20ac53ce28ae6e72
   07f33c3295e03bb5c0732a1d20dc6490
   8922a8b052cf99b7c4fe107a5abb5b2c
   4085ae75890d02df26269d8945f84b0b
)"_sb);
        check_ed25519_ctx(R"(
   ab9c2853ce297ddab85c993b3ae14bca
   d39b2c682beabc27d6d4eb20711d6560
)"_sb, R"(
   0f1d1274943b91415889152e893d80e9
   3275a1fc0b65fd71b4b0dda10ad7d772
)"_sb, "f726936d19c800494e3fdaff20b276a8"_sb, "foo"sv, R"(
   21655b5f1aa965996b3f97b3c849eafb
   a922a0a62992f73b3d1b73106a84ad85
   e9b86a7b6005ea868337ff2d20a7f5fb
   d4cd10b0be49a68da2b2e0dc0ad8960f
)"_sb);

        auto check_ed25519_ctx_ph = [](bytes_concept priv, auto &&in_pubk, auto &&msg, auto &&ctx, auto &&in_sig) {
            ed25519 ed;
            ed.private_key_ = priv;
            auto pubk = ed.public_key();
            cmp_bytes(pubk, in_pubk);
            auto sig = ed.sign_ph(msg, ctx);
            cmp_bytes(sig, in_sig);
            cmp_base(ed.verify_ph(pubk, msg, ctx, sig), true);
        };
        check_ed25519_ctx_ph(R"(
   833fe62409237b9d62ec77587520911e
   9a759cec1d19755b7da901b96dca3d42
)"_sb, R"(
   ec172b93ad5e563bf4932c70e1245034
   c35467ef2efd4d64ebf819683467e2bf
)"_sb, "abc"sv, ""sv, R"(
   98a70222f0b8121aa9d30f813d683f80
   9e462b469c7ff87639499bb94e6dae41
   31f85042463c2a355a2003d062adf5aa
   a10b8c61e636062aaad11c2a26083406
)"_sb);
    }

    // ed448
    {
        auto check_ed448 = [](bytes_concept priv, auto &&in_pubk, auto &&msg, auto &&in_sig) {
            ed448 ed;
            ed.private_key_ = priv;
            auto pubk = ed.public_key();
            cmp_bytes(pubk, in_pubk);
            auto sig = ed.sign(msg);
            cmp_bytes(sig, in_sig);
            cmp_base(ed.verify(pubk, msg, sig), true);
        };
        check_ed448(R"(
   6c82a562cb808d10d632be89c8513ebf
   6c929f34ddfa8c9f63c9960ef6e348a3
   528c8a3fcc2f044e39a3fc5b94492f8f
   032e7549a20098f95b
)"_sb, R"(
   5fd7449b59b461fd2ce787ec616ad46a
   1da1342485a70e1f8a0ea75d80e96778
   edf124769b46c7061bd6783df1e50f6c
   d1fa1abeafe8256180
)"_sb, ""sv, R"(
   533a37f6bbe457251f023c0d88f976ae
   2dfb504a843e34d2074fd823d41a591f
   2b233f034f628281f2fd7a22ddd47d78
   28c59bd0a21bfd3980ff0d2028d4b18a
   9df63e006c5d1c2d345b925d8dc00b41
   04852db99ac5c7cdda8530a113a0f4db
   b61149f05a7363268c71d95808ff2e65
   2600
)"_sb);
        check_ed448(R"(
   c4eab05d357007c632f3dbb48489924d
   552b08fe0c353a0d4a1f00acda2c463a
   fbea67c5e8d2877c5e3bc397a659949e
   f8021e954e0a12274e
)"_sb, R"(
   43ba28f430cdff456ae531545f7ecd0a
   c834a55d9358c0372bfa0c6c6798c086
   6aea01eb00742802b8438ea4cb82169c
   235160627b4c3a9480
)"_sb, "03"_sb, R"(
   26b8f91727bd62897af15e41eb43c377
   efb9c610d48f2335cb0bd0087810f435
   2541b143c4b981b7e18f62de8ccdf633
   fc1bf037ab7cd779805e0dbcc0aae1cb
   cee1afb2e027df36bc04dcecbf154336
   c19f0af7e0a6472905e799f1953d2a0f
   f3348ab21aa4adafd1d234441cf807c0
   3a00
)"_sb);
        auto check_ed448_ctx = [](bytes_concept priv, auto &&in_pubk, auto &&msg, auto &&ctx, auto &&in_sig) {
            ed448 ed;
            ed.private_key_ = priv;
            auto pubk = ed.public_key();
            cmp_bytes(pubk, in_pubk);
            auto sig = ed.sign(msg, ctx);
            cmp_bytes(sig, in_sig);
            cmp_base(ed.verify(pubk, msg, ctx, sig), true);
        };
        check_ed448_ctx(R"(
   c4eab05d357007c632f3dbb48489924d
   552b08fe0c353a0d4a1f00acda2c463a
   fbea67c5e8d2877c5e3bc397a659949e
   f8021e954e0a12274e
)"_sb, R"(
   43ba28f430cdff456ae531545f7ecd0a
   c834a55d9358c0372bfa0c6c6798c086
   6aea01eb00742802b8438ea4cb82169c
   235160627b4c3a9480
)"_sb, "03"_sb, "foo"sv, R"(
   d4f8f6131770dd46f40867d6fd5d5055
   de43541f8c5e35abbcd001b32a89f7d2
   151f7647f11d8ca2ae279fb842d60721
   7fce6e042f6815ea000c85741de5c8da
   1144a6a1aba7f96de42505d7a7298524
   fda538fccbbb754f578c1cad10d54d0d
   5428407e85dcbc98a49155c13764e66c
   3c00
)"_sb);
        //
        check_ed448(R"(
   cd23d24f714274e744343237b93290f5
   11f6425f98e64459ff203e8985083ffd
   f60500553abc0e05cd02184bdb89c4cc
   d67e187951267eb328
)"_sb, R"(
   dcea9e78f35a1bf3499a831b10b86c90
   aac01cd84b67a0109b55a36e9328b1e3
   65fce161d71ce7131a543ea4cb5f7e9f
   1d8b00696447001400
)"_sb, "0c3e544074ec63b0265e0c"_sb, R"(
   1f0a8888ce25e8d458a21130879b840a
   9089d999aaba039eaf3e3afa090a09d3
   89dba82c4ff2ae8ac5cdfb7c55e94d5d
   961a29fe0109941e00b8dbdeea6d3b05
   1068df7254c0cdc129cbe62db2dc957d
   bb47b51fd3f213fb8698f064774250a5
   028961c9bf8ffd973fe5d5c206492b14
   0e00
)"_sb);
        check_ed448(R"(
   258cdd4ada32ed9c9ff54e63756ae582
   fb8fab2ac721f2c8e676a72768513d93
   9f63dddb55609133f29adf86ec9929dc
   cb52c1c5fd2ff7e21b
)"_sb, R"(
   3ba16da0c6f2cc1f30187740756f5e79
   8d6bc5fc015d7c63cc9510ee3fd44adc
   24d8e968b6e46e6f94d19b945361726b
   d75e149ef09817f580
)"_sb, "64a65f3cdedcdd66811e2915"_sb, R"(
   7eeeab7c4e50fb799b418ee5e3197ff6
   bf15d43a14c34389b59dd1a7b1b85b4a
   e90438aca634bea45e3a2695f1270f07
   fdcdf7c62b8efeaf00b45c2c96ba457e
   b1a8bf075a3db28e5c24f6b923ed4ad7
   47c3c9e03c7079efb87cb110d3a99861
   e72003cbae6d6b8b827e4e6c143064ff
   3c00
)"_sb);
        check_ed448(R"(
   7ef4e84544236752fbb56b8f31a23a10
   e42814f5f55ca037cdcc11c64c9a3b29
   49c1bb60700314611732a6c2fea98eeb
   c0266a11a93970100e
)"_sb, R"(
   b3da079b0aa493a5772029f0467baebe
   e5a8112d9d3a22532361da294f7bb381
   5c5dc59e176b4d9f381ca0938e13c6c0
   7b174be65dfa578e80
)"_sb, "64a65f3cdedcdd66811e2915e7"_sb, R"(
   6a12066f55331b6c22acd5d5bfc5d712
   28fbda80ae8dec26bdd306743c5027cb
   4890810c162c027468675ecf645a8317
   6c0d7323a2ccde2d80efe5a1268e8aca
   1d6fbc194d3f77c44986eb4ab4177919
   ad8bec33eb47bbb5fc6e28196fd1caf5
   6b4e7e0ba5519234d047155ac727a105
   3100
)"_sb);
        check_ed448(R"(
   d65df341ad13e008567688baedda8e9d
   cdc17dc024974ea5b4227b6530e339bf
   f21f99e68ca6968f3cca6dfe0fb9f4fa
   b4fa135d5542ea3f01
)"_sb, R"(
   df9705f58edbab802c7f8363cfe5560a
   b1c6132c20a9f1dd163483a26f8ac53a
   39d6808bf4a1dfbd261b099bb03b3fb5
   0906cb28bd8a081f00
)"_sb, R"(
   bd0f6a3747cd561bdddf4640a332461a
   4a30a12a434cd0bf40d766d9c6d458e5
   512204a30c17d1f50b5079631f64eb31
   12182da3005835461113718d1a5ef944
)"_sb, R"(
   554bc2480860b49eab8532d2a533b7d5
   78ef473eeb58c98bb2d0e1ce488a98b1
   8dfde9b9b90775e67f47d4a1c3482058
   efc9f40d2ca033a0801b63d45b3b722e
   f552bad3b4ccb667da350192b61c508c
   f7b6b5adadc2c8d9a446ef003fb05cba
   5f30e88e36ec2703b349ca229c267083
   3900
)"_sb);
        check_ed448(R"(
   2ec5fe3c17045abdb136a5e6a913e32a
   b75ae68b53d2fc149b77e504132d3756
   9b7e766ba74a19bd6162343a21c8590a
   a9cebca9014c636df5
)"_sb, R"(
   79756f014dcfe2079f5dd9e718be4171
   e2ef2486a08f25186f6bff43a9936b9b
   fe12402b08ae65798a3d81e22e9ec80e
   7690862ef3d4ed3a00
)"_sb, R"(
   15777532b0bdd0d1389f636c5f6b9ba7
   34c90af572877e2d272dd078aa1e567c
   fa80e12928bb542330e8409f31745041
   07ecd5efac61ae7504dabe2a602ede89
   e5cca6257a7c77e27a702b3ae39fc769
   fc54f2395ae6a1178cab4738e543072f
   c1c177fe71e92e25bf03e4ecb72f47b6
   4d0465aaea4c7fad372536c8ba516a60
   39c3c2a39f0e4d832be432dfa9a706a6
   e5c7e19f397964ca4258002f7c0541b5
   90316dbc5622b6b2a6fe7a4abffd9610
   5eca76ea7b98816af0748c10df048ce0
   12d901015a51f189f3888145c03650aa
   23ce894c3bd889e030d565071c59f409
   a9981b51878fd6fc110624dcbcde0bf7
   a69ccce38fabdf86f3bef6044819de11
)"_sb, R"(
   c650ddbb0601c19ca11439e1640dd931
   f43c518ea5bea70d3dcde5f4191fe53f
   00cf966546b72bcc7d58be2b9badef28
   743954e3a44a23f880e8d4f1cfce2d7a
   61452d26da05896f0a50da66a239a8a1
   88b6d825b3305ad77b73fbac0836ecc6
   0987fd08527c1a8e80d5823e65cafe2a
   3d00
)"_sb);
        check_ed448(R"(
   872d093780f5d3730df7c212664b37b8
   a0f24f56810daa8382cd4fa3f77634ec
   44dc54f1c2ed9bea86fafb7632d8be19
   9ea165f5ad55dd9ce8
)"_sb, R"(
   a81b2e8a70a5ac94ffdbcc9badfc3feb
   0801f258578bb114ad44ece1ec0e799d
   a08effb81c5d685c0c56f64eecaef8cd
   f11cc38737838cf400
)"_sb, R"(
   6ddf802e1aae4986935f7f981ba3f035
   1d6273c0a0c22c9c0e8339168e675412
   a3debfaf435ed651558007db4384b650
   fcc07e3b586a27a4f7a00ac8a6fec2cd
   86ae4bf1570c41e6a40c931db27b2faa
   15a8cedd52cff7362c4e6e23daec0fbc
   3a79b6806e316efcc7b68119bf46bc76
   a26067a53f296dafdbdc11c77f7777e9
   72660cf4b6a9b369a6665f02e0cc9b6e
   dfad136b4fabe723d2813db3136cfde9
   b6d044322fee2947952e031b73ab5c60
   3349b307bdc27bc6cb8b8bbd7bd32321
   9b8033a581b59eadebb09b3c4f3d2277
   d4f0343624acc817804728b25ab79717
   2b4c5c21a22f9c7839d64300232eb66e
   53f31c723fa37fe387c7d3e50bdf9813
   a30e5bb12cf4cd930c40cfb4e1fc6225
   92a49588794494d56d24ea4b40c89fc0
   596cc9ebb961c8cb10adde976a5d602b
   1c3f85b9b9a001ed3c6a4d3b1437f520
   96cd1956d042a597d561a596ecd3d173
   5a8d570ea0ec27225a2c4aaff26306d1
   526c1af3ca6d9cf5a2c98f47e1c46db9
   a33234cfd4d81f2c98538a09ebe76998
   d0d8fd25997c7d255c6d66ece6fa56f1
   1144950f027795e653008f4bd7ca2dee
   85d8e90f3dc315130ce2a00375a318c7
   c3d97be2c8ce5b6db41a6254ff264fa6
   155baee3b0773c0f497c573f19bb4f42
   40281f0b1f4f7be857a4e59d416c06b4
   c50fa09e1810ddc6b1467baeac5a3668
   d11b6ecaa901440016f389f80acc4db9
   77025e7f5924388c7e340a732e554440
   e76570f8dd71b7d640b3450d1fd5f041
   0a18f9a3494f707c717b79b4bf75c984
   00b096b21653b5d217cf3565c9597456
   f70703497a078763829bc01bb1cbc8fa
   04eadc9a6e3f6699587a9e75c94e5bab
   0036e0b2e711392cff0047d0d6b05bd2
   a588bc109718954259f1d86678a579a3
   120f19cfb2963f177aeb70f2d4844826
   262e51b80271272068ef5b3856fa8535
   aa2a88b2d41f2a0e2fda7624c2850272
   ac4a2f561f8f2f7a318bfd5caf969614
   9e4ac824ad3460538fdc25421beec2cc
   6818162d06bbed0c40a387192349db67
   a118bada6cd5ab0140ee273204f628aa
   d1c135f770279a651e24d8c14d75a605
   9d76b96a6fd857def5e0b354b27ab937
   a5815d16b5fae407ff18222c6d1ed263
   be68c95f32d908bd895cd76207ae7264
   87567f9a67dad79abec316f683b17f2d
   02bf07e0ac8b5bc6162cf94697b3c27c
   d1fea49b27f23ba2901871962506520c
   392da8b6ad0d99f7013fbc06c2c17a56
   9500c8a7696481c1cd33e9b14e40b82e
   79a5f5db82571ba97bae3ad3e0479515
   bb0e2b0f3bfcd1fd33034efc6245eddd
   7ee2086ddae2600d8ca73e214e8c2b0b
   db2b047c6a464a562ed77b73d2d841c4
   b34973551257713b753632efba348169
   abc90a68f42611a40126d7cb21b58695
   568186f7e569d2ff0f9e745d0487dd2e
   b997cafc5abf9dd102e62ff66cba87
)"_sb, R"(
   e301345a41a39a4d72fff8df69c98075
   a0cc082b802fc9b2b6bc503f926b65bd
   df7f4c8f1cb49f6396afc8a70abe6d8a
   ef0db478d4c6b2970076c6a0484fe76d
   76b3a97625d79f1ce240e7c576750d29
   5528286f719b413de9ada3e8eb78ed57
   3603ce30d8bb761785dc30dbc320869e
   1a00
)"_sb);
        auto check_ed448_ctx_ph = [](bytes_concept priv, auto &&in_pubk, auto &&msg, auto &&ctx, auto &&in_sig) {
            ed448 ed;
            ed.private_key_ = priv;
            auto pubk = ed.public_key();
            cmp_bytes(pubk, in_pubk);
            auto sig = ed.sign_ph(msg, ctx);
            cmp_bytes(sig, in_sig);
            cmp_base(ed.verify_ph(pubk, msg, ctx, sig), true);
        };
        check_ed448_ctx_ph(R"(
   833fe62409237b9d62ec77587520911e
   9a759cec1d19755b7da901b96dca3d42
   ef7822e0d5104127dc05d6dbefde69e3
   ab2cec7c867c6e2c49
)"_sb, R"(
   259b71c19f83ef77a7abd26524cbdb31
   61b590a48f7d17de3ee0ba9c52beb743
   c09428a131d6b1b57303d90d8132c276
   d5ed3d5d01c0f53880
)"_sb, "abc"sv, ""sv, R"(
   822f6901f7480f3d5f562c592994d969
   3602875614483256505600bbc281ae38
   1f54d6bce2ea911574932f52a4e6cadd
   78769375ec3ffd1b801a0d9b3f4030cd
   433964b6457ea39476511214f97469b5
   7dd32dbc560a9a94d00bff07620464a3
   ad203df7dc7ce360c3cd3696d9d9fab9
   0f00
)"_sb);
        check_ed448_ctx_ph(R"(
   833fe62409237b9d62ec77587520911e
   9a759cec1d19755b7da901b96dca3d42
   ef7822e0d5104127dc05d6dbefde69e3
   ab2cec7c867c6e2c49
)"_sb, R"(
   259b71c19f83ef77a7abd26524cbdb31
   61b590a48f7d17de3ee0ba9c52beb743
   c09428a131d6b1b57303d90d8132c276
   d5ed3d5d01c0f53880
)"_sb, "abc"sv, "foo"sv, R"(
   c32299d46ec8ff02b54540982814dce9
   a05812f81962b649d528095916a2aa48
   1065b1580423ef927ecf0af5888f90da
   0f6a9a85ad5dc3f280d91224ba9911a3
   653d00e484e2ce232521481c8658df30
   4bb7745a73514cdb9bf3e15784ab7128
   4f8d0704a608c54a6b62d97beb511d13
   2100
)"_sb);
    }

    // sign & verify
    // rfc6979
    {
        const auto message1 = "sample"s;
        const auto message2 = "test"s;

        auto check = [](auto c_in, auto hash, auto &&msg, auto &&pk, auto &&r_in, auto &&s_in) {
            auto h = decltype(hash)::digest(msg);

            decltype(c_in) c{bytes_concept{pk}};
            auto pubkey = c.public_key();

            auto [r, s] = c.template sign_deterministic<decltype(hash)>(h);
            cmp_bytes(r, r_in);
            cmp_bytes(s, s_in);

            cmp_base(c.verify(h, bytes_concept{&pubkey, sizeof(pubkey)}, r, s), true);
        };

        {
            // curve K-163 ansit163k1
            bitlen qlen{163};
            bigint q{"0x4000000000000000000020108A2E0CC0D99F8A5EF"};
            auto h1 = sha256::digest(message1);
            auto hs = ec::prepare_hash_for_signature(h1, q, qlen);
            hmac_drbg<sha256> d{expand_bytes("9A 4D 67 92 29 5A 7F 73 0F C3 F2 B4 9C BC 0F 62 E8 62 27 2F"_sb, qlen), hs, {}};
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
            // auto h = sha256::digest(message1);
            // bigint hb = bytes_to_bigint(h);
            // if (hb > q) {
            //     hb = hb - q;
            // }
            // auto hh = hb.to_string();
            // hmac_drbg<sha256> d{"00 9A 4D 67 92 29 5A 7F 73 0F C3 F2 B4 9C BC 0F 62 E8 62 27 2F"_sb, hh, {}};
            // d.digest();
            // auto h = sha256::digest(message1);
            // std::string hs(h.begin(), h.end());
            // take_left_bits(hs, qlen);
            // cmp_bytes(hs,
            //     "00 9A 4D 67 92 29 5A 7F 73 0F C3 F2 B4 9C BC 0F 62 E8 62 27 2F"_sb
            //);
        }

        auto check_big = [&](auto c, auto &&msg, auto &&pk, auto &&rs) {
            int i{};
            auto f = [&](auto h) {
                if (rs.size() <= i) {
                    return;
                }
                check(c, h, msg, pk, rs[i + 0], rs[i + 1]);
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
                      "61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32"_sb,
                      "6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB"_sb,
                      "53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F"_sb,
                      "B9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C"_sb,
                      "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"_sb,
                      "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"_sb,
                      "0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719"_sb,
                      "4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954"_sb,
                      "8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00"_sb,
                      "2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE"_sb,
                  });
        check_big(ec::secp384r1{}, message1, "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5"_sb,
                  std::vector{
                      "EC748D839243D6FBEF4FC5C4859A7DFFD7F3ABDDF72014540C16D73309834FA37B9BA002899F6FDA3A4A9386790D4EB2"_sb,
                      "A3BCFA947BEEF4732BF247AC17F71676CB31A847B9FF0CBC9C9ED4C1A5B3FACF26F49CA031D4857570CCB5CA4424A443"_sb,
                      "42356E76B55A6D9B4631C865445DBE54E056D3B3431766D0509244793C3F9366450F76EE3DE43F5A125333A6BE060122"_sb,
                      "9DA0C81787064021E78DF658F2FBB0B042BF304665DB721F077A4298B095E4834C082C03D83028EFBF93A3C23940CA8D"_sb,
                      "21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD"_sb,
                      "F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0"_sb,
                      "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46"_sb,
                      "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8"_sb,
                      "ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799CFE30F35CC900056D7C99CD7882433709"_sb,
                      "512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112DC7CC3EF3446DEFCEB01A45C2667FDD5"_sb,
                  });
        check_big(ec::secp521r1{}, message1,
                  "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"_sb,
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
                  });

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
                  });
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
                  });
        check_big(ec::secp521r1{}, message2,
                  "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"_sb,
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
                  });
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

    f(sha1{}, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"s, "84997448f7991149b3e28fbe31314836e7cbb0cd"s);
    f(sha2<256>{}, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"s, "05ef8d2632d4140db730878ffb03a0bd9b32de06fb74df0471bde777cba1eff7"s);
    f(sha2<512>{}, "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"s,
      "ed9bb695a3ccfe82fea7055e79fad7d225f5cc9c9b7b1808fc7121237a47903f59d8fad228c5710c487541db2bbecb09891b96b87c8718759ca4aa302cc72598"s);
    f(sha3<256>{}, "8c6e0683409427f8931711b10ca92a506eb1fafa48fadd66d76126f47ac2c333"s, "e2f178144221853d60f7e9ddaf13ea57c6bddd54d9bd18b175fc59278f491a63"s);
}

void test_hkdf() {
    LOG_TEST();

    using namespace crypto;

    {
        auto ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"_sb;
        auto salt = "000102030405060708090a0b0c"_sb;
        auto info = "f0f1f2f3f4f5f6f7f8f9"_sb;
        auto prk = hkdf<sha256>::extract(salt, ikm);
        auto okm = hkdf<sha256>::expand<42>(prk, info);
        cmp_bytes(prk, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"_sb);
        cmp_bytes(okm, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"_sb);
    }
    {
        auto ikm = R"(
000102030405060708090a0b0c0d0e0f
101112131415161718191a1b1c1d1e1f
202122232425262728292a2b2c2d2e2f
303132333435363738393a3b3c3d3e3f
404142434445464748494a4b4c4d4e4f
)"_sb;
        auto salt = R"(
606162636465666768696a6b6c6d6e6f
707172737475767778797a7b7c7d7e7f
808182838485868788898a8b8c8d8e8f
909192939495969798999a9b9c9d9e9f
a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
)"_sb;
        auto info = R"(
b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
e0e1e2e3e4e5e6e7e8e9eaebecedeeef
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
)"_sb;
        {
            auto prk = hkdf<sha256>::extract(salt, ikm);
            auto okm = hkdf<sha256>::expand<82>(prk, info);
            cmp_bytes(prk, "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"_sb);
            cmp_bytes(okm, R"(
b11e398dc80327a1c8e7f78c596a4934
4f012eda2d4efad8a050cc4c19afa97c
59045a99cac7827271cb41c65e590e09
da3275600c2f09b8367793a9aca3db71
cc30c58179ec3e87c14c01d5c1f3434f
1d87
)"_sb);
        }
        {
            auto prk = hkdf<sha1>::extract(salt, ikm);
            auto okm = hkdf<sha1>::expand<82>(prk, info);
            cmp_bytes(prk, "8adae09a2a307059478d309b26c4115a224cfaf6"_sb);
            cmp_bytes(okm, R"(
0bd770a74d1160f7c9f12cd5912a06eb
ff6adcae899d92191fe4305673ba2ffe
8fa3f1a4e5ad79f3f334b3b202b2173c
486ea37ce3d397ed034c7f9dfeb15c5e
927336d0441f4c4300e2cff0d0900b52
d3b4
)"_sb);
        }
    }
    {
        auto ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"_sb;
        auto salt = ""_sb;
        auto info = ""_sb;
        {
            auto prk = hkdf<sha256>::extract(salt, ikm);
            auto okm = hkdf<sha256>::expand<42>(prk, info);
            cmp_bytes(prk, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"_sb);
            cmp_bytes(okm, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"_sb);
        }
        {
            auto prk = hkdf<sha1>::extract(salt, ikm);
            auto okm = hkdf<sha1>::expand<42>(prk, info);
            cmp_bytes(prk, "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01"_sb);
            cmp_bytes(okm, "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918"_sb);
        }
    }
    {
        auto ikm = "0b0b0b0b0b0b0b0b0b0b0b"_sb;
        auto salt = "000102030405060708090a0b0c"_sb;
        auto info = "f0f1f2f3f4f5f6f7f8f9"_sb;
        auto prk = hkdf<sha1>::extract(salt, ikm);
        auto okm = hkdf<sha1>::expand<42>(prk, info);
        cmp_bytes(prk, "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243"_sb);
        cmp_bytes(okm, "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"_sb);
    }
    {
        auto ikm = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"_sb;
        auto info = ""_sb;
        auto prk = hkdf<sha1>::extract(ikm);
        auto okm = hkdf<sha1>::expand<42>(prk, info);
        cmp_bytes(prk, "2adccada18779e7c2077ad2eb19d3f3e731385dd"_sb);
        cmp_bytes(okm, "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48"_sb);
    }
}

void test_pbkdf2() {
    LOG_TEST();

    using namespace crypto;

    auto pass = "123"s;
    auto salt = "0"s;

    auto cmp = [](auto &&x, auto &&y) {
        return cmp_bytes(x, y);
    };

    cmp(pbkdf2<sha256>(pass, salt, 1000, 1), "4f"_sb);
    cmp(pbkdf2<sha256>(pass, salt, 1000, 2), "4ff5"_sb);
    cmp(pbkdf2<sha256>(pass, salt, 1000, 33), "4ff53b205602ea576b8a6bd69fb594a0a98a91299f14810092a23d925decca4208"_sb);
    cmp(pbkdf2<sha256>(pass, salt, 1000, 34), "4ff53b205602ea576b8a6bd69fb594a0a98a91299f14810092a23d925decca420882"_sb);
    cmp(pbkdf2<sha256>(pass, salt, 1000), "4ff53b205602ea576b8a6bd69fb594a0a98a91299f14810092a23d925decca42"_sb);
    cmp(pbkdf2<sha256>(pass, salt, 1000, 64),
        "4ff53b205602ea576b8a6bd69fb594a0a98a91299f14810092a23d925decca420882b3fc2a7336de94bcb473ea3d3e3155b8657bc512f349cb6141c116edda9d"_sb);
    cmp(pbkdf2<sha2<512>>(pass, salt, 1000),
        "2e18d9ea31a4e2c02321ea3f05a143f3b1b9952a947905a7393a7ba37e1150d01a0130b2754cc30427ade14fccf09b43b5a842f6898638c558e4487c84c8249a"_sb);
    cmp(pbkdf2<sha2<224>>(pass, salt, 1000), "e4e398e3022aa476b04abafc41b1725a00b4fec831ac4602269c758e"_sb);
    cmp(pbkdf2<sha2<384>>(pass, salt, 1000), "6bec9cbb3d01f590f321835e273a2f38f2778676a9e2b925bbdc3183132eadaad551cb9e1087666c2d13a1596ee61f61"_sb);

    cmp(pbkdf2<sha2<512>>(pass, salt, 999),
        "3b90da3da8c6180af0717d31f618e4572af386108afef6ec31c71be4298c38693153489141454ef0f2b4e794ee7b4ed2d9873bfbc3696e5f8acf384cfd0f7428"_sb);
    cmp(pbkdf2<sha256>(pass, salt, 1), "7426ee6b7a29c894a4b6953c8ed5df1a73e809de6a3f1e22e3379f95dce75a33"_sb);

    cmp(pbkdf2<sha1>(pass, salt, 1), "aea972ef0d1b000f8e379a2627d4e76ab3741c72"_sb);
    cmp(pbkdf2<sha1>(pass, salt, 998), "3ffed4bae693ca5c3fbf8eddb6977a6013467168"_sb);

    // collision, should be the same
    cmp(pbkdf2<sha1>("plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd"s, "A009C1A485912C6AE630D3E744240B04"_sb, 1000, 16),
        pbkdf2<sha1>("eBkXQTfuBqp'cTcar&g*"s, "A009C1A485912C6AE630D3E744240B04"_sb, 1000, 16));

    cmp(pbkdf2<sha3<256>>("password"s, "salt"s, 4096), "778b6e237a0f49621549ff70d218d2080756b9fb38d71b5d7ef447fa2254af61"_sb);

    cmp(pbkdf2<sha3<256>>(pass, salt, 1), "c6c9bd558a9bc83a1d585e430194fcb6ae24a463082e7a61369e9213303fd450"_sb);
    cmp(pbkdf2<sha3<512>>(pass, salt, 1000),
        "34cbcad0f754e6f95f1a11fa5bc24da5378a1dda9fd94961c7413644d22a8ab083837fe831c48128a89ac63840ca11967121a08a83d92f21ed1347615c68ce85"_sb);
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

    // scoped_timer st;

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
        scryptBlockMix(in.data(), (uint8_t *)out, 1);

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
        // return scrypt2()(args...);
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
            // scoped_timer t;
            cmp_bytes(scr("pleaseletmein"s, "SodiumChloride"s, 1048576, 8, 1, 64), R"(
           21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81
           ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47
           8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3
           37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4
            )"_sb);
        }
        {
            // scoped_timer t;
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
        argon2 a{.password = pass, .salt = salt, .key = key, .associated_data = associated_data, .taglen = 32, .p = 4, .m = 32, .t = 3, .y = argon2::argon2d};
        cmp_bytes(a(), R"(
            51 2b 39 1b 6f 11 62 97
            53 71 d3 09 19 73 42 94
            f8 68 e3 be 39 84 f3 c1
            a1 3a 4d b9 fa be 4a cb
    )"_sb);
    }
    {
        argon2 a{.password = pass, .salt = salt, .key = key, .associated_data = associated_data, .taglen = 32, .p = 4, .m = 32, .t = 3, .y = argon2::argon2i};
        cmp_bytes(a(), R"(
            c8 14 d9 d1 dc 7f 37 aa
            13 f0 d7 7f 24 94 bd a1
            c8 de 6b 01 6d d3 88 d2
            99 52 a4 c4 67 2b 6c e8
    )"_sb);
    }
    {
        argon2 a{.password = pass, .salt = salt, .key = key, .associated_data = associated_data, .taglen = 32, .p = 4, .m = 32, .t = 3, .y = argon2::argon2id};
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
        argon2 a{.password = pass, .salt = salt, .taglen = 4, .p = 1, .m = 8, .t = 1, .y = argon2::argon2id};
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
        argon2 a{.password = pass, .salt = salt, .taglen = 5, .p = 1, .m = 8, .t = 1, .y = argon2::argon2id};
        cmp_bytes(a(), R"(
6d6fc6afe9
    )"_sb);
    }
    {
        argon2 a{
            .password = pass, .salt = salt, .key = key, .associated_data = associated_data, .taglen = 64, .p = 16, .m = 256, .t = 10, .y = argon2::argon2id};
        cmp_bytes(a(), R"(
f73b80dd42a7669e98aa98c58007b022055a0c0024d6b9064119b9d3ecba2476e4dcf4e444ba59762960a16660fff039ea80448a1f1e9b35814a05e311f52426
    )"_sb);
    }
#ifndef CI_TESTS
    {
        argon2 a{
            .password = pass, .salt = salt, .key = key, .associated_data = associated_data, .taglen = 64, .p = 64, .m = 4096, .t = 32, .y = argon2::argon2id};
        cmp_bytes(a(), R"(
f76f7ac4e23bae5c3d1797f5d8a7b40222f770f0b6d339d8b5d4c168a2dfb512838b2bd5f110397e1c15267f782f0067d8ef567a7556470cd13af4dedf1d585d
    )"_sb);
    }
#endif
    // custom
    {
        argon2 a{
            .password = pass, .salt = salt, .key = key, .associated_data = associated_data, .taglen = 64, .p = 1, .m = 4096, .t = 32, .y = argon2::argon2id};
        cmp_bytes(a(), R"(
e5 e7 84 a7 19 f2 2b 70 e9 ac 5f 2e 87 57 31 81
b0 99 ff 9e fd 7c 16 0c 85 e3 bc 9e 5e fe d2 50
6e c1 9b b8 87 f5 43 24 ae 0c be 28 e4 5c 2b 5e
db 8f 1d c8 3f f3 f0 00 22 05 76 c5 4f 3b ed a4
    )"_sb);
    }
    {
        argon2 a{
            .password = pass, .salt = salt, .key = key, .associated_data = associated_data, .taglen = 64, .p = 10, .m = 4096, .t = 32, .y = argon2::argon2id};
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
        salsa_block((uint32_t *)in.data(), out, 8);

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
        array<32> K = (bytes_concept) "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"_sb;

        // auto onetimekey = poly1305_key_gen((uint8_t *)K.c_str(), (uint8_t *)nonce.c_str());

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
        array<32> K = (bytes_concept) R"(
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

void test_x509() {
    LOG_TEST();

    using namespace crypto;

    x509_storage ss;
    ss.load_pem(read_file(cacert_pem()), true);
    ss.load_der(read_file(infotecs_ca()), true);

    auto data1 = read_file("test1.der");
    auto data2 = read_file("test2.der");

    /*x509_storage s;
    s.add(data1);
    s.add(data2);
    cmp_bool(s.verify(ss), true);

    x509_storage s2;
    auto data3 = read_file("infotecs.der");
    s2.add(data3);
    cmp_bool(s2.verify(ss), true);*/
}

void test_pki() {
    LOG_TEST();

    using namespace crypto;

    public_key_infrastructure p{".sw/pki"};
    gost_sig<ec::gost::r34102001::ec256a, oid::gost_r34102001_param_set_a, streebog<256>> gs256, gs256_child;
    gost_sig<ec::gost::r34102012::ec512c, oid::gost_3410_12_512_param_set_c, streebog<512>> gs512;
    auto &&[cakey, casubj] = p.make_ca("ca256", gs256, cert_request{.subject = {.common_name = "localhost CA 256", .country = "RU"}});
    auto &&[cakey2, casubj2] = p.make_cert("ca256_child", casubj, gs256, gs256_child, cert_request{.subject = {.common_name = "localhost", .country = "RU"}});
    auto &&[cakey3, casubj3] = p.make_ca("ca512", gs512, cert_request{.subject = {.common_name = "localhost CA 512", .country = "RU"}});

    x509_storage s;
    s.load_der(p.certs[cakey], true);
    s.load_der(p.certs[cakey3], true);
    s.add(p.certs[cakey2]);
    // cmp_bool(s.verify(s), true);
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
        fox(stb, "3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4", "36816a824dcbe7d6171aa58500741f2ea2757ae2e1784ab72c5c3c6c198d71da");
    }
    {
        streebog<512> stb;
        fox(stb, "d2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b97e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe",
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

    f("88 99AABB CC DD EE FF 00 11 22 33 44 55 66 77 FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF "_sb, "11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88"_sb,
      "7f679d90bebc24305a468d42b9d4edcd"_sb);
    f("0000000000000000000000000000000000000000000000000000000000000000"_sb, "00000000000000000000000000000000"_sb, "98CC6B54DBCF7BD2F0800C1FAB0677EF"_sb);
    f("ef cd ab 89 67 45 23 01 10 32 54 76 98 ba dc fe 77 66 55 44 33 22 11 00 ff ee dd cc bb aa 99 88"_sb,
      "88 99 aa bb cc dd ee ff 00 77 66 55 44 33 22 11"_sb, "B2135B9C8EDA608E3D16385C396CB98B"_sb);
    f("77 66 55 44 33 22 11 00 ff ee dd      cc bb aa 99 88 ef cd ab 89 67 45 23 01 10 32 54 76 98 ba dc fe      "_sb,
      "88 99 aa bb cc dd ee ff 00 77 66 55 44 33 22 11"_sb, "DF4B256B59D499A552B77EF74C590B8B"_sb);
}

void test_mgm() {
    LOG_TEST();

    using namespace crypto;

    {
        auto K = "88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF"_sb;
        auto nonce = "11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88"_sb;
        auto A = "02 02 02 02 02 02 02 02 01 01 01 01 01 01 01 01         04 04 04 04 04 04 04 04 03 03 03 03 03 03 03 03 EA 05 05 05 05 05 05 05 05 "_sb;
        auto P =
            "11 22 33 44 55 66 77 00 FF EE DD CC BBAA99 88        00 11 22 33 44 55 66 77 88 99AABB CC EE FF 0A 11 22 33 44 55 66 77 88 99AABB CC EE            FF0A00 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 AA BB CC "_sb;
        auto E =
            "A9 75 7B 81 47 95 6E 90 55 B8 A3 3D E8 9F 42 FC 80 75 D2 21 2B F9 FD 5B D3 F7 06 9A AD C1 6B 39 49 7A B1 59 15 A6 BA 85 93 6B 5D 0E A9 F6 85 1C C6 0C 14 D4 D3 F8 83 D0 AB 94 42 06 95 C7 6D EB 2C 75 52"_sb;

        mgm<grasshopper> m{K};
        auto [enc, tag] = m.encrypt(nonce, P, A);
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
    cmp_bytes(hmac<streebog<256>>("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"_sb,
                                  "01 26 bd b8 78 00 af 21 43 41 45 65 63 78 01 00"_sb),
              "a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34 01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9"_sb);
    cmp_bytes(
        hmac<streebog<512>>("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"_sb,
                            "01 26 bd b8 78 00 af 21 43 41 45 65 63 78 01 00"_sb),
        "a5 9b ab 22 ec ae 19 c6 5f bd e6 e5 f4 e9 f5 d8 54 9d 31 f0 37 f9 df 9b 90 55 00 e1 71 92 3a 77 3d 5f 15 30 f2 ed 7e 96 4c b2 ee dc 29 e9 ad 2f 3a fe 93 b2 81 4f 79 f5 00 0f fc 03 66 c2 51 e6"_sb);

    cmp_bytes(gost::kdf<streebog<256>>("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"_sb, "26 bd b8 78"_sb,
                                       "af 21 43 41 45 65 63 78"_sb),
              "a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34 01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9"_sb);
}

void test_dns() {
    LOG_TEST();

    using namespace crypto;

    dns_resolver serv{"178.208.90.175", "8.8.8.8", "8.8.4.4", "1.1.1.1"};
    bool ok{true};
    auto res_and_print = [&](auto &&what, uint16_t type = dns_packet::qtype::A, SRCLOC) {
        try {
            auto res = serv.query(what, type);
            cmp_base(!res.empty(), ok, loc);
        } catch (...) {
            cmp_base(1, 0, loc);
        }
    };
    res_and_print("gql.twitch.tv"s);
    res_and_print("twitch.tv"s);
    res_and_print("www.youtube.com"s);
    res_and_print("google.com"s);
    res_and_print("google.com"s, dns_packet::qtype::MX);
    res_and_print("google.com"s, dns_packet::qtype::AAAA);
    res_and_print("gmail.com"s);
    res_and_print("gmail.com"s, dns_packet::qtype::MX);
    res_and_print("egorpugin.ru"s);
    res_and_print("aspia.egorpugin.ru"s);
    ok = false;
    res_and_print("egorpugin.ru"s, dns_packet::qtype::MX);
    res_and_print("egorpugin.ru"s, dns_packet::qtype::AAAA);

    auto &dd = get_default_dns();
    auto res_and_print2 = [&](SRCLOC) {
        try {
            dd.query_one<dns_packet::mx>("google.com"s);
            cmp_base(1, 1, loc);
        }
        catch (...) {
            cmp_base(1, 0, loc);
        }
        };
    res_and_print2();
    res_and_print2();
}

void test_tls() {
    LOG_TEST();

    using namespace crypto;

    load_system_certs();

    auto run0 = [](auto &&t, auto &&url) {
        t.follow_location = false;
        t.tls_layer.ignore_server_hostname_check = true;
#ifndef CI_TESTS
        std::cout << "connecting to " << url << "\n";
#endif
        try {
            t.run();
#ifndef CI_TESTS
            std::cout << "ok" << "\n";
#endif
            cmp_base(0, 0);
        } catch (std::exception &e) {
#ifdef CI_TESTS
            std::cout << "connecting to " << url << "\n";
#endif
            std::cout << e.what() << "\n";
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

    //tcs.load_pem(read_file("d:/dev/wolfssl/certs/sm2/root-sm2.pem"), true);
    //run("127.0.0.1:11111");
    //run("nalog.gov.ru");
    //run("gmail.com");
    //run_with_params("gmail.com", (tls13::CipherSuite)0, parameters::supported_groups::X25519MLKEM768);

    //run_with_params("tls13.1d.pw", (tls13::CipherSuite)0, parameters::supported_groups::X25519MLKEM768);

    ////// https://infotecs.ru/stand_tls/
    //
#ifdef CI_TESTS
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

        // run_with_params("91.244.183.22:15083", s, parameters::supported_groups::GC512B); // this server or their suite does not work well
        // run_with_params("91.244.183.22:15081", s, parameters::supported_groups::GC512B); // this server or their suite does not work well
    }
#endif

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
    // run("tls13.1d.pw");
    // run("127.0.0.1:11111");

    // some other tests
    run("https://www.reuters.com/");
    run("https://edition.cnn.com/");
    run("https://www.cloudflare.com/");
#ifndef CI_TESTS
    run("gosuslugi.ru"); // works bad on ci
#endif
    //
    //// does not support tls13
    // run("https://www.globaltimes.cn/");
    // run("https://www.gov.cn/");
    // run("https://english.news.cn/");
    // run("sberbank.ru");
    // run("gost.cryptopro.ru");
    //// requires RFC 5746(Renegotiation Indication)
    // run("tlsgost-512.cryptopro.ru"); // https://www.cryptopro.ru/products/csp/tc26tls
    //  return tls 1.0/1.1
    // run("https://tlsgost-512.cryptopro.ru");
    // run("https://tlsgost-512.cryptopro.ru:1443");
}

void test_email() {
    LOG_TEST();

    using namespace crypto;

    load_system_certs();

    //
    {
        auto msg =
"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=yandex.ru; s=mail;\r\n"
"	t=1742406861; bh=eJSordZTKKgCW9s4DISERXxyXZB6PI8ufAgpMa6cwgw=;\r\n"
"	h=Message-Id:Date:To:From;\r\n"
"	b=UEQUG7oRdUFRK5QxRBvHr7raa8W6Vgzi1zLTtGWIrkBoMS9861B3l8/xNd5KODpIi\r\n"
"	 aNz2jRK6G6OuwH93ZAOSBdNixVCoBwr+BOLhEOS7aTPswoFeQfrkk5rPJvNV7FuOwl\r\n"
"	 aNTw4g8ugIo8Co3TDxu0QHa7Vz+n4Mgakuyv1H6I=\r\n"
"From: Egor Pugin <egorvpugin@yandex.ru>\r\n"
"To: Joe Smith <egor.pugin@gmail.com>\r\n"
"Date: Wed, 19 Mar 2025 20:54:21 +0300\r\n"
"Message-Id: <3661742406848@mail.yandex.ru>\r\n"
"\r\n"
"<div>test</div>\r\n"
""sv;
        input_email ie{msg};
        cmp_bytes(base64::encode(sha256::digest(ie.body)), "eJSordZTKKgCW9s4DISERXxyXZB6PI8ufAgpMa6cwgw="sv);

        auto pubk = rsa::public_key::load_pkcs8(base64::decode("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDEc6Lkc9kLHjIxLkeszz1dYzGIfPH8qaUx2wLojYefUzZiCjyl0s/YT17WJMfGFZkl0gHgkEj5/I2C72MmaHVtTFzNqD48ZuqVydlDyfLed0A6vxb+MS34DIbpCgCi0HxQO1QRG7PechKza0iazWTIAQ1xRU24ZYM70kGDzhFHSwIDAQAB"sv));

        auto sigtext =
"message-id:<3661742406848@mail.yandex.ru>\r\n"
"date:Wed, 19 Mar 2025 20:54:21 +0300\r\n"
"to:Joe Smith <egor.pugin@gmail.com>\r\n"
"from:Egor Pugin <egorvpugin@yandex.ru>\r\n"
"dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=yandex.ru; s=mail; t=1742406861; bh=eJSordZTKKgCW9s4DISERXxyXZB6PI8ufAgpMa6cwgw=; h=Message-Id:Date:To:From; b="
""s;
        auto sig1 = base64::decode(
"UEQUG7oRdUFRK5QxRBvHr7raa8W6Vgzi1zLTtGWIrkBoMS9861B3l8/xNd5KODpIi"
"aNz2jRK6G6OuwH93ZAOSBdNixVCoBwr+BOLhEOS7aTPswoFeQfrkk5rPJvNV7FuOwl"
"aNTw4g8ugIo8Co3TDxu0QHa7Vz+n4Mgakuyv1H6I="sv
);
        auto sig = base64::decode<true>(
"UEQUG7oRdUFRK5QxRBvHr7raa8W6Vgzi1zLTtGWIrkBoMS9861B3l8/xNd5KODpIi"
"   aNz2jRK6G6OuwH93ZAOSBdNixVCoBwr+BOLhEOS7aTPswoFeQfrkk5rPJvNV7FuOwl"
"aNTw4g8ugIo8Co3TDxu0QHa7Vz+n4Mgakuyv1H6I="sv
);
        cmp_base(pubk.verify_pkcs1<256>(sigtext, sig1), true);
        cmp_base(pubk.verify_pkcs1<256>(sigtext, sig), true);
        cmp_base(ie.verify_dkim(), true);
    }

    //
    {
        auto msg = read_file("original_msg.eml");
        replace_all(msg, "\r\n"sv, "\n"sv);
        replace_all(msg, "\n"sv, "\r\n"sv);
        input_email ie{msg};
        cmp_base(ie.verify_dkim(), true);
    }

    // DKIM rfc6376
    {
        cmp_bytes(base64::encode(sha1::digest("\r\n"sv)), "uoq1oCgLlTqpdDX/iUbLy7J1Wic="sv);
        cmp_bytes(base64::encode(sha256::digest("\r\n"sv)), "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="sv);
        cmp_bytes(base64::encode(sha256::digest("<div>test</div>\r\n"sv)), "eJSordZTKKgCW9s4DISERXxyXZB6PI8ufAgpMa6cwgw="sv);

        auto msg =
"DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;\r\n"
"      c=simple/simple; q=dns/txt; i=joe@football.example.com;\r\n"
"      h=Received : From : To : Subject : Date : Message-ID;\r\n"
"      bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n"
"      b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB\r\n"
"      4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut\r\n"
"      KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV\r\n"
"      4bmp/YzhwvcubU4=;\r\n"
"Received: from client1.football.example.com  [192.0.2.1]\r\n"
"      by submitserver.example.com with SUBMISSION;\r\n"
"      Fri, 11 Jul 2003 21:01:54 -0700 (PDT)\r\n"
"From: Joe SixPack <joe@football.example.com>\r\n"
"To: Suzie Q <suzie@shopping.example.net>\r\n"
"Subject: Is dinner ready?\r\n"
"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n"
"Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n"
"\r\n"
"Hi.\r\n"
"\r\n"
"We lost the game. Are you hungry yet?\r\n"
"\r\n"
"Joe.\r\n"
""s;
        auto privtext = R"(
   -----BEGIN RSA PRIVATE KEY-----
   MIICXwIBAAKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFC
   jxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gb
   to/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
   AoGBALmn+XwWk7akvkUlqb+dOxyLB9i5VBVfje89Teolwc9YJT36BGN/l4e0l6QX
   /1//6DWUTB3KI6wFcm7TWJcxbS0tcKZX7FsJvUz1SbQnkS54DJck1EZO/BLa5ckJ
   gAYIaqlA9C0ZwM6i58lLlPadX/rtHb7pWzeNcZHjKrjM461ZAkEA+itss2nRlmyO
   n1/5yDyCluST4dQfO8kAB3toSEVc7DeFeDhnC1mZdjASZNvdHS4gbLIA1hUGEF9m
   3hKsGUMMPwJBAPW5v/U+AWTADFCS22t72NUurgzeAbzb1HWMqO4y4+9Hpjk5wvL/
   eVYizyuce3/fGke7aRYw/ADKygMJdW8H/OcCQQDz5OQb4j2QDpPZc0Nc4QlbvMsj
   7p7otWRO5xRa6SzXqqV3+F0VpqvDmshEBkoCydaYwc2o6WQ5EBmExeV8124XAkEA
   qZzGsIxVP+sEVRWZmW6KNFSdVUpk3qzK0Tz/WjQMe5z0UunY9Ax9/4PVhp/j61bf
   eAYXunajbBSOLlx4D+TunwJBANkPI5S9iylsbLs6NkaMHV6k5ioHBBmgCak95JGX
   GMot/L2x0IYyMLAz6oLWh2hm7zwtb0CgOrPo1ke44hFYnfc=
   -----END RSA PRIVATE KEY-----
)"s;
        auto priv = rsa::private_key::load_from_string_container(privtext);
        rsa::public_key pubk{priv};

        auto sig = base64::decode(
"AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB"
"4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut"
"KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV"
"4bmp/YzhwvcubU4="sv);
        auto sigtext =
"Received: from client1.football.example.com  [192.0.2.1]\r\n"
"      by submitserver.example.com with SUBMISSION;\r\n"
"      Fri, 11 Jul 2003 21:01:54 -0700 (PDT)\r\n"
"From: Joe SixPack <joe@football.example.com>\r\n"
"To: Suzie Q <suzie@shopping.example.net>\r\n"
"Subject: Is dinner ready?\r\n"
"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n"
"Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n"
"DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;\r\n"
"      c=simple/simple; q=dns/txt; i=joe@football.example.com;\r\n"
"      h=Received : From : To : Subject : Date : Message-ID;\r\n"
"      bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n"
"      b=;" // notice last ';'
""sv;
        auto res = pubk.verify_pkcs1<256>(sigtext, sig);
        cmp_base(res, true);

        input_email ie{msg};
        cmp_bytes(base64::encode(sha256::digest(ie.body)), "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8="sv);
        cmp_base(ie.verify_dkim_rsa(pubk), true);
    }

    //
    {
        auto dnsEd25519PublicKey = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="s;

        auto msg = R"(DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
 d=football.example.com; i=@football.example.com;
 q=dns/txt; s=brisbane; t=1528637909; h=from : to :
 subject : date : message-id : from : subject : date;
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
 b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
 Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game.  Are you hungry yet?

Joe.
)"s;
        replace_all(msg, "\n"sv, "\r\n"sv);

        auto fields = input_email::extract_fields(dnsEd25519PublicKey, ";"sv);
        auto pubk = base64::decode(input_email::get_field(fields, "p="sv));

        ed25519 ed;
        ed.private_key_ = bytes_concept{base64::decode("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A="sv)};
        cmp_bytes(ed.public_key(), pubk);

        input_email ie{msg};
        cmp_base(ie.verify_dkim_ed25519(pubk), true);
    }

    email e;
    e.from = "egor@egorpugin.ru";
    e.to = "egor.pugin@gmail.com";
    e.title = "title";
    e.text = "test";

    dkim_ed25519_signer s{"pc_test"};
    s.ed.private_key();
    auto msg = e.sign_message(s);
    input_email ie{msg};
    cmp_base(ie.verify_dkim_ed25519(s.ed.public_key()), true);

#ifdef CI_TESTS
    return;
#endif

    auto fn = "pc_test_ed25519.key"sv;
    //write_file("pc_test_ed25519.key", s.ed.private_key_);
    auto data = read_file(fn);
    if (data.size() != s.ed.private_key_.size()) {
        throw;
    }
    memcpy(s.ed.private_key_.data(), data.data(), data.size());
    //std::println("{}", base64::encode(s.ed.public_key()));

    //e.send();
}

void test_ssh2() {
    LOG_TEST();

    using namespace crypto;

    ssh2 s;
    s.connect("fedora@software-network.org"sv);
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
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.kH64lXJbz0NS5uG8NaoQjxmi-zgSgA-U1UCe5Plkzhw"_jwt);
    check_hs256(
        R"( { "sub" : "1234567890" , "name":"John Doe","iat":1516239022 })"_json, "0000",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABtGopfXew_rfoHUtAlV58GLAMWmdhsecKxVlDTuZAE"_jwt);
    check_hs256(R"({"loggedInAs":"admin","iat":1422779638} )"_json, "secretkey",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjI3Nzk2MzgsImxvZ2dlZEluQXMiOiJhZG1pbiJ9.bHroWl3rTXUTNjwZQ_N8w2YRYs6x1ZWkEMckM53_D9E"_jwt);

    auto pks = read_file("jwtRS256.key");
    auto pubs = read_file("jwtRS256.key.pub");

    auto pk = private_key::load_from_string_container(pks);
    auto pubk = public_key::load_from_string_container(pubs);

    check_rs256(
        R"({"loggedInAs":"admin","iat":1422779638} )"_json, pk, pubk,
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjI3Nzk2MzgsImxvZ2dlZEluQXMiOiJhZG1pbiJ9.VJkvpYvlELE2Hrnz6JKGZuoWshycW3HNdrgV8KOoIKatI64KYBs-a1wK6JUaTY1bkViEh_YrdrKKb3iDU_nJYkRZHIfNmM7J_sQeE04zUpit4ketxWzGk2daF10gRaO8nefH7b9bvMYLMyiqq4kOaaCVhTgTFHm73iu42Tl_ybqRVp5ArWzru2MYQrdCxK2X3qJ5mPx9GgHBtjjBSQkT6Np-XZphdEYXj7juOxeX6oE6FAl749PlYQXjWU23UaHDwIDzM8vfk9gPmQeuA1PQ7UMZ-MWrhC-ym7_cA4zq4USn-YmFSOsf_A96kSMlh9xiL2FlgE1C6DvrjGoyVl025w"_jwt);
    check_rs256(
        R"({"sub":"1234567890","name": "John Doe" ,"iat": 1516239022})"_json, pk, pubk,
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.MmNFMRvbzG6eb9kYkHXRMwOiEbkDBMXIQOk0Vrnipt4GL39Vz-y5YayzgfUOE_-xZdQGWYQWhxGnBIBQDRqkIBR1UMzL_adWd4FgpdMxaGdXScWupTj8_chBPsCzYvvImqm0b5buLHSs7FwXUVrMeEodpN3lyeuu8RV7vwTiitV3HwuQdm9z5TcOSPJjYw0tv1qNfoKscNiJK4-1VGl00rbneKevRKtlmuz8ddLMW7el-IoY9mwZyEkFpL5BsWZUiYN_64PgTmGYuBN7qU32PgWX9QAgwn6YjgwaY43pyet65jUwC7-bx2QnL6lBeja3rACuk3ph0PWNUZHZgNXbrg"_jwt);

    // salt is different every time, but verify will work
    check_ps512(R"({"loggedInAs":"admin","iat":1422779638} )"_json, pk, pubk, ""_jwt);
    check_ps512(R"({"sub":"1234567890","name": "John Doe" ,"iat": 1516239022})"_json, pk, pubk, ""_jwt);
    verify_ps512(
        R"(eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjI3Nzk2MzgsImxvZ2dlZEluQXMiOiJhZG1pbiJ9.V0xxUc58hL2QGsrKdeAWRCFqZULhYg98lNrHkMVqo8nB1No88-VHmti1EIVvZSV2fxMGNXbu0xNZ4qUMy8x43JieP4uvWGggX5KZTZn_dRpqtZKfC7o6pt5F2lwetnQjp9bhsYGqbOoQ9MLchRKg4oDtCYIl03yE4oiJuRQR-FobKHW-M61vkXGGvcnTL3AUyvyLgFRXYzzYPAy3JIhmLjy4IqQ8s4Vrz9sRiGw6zUpl3YSk0gq7KUdxR6DTtk5HF-WSHwNKtvmpgEFfuxHJm0amH3RQwvx-vwUjGTEogpOleeaYTUvWgzv-D9DHB5lW6uQbs2P7xf0ZWJ_wnHU2Dg)",
        pk, pubk, ""_jwt);
}

void test_hpke() {
    LOG_TEST();

    using namespace crypto;

    auto info = "4f6465206f6e2061204772656369616e2055726e"_sb;
    auto pt = "4265617574792069732074727574682c20747275746820626561757479"_sb;
    auto psk = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"_sb;
    auto psk_id = "456e6e796e20447572696e206172616e204d6f726961"_sb;
    auto aad = "Count-"s; // "436f756e742d"_sb;
    auto make_aad = [&](int i) {
        return aad + std::to_string(i);
    };

    {
        auto ikmE = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"_sb;
        auto ikmR = "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037"_sb;

        hpke<dhkem<curve25519, hkdf<sha256>>, hkdf<sha256>, gcm<aes_ecb<128>>> hE, hR;

        auto [skEm, pkEm] = hE.derive_key_pair(ikmE);
        cmp_bytes(skEm, "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"_sb);
        cmp_bytes(pkEm, "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"_sb);

        auto [skRm, pkRm] = hR.derive_key_pair(ikmR);
        cmp_bytes(skRm, "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"_sb);
        cmp_bytes(pkRm, "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"_sb);

        auto ssE = hE.template shared_secret<'S'>(pkRm);
        auto ssR = hR.template shared_secret<'R'>(pkEm);

        cmp_bytes(ssE, "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"_sb);
        cmp_bytes(ssR, "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"_sb);

        auto ctxE = hE.template key_schedule<'S'>(mode_type::base, ssE, info, ""sv, ""sv);
        auto ctxR = hR.template key_schedule<'R'>(mode_type::base, ssR, info, ""sv, ""sv);
        int i = 0;
        auto test = [&](auto &&ct, int i2) {
            while (i != i2) {
                ctxE.increment_seq();
                ctxR.increment_seq();
                ++i;
            }
            cmp_bytes(ctxE.seal(make_aad(i), pt), ct);
            cmp_bytes(ctxR.open(make_aad(i), ct), pt);
            ++i;
        };
        test("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"_sb, 0);
        test("af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"_sb, 1);
        test("583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d"_sb, 4);
        test("7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a"_sb, 255);
        test("957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2"_sb, 256);

        cmp_bytes(ctxE.export_(""_sb), "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee"_sb);
        cmp_bytes(ctxE.export_("00"_sb), "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5"_sb);
        cmp_bytes(ctxE.export_("TestContext"s), "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931"_sb);
    }

    auto check_simple = [&](auto hpke, auto &&ikmE, auto &&ikmR, auto &&ikmS, auto mode, auto &&psk, auto &&psk_id, auto &&ct256, auto &&exp) {
        decltype(hpke) hE, hR, hS;

        auto [skEm, pkEm] = hE.derive_key_pair(ikmE);
        auto [skRm, pkRm] = hR.derive_key_pair(ikmR);
        auto [skSm, pkSm] = hS.derive_key_pair(ikmS);
        auto ssE = ikmS.empty() ? hE.template shared_secret<'S'>(pkRm) : hE.template shared_secret<'S'>(pkRm, skSm);
        auto ssR = ikmS.empty() ? hR.template shared_secret<'R'>(pkEm) : hR.template shared_secret<'R'>(pkEm, pkSm);
        cmp_bytes(ssE, ssR);

        auto ctxE = hE.template key_schedule<'S'>(mode, ssE, info, psk, psk_id);
        if constexpr (!decltype(hpke)::export_only) {
            auto ctxR = hR.template key_schedule<'R'>(mode, ssR, info, psk, psk_id);
            int i = 0;
            auto test = [&](auto &&ct, int i2) {
                while (i != i2) {
                    ctxE.increment_seq();
                    ctxR.increment_seq();
                    ++i;
                }
                cmp_bytes(ctxE.seal(make_aad(i), pt), ct);
                cmp_bytes(ctxR.open(make_aad(i), ct), pt);
                ++i;
            };
            test(ct256, 256);
        }
        cmp_bytes(ctxE.template export_<32>("TestContext"s), exp);
    };
    // A.1
    check_simple(hpke<dhkem<curve25519, hkdf<sha256>>, hkdf<sha256>, gcm<aes_ecb<128>>>{},
                 "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"_sb, "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037"_sb,
                 ""_sb, mode_type::base, ""_sb, ""_sb, "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2"_sb,
                 "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931"_sb);
    check_simple(hpke<dhkem<curve25519, hkdf<sha256>>, hkdf<sha256>, gcm<aes_ecb<128>>>{},
                 "78628c354e46f3e169bd231be7b2ff1c77aa302460a26dbfa15515684c00130b"_sb, "d4a09d09f575fef425905d2ab396c1449141463f698f8efdb7accfaff8995098"_sb,
                 ""_sb, mode_type::psk, psk, psk_id, "c5bf246d4a790a12dcc9eed5eae525081e6fb541d5849e9ce8abd92a3bc1551776bea16b4a518f23e237c14b59"_sb,
                 "8aff52b45a1be3a734bc7a41e20b4e055ad4c4d22104b0c20285a7c4302401cd"_sb);
    check_simple(hpke<dhkem<curve25519, hkdf<sha256>>, hkdf<sha256>, gcm<aes_ecb<128>>>{},
                 "6e6d8f200ea2fb20c30b003a8b4f433d2f4ed4c2658d5bc8ce2fef718059c9f7"_sb, "f1d4a30a4cef8d6d4e3b016e6fd3799ea057db4f345472ed302a67ce1c20cdec"_sb,
                 "94b020ce91d73fca4649006c7e7329a67b40c55e9e93cc907d282bbbff386f58"_sb, mode_type::auth, ""_sb, ""_sb,
                 "42fa248a0e67ccca688f2b1d13ba4ba84755acf764bd797c8f7ba3b9b1dc3330326f8d172fef6003c79ec72319"_sb,
                 "5a0131813abc9a522cad678eb6bafaabc43389934adb8097d23c5ff68059eb64"_sb);
    check_simple(hpke<dhkem<curve25519, hkdf<sha256>>, hkdf<sha256>, gcm<aes_ecb<128>>>{},
                 "4303619085a20ebcf18edd22782952b8a7161e1dbae6e46e143a52a96127cf84"_sb, "4b16221f3b269a88e207270b5e1de28cb01f847841b344b8314d6a622fe5ee90"_sb,
                 "62f77dcf5df0dd7eac54eac9f654f426d4161ec850cc65c54f8b65d2e0b4e345"_sb, mode_type::auth_psk, psk, psk_id,
                 "13239bab72e25e9fd5bb09695d23c90a24595158b99127505c8a9ff9f127e0d657f71af59d67d4f4971da028f9"_sb,
                 "a30c20370c026bbea4dca51cb63761695132d342bae33a6a11527d3e7679436d"_sb);
    // A.2
    check_simple(hpke<dhkem<curve25519, hkdf<sha256>>, hkdf<sha256>, chacha20_poly1305_aead>{},
                 "49d6eac8c6c558c953a0a252929a818745bb08cd3d29e15f9f5db5eb2e7d4b84"_sb, "f3304ddcf15848488271f12b75ecaf72301faabf6ad283654a14c398832eb184"_sb,
                 "20ade1d5203de1aadfb261c4700b6432e260d0d317be6ebbb8d7fffb1f86ad9d"_sb, mode_type::auth_psk, psk, psk_id,
                 "9b7f84224922d2a9edd7b2c2057f3bcf3a547f17570575e626202e593bfdd99e9878a1af9e41ded58c7fb77d2f"_sb,
                 "d3bae066aa8da27d527d85c040f7dd6ccb60221c902ee36a82f70bcd62a60ee4"_sb);
    // A.3
    check_simple(hpke<dhkem<ec::secp256r1, hkdf<sha256>>, hkdf<sha256>, gcm<aes_ecb<128>>>{},
                 "3c1fceb477ec954c8d58ef3249e4bb4c38241b5925b95f7486e4d9f1d0d35fbb"_sb, "abcc2da5b3fa81d8aabd91f7f800a8ccf60ec37b1b585a5d1d1ac77f258b6cca"_sb,
                 "6262031f040a9db853edd6f91d2272596eabbc78a2ed2bd643f770ecd0f19b82"_sb, mode_type::auth_psk, psk, psk_id,
                 "f380e19d291e12c5e378b51feb5cd50f6d00df6cb2af8393794c4df342126c2e29633fe7e8ce49587531affd4d"_sb,
                 "18ee4d001a9d83a4c67e76f88dd747766576cac438723bad0700a910a4d717e6"_sb);
    // A.4
    check_simple(hpke<dhkem<ec::secp256r1, hkdf<sha256>>, hkdf<sha2<512>>, gcm<aes_ecb<128>>>{},
                 "37ae06a521cd555648c928d7af58ad2aa4a85e34b8cabd069e94ad55ab872cc8"_sb, "7466024b7e2d2366c3914d7833718f13afb9e3e45bcfbb510594d614ddd9b4e7"_sb,
                 "ee27aaf99bf5cd8398e9de88ac09a82ac22cdb8d0905ab05c0f5fa12ba1709f3"_sb, mode_type::auth_psk, psk, psk_id,
                 "9f659482ebc52f8303f9eac75656d807ec38ce2e50c72e3078cd13d86b30e3f890690a873277620f8a6a42d836"_sb,
                 "bed80f2e54f1285895c4a3f3b3625e6206f78f1ed329a0cfb5864f7c139b3c6a"_sb);
    // A.5
    check_simple(hpke<dhkem<ec::secp256r1, hkdf<sha256>>, hkdf<sha2<256>>, chacha20_poly1305_aead>{},
                 "f3a07f194703e321ef1f753a1b9fe27a498dfdfa309151d70bedd896c239c499"_sb, "1240e55a0a03548d7f963ef783b6a7362cb505e6b31dfd04c81d9b294543bfbd"_sb,
                 "ce2a0387a2eb8870a3a92c34a2975f0f3f271af4384d446c7dc1524a6c6c515a"_sb, mode_type::auth_psk, psk, psk_id,
                 "fb857f4185ce5286c1a52431867537204963ea66a3eee8d2a74419fd8751faee066d08277ac7880473aa4143ba"_sb,
                 "e01dd49e8bfc3d9216abc1be832f0418adf8b47a7b5a330a7436c31e33d765d7"_sb);
    // A.6
    check_simple(hpke<dhkem<ec::secp521r1, hkdf<sha2<512>>>, hkdf<sha2<512>>, gcm<aes_ecb<256>>>{},
                 "54272797b1fbc128a6967ff1fd606e0c67868f7762ce1421439cbc9e90ce1b28d566e6c2acbce712e48eebf236696eb680849d6873e9959395b2931975d61d38bd6c"_sb,
                 "3db434a8bc25b27eb0c590dc64997ab1378a99f52b2cb5a5a5b2fa540888f6c0f09794c654f4468524e040e6b4eca2c9dcf229f908b9d318f960cc9e9baa92c5eee6"_sb,
                 "65d523d9b37e1273eb25ad0527d3a7bd33f67208dd1666d9904c6bc04969ae5831a8b849e7ff642581f2c3e56be84609600d3c6bbdaded3f6989c37d2892b1e978d5"_sb,
                 mode_type::auth_psk, psk, psk_id, "24f9d8dadd2107376ccd143f70f9bafcd2b21d8117d45ff327e9a78f603a32606e42a6a8bdb57a852591d20907"_sb,
                 "f8b4e72cefbff4ca6c4eabb8c0383287082cfcbb953d900aed4959afd0017095"_sb);
    // A.7
    check_simple(hpke<dhkem<curve25519, hkdf<sha256>>, hkdf<sha256>, hpke_export_only>{}, "94efae91e96811a3a49fd1b20eb0344d68ead6ac01922c2360779aa172487f40"_sb,
                 "4dfde6fadfe5cb50fced4034e84e6d3a104aa4bf2971360032c1c0580e286663"_sb, "26c12fef8d71d13bbbf08ce8157a283d5e67ecf0f345366b0e90341911110f1b"_sb,
                 mode_type::auth_psk, psk, psk_id, ""_sb, "84f3466bd5a03bde6444324e63d7560e7ac790da4e5bbab01e7c4d575728c34a"_sb);
}

void test_mlkem() {
    LOG_TEST();

    using namespace crypto;

    auto check1 = [&](auto k, auto &&sk, auto &&pk, auto &&in_c, auto &&in_ss, auto &&d, auto &&z, auto &&m) {
        k.ml_kem_keygen(d, z);
        cmp_bytes(k.private_key_, sk);
        cmp_bytes(k.public_key_, pk);
        array<decltype(k)::pke_cipher_text_len> c;
        array<decltype(k)::shared_secret_byte_len> ss;
        cmp_base(k.encapsulate(std::span<u8, 32>{m}, c, ss), true);
        cmp_bytes(c, in_c);
        cmp_bytes(ss, in_ss);
        array<decltype(k)::shared_secret_byte_len> ss2;
        k.decapsulate(c, ss2);
        cmp_bytes(ss2, in_ss);
    };
    auto check = [&](auto k, auto &&sk, auto &&pk, auto &&in_c, auto &&in_ss) {
        auto d = "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d"_sb;
        auto z = "b505d7cfad1b497499323c8686325e4792f267aafa3f87ca60d01cb54f29202a"_sb;
        auto m = "eb4a7c66ef4eba2ddb38c88d8bc706b1d639002198172a7b1942eca8f6c001ba"_sb;
        return check1(k, sk, pk, in_c, in_ss, d, z, m);
    };
    auto check2 = [&](auto k, bytes_concept dz, auto &&m, auto &&sk, auto &&pk, auto &&in_c, auto &&in_ss) {
        return check1(k, sk, pk, in_c, in_ss, dz.subspan(0, 32), dz.subspan(32), m);
    };

    {
        check(
            mlkem<512>{},
            "9cda1686a3396a7c109b415289f56a9ec44cd5b9b674c38a3bbab30a2c90f00437a264b0be9a1e8ba887d3c3b100898054272f941c88a1f208f1c914f964c1aad613a6a84f88e42d3556835fb161fdc5cd15a3bc7e74b6f2612fa8271c7ea112b05c2a36cc707ce38d5d1acc5115462a8c1aabf07276c72318337f74b5cbefea7a803790bc0393f3a54c724a5765a48f296b03f484376023626930222704c08fd3bc729315d1fc70eb7975a97b9deed162f486bbc64a097111952d89b57d765e8a991a2e564206ea7bf5e4007a66358831ca0e34b2f6a84d10f79c477cb66a8a952569367388130d7b974a63aa51996c97709bb8eabc94e6a535d792d2905474952d6b8c2222b2ae56dc66fb0461192066cddb43ec05984fb4982649771397c6a8379f3b5643069848875919e89cc439a3be2f081490f341bd1240add80ddb8c9963b47a2a0992290338da9c3b725c6da44718c01046812562afb084837acb3c575e4f93936c352ac0e70aa3845ee485296e6b02de0b47b5c4c96b0b7cf94c4abe95486153118e43c2b9c84d9da91c6c5acd5a57002d058497992799e5ba1ce6c25eb29844d858ba1c37850c0c2f57c60de37f77c082ec14494eba288a65915116c20a325de31aaadd680db19c0cfcc3460f0aa01a87a6a580c6ca291faef0ccc49b76a8dac4f9d41640509dbd0b4045c1530ed34755d47462700f2a8caf9680a6d7e38a7e2a63e937650a23306d855da2a2b7ef505ca596ab0485013ea927c7342343613643ba4007d6c874b980c79c3aa1c74f8581c34849b36ea79815fbb4ccf9610583081d7c5b4409b8d0531c04bcaf7cc751103a5fd1ba4470833e89775aded970b5471859250fe7267105835f390030c5e7cd3f961019eaaea23777d347bb2adcb673c02034f394342271bcea6414e546c3b20bd57481c7ea14c77c388cc86251c12558b100f8c5b3d03ca2c70713909659c8ba26d0d1765e0bc823d68ca5570de600cd0941725d386e14c1012df5951beb8d8281a4f6815d3760b764295ad0406c2bf7928ad65032b65f14b77ccb8917c93a29d6287d8a6062399cb6400865ed10b619aa5811139bc086825782b2b7124f757c83ae794444bc78a47896acf1262c81351077893bfc56f90449c2fa5f6e586dd37c0b9b581992638cb7e7bcbbb99afe4781d80a50e69463fbd988722c3635423e27466c71dcc674527ccd728968cbcdc00c5c9035bb0af2c9922c7881a41dd2875273925131230f6ca59e9136b39f956c93b3b2d14c641b089e07d0a840c893ecd76bbf92c805456668d07c621491c5c054991a656f511619556eb97782e27a3c785124c70b0daba6c624d18e0f9793f96ba9e1599b17b30dccc0b4f3766a07b23b257309cd76aba072c2b9c9744394c6ab9cb6c54a97b5c57861a58dc0a03519832ee32a07654a070c0c8c4e8648addc355f274fc6b92a087b3f9751923e44274f858c49caba72b65851b3adc48936955097cad9553f5a263f1844b52a020ff7ca89e881a01b95d957a3153c0a5e0a1ccd66b1821a2b8632546e24c7cbbc4cb08808cac37f7da6b16f8aced052cdb2564948f1ab0f768a0d3286ccc7c3749c63c781530fa1ae670542855004a645b522881ec1412bdae342085a9dd5f8126af96bbdb0c1af69a15562cb2a155a100309d1b641d08b2d4ed17bfbf0bc04265f9b10c108f850309504d772811bba8e2be16249aa737d879fc7fb255ee7a6a0a753bd93741c61658ec074f6e002b019345769113cc013ff7494ba8378b11a172260aaa53421bde03a35589d57e322fefa4100a4743926ab7d62258b87b31ccbb5e6b89cb10b271aa05d994bb5708b23ab327ecb93c0f3156869f0883da2064f795e0e2ab7d3c64d61d2303fc3a29e1619923ca801e59fd752ca6e7649d303c9d20788e1214651b06995eb260c929a1344a849b25ca0a01f1eb52913686bba619e23714464031a78439287fca78f4c0476223eea61b7f25a7ce42cca901b2aea129817894ba3470823854f3e5b28d86ba979e54671862d90470b1e7838972a81a48107d6ac0611406b21fbcce1db7702ea9dd6ba6e40527b9dc663f3c93bad056dc28511f66c3e0b928db8879d22c592685cc775a6cd574ac3bce3b27591c821929076358a2200b377365f7efb9e40c3bf0ff0432986ae4bc1a242ce9921aa9e22448819585dea308eb03950c8dd152a4531aab560d2fc7ca9a40ad8af25ad1dd08c6d79afe4dd4d1eee5ab505d7cfad1b497499323c8686325e4792f267aafa3f87ca60d01cb54f29202a"_sb, "400865ed10b619aa5811139bc086825782b2b7124f757c83ae794444bc78a47896acf1262c81351077893bfc56f90449c2fa5f6e586dd37c0b9b581992638cb7e7bcbbb99afe4781d80a50e69463fbd988722c3635423e27466c71dcc674527ccd728968cbcdc00c5c9035bb0af2c9922c7881a41dd2875273925131230f6ca59e9136b39f956c93b3b2d14c641b089e07d0a840c893ecd76bbf92c805456668d07c621491c5c054991a656f511619556eb97782e27a3c785124c70b0daba6c624d18e0f9793f96ba9e1599b17b30dccc0b4f3766a07b23b257309cd76aba072c2b9c9744394c6ab9cb6c54a97b5c57861a58dc0a03519832ee32a07654a070c0c8c4e8648addc355f274fc6b92a087b3f9751923e44274f858c49caba72b65851b3adc48936955097cad9553f5a263f1844b52a020ff7ca89e881a01b95d957a3153c0a5e0a1ccd66b1821a2b8632546e24c7cbbc4cb08808cac37f7da6b16f8aced052cdb2564948f1ab0f768a0d3286ccc7c3749c63c781530fa1ae670542855004a645b522881ec1412bdae342085a9dd5f8126af96bbdb0c1af69a15562cb2a155a100309d1b641d08b2d4ed17bfbf0bc04265f9b10c108f850309504d772811bba8e2be16249aa737d879fc7fb255ee7a6a0a753bd93741c61658ec074f6e002b019345769113cc013ff7494ba8378b11a172260aaa53421bde03a35589d57e322fefa4100a4743926ab7d62258b87b31ccbb5e6b89cb10b271aa05d994bb5708b23ab327ecb93c0f3156869f0883da2064f795e0e2ab7d3c64d61d2303fc3a29e1619923ca801e59fd752ca6e7649d303c9d20788e1214651b06995eb260c929a1344a849b25ca0a01f1eb52913686bba619e23714464031a78439287fca78f4c0476223eea61b7f25a7ce42cca901b2aea129817894ba3470823854f3e5b28d86ba979e54671862d90470b1e7838972a81a48107d6ac0611406b21fbcce1db7702ea9dd6ba6e40527b9dc663f3c93bad056dc28511f66c3e0b928db8879d22c592685cc775a6cd574ac3bce3b27591c821929076358a2200b377365f7efb9e40c3bf0ff0432986ae4bc1a242ce9921aa9e22448819585dea308eb039"_sb, "521c88486c35f6c245839212ab0e23660cd5b68fccd5a7b41eb5a3ce8844a31088c878eefeb44739cf9130013a83faaa78037443e5d749ba4d6f156934cc89c2d9abc76cb7ff050b4eeeb4a58611be330b3fdee875c1f366216ad659fabbebce37114e795c65f1eeca93181343005410febae042dfaeead873cf1c575d38ce26ec5c02940c0224e983881c2a1a4771ba316628a0f425ef54e984fe70e3866c79780b7572462ce5a9e116b55439ae921ff8b0d89d8616d405135dfab8f14d7da03f752517da847458ab83646ce5b4073788c66a6b60faf64b8fed507ee2a7d931f746b9f2595769721a59d93e4852aaf8185114f4a04f0f6f3ca144ba8ee1ba52db4aa7dc274156862812dc36e06997942bab02822bfc5fdfcdacea869c1a7672a4c794c9c09cc8a76df894324c14a53e9961cf40f0e70dc18583aa5e3d025a5b8d9ceda71d7902ebc5d499f059386b9910c75ba834b9d0c70ad9b9ea683aa699865f9ca7f3f30d20b78ff99850216a62f919a9d9eca482a52eaa2500fe5b80853cbb88e17ce593eb23709bac01fdfc941b527f5180e0decc3785f04d9120098f14c07f9244b441f2897f243c846a1d093d6a9c0b40e842a6d12e1d2e01bb44693d61c875ef007673787aaf167c1ec2b2f61ab8b504032a14490c109a0c2aee872fcd629594992ebd6dcde42ff6a602a5c7e15f50b799a7780829db1cb2e70e89944cf543224d4339ccf317a0ba195a07df0f43d7eee2400080da25a40f320061b15ae23ea0dee42474b2274d92c72c7e82f938bf826934ca2aaaca49cd73eb36d182591b8145d89ac8d6ceb7be8a1d7960d04171d7d03d84580bca9b5976ad1ed6cc8b021beecdbcc8b51a9b091c6625861097a32fb5a41e15b856cda135c3ca29c8656603ce3eb78071494197f0906d8b2a2cb208076ec89ce5760b199e937e13febc7893665ab6b2d5c85dc9a5d873cbf55b4a69343d768fbeef4b5eb88d0c31ffd366c66e13866e3f33eecbf2c3329c111c0cde2b9560892ce1a2686a2a1c18b7a7261a55bda57ade241544f3561390bdc69514429c8d5fbea9188baf2892"_sb, "b4c8e3c4115f9511f2fddb288c4b78c5cd7c89d2d4d321f46b4edc54ddf0eb36"_sb);
    }
    {
        check(
            mlkem<768>{},
            "da0ac7b660404e613aa1f980380cb36dba18d23256c7267a00a67ba6c2a2b14c414239662f68bd446c8efdf36656a0891a3cc623fc68b6572f7b29a6de128014411ee41906d08071f94856e36a832b40338d743516659bd25879c007a52bc9586f79876afac6c9a30d8fac243bd22425d6adce42ab7ed39014757a958bc8a74565f019234ff04b34893ed6d05501c37255239aae2ac19f8c75ac5900dae8300dbba710dc2caae1bca3a38c58342b286b8518f136ad15b9f7bcbb06a5607db375dbe976457c26c6598257531b2cfb6ee7f51591840804c38388376c27148413da9e92920bfd9a069e018bd272053da8775c0b739f761db2107cf35a434d69b07e5bcdb87434138b0cb556761ba522a5747b28747d80eb9d6cc673bee5769377b996d36ceb0c0c7ed9a658533324869c18a1a36f31470f14c5ae49ab070507f8249ce404b49c0a8c3ee42fea9631fa1a0d10d86b93f986e0e3a82e703b74e5ae6101242421a89aa07fe68588460baa368786486a72e4f24d2dd76cfc03b694a5ba91a755a0b98f3bf93307c0ab64639aea7a6498a3c3ddc571141abca4678cd2e2b857fb88f600caa596b44bc422250b2819e0515f0472391853700b01eff9453fd11876b7c759a07dd845caba4555264a82765193fdf81b620a1e1f923fb24442cd1cbe94175003ec06ce77a3c64493c199987a300c95c53c0089b5d65c92ea971b2ffa93b52a461ea2ac8c199c2f4c2b704297ce3c3949e0735ea8a14aa59e8dec0c878399ff70747ab244ce46b5f2230473323d25c66fe6b419b1f4a112e5214035256bc43ffd2b6b7b378769a6b47000bfb6357d45814baef3857d379e2fb8b5e5201ab26274bb1b70ad322cd0439b2db109cff0a2f8e600995571ffc38c590bc4c7615c69d0c98ef430f30861a77238ffc07061e475d6a30ad1b47fd039c3a447762db2211dc31d0acacfd55890a5824798f9aead7413dfe028b1012be8b6ca1026666ac6bc9440a449b51ad8bba7b0921dd4d8b4a578136d1a05db38cc858437b25161d1c3c28ee07bbcf2b249110d22781dc3050d8cc0090096b38a850696f86e9e6bab325271b2248675011968502881090497fac0af843c1aea76dd81cf29c012c66227b7f06d9961309b0262f732c9a4d0bbd06727abb8371ff2c11899a098375c460516b2cc88bcf628ede37d8f3b3342e4490a85606ec03da29b0256275382a3313dc041114801032c519f350c3e6abac3e33b93b4a19f7c5466e58cb1dc14b4a96c475729f971bdf173cdf354824d019427f95b3b4a4a4a958e476a6e6991ce6f06cb5dfca7d4380c3d920b5711ac1fcbaf4b9ac800b976d1ec766a626cc1900b66b3a9dc62c5c144527a296baf70433bf657c0437f87597bd7c8bbbe9abc37050931a4a86982a2028a74454c9b810c88d1701c8cc98a1d4ca107a6b25e962fe4b6b03c95453260b807228637cc9eb12acc0954959a52ae54d1977300aba0ba2c14609bb28c11d5fac5cac88297603283e867a3648366c724d9354cd7a196dbd9802f7b88d3fa001f9c9773225462235e91352a20791fd8b87fe3377ec6a3940b1130a0bb04e7410a34e2580d071d6c56202086787a6590f84393a8e651a1e685f22478a8954f007bc7711b930772c78f092e82878e3e937f367967532913a8d53dfdf4bfb1f8846746596705cf345142b972a3f16325c40c2952a37b25897e5ef35fbaeb73a4acbeb6a0b89942ceb195531cfc0a07993954483e6cbc87c06aa74ff0cac5207e535b260aa98d1198c07da605c4d11020f6c9f7bb68bb3456c73a01b710bc99d17739a51716aa01660c8b628b2f5602ba65f07ea993336e896e83f2c5731bbf03460c5b6c8afecb748ee391e98934a2c57d4d069f50d88b30d6966f38c37bc649b82634ce7722645ccd625063364646d6d699db57b45eb67465e16de4d406a818b9eae1ca916a2594489708a43cea88b02a4c03d09b44815c97101caf5048bbcb247ae2366cdc254ba22129f45b3b0eb399ca91a303402830ec01db7b2ca480cf350409b216094b7b0c3ae33ce10a9124e89651ab901ea253c8415bd7825f02bb229369af972028f22875ea55af16d3bc69f70c2ee8b75f28b47dd391f989ade314729c331fa04c1917b278c3eb602868512821adc825c64577ce1e63b1d9644a612948a3483c7f1b9a258000e30196944a403627609c76c7ea6b5de01764d24379117b9ea29848dc555c454bceae1ba5cc72c74ab96b9c91b910d26b88b25639d4778ae26c7c6151a19c6cd7938454372465e4c5ec29245acb3db5379de3dabfa629a7c04a8353a8530c95acb732bb4bb81932bb2ca7a848cd366801444abe23c83b366a87d6a3cf360924c002bae90af65c48060b3752f2badf1ab2722072554a5059753594e6a702761fc97684c8c4a7540a6b07fbc9de87c974aa8809d928c7f4cbbf8045aea5bc667825fd05a521f1a4bf539210c7113bc37b3e58b0cbfc53c841cbb0371de2e511b989cb7c70c023366d78f9c37ef047f8720be1c759a8d96b93f65a94114ffaf60d9a81795e995c71152a4691a5a602a9e1f3599e37c768c7bc108994c0669f3adc957d46b4b6256968e290d7892ea85464ee7a750f39c5e3152c2dfc56d8b0c924ba8a959a68096547f66423c838982a5794b9e1533771331a9a656c28828beb9126a60e95e8c5d906832c7710705576b1fb9507269ddaf8c95ce9719b2ca8dd112be10bcc9f4a37bd1b1eeeb33ecda76ae9f69a5d4b2923a86957671d619335be1c4c2c77ce87c41f98a8cc466460fa300aaf5b301f0a1d09c88e65da4d8ee64f68c02189bbb3584baff716c85db654048a004333489393a07427cd3e217e6a345f6c2c2b13c27b337271c0b27b2dbaa00d237600b5b594e8cf2dd625ea76cf0ed899122c9796b4b0187004258049a477cd11d68c49b9a0e7b00bce8cac7864cbb375140084744c93062694ca795c4f40e7acc9c5a1884072d8c38dafb501ee4184dd5a819ec24ec1651261f962b17a7215aa4a748c15836c389137678204838d7195a85b4f98a1b574c4cd7909cd1f833effd1485543229d3748d9b5cd6c17b9b3b84aef8bce13e683733659c79542d615782a71cdeee792bab51bdc4bbfe8308e663144ede8491830ad98b4634f64aba8b9c042272653920f380c1a17ca87ced7aac41c82888793181a6f76e197b7b90ef90943bb3844912911d8551e5466c5767ab0bc61a1a3f736162ec098a900b12dd8fabbfb3fe8cb1dc4e8315f2af0d32f0017ae136e19f028f57262661358cde8d3ebf990e5fd1d5b896c992ccfaadb5256b68bbf5943b132b505d7cfad1b497499323c8686325e4792f267aafa3f87ca60d01cb54f29202a"_sb,
            "a8e651a1e685f22478a8954f007bc7711b930772c78f092e82878e3e937f367967532913a8d53dfdf4bfb1f8846746596705cf345142b972a3f16325c40c2952a37b25897e5ef35fbaeb73a4acbeb6a0b89942ceb195531cfc0a07993954483e6cbc87c06aa74ff0cac5207e535b260aa98d1198c07da605c4d11020f6c9f7bb68bb3456c73a01b710bc99d17739a51716aa01660c8b628b2f5602ba65f07ea993336e896e83f2c5731bbf03460c5b6c8afecb748ee391e98934a2c57d4d069f50d88b30d6966f38c37bc649b82634ce7722645ccd625063364646d6d699db57b45eb67465e16de4d406a818b9eae1ca916a2594489708a43cea88b02a4c03d09b44815c97101caf5048bbcb247ae2366cdc254ba22129f45b3b0eb399ca91a303402830ec01db7b2ca480cf350409b216094b7b0c3ae33ce10a9124e89651ab901ea253c8415bd7825f02bb229369af972028f22875ea55af16d3bc69f70c2ee8b75f28b47dd391f989ade314729c331fa04c1917b278c3eb602868512821adc825c64577ce1e63b1d9644a612948a3483c7f1b9a258000e30196944a403627609c76c7ea6b5de01764d24379117b9ea29848dc555c454bceae1ba5cc72c74ab96b9c91b910d26b88b25639d4778ae26c7c6151a19c6cd7938454372465e4c5ec29245acb3db5379de3dabfa629a7c04a8353a8530c95acb732bb4bb81932bb2ca7a848cd366801444abe23c83b366a87d6a3cf360924c002bae90af65c48060b3752f2badf1ab2722072554a5059753594e6a702761fc97684c8c4a7540a6b07fbc9de87c974aa8809d928c7f4cbbf8045aea5bc667825fd05a521f1a4bf539210c7113bc37b3e58b0cbfc53c841cbb0371de2e511b989cb7c70c023366d78f9c37ef047f8720be1c759a8d96b93f65a94114ffaf60d9a81795e995c71152a4691a5a602a9e1f3599e37c768c7bc108994c0669f3adc957d46b4b6256968e290d7892ea85464ee7a750f39c5e3152c2dfc56d8b0c924ba8a959a68096547f66423c838982a5794b9e1533771331a9a656c28828beb9126a60e95e8c5d906832c7710705576b1fb9507269ddaf8c95ce9719b2ca8dd112be10bcc9f4a37bd1b1eeeb33ecda76ae9f69a5d4b2923a86957671d619335be1c4c2c77ce87c41f98a8cc466460fa300aaf5b301f0a1d09c88e65da4d8ee64f68c02189bbb3584baff716c85db654048a004333489393a07427cd3e217e6a345f6c2c2b13c27b337271c0b27b2dbaa00d237600b5b594e8cf2dd625ea76cf0ed899122c9796b4b0187004258049a477cd11d68c49b9a0e7b00bce8cac7864cbb375140084744c93062694ca795c4f40e7acc9c5a1884072d8c38dafb501ee4184dd5a819ec24ec1651261f962b17a7215aa4a748c15836c389137678204838d7195a85b4f98a1b574c4cd7909cd1f833effd1485543229d3748d9b5cd6c17b9b3b84aef8bce13e683733659c79542d615782a71cdeee792bab51bdc4bbfe8308e663144ede8491830ad98b4634f64aba8b9c042272653920f380c1a17ca87ced7aac41c82888793181a6f76e197b7b90ef90943bb3844912911d8551e5466c5767ab0bc61a1a3f736162ec098a900b12dd8fabbfb3fe8cb1dc4e8315f2af0d32f0017ae136e19f028"_sb, "3b835a5fa145387a0819c4daa1e65fbe2ba5400afcd640bbddbbe3585f24bedd51289694a4fe643cd5af9c8eb277c3f1877a347a97ebea8a037971c6b37993e433cfaf580eba4b7fda990d54bf4d60caf9d1cafc477fd956f8e6070b6aeec6776eb814835407b5f705db9472701d16e00655024a309b14ddbf36d222bb509647a5a049d5816f49ad9f2975ddb64c2df05ffeb24c6a3f24a786dbf4f6d5666fc55fb73539679dc15b72fb4f6ce38feb281d28c908d5195db7008315978ef9d2c67dc4dbcc4962467a2d44f7235fa54ebd88bdec32408b1f7aff1b842064075651f03a3afd2721ed1fe4ff1a8775c6b4d95764555412cff2f8aa4404900f33585f0bd1b70955cff80130dcc2403920e9744a3d0da914405561ecb2bb32120b7adbd2f4d8e9a07b4630480b8df8c068934ffd9bc9b855a888eeca090f211905e074a078ab68917e7445a6c7c7e39403753ce19b6614b9d222ab99f263a681cec6c037587ef051f0f7294e376528b31789a530342258241c99ae7d384bcd61012a32a977c638b09a3bc16a33aa47cf2d7f12d79d8aa50f63c8c53c439800b2ed9bba9481eb181b4244ed067d62695d6a99dfd7bf8788c159caaf94e9fda92ac5a93f59a0df7c0f9bbd417cb8cf45d1076006e08a9e585ee4d7394265582a87641f1653be9edf194401e6e4ee93c4ab054a1b6e81e3bf01fd26f2e9a6db5bf6c0dbd21e14c2e1a5a4cff0b267ed95427b0b049eff7fbc093b054510578523ac7a32cc1f8edfcf078a6c71e6e6788edfda7d7badd375f7d911efafb9cb406e968bc5989418fb09729ed51c92c4aeae10846384f4a091c405ad85773fe0ade816eddfd618ba0ea5deb73cc43592e063015118025542871e7a60f844a6b2c3d630f9c6f85791e8d2bdf3578ff92628e8acaf02b88d79797fb1ac30153201fcad2234fbd4f2fc84fa7d2ab6fb2e4d9b55f11dd91a798726107c6842c3e7a1ca895035a8fe701058e3426e17bbf04c23e78ffb283e027e1c636b1cf9ded3f5909ebcb0fc63608e918c9ea9a7f7b6d3ece727dac128d31b7c0ffd9e43046ae6a53c25888d0e602b2302e255dca8c58c10c010269152582c598fdda0b8f43e311ea15ba96e0d9ff3936f5f18631fb9d03020e342647be078c12a9475474b3dee55abc0e3dd804d73fd929b6af94a67dd27c35b5fc2c9bce500b8103b984423cec746231a5b819acdea138816e70a95005ea92f7232b666e772c060f95e20612eb7dad3297a342a7817c73e24318a0b761562d1ccb6b5d618cbe06f4b1e7b351b6b831fc83479eb34bf947b68b3a1b557ad866872656c9f59e7578061e84dbae900af3301bef1eaa0c6424746302930bb685c8f3d9721521ed61bb648a4d5335c4ebf3061f8863941955242feeec86462828239f460f55cf9de10bada5627f9d3328362d6ada08f70f0c65c5a155b2da66156a6aae555c0371328924928e046135daaf48b86c1ea78b56f40afb2794fb74b9627e2a43aabf3e17a84ee7ad30cf79eb20a72ac69"_sb,
            "ac865f839fef1bf3d528dd7504bed2f64b5502b0fa81d1c32763658e4aac5037"_sb);
    }
    {
        check(
            mlkem<1024>{},
            "433a70ee6950f9882acdd5a47820a6a8163708f04d457c779979b83fe117224701490830386637da332e74b1aeda0b2f81ca4f9bb2c2b02b0cfd680c11482f335acf7b9139b5b88a34e3542c6861377545983343cd829414e47864212e78f855f52390379acc3a62953131b63ee832adb3bf4bf58e247349b5e097e55abe497b15982373ae732e0439ac67d05c7f037c8a739b18140e144c851dc9611f4bcf04f3a2093c197bd63bb5e6190100545ff81db7fccddd9a324b0bac3c2c2382284058f08b961952c094019c10be37a53d5ac794c010a9d0821f15027a1c419c3c71c9a1d28aed02597ab79b875394626ba39adc090c3a90cf75871a65275eb1c5b03372e13a1a23d0cf9374111f80cc83a905622b83fc513971ec8419f0880c3067633671b09b5456ab6057936d19a4a2a267911b000a13956fbd493821da072c04642b0c20da6cc0d9d864a39365dfd64f10187825fa33250749cbc0c905d7b1ff3cae2412bf86b81a817b86baa30edf7862e5f6bac98726e56b3cec60664caa2a7df670c5e207dfac03824c89897cb490eaa76521222c86205169c91c329c4a184d78721af836ad4db0ca78464d4171473012b7d183bafa627585c64be3809d7e6004cbdc79a5460f0ad677cb716512407d3a619ad09543b739547472a706b317a509be5d861fd66c7d0ed94cd5004795c18159e3a33d798711525f1635a68428172923249635aad032b9e56664bdd48ed24ac75c6468d1903e471086c5f1567e831a0508c539632591ab577d324a82429725809950761d8434288c14034f1c06c1d0aae09a71c740a55701c28ff84499f2bb18b6628caaa3fe75ac4de04c6f913900d86c88126252a17c4d303991db0287120881bb88478aaa9af9bc53d3729843858fdb4648059cac82c1a10878ba39823b041bd0e258487b56cc8a3220c1a58bf66a172b5b9a0c632d674eae885a015c4e37ba073680bede7534f3e34b6050c86b21c3c090941f23b7f6731e2bda0e6ea4646771cec572b98ca0a158919adbeb84ce585ff9f25ebdda6cb6f07a8f811232607e7217bb039babd0d91934a8594059c9687723c04381bfd627a10517f5f4bfc77777aa2671ae124f2b7a5f4d5614029197e6586fa8c17e0ad90781bc7bb19a772d5a4efe32cac89b76c42a5ede9bcc20c1898c08a5b0c07e478b1bbc226efad15f2ac737514b8c6149810779222416537ed00daeab177e903ead6b4ac42370af1b1f50ebafaa1c6e647bbacce72c7d0b88aeb0b06fc1a45457a9c187579bf184579cc351c43dff942605aa5604fc85fc5583f6f1496fe61d70d6cde2327fee713d86f29b3afcbb54e9a92a33a6c1ea6ffa309566b0686233c0f3b1c3144890e4f0829a6099c5749cdec84328ec2cb64a7385a761d64b3a23c489343343b97723ae78c7d805458e1620f0292897691704cb76e3b0b281a83cf64490498cbcaf04802416b33c565171d772d3b9354037587629ae14a5c5031ac36671a0d0c91cc0b4cd69d8402e33b9bcc2bbaf6b971e303fa137be232598a4999bc012574c81651b38b38396c1c365303ad25d49fc6b689951a1cc4c6007613065495f97910f9735d4ea4e442acb2fabaecfe1adef0667ba422c954a05d1b6167a263e1275c6ada8385965304b30324040542cf5a451bcafc74788be3b9b9fcc45d4790e2d7335c60a14f0a49d13053f2626a627ca19553cb336a2cb4a455d8ef3989491472ba0051ef7416e0bbf1a6108fa07c161548e7c62331ae5a2b4e4a108a51093d3150821a2fb547170a1b73c43c550c6557a4048a58a2cd77a244234b2235175a0897d5061b4613482dc136414048c11db37eae0a5df87c19314b0e82397a0d338dc21538af36149d93f8b1a11c53bb5def8b7a2cca3362b7fe3a1408a2547e209058c673a7566c26123a6d8b692a5f33ebdcb2624b79d877bce5fa14e42e83faad82e9900553a3c6045ca329fea4a506558c491b6a616c6fd400b42136f44cb0d0257650819018d3c568ef6c60c6c409e70a829287108c1b6a4d32f76e5cc4d104b02438ef7a467912398ea9c7cbd9981589a341897687b516a13307d66c068c444b4b949a17412413315ccf49b99980034b5b8cfdec4a60b9c1e7455aafbf3a757346990cc32b0599ba217a6c5fc39537911957c125148a87f41589cb222d0d19229e2cb55e1a044791e7ca61192a46460c3183d2bcd6de08a5e7651603acc349ca16cba18abb23a3e8c330d7421598a6278ec7ebfabca0ef488b2290554753499c0452e453815309955b8150fa1a1e393386dc12fdb27b38c6745f2944016ec457f39b18d604a07a1abe07bc844050ffa8a06fa154a49d88fac775452d6a7c0e589bfb5c370c2c4b6201dda80c9ab2076ecc08b44522fda3326f033806dd2693f319739f40c4f42b24aca7098fb8ff5f9ac20292d02b56ac746801acccc84863dee32878497b69438bf991776286650482c8d9d9587bc6a55b85c4d7fa74d02656b421c9e23e03a48d4b74425c26e4a20dd9562a4da0793f3a352ccc0f18217d868c7f5002abe768b1fc73f05744e7cc28f10344062c10e08eccced3c1f7d392c01d979dd718d8398374665a16a9870585c39d5589a50e133389c9b9a276c024260d9fc7711c81b6337b57da3c376d0cd74e14c73727b276656b9d8a4eb71896ff589d4b893e7110f3bb948ece291dd86c0b7468a678c746980c12aa6b95e2b0cbe4331bb24a33a270153aa472c47312382ca365c5f35259d025746fc6595fe636c767510a69c1e8a176b7949958f2697399497a2fc7364a12c8198295239c826cb5082086077282ed628651fc04c639b438522a9de309b14b086d6e923c551623bd72a733cb0dabc54a9416a99e72c9fda1cb3fb9ba06b8adb2422d68cadc553c98202a17656478ac044ef3456378abce9991e0141ba79094fa8f77a300805d2d32ffc62bf0ca4554c330c2bb7042db35102f68b1a0062583865381c74dd913af70b26cf0923d0c4cb971692222552a8f4b788b4afd1341a9df415cf203900f5ccf7f65988949a75580d049639853100854b21f4018003502bb1ba95f556a5d67c7eb52410eba288a6d0635ca8a4f6d696d0a020c826938d34943c3808c79cc007768533216bc1b29da6c812eff3340baa8d2e65344f09bd47894f5a3a4118715b3c5020679327f9189f7e10856b238bb9b0ab4ca85abf4b21f5c76bccd71850b22e045928276a0f2e951db0707c6a116dc19113fa762dc5f20bd5d2ab5be71744dc9cbdb51ea757963aac56a90a0d8023bed1f5cae8a64da047279b353a096a835b0b2b023b6aa048989233079aeb467e522fa27a5822921e5c551b4f537536e46f3a6a97e72c3b063104e09a040598940d872f6d871f5ef9b4355073b54769e45454e6a0819599408621ab4413b35507b0df578ce2d511d52058d5749df38b29d6cc58870caf92f69a75161406e71c5ff92451a77522b8b2967a2d58a49a81661aa65ac09b08c9fe45abc3851f99c730c45003aca2bf0f8424a19b7408a537d541c16f5682bfe3a7faea564f1298611a7f5f60922ba19de73b1917f1853273555199a649318b50773345c997460856972acb43fc81ab6321b1c33c2bb5098bd489d696a0f70679c1213873d08bdad42844927216047205633212310ee9a06cb10016c805503c341a36d87e56072eabe23731e34af7e2328f85cdb370ccaf00515b64c9c54bc837578447aacfaed5969aa351e7da4efa7b115c4c51f4a699779850295ca72d781ad41bc680532b89e710e2189eb3c50817ba255c7474c95ca9110cc43b8ba8e682c7fb7b0fdc265c0483a65ca4514ee4b832aac5800c3b08e74f563951c1fbb210353efa1aa866856bc1e034733b0485dab1d020c6bf765ff60b3b801984a90c2fe970bf1de97004a6cf44b4984ab58258b4af71221cd17530a700c32959c9436344b5316f09ccca7029a230d639dcb022d8ba79ba91cd6ab12ae1579c50c7bb10e30301a65cae3101d40c7ba927bb553148d1647024d4a06c8166d0b0b81269b7d5f4b34fb022f69152f514004a7c685368552343bb60360fbb9945edf446d345bdcaa7455c74ba0a551e184620fef97688773d50b6433ca7a7ac5cb6b7f671a15376e5a6747a623fa7bc6630373f5b1b512690a661377870a60a7a189683f9b0cf0466e1f750762631c4ab09f505c42dd28633569472735442851e321616d4009810777b6bd46fa7224461a5cc27405dfbac0d39b002cab33433f2a86eb8ce91c134a6386f860a1994eb4b6875a46d195581d173854b53d2293df3e9a822756cd8f212b325ca29b4f9f8cfbadf2e41869abfbad10738ad04cc752bc20c394746850e0c4847dbebbe41cd4dea489dedd00e76ae0bcf54aa8550202920eb64d5892ad02b13f2e5b505d7cfad1b497499323c8686325e4792f267aafa3f87ca60d01cb54f29202a"_sb, "537911957c125148a87f41589cb222d0d19229e2cb55e1a044791e7ca61192a46460c3183d2bcd6de08a5e7651603acc349ca16cba18abb23a3e8c330d7421598a6278ec7ebfabca0ef488b2290554753499c0452e453815309955b8150fa1a1e393386dc12fdb27b38c6745f2944016ec457f39b18d604a07a1abe07bc844050ffa8a06fa154a49d88fac775452d6a7c0e589bfb5c370c2c4b6201dda80c9ab2076ecc08b44522fda3326f033806dd2693f319739f40c4f42b24aca7098fb8ff5f9ac20292d02b56ac746801acccc84863dee32878497b69438bf991776286650482c8d9d9587bc6a55b85c4d7fa74d02656b421c9e23e03a48d4b74425c26e4a20dd9562a4da0793f3a352ccc0f18217d868c7f5002abe768b1fc73f05744e7cc28f10344062c10e08eccced3c1f7d392c01d979dd718d8398374665a16a9870585c39d5589a50e133389c9b9a276c024260d9fc7711c81b6337b57da3c376d0cd74e14c73727b276656b9d8a4eb71896ff589d4b893e7110f3bb948ece291dd86c0b7468a678c746980c12aa6b95e2b0cbe4331bb24a33a270153aa472c47312382ca365c5f35259d025746fc6595fe636c767510a69c1e8a176b7949958f2697399497a2fc7364a12c8198295239c826cb5082086077282ed628651fc04c639b438522a9de309b14b086d6e923c551623bd72a733cb0dabc54a9416a99e72c9fda1cb3fb9ba06b8adb2422d68cadc553c98202a17656478ac044ef3456378abce9991e0141ba79094fa8f77a300805d2d32ffc62bf0ca4554c330c2bb7042db35102f68b1a0062583865381c74dd913af70b26cf0923d0c4cb971692222552a8f4b788b4afd1341a9df415cf203900f5ccf7f65988949a75580d049639853100854b21f4018003502bb1ba95f556a5d67c7eb52410eba288a6d0635ca8a4f6d696d0a020c826938d34943c3808c79cc007768533216bc1b29da6c812eff3340baa8d2e65344f09bd47894f5a3a4118715b3c5020679327f9189f7e10856b238bb9b0ab4ca85abf4b21f5c76bccd71850b22e045928276a0f2e951db0707c6a116dc19113fa762dc5f20bd5d2ab5be71744dc9cbdb51ea757963aac56a90a0d8023bed1f5cae8a64da047279b353a096a835b0b2b023b6aa048989233079aeb467e522fa27a5822921e5c551b4f537536e46f3a6a97e72c3b063104e09a040598940d872f6d871f5ef9b4355073b54769e45454e6a0819599408621ab4413b35507b0df578ce2d511d52058d5749df38b29d6cc58870caf92f69a75161406e71c5ff92451a77522b8b2967a2d58a49a81661aa65ac09b08c9fe45abc3851f99c730c45003aca2bf0f8424a19b7408a537d541c16f5682bfe3a7faea564f1298611a7f5f60922ba19de73b1917f1853273555199a649318b50773345c997460856972acb43fc81ab6321b1c33c2bb5098bd489d696a0f70679c1213873d08bdad42844927216047205633212310ee9a06cb10016c805503c341a36d87e56072eabe23731e34af7e2328f85cdb370ccaf00515b64c9c54bc837578447aacfaed5969aa351e7da4efa7b115c4c51f4a699779850295ca72d781ad41bc680532b89e710e2189eb3c50817ba255c7474c95ca9110cc43b8ba8e682c7fb7b0fdc265c0483a65ca4514ee4b832aac5800c3b08e74f563951c1fbb210353efa1aa866856bc1e034733b0485dab1d020c6bf765ff60b3b801984a90c2fe970bf1de97004a6cf44b4984ab58258b4af71221cd17530a700c32959c9436344b5316f09ccca7029a230d639dcb022d8ba79ba91cd6ab12ae1579c50c7bb10e30301a65cae3101d40c7ba927bb553148d1647024d4a06c8166d0b0b81269b7d5f4b34fb022f69152f514004a7c685368552343bb60360fbb9945edf446d345bdcaa7455c74ba0a551e184620fef97688773d50b6433ca7a7ac5cb6b7f671a15376e5a6747a623fa7bc6630373f5b1b512690a661377870a60a7a189683f9b0cf0466e1f750762631c4ab09f505c42dd28633569472735442851e321616d4009810777b6bd46fa7224461a5cc27405dfbac0d39b002cab33433f2a86eb8ce91c134a6386f860a1994eb4b6875a46d195581d173854b53d2293df3e9a822756cd8f212b325ca29b4f9f8cfbadf2e41869abfbad10738ad04cc752bc20c394746850e0c4847db"_sb, "3ca7a7838b26ff0e598f1d4cd6516fd8d28b7c3a61607204c7fdb39009d04911c11f9187db0e6dc05dedea6462aa00ff67bb40285cac7501fd5b7d9e2cfc8b9177a126b62567cff1f665ee05705495017c5c40001f6a7abc47d34f36d183b624e4bb75f92600f2eea70a2052ffea7919871ec27f960e9eed46bcf8713c396c6f2f3cbd0b1eb6cf136a97ff2435f1b310db70206f52b268bb768407a27b31edc8de55ef53192de1304d15e6c5523e5b1bb96d9f288ddb9ed65e8e32701d3858832d9d7cde72e716565f5788035a087121f60bcdc72aa386a1bcda978e15f4aa736bd2f884e0a66775d6e2ce78b73d109267c48080396e22b42d4dd0c2d8e75065f1eeae8654ff9c259465ff4ab2c253f517b8db481cd6c00d573d0b46cc7e4644dfe0e1e2f997b586b2cccc75f52dec788ac214f8013782206023ebe8f72289664ec637a6f988bee8cba25226aeabbf09179e41e7e6168e30819af0a89a745671f3c5a10560db93d5edaf63ac7539a8616d84b37bf4245b09e5248d7e4042c4c0d5585504bb825e0ed05ec08f3f3b4365611299f8f5d2be0b2e4538a2bd3938194d7f5c79ff8af9622b336dbc31bcb7d60f6a190883f498b4de4688b3f5475a200493d9c8218f85256e87ccb3013723c7a264a3ab764acfc8dcfe2ce359a7bd53ff7f68a842751cfcbdd39ebb1c44f65739c071af6c24220575296e85ae4458e0f676348a2d7cdb64378e75abc74e86d346480949c6a6d3627611cb2cdf7714ec779bf08a47616760a49f30a1a712493f190d433e7828cab45037cef6c863c5a3cacd5c14bc2e36bb3296e187e1796d2738b32835620e142e1adf096bf309cdc83a1545e414232b9905bbab1fd23bab0d93d4df0ad8314809fedf7a97992871f5bd238fd72ff52bad31f934ee5435e0e32a2be4519e2ba670bb443a0e227a3d44b400cc48a31475a98233930cab930bf498cc30ccb0421dc412c3190a98a03d8ece1816def4d358e3c3c1d4249264252d02de48e2b2216a2b246a61eac8dec3f8a4bdc2a69085dfec3ad5c80852b0960da201828ef04aae93e026deb3c6704904801b4101aae305013581294f1f34877376a18db8eec0f1bfe9b596be86383244f999e298acb04287ace035d5b89b2f9da1cbdb5779994e5733dcc4de22ad2f3f9f1ef49e5deb80ec9ac133df3e0bb9be7cd8db478eb3111bb6d716849f4a48ca795bd049ac1c3939862bf9091697f054ea7dddb4224579bc3e3d946e7d881669a290c23a4a222b3c90071333e404bc10842749f7d3051175ccc645146a991cf07af05020a2fdf94f474df6bfe24790047497257930fafc7b9a56d1c06ec95859b9576acf45c98cc8d7434c03c90b0117da333388aa87de75a5441ea63f27235be4a7d25b1d1afe291c857955e38ae39d3cf469b2fbbeb327aae7c56e9057f5cc592b37d9d9d671f7c91ccfe0c282c3f285b6cf2fdd6fb110b898cddcbd37787ce8e954b70890f0daa90f4a5791360f4f1e68d64fa7a48a0fd2e38490482efa90a869535d320c6b6575fe8e0e5518e9de40d9f10bf35f499a30adb975cfabba568e28ca3ab81e21679e6768ee5c890f4c5e9349f02337edfafe4efe1023e93ce32e84039bfca516e86986649aee3e475be7b3644774dabbb6ca8b5c77b4ca1865d776a10043cdcbc612df0f436a8252dea172a9f2686b03ff96f9b2905240afa24551916f8f82944f3ff7173f6ea487159ec83c290fae1440cc54ce6f785bbc3cb3763fa98cf917d33bca00f56d90491668a1ee89d76116f7f19edcdf7160240b9882261387e190b116a95f2ddfd2d8e5b03dcb850b89584ee9ffecedabaf7f15030e16679757d4a27e2014a04dd8feefffca2ec795fa9a6fd31a3f3a74e440dae018e5f174141e200ade656e3c9689bffa04d3feafaab95d7ed5d5e75461b236559826347daf9e8df8fa27904bab7078433ed9bd4557c78468da6b747e13d6e5c97d927a5b0915097316a6fe21eda26d230cf19ba826485c93365814bf50fc8e4af90392cb0bb79570216fd9543271b6205dc44416bbf41448240d283e367c4cab21f090941d2e4033b7cf02a345ae9ee8550a4cf19775cfd440e70ce838552a31719d8789401d33f01f3ee558a992d71fd309ccbe9689c48b3667930fd8c7ddca717e7c77dac273d7f4ca77757aca23ff2e558ceef152075add70baa763c29f"_sb,
            "ea636ce31b73f40229572146b97e590f1605fdadd1c3781861530effcf2b1e18"_sb);
    }

    // boring ssl
    {
        // # Official test vector 0, seed: "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1"
        check2(
            mlkem<768>{}, "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f"_sb,
            "147c03f7a5bebba406c8fae1874d7f13c80efe79a3a9a874cc09fe76f6997615"_sb,
            "da0ac7b660404e613aa1f980380cb36dba18d23256c7267a00a67ba6c2a2b14c414239662f68bd446c8efdf36656a0891a3cc623fc68b6572f7b29a6de128014411ee41906d08071f94856e36a832b40338d743516659bd25879c007a52bc9586f79876afac6c9a30d8fac243bd22425d6adce42ab7ed39014757a958bc8a74565f019234ff04b34893ed6d05501c37255239aae2ac19f8c75ac5900dae8300dbba710dc2caae1bca3a38c58342b286b8518f136ad15b9f7bcbb06a5607db375dbe976457c26c6598257531b2cfb6ee7f51591840804c38388376c27148413da9e92920bfd9a069e018bd272053da8775c0b739f761db2107cf35a434d69b07e5bcdb87434138b0cb556761ba522a5747b28747d80eb9d6cc673bee5769377b996d36ceb0c0c7ed9a658533324869c18a1a36f31470f14c5ae49ab070507f8249ce404b49c0a8c3ee42fea9631fa1a0d10d86b93f986e0e3a82e703b74e5ae6101242421a89aa07fe68588460baa368786486a72e4f24d2dd76cfc03b694a5ba91a755a0b98f3bf93307c0ab64639aea7a6498a3c3ddc571141abca4678cd2e2b857fb88f600caa596b44bc422250b2819e0515f0472391853700b01eff9453fd11876b7c759a07dd845caba4555264a82765193fdf81b620a1e1f923fb24442cd1cbe94175003ec06ce77a3c64493c199987a300c95c53c0089b5d65c92ea971b2ffa93b52a461ea2ac8c199c2f4c2b704297ce3c3949e0735ea8a14aa59e8dec0c878399ff70747ab244ce46b5f2230473323d25c66fe6b419b1f4a112e5214035256bc43ffd2b6b7b378769a6b47000bfb6357d45814baef3857d379e2fb8b5e5201ab26274bb1b70ad322cd0439b2db109cff0a2f8e600995571ffc38c590bc4c7615c69d0c98ef430f30861a77238ffc07061e475d6a30ad1b47fd039c3a447762db2211dc31d0acacfd55890a5824798f9aead7413dfe028b1012be8b6ca1026666ac6bc9440a449b51ad8bba7b0921dd4d8b4a578136d1a05db38cc858437b25161d1c3c28ee07bbcf2b249110d22781dc3050d8cc0090096b38a850696f86e9e6bab325271b2248675011968502881090497fac0af843c1aea76dd81cf29c012c66227b7f06d9961309b0262f732c9a4d0bbd06727abb8371ff2c11899a098375c460516b2cc88bcf628ede37d8f3b3342e4490a85606ec03da29b0256275382a3313dc041114801032c519f350c3e6abac3e33b93b4a19f7c5466e58cb1dc14b4a96c475729f971bdf173cdf354824d019427f95b3b4a4a4a958e476a6e6991ce6f06cb5dfca7d4380c3d920b5711ac1fcbaf4b9ac800b976d1ec766a626cc1900b66b3a9dc62c5c144527a296baf70433bf657c0437f87597bd7c8bbbe9abc37050931a4a86982a2028a74454c9b810c88d1701c8cc98a1d4ca107a6b25e962fe4b6b03c95453260b807228637cc9eb12acc0954959a52ae54d1977300aba0ba2c14609bb28c11d5fac5cac88297603283e867a3648366c724d9354cd7a196dbd9802f7b88d3fa001f9c9773225462235e91352a20791fd8b87fe3377ec6a3940b1130a0bb04e7410a34e2580d071d6c56202086787a6590f84393a8e651a1e685f22478a8954f007bc7711b930772c78f092e82878e3e937f367967532913a8d53dfdf4bfb1f8846746596705cf345142b972a3f16325c40c2952a37b25897e5ef35fbaeb73a4acbeb6a0b89942ceb195531cfc0a07993954483e6cbc87c06aa74ff0cac5207e535b260aa98d1198c07da605c4d11020f6c9f7bb68bb3456c73a01b710bc99d17739a51716aa01660c8b628b2f5602ba65f07ea993336e896e83f2c5731bbf03460c5b6c8afecb748ee391e98934a2c57d4d069f50d88b30d6966f38c37bc649b82634ce7722645ccd625063364646d6d699db57b45eb67465e16de4d406a818b9eae1ca916a2594489708a43cea88b02a4c03d09b44815c97101caf5048bbcb247ae2366cdc254ba22129f45b3b0eb399ca91a303402830ec01db7b2ca480cf350409b216094b7b0c3ae33ce10a9124e89651ab901ea253c8415bd7825f02bb229369af972028f22875ea55af16d3bc69f70c2ee8b75f28b47dd391f989ade314729c331fa04c1917b278c3eb602868512821adc825c64577ce1e63b1d9644a612948a3483c7f1b9a258000e30196944a403627609c76c7ea6b5de01764d24379117b9ea29848dc555c454bceae1ba5cc72c74ab96b9c91b910d26b88b25639d4778ae26c7c6151a19c6cd7938454372465e4c5ec29245acb3db5379de3dabfa629a7c04a8353a8530c95acb732bb4bb81932bb2ca7a848cd366801444abe23c83b366a87d6a3cf360924c002bae90af65c48060b3752f2badf1ab2722072554a5059753594e6a702761fc97684c8c4a7540a6b07fbc9de87c974aa8809d928c7f4cbbf8045aea5bc667825fd05a521f1a4bf539210c7113bc37b3e58b0cbfc53c841cbb0371de2e511b989cb7c70c023366d78f9c37ef047f8720be1c759a8d96b93f65a94114ffaf60d9a81795e995c71152a4691a5a602a9e1f3599e37c768c7bc108994c0669f3adc957d46b4b6256968e290d7892ea85464ee7a750f39c5e3152c2dfc56d8b0c924ba8a959a68096547f66423c838982a5794b9e1533771331a9a656c28828beb9126a60e95e8c5d906832c7710705576b1fb9507269ddaf8c95ce9719b2ca8dd112be10bcc9f4a37bd1b1eeeb33ecda76ae9f69a5d4b2923a86957671d619335be1c4c2c77ce87c41f98a8cc466460fa300aaf5b301f0a1d09c88e65da4d8ee64f68c02189bbb3584baff716c85db654048a004333489393a07427cd3e217e6a345f6c2c2b13c27b337271c0b27b2dbaa00d237600b5b594e8cf2dd625ea76cf0ed899122c9796b4b0187004258049a477cd11d68c49b9a0e7b00bce8cac7864cbb375140084744c93062694ca795c4f40e7acc9c5a1884072d8c38dafb501ee4184dd5a819ec24ec1651261f962b17a7215aa4a748c15836c389137678204838d7195a85b4f98a1b574c4cd7909cd1f833effd1485543229d3748d9b5cd6c17b9b3b84aef8bce13e683733659c79542d615782a71cdeee792bab51bdc4bbfe8308e663144ede8491830ad98b4634f64aba8b9c042272653920f380c1a17ca87ced7aac41c82888793181a6f76e197b7b90ef90943bb3844912911d8551e5466c5767ab0bc61a1a3f736162ec098a900b12dd8fabbfb3fe8cb1dc4e8315f2af0d32f0017ae136e19f028f57262661358cde8d3ebf990e5fd1d5b896c992ccfaadb5256b68bbf5943b1328626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f"_sb,
            "a8e651a1e685f22478a8954f007bc7711b930772c78f092e82878e3e937f367967532913a8d53dfdf4bfb1f8846746596705cf345142b972a3f16325c40c2952a37b25897e5ef35fbaeb73a4acbeb6a0b89942ceb195531cfc0a07993954483e6cbc87c06aa74ff0cac5207e535b260aa98d1198c07da605c4d11020f6c9f7bb68bb3456c73a01b710bc99d17739a51716aa01660c8b628b2f5602ba65f07ea993336e896e83f2c5731bbf03460c5b6c8afecb748ee391e98934a2c57d4d069f50d88b30d6966f38c37bc649b82634ce7722645ccd625063364646d6d699db57b45eb67465e16de4d406a818b9eae1ca916a2594489708a43cea88b02a4c03d09b44815c97101caf5048bbcb247ae2366cdc254ba22129f45b3b0eb399ca91a303402830ec01db7b2ca480cf350409b216094b7b0c3ae33ce10a9124e89651ab901ea253c8415bd7825f02bb229369af972028f22875ea55af16d3bc69f70c2ee8b75f28b47dd391f989ade314729c331fa04c1917b278c3eb602868512821adc825c64577ce1e63b1d9644a612948a3483c7f1b9a258000e30196944a403627609c76c7ea6b5de01764d24379117b9ea29848dc555c454bceae1ba5cc72c74ab96b9c91b910d26b88b25639d4778ae26c7c6151a19c6cd7938454372465e4c5ec29245acb3db5379de3dabfa629a7c04a8353a8530c95acb732bb4bb81932bb2ca7a848cd366801444abe23c83b366a87d6a3cf360924c002bae90af65c48060b3752f2badf1ab2722072554a5059753594e6a702761fc97684c8c4a7540a6b07fbc9de87c974aa8809d928c7f4cbbf8045aea5bc667825fd05a521f1a4bf539210c7113bc37b3e58b0cbfc53c841cbb0371de2e511b989cb7c70c023366d78f9c37ef047f8720be1c759a8d96b93f65a94114ffaf60d9a81795e995c71152a4691a5a602a9e1f3599e37c768c7bc108994c0669f3adc957d46b4b6256968e290d7892ea85464ee7a750f39c5e3152c2dfc56d8b0c924ba8a959a68096547f66423c838982a5794b9e1533771331a9a656c28828beb9126a60e95e8c5d906832c7710705576b1fb9507269ddaf8c95ce9719b2ca8dd112be10bcc9f4a37bd1b1eeeb33ecda76ae9f69a5d4b2923a86957671d619335be1c4c2c77ce87c41f98a8cc466460fa300aaf5b301f0a1d09c88e65da4d8ee64f68c02189bbb3584baff716c85db654048a004333489393a07427cd3e217e6a345f6c2c2b13c27b337271c0b27b2dbaa00d237600b5b594e8cf2dd625ea76cf0ed899122c9796b4b0187004258049a477cd11d68c49b9a0e7b00bce8cac7864cbb375140084744c93062694ca795c4f40e7acc9c5a1884072d8c38dafb501ee4184dd5a819ec24ec1651261f962b17a7215aa4a748c15836c389137678204838d7195a85b4f98a1b574c4cd7909cd1f833effd1485543229d3748d9b5cd6c17b9b3b84aef8bce13e683733659c79542d615782a71cdeee792bab51bdc4bbfe8308e663144ede8491830ad98b4634f64aba8b9c042272653920f380c1a17ca87ced7aac41c82888793181a6f76e197b7b90ef90943bb3844912911d8551e5466c5767ab0bc61a1a3f736162ec098a900b12dd8fabbfb3fe8cb1dc4e8315f2af0d32f0017ae136e19f028"_sb, "c8391085b8d3ea9794212541b2914f08964d33521d3f67ad66096ebfb1f706424b49558f755b5625bae236f2e0079601c766f7d960808f7e2bb0c7a5e066ed346de628f8c57eebabbb0c22d911548463693ef3ce52a53f7ff415f00e657ae1c5a48fa5ec6e4be5cf462daffc84d2f6d5ff55dc9bbe8bb0d725ec64fd4cd4bd8dba0a844e8b5ce4b6a28934d7f7a050991fe185b506b451dabfad52d52cb2114ca7d9a5cf986c8fdc1bc10ec0c1869e50c03c55a76192a1049aca636ba9020bdaa8d0f58c763b0b89845ca06d4c4ddc21433e16b9c62e44871fdbc05ba218af871fdd7dcfa464e60faa5265264ce1391bd9a8c5faa7626d5f159b9805b975710a3503a0b858a11c6a647cc0e19ac88b1be9056c95b4d2087d0951d1d2f4992491117e6347794ba54571ec49bba71af3413d38a30bf5872248d1f6d07c86baf782e73d2637f043d341a00921857d8b21ddf3e1d6310036ed27af49e5de1b900fe4de79808ff29f9570859612b15adc01fbb265b305b1e3a12ae419da5b74261fa284c101da3d8dca8b2e4521aca571ef44a058e844ff32b16d5aaea05f7f3af8e2ab16222e347662eddfb891d0ecc2a55c5638f9dde92d9a3d544a5f901ac501acd1ea6a010201fcb10ad702c425a94bdf5890d500a2a147eee1d1fcba8c3abe7c2dfe70f346f033d816a0b2791b4f0b2d956d9ee5971715399a5688302495e2e07c1c8c01527184bcd0c208bc159f2e13318c0bb3dd24a6a7fc849f83385ed4dba07fe1d7bd5640cc9ed5ccfdd68763cb0d0edf61b292177fc1d2d3c11dd0495056bcb12558aebcfddef9feb4aebc57afd9023c65cfe65a24e33f1b00111e92e63e011eaf0b212cf95743cd07f5189ece1f205b7f6fcb2e6b1961b5404cebe47c8cd13b8599d5b49e6d87eeda36e9b8fc4c00635896aa2b75896e336d1b612ee13db811e1f07e61748d920f4865f3f11741399dc6162c91ca168a02329dff821d58198712dd558abb099b3a0baf9da1b730b2aa73bcf58d74f357b06f7211c804b6c8af16ff3509fad1d35b14bfdced7db8a6a25c48e5956480724daa057cd660b67ee3e472574182679d485838a6476eac02141075c812af7967ba7c9185cc2abd2a4545b80f3d3104d58d654a57792dcfabbe9c0715e8de2ef81ef404c8168fd7a43efab3d448e686a088efd26a26159948926723d7eccc39e3c1b719cf8becb7be7e964f22cd8cb1b7e25e800ea97d60a64cc0bbd9cb407a3ab9f88f5e29169eeafd4e0322fde6590ae093ce8feeae98b622caa7556ff426c9e7a404ce69355830a7a67767a76c7d9a97b84bfcf50a02f75c235d2f9c671138049ffc7c8055926c03eb3fb87f9695185a42eca9a41655873d30a6b3bf428b246223484a8ff61ee3eeafff10e99c2c13a76284d063e56ab711a35a85b5383df81da23490f66e8ea3fcba067f5530c6541c2b8f74717c35023e7b9b3956c3ee2ff84ba03ccf4b4b5321b9240895481bc6d63c1693c1847852f8e97f50a133532ac3ee1e52d464"_sb,
            "e7184a0975ee3470878d2d159ec83129c8aec253d4ee17b4810311d198cd0368"_sb);
    }
    {
        // # Official test vector 99, seed: "2a6f7386b815366f572aeb6c79e272cc21b7095fe09575f18072c9d677da23bc9c8a4bc393b7524604d299bedd260c8b"
        check2(
            mlkem<768>{}, "195d6c86a3df4c21e3007d7f2768b43c74cb3060e0eca77f0a5d3271542b9a84ae77e0f9f21eabd8c0c6eea7767f4e10fde5c2d79b8400bf96b19014b457ec21"_sb,
            "fa0489f3730100609488e951e6aaa15c0f193bc1dbcfcd013bc418d6c507b176"_sb,
            "2feaa7e47b8e973ca66cd8be82e5983d295eee270134086481a92e55d3a282cb4e702b234e3a49ae7b532f6183e0b57e4cf688121a5da377aafdd36f1180816ed91c28038776169ea0a11937e229f7b57447f4295f457bdd89191d6a89f6a7146b55a5cd16c743bc3f3f60bdac4c1ee7727946157bf1929d6b7c15836c6b28445601497e07376426239aa3c0bc8135570d9623ad828f858a6ec5e4946f189864e87249eb574875409aa22967141380c633ece33567da5811b9a40759403becc297ab63622bb9f0b5cbf52378be037882ac9b25414817b4784101683b8696a6f9178323762bc419fe939ab0c8640422743b3a7e628382d36bc42afc4dd206a160dab1d1551b0e7a349e14b5b66077d6b85082306b1dd83ad0b16157e0c1b910a5d3fa562ff2c008804f6c1caa8f18336082ac4f8abce7d4a1e680361140b69b80574658c6f6f0a4d27104dcf29c55c74500db129e55114121764152c0eafc1e88350816057197466b50da92cc034996001a503040b7847fafa5950e8acda9a3c3eaa6b7e475c806401be2183100447d82284515a1a191d01ec7ea8eba84701feb15bd149af2e66cb3844204e3bca83976a088a291fb6c70425a09e42d292b1afeb0c0ac94361b5673ffc25a4b5812d211b0aad388fe1538a5929edcabb11e317de597b8db653cdc552938925a2be642fcb78bbc271584a8b27904c4fb6001304822cba9b96b9b0a79901668236494d68a455129e9869693dab64d4b13b7ca6fad71942b955c1356735b0a27aa037b420300983155c96903bd4b1235c21e8273416660b5b977ce37b6b44bbb09bd197a97cca98cb87a2ff1bc9c0a051ed98560b6b761055d84143f052a686bb3623da02a208b184d1426683484a7594aa22cc705173024f35b8e24977d421606197e0c21c9d145c316b7cedaa13202dc2cd4c62224e01eaf865f7b018a4a938920f848f436ae530a591a2617aa97143f8ab2005b9f9b734c82145c34567c59518a8ca13100ea8b4e3420d698450b70237765b62e433cdd2a842468bcdb42a639aa9644d89f4840351f3096f5c67cf17baad6cba5c79c002ae25a55f224e3b577111b4647e0cb0cb12907554fb96b77a8f267593a3f506b1cf53b6a01136edc0a684e2b8b4825066053c8c232b736c321f1708226fc3a131b1073867cc0872c53a85426ca1bc3756b329598072a352ab82fa8a61429a58ef21c2833d1bde2c1a919c75ad52a4162abbe2829b2fe93c7990ac7cfec8eea930fc5cb9ca13b2da2e80de600325d965982626f001371f59aabff88c74e028c49d5ac3c766efea499e2375a330c91385831e990cd69d6cc8a415a4e563eafa0319607b171b130ac842c66589dcae283af2b884beb6b6ec84e48f037afab54fc2c6486a7a13c9c3396d3b6512a576cb87599aa7aedc97275766d6a96af28327dedb27386923b98b647d5003d5edc718b0477a5164000799ca30c08e8f8a9ee728cd0b0aef4c16b1d61c751e32463e4b785223bee6227e3f88fcb469cf250a64bc7a3149ab3edaa730d6b4e6920b7b5c2bd55b97473b91c3c1c5923067c08db693c97ae832427dc6439576749df139e19d9580ab8c49eb15b80e09e6845335fe1c21f16c49f6b02f2450f4ac135a9eaa5e24a3e3f350a6982b5979a93120285dac88e01923060a795d251c1fedb130828582c95ca7340b2e8e105cfd64f63e63f85a955dcc4b12b0482d0994df7ec61b8b09aa4d1b8ceb94b769a2ae12031d16c05cada3a4d0350e8d970ccf716953543a984cdb086c425915858d454880c97505bbb9ac7cfa54055526689033c8241300e11d09283441043b91354d1c0dcb4a869f225c8ba5b290a77629004ba336c8975366002667c99b88b53a4b08ab564733b5d2a3011f944b2259845dcb6ab8956836656e3370f5981203943b343389f2a98cdc96bc1a996648580b7fe837817ac4db31a2d325a869950a32d99446256cb3d8b91c159683bc8c1ff41287ca54530e84082bbafad485c0f179781950a4722c9114485f6b403f3760678e3bbefda309adc41ca562dbcb739654abc6cb05216807e2fe18fbb485977380d8c0282e271c7f1f8c14694484b76241a1b0cf3928ad9e328357ab75fe909957419defc8e0da3469e7720a5e91df7c4857ed50b89d18ffaf6a045e2c950e178adec7a3d690fa23527d3d353d8731857018d7cc909d081cab0370cfcc8bf8f5463a4fa8706a1abdf2c6a7fe8c834a4ccd8b6c869c6bf93c808a43274620b30aff22bbce53a7ff85145779cba220dabd1b597f4515c1664a374a64ae18884b0919668a70b371e24d2ac1a84af7de3b84f804e105177f6a9b914cb5dce45c678c886b3b24e3649cb194c548fba4114f278a56a4310a7cf1cb16e8ecc0b0fb8a2685b30631753b7f87eec8578684a67634119fe8cb334b67b741305aee8762639a212b9baab4032653b1537327eba5b6fed245d17631e748532426c5a4f4646716521dcc72f4c34a38bc87a892650def1bf09991e4c175d0baa1bf6469277f75a2812aacb88534c491f4d3c884a4470f01b805efc160ec17f68b0b0eb9910889a02467232fdb268848a5d6969c91410775fe717c9103cffb9a2bc13b1bbba01abb92ae303abfefc51af169d25d29316e7a12a5bca6827c25df567ef0c20f13a6fd728a32e229f72b42e74470c88c105bec0a12a1810c3d2a3d84b89a8c9bf66cc305f0b0c3fb989c3541daf147d5b02813e7904cc18a5dbb6632af4a34cd42007f09ab4a88c1705958058bbd6f996fe7642a0b45b690317d0e658ea82094d6b8d55722123fc1bd349433ad4850b19a4f6616685767e67bc21333a9f667a6c422087398b3331c075cea9aea6e29e424653d5e7a86766613732343341491726869eda4f97f1982e62c4cf135b1553a0a842b35e8ac23f29a921039bf31833f12ca8c4f02021559e1ab5bc37d247a5078280f02956ba2e2f897b48e18a769908e6b8b15c63b5a780580d02b5f70749a5442c824a0f56cb00378bc0ea2b033fbc9d45d535ecc00f5579a687865702436d3065461a06c8b274561d938d92290a8c0bbc0cc746aeb253e4823f8bd7b6becb5b1f8a5403fcb40efa5f6c34c43620921a416aa769a6ea1ca15c765d0e53c70b0a719f7b47ff783b63701af5a9cfe704c7d99830734c1b1fe00a1d9166b11060baa09501715310b93ead6825ba9998d922ae362092349aa45abb04781a98b25989e8309c40698a2676b49fbdca7775f554d2448358e6a4bf5373892b712b63af3392fa95dea1a8b6f12914ed31f14f79c652eed4db478de7ebd263fe27052509fee10b50f2d053ae77e0f9f21eabd8c0c6eea7767f4e10fde5c2d79b8400bf96b19014b457ec21"_sb,
            "5fe1c21f16c49f6b02f2450f4ac135a9eaa5e24a3e3f350a6982b5979a93120285dac88e01923060a795d251c1fedb130828582c95ca7340b2e8e105cfd64f63e63f85a955dcc4b12b0482d0994df7ec61b8b09aa4d1b8ceb94b769a2ae12031d16c05cada3a4d0350e8d970ccf716953543a984cdb086c425915858d454880c97505bbb9ac7cfa54055526689033c8241300e11d09283441043b91354d1c0dcb4a869f225c8ba5b290a77629004ba336c8975366002667c99b88b53a4b08ab564733b5d2a3011f944b2259845dcb6ab8956836656e3370f5981203943b343389f2a98cdc96bc1a996648580b7fe837817ac4db31a2d325a869950a32d99446256cb3d8b91c159683bc8c1ff41287ca54530e84082bbafad485c0f179781950a4722c9114485f6b403f3760678e3bbefda309adc41ca562dbcb739654abc6cb05216807e2fe18fbb485977380d8c0282e271c7f1f8c14694484b76241a1b0cf3928ad9e328357ab75fe909957419defc8e0da3469e7720a5e91df7c4857ed50b89d18ffaf6a045e2c950e178adec7a3d690fa23527d3d353d8731857018d7cc909d081cab0370cfcc8bf8f5463a4fa8706a1abdf2c6a7fe8c834a4ccd8b6c869c6bf93c808a43274620b30aff22bbce53a7ff85145779cba220dabd1b597f4515c1664a374a64ae18884b0919668a70b371e24d2ac1a84af7de3b84f804e105177f6a9b914cb5dce45c678c886b3b24e3649cb194c548fba4114f278a56a4310a7cf1cb16e8ecc0b0fb8a2685b30631753b7f87eec8578684a67634119fe8cb334b67b741305aee8762639a212b9baab4032653b1537327eba5b6fed245d17631e748532426c5a4f4646716521dcc72f4c34a38bc87a892650def1bf09991e4c175d0baa1bf6469277f75a2812aacb88534c491f4d3c884a4470f01b805efc160ec17f68b0b0eb9910889a02467232fdb268848a5d6969c91410775fe717c9103cffb9a2bc13b1bbba01abb92ae303abfefc51af169d25d29316e7a12a5bca6827c25df567ef0c20f13a6fd728a32e229f72b42e74470c88c105bec0a12a1810c3d2a3d84b89a8c9bf66cc305f0b0c3fb989c3541daf147d5b02813e7904cc18a5dbb6632af4a34cd42007f09ab4a88c1705958058bbd6f996fe7642a0b45b690317d0e658ea82094d6b8d55722123fc1bd349433ad4850b19a4f6616685767e67bc21333a9f667a6c422087398b3331c075cea9aea6e29e424653d5e7a86766613732343341491726869eda4f97f1982e62c4cf135b1553a0a842b35e8ac23f29a921039bf31833f12ca8c4f02021559e1ab5bc37d247a5078280f02956ba2e2f897b48e18a769908e6b8b15c63b5a780580d02b5f70749a5442c824a0f56cb00378bc0ea2b033fbc9d45d535ecc00f5579a687865702436d3065461a06c8b274561d938d92290a8c0bbc0cc746aeb253e4823f8bd7b6becb5b1f8a5403fcb40efa5f6c34c43620921a416aa769a6ea1ca15c765d0e53c70b0a719f7b47ff783b63701af5a9cfe704c7d99830734c1b1fe00a1d9166b11060baa09501715310b93ead6825ba9998d922ae362092349aa45abb04781a98b25989e8309c40698a2676b49fbdca7775f554d2448358e6a4bf5373892b712b63af3392fa95dea1a8"_sb, "381ebfb00ef96db47a1c412af508a5509ec6e92bb3eb0bdbc9cd3611ec6b875764aa7dc3aeb515709f9d3b4cfdf6209598233df9a84e13a1dd779cac72eba5c20c5659e8c12677eebd55584cd34bffa6572ef7e83479c271cf5131bb5070085c3e513217bae58724f5e4ff3d5eb3c21d6c46e18fdc7d95ce55c3e2e697a0c99bcd8734628e1a93f73647ffc721a0d325b4cc9ab028e1f3beb2006b46a61632d1b69f26514c0ffc18a5a7443d4719e46a55476511c868427df2cd91d9626ccfdf2b1232aa5782b698d0d5ba501ff0c993b92b263e4cadaf631522a5cc7bd293554598dc42056efe2dccc8499dd574616092461bacfef03a85c4100550514651c5fa70c7c172ad82e3844a7c5c940997ca9e9cc6333a0ef5dd0c60a97b93c6bd56f18f014182b3df3e1127411b58e2a095b8fb4a7ce43fb5ac658135952c16e8c4a2ca78b780b39518dacfdacf9e93ba28972293859644c411e37070c877e6a96dc08875d2bd92d54b60a56951af537f02cc4dec141eb68ed3ef48e4d598a0cc899488cd73d2b676cca349b2c2b70d9931dd672bcc7a15d41db475c058528c5e1f8902752a4840be08a733f277b5ae5829c36fbf55ba91338ff92bf7811f5c660e12d3d3699ad04ad1d54a21174c8c630059acc5f8f46662f0591769efb02a8bb6af57ccd05d53b96b987f2ea676bacacd6fa4be275503a726d6f1eb65438ccb9563ae9bf6dcd313f3b819eaed568ac05192886e7e2b19ee532bd076999ab8e3e489bc596f9904e7c35b0d93614c6afe2081e5d9bf545c711af029107183f1ba308d78c4becec16f49656fc03ec86d8ee25a39d11517be38d270601f888df16a70733ec3230b1cb537db4e5bc13e8b099f7337f9e3e5709ad3fb8ce2445c332b87b9f263d4cedb3f7d30f014905a214ae7223fe1263b99ed02bebc0f4a298b7b1f4722ce622f02a6e75754e567e1ceeec73ef725ed5e7caa497d5e67d133a08db2c42d876599c22e052673ff4ca3a9802dbe7b3e8f69dbc36e713e8caa0765cdd74a3902d5a23dc10a01deab09d05418ac3b30f7c06e594d550843794c4deabf8e805806583dc30f926ec191786c661e66283b01d995adde5e0d2f59fa044abcc55b78c05613d88cccbbbe8ccc19208569493831115000a8c0dc41ce0f3e7818f0d2cde58826ea8c562b84999f6a9c3d914eb109af6c804c16fc0648336e10427800a146339dd6cad05667e98a2ad35ed890095104ff45bd7c51121bc141866671d097006b491b1e6841fd34f0ae5f8298ab62a4dbff7ffaaf67e1fc29656b75aaa1a1949db4d8d3dd4cb2ca2a8fa70ed3a70db112bc261c2b58ae0ca834cb2c358278d5af6c72ff4c64fe0734f6932329d7a6c6a6ac19514401128e45e33f69a8c484ee7bf11c0e729970364490affcb5fd8ce9fae282848b7c36957b033253b8aac9b83bcb9ebd551ba3a1d1511a0847fb7657b2da87fec3a5e0e90e9a0af46d826c5c1a932f0158e5daa18397c51cd42d4e8d5c8571a065ca8568393c6a5f2e"_sb,
            "fef3730b905431d14aa7aa7bb1d253cd912335c590b8d7de1e7aa4e0ff76be04"_sb);
    }

    {
        mlkem<768> k;
        k.ml_kem_keygen("E34A701C4C87582F42264EE422D3C684D97611F2523EFE0C998AF05056D693DC"_sb,
                        "A85768F3486BD32A01BF9A8F21EA938E648EAE4E5448C34C3EB88820B159EEDD"_sb);
        cmp_bytes(
            k.private_key_,
            "98A1B2DA4A65CFB5845EA7311E6A06DB731F1590C41EE74BA10782715B35A3102DF637872BE65BAB37A1DE2511D703C70247B35EF27435485024D93FD9E77C43804F371749BA00B20A8C5C588BC9ABE068AEAAA938517EBFE53B6B663282903DCD189736D7296816C733A1C77C6375E5397C0F189BBFE47643A61F58F8A3C6911BE4611A8C7BC050021163D0A404DC14065748FF29BE60D2B9FDCC8FFD98C587F38C67115786464BDB342B17E897D64617CBFB117973A5458977A7D7617A1B4D83BA03C611138A4673B1EB34B078033F97CFFE80C146A26943F842B976327BF1CBC60119525BB9A3C03493349000DD8F51BA21A2E92361762324600E0C13AAA6CB69BFB24276483F6B02421259B7585263C1A028D682C508BBC2801A56E98B8F620B0483D79B5AD8585AC0A475BAC77865194196338791B7985A05D109395CCA8932722A91950D37E12B891420A52B62CBFA815DF6174CE00E68BCA75D4838CA280F713C7E6924AFD95BAA0D01ADA637B158347034C0AB1A7183331A820ACBCB83193A1A94C8F7E384AED0C35ED3CB3397BB638086E7A35A6408A3A4B90CE953707C19BC46C3B2DA3B2EE32319C56B928032B5ED1256D0753D341423E9DB139DE7714FF075CAF58FD9F57D1A54019B5926406830DAE29A875302A81256F4D6CF5E74034EA614BF70C2764B20C9589CDB5C25761A04E58292907C578A94A35836BEE3112DC2C3AE2192C9DEAA304B29C7FEA1BDF47B3B6BCBA2C0E55C9CDB6DE7149E9CB17917718F12C8032DE1ADE0648D405519C70719BECC701845CF9F4B912FE71983CA34F9018C7CA7BB2F6C5D7F8C5B297359EC75209C2543FF11C4244977C5969524EC454D44C323FCCA94ACAC273A0EC49B4A8A585BCE7A5B305C04C3506422580357016A850C3F7EE17205A77B291C7731C9836C02AEE5406F63C6A07A214382AA15336C05D1045588107645EA7DE6870FC0E55E1540974301C42EC14105518680F688ABE4CE453738FE471B87FC31F5C68A39E68AF51B0240B90E0364B04BAC43D6FB68AB65AE028B62BD683B7D28AD38806BEE725B5B2416A8D79C16EC2A99EA4A8D92A2F5052E67F97352289761C5C39FC5C742E9C0A740CA59FC0182F709D01B5187F00063DAAB397596EEA4A31BDBCBD4C1BB0C55BE7C6850FDA9326B353E288C5013226C3C3923A791609E8002E73A5F7B6BB4A877B1FDF53BB2BAB3DD424D31BBB448E609A66B0E343C286E8760312B6D37AA5201D21F53503D88389ADCA21C70FB6C0FC9C69D6616C9EA3780E35565C0C97C15179C95343ECC5E1C2A24DE4699F6875EA2FA2DD3E357BC43914795207E026B850A2237950C108A512FC88C22488112607088185FB0E09C2C4197A83687266BAB2E583E21C40F4CC008FE652804D8223F1520A90B0D5385C7553CC767C58D120CCD3EF5B5D1A6CD7BC00DFF1321B2F2C432B64EFB8A3F5D0064B3F34293026C851C2DED68B9DFF4A28F6A8D225535E0477084430CFFDA0AC0552F9A212785B749913A06FA2274C0D15BAD325458D323EF6BAE13C0010D525C1D5269973AC29BDA7C983746918BA0E002588E30375D78329E6B8BA8C4462A692FB6083842B8C8C92C60F252726D14A071F7CC452558D5E71A7B087062ECB1386844588246126402B1FA1637733CD5F60CC84BCB646A7892614D7C51B1C7F1A2799132F13427DC482158DA254470A59E00A4E49686FDC077559367270C2153F11007592C9C4310CF8A12C6A8713BD6BB51F3124F989BA0D54073CC242E0968780B875A869EFB851586B9A868A384B9E6821B201B932C455369A739EC22569C977C212B381871813656AF5B567EF893B584624C863A259000F17B254B98B185097C50EBB68B244342E05D4DE520125B8E1033B1436093ACE7CE8E71B458D525673363045A3B3EEA9455428A398705A42327ADB3774B7057F42B017EC0739A983F19E8214D09195FA24D2D571DB73C19A6F8460E50830D415F627B88E94A7B153791A0C0C7E9484C74D53C714889F0E321B6660A532A5BC0E557FBCA35E29BC611200ED3C633077A4D873C5CC67006B753BF6D6B7AF6CA402AB618236C0AFFBC801F8222FBC36CE0984E2B18C944BBCBEF03B1E1361C1F44B0D734AFB1566CFF8744DA8B9943D6B45A3C09030702CA201FFE20CB7EC5B0D4149EE2C28E8B23374F471B57150D0EC9336261A2D5CB84A3ACACC4289473A4C0ABC617C9ABC178734434C82E1685588A5C2EA2678F6B3C2228733130C466E5B86EF491153E48662247B875D201020B566B81B64D839AB4633BAA8ACE202BAAB4496297F9807ADBBB1E332C6F8022B2A18CFDD4A82530B6D3F007C3353898D966CC2C21CB4244BD00443F209870ACC42BC33068C724EC17223619C1093CCA6AEB29500664D1225036B4B81091906969481F1C723C140B9D6C168F5B64BEA69C5FD6385DF7364B8723BCC85E038C7E464A900D68A2127818994217AEC8BDB39A970A9963DE93688E2AC82ABCC22FB9277BA22009E878381A38163901C7D4C85019538D35CAAE9C41AF8C929EE20BB08CA619E72C2F2262C1C9938572551AC02DC9268FBCC35D79011C3C090AD40A4F111C9BE55C427EB796C1932D8673579AF1B4C638B0944489012A2559A3B02481B01AC30BA8960F80C0C2B3947D36A12C080498BEE448716C973416C8242804A3DA099EE137B0BA90FE4A5C6A89200276A0CFB643EC2C56A2D708D7B4373E44C1502A763A600586E6CDA6273897D44448287DC2E602DC39200BF6166236559FD12A60892AEB153DD651BB469910B4B34669F91DA8654D1EB72EB6E02800B3B0A7D0A48C836854D3A83E65569CB7230BB44F3F143A6DEC5F2C39AB90F274F2088BD3D6A6FCA0070273BEDC84777FB52E3C558B0AE06183D5A48D452F68E15207F861627ACA14279630F82EC3A0CA078633B600AFA79743A600215BE5637458CE2CE8AFF5A08EB5017B2C766577479F8DC6BF9F5CC75089932161B96CEA406620AEDB630407F7687EBBB4814C7981637A48A90DE68031E062A7AF7612B4F5C7A6DA86BD136529E64295A5613EA73BD3D4448CB81F243135C0A660BEB9C17E651DEF469A7D90A15D3481090BCBF227012328941FA46F39C5006AD93D458AA6ADD655862B418C3094F551460DF2153A5810A7DA74F0614C2588BE49DC6F5E88154642BD1D3762563326433507156A57C57694BDD26E7A246FEB723AED67B04887C8E476B48CAB59E5362F26A9EF50C2BC80BA146226216FE62968A60D04E8C170D741C7A2B0E1ABDAC968E29020839D052FA372585627F8B59EE312AE414C979D825F06A6929A79625718A85768F3486BD32A01BF9A8F21EA938E648EAE4E5448C34C3EB88820B159EEDD"_sb);
        cmp_bytes(
            k.public_key_,
            "6D14A071F7CC452558D5E71A7B087062ECB1386844588246126402B1FA1637733CD5F60CC84BCB646A7892614D7C51B1C7F1A2799132F13427DC482158DA254470A59E00A4E49686FDC077559367270C2153F11007592C9C4310CF8A12C6A8713BD6BB51F3124F989BA0D54073CC242E0968780B875A869EFB851586B9A868A384B9E6821B201B932C455369A739EC22569C977C212B381871813656AF5B567EF893B584624C863A259000F17B254B98B185097C50EBB68B244342E05D4DE520125B8E1033B1436093ACE7CE8E71B458D525673363045A3B3EEA9455428A398705A42327ADB3774B7057F42B017EC0739A983F19E8214D09195FA24D2D571DB73C19A6F8460E50830D415F627B88E94A7B153791A0C0C7E9484C74D53C714889F0E321B6660A532A5BC0E557FBCA35E29BC611200ED3C633077A4D873C5CC67006B753BF6D6B7AF6CA402AB618236C0AFFBC801F8222FBC36CE0984E2B18C944BBCBEF03B1E1361C1F44B0D734AFB1566CFF8744DA8B9943D6B45A3C09030702CA201FFE20CB7EC5B0D4149EE2C28E8B23374F471B57150D0EC9336261A2D5CB84A3ACACC4289473A4C0ABC617C9ABC178734434C82E1685588A5C2EA2678F6B3C2228733130C466E5B86EF491153E48662247B875D201020B566B81B64D839AB4633BAA8ACE202BAAB4496297F9807ADBBB1E332C6F8022B2A18CFDD4A82530B6D3F007C3353898D966CC2C21CB4244BD00443F209870ACC42BC33068C724EC17223619C1093CCA6AEB29500664D1225036B4B81091906969481F1C723C140B9D6C168F5B64BEA69C5FD6385DF7364B8723BCC85E038C7E464A900D68A2127818994217AEC8BDB39A970A9963DE93688E2AC82ABCC22FB9277BA22009E878381A38163901C7D4C85019538D35CAAE9C41AF8C929EE20BB08CA619E72C2F2262C1C9938572551AC02DC9268FBCC35D79011C3C090AD40A4F111C9BE55C427EB796C1932D8673579AF1B4C638B0944489012A2559A3B02481B01AC30BA8960F80C0C2B3947D36A12C080498BEE448716C973416C8242804A3DA099EE137B0BA90FE4A5C6A89200276A0CFB643EC2C56A2D708D7B4373E44C1502A763A600586E6CDA6273897D44448287DC2E602DC39200BF6166236559FD12A60892AEB153DD651BB469910B4B34669F91DA8654D1EB72EB6E02800B3B0A7D0A48C836854D3A83E65569CB7230BB44F3F143A6DEC5F2C39AB90F274F2088BD3D6A6FCA0070273BEDC84777FB52E3C558B0AE06183D5A48D452F68E15207F861627ACA14279630F82EC3A0CA078633B600AFA79743A600215BE5637458CE2CE8AFF5A08EB5017B2C766577479F8DC6BF9F5CC75089932161B96CEA406620AEDB630407F7687EBBB4814C7981637A48A90DE68031E062A7AF7612B4F5C7A6DA86BD136529E64295A5613EA73BD3D4448CB81F243135C0A660BEB9C17E651DEF469A7D90A15D3481090BCBF227012328941FA46F39C5006AD93D458AA6ADD655862B418C3094F551460DF2153A5810A7DA74F0614C2588BE49DC6F5E88154642BD1D3762563326433507156A57C57694BDD26E7A246FEB723AED67B04887C8E476B48CAB59E5362F26A9EF50C2BC80BA146226216FE62968A60D04E8C170D741C7A2B0E1ABDAC968"_sb);
    }
    {
        mlkem<768> k;
        k.ml_kem_keygen("D21D5AFED9AFAA3B49FB45245B2BCA1505E4000CDC29094A3600F5CAA49A7B3A"_sb,
                        "4DD0E86091649A0A08EA44DAB85DF56797F8BF46222C2DBA7DEC6374B9B2268E"_sb);
        cmp_bytes(
            k.private_key_,
            "045AA22AEAA4A8E0C66661A183700F04025D413CCDCBE1B7CD9B839BA61671B08A859B1AECA9014CB3695B29703CD4314954C48CC19A89E106079720EF23B597FA6A833638B7A7B1E74A40C8BA7A005AA799D22DC5AA97627A037BA2623C659621EA2FF40651DAA0A95B2218CF934DB132BDE8A29F889BA084DA3EA9C8B58FD1BEF4D45EB4A2501447640C7869F21C9B031718209288E442018F63097459AFCEB75815829B16EC48FF822B1F69B6B48C3AA3C65441E60F552A154BD85A71397AB8290564F527FA8B1E84AB4EE6450EB5CA658B2120164B7D84637CC7488FFDF717F9349734E6B2F585C040065A2E910CCCA070C0070C2C215BC8060930D30D7A73A0FADA94E46257BE169B73D7A35DD43EB9B0183589AD657A429D983564031166253B4EE513AFE986E007727D75BA22F41A0AEA4939081C7CE1BEA5AA8D8DFB692AD37726E05A9DBA9D70102A1DE64479A928D9789035D4B645F088ABE8A51B06826BA64079C4AD3EC2C8A7EBC9F5EA6A0C707E88B2224DEA55FC0C39EC258088E319CA48C3F0C86AA203669F164E5FD0BA467548050CA496579BD4099D705A82BF9634995ACE60DCAC96C9115226AF2B6A9D86497DA1C49FEEE35F5639BA1A8363DF5114EA06C190179161C3C4238115DD55200BD28A03EACCAA46C7A9126B6F0CC2BFD9047D9BBF7A2043BD965F244158C7F10548FBBC39E040F040145A45B12BC90A74065BD3E34925C94FFA968BEAD241A79B6B0F1C3911C444E3958906DB8834984897CA886DC1B9D63CA43803C74C5633F003BD148A691D396C98BA81918A560542CC6435082957A70A312DAD0AC54F81903B2280BEF3638A013654D26E0D2705939A31EF39547FB80BE113A336E277E04B8B905C9DD90509C434277246916A1A0A7E66BC1C74C4719751BD8879E07AB97721C0B27BC08B69B284F2BB47E43290F2BB434C489570C22AC867F06643AB100457D336CB944B6B5A185B639A403A332FC755584A9F2EAA315C319D3099B30710B7EFAA5BBE8A3981A9B158E0C7484595AA1B7CA3F335BB38A7E5AB51F2799E0EC2049AB781514A82CA7CC5A53BCFF3029320636285902EC1D24432B5292EF7600097929D374F3485AB2AA5C8A154CC3171693DBBC4382A5E44600AC8B1646A84A47B078D06EC554A309A1FC2BB473C69EA4732B6485BE812A1004D583D9A0B9953312CAB9B014A482D8C7BD1097231D0041FF599D0E043C7CA08FD0CA71AEB977EF271EC13AF122766566BCAEAA26554F87394847C50DC2B8D3885184069B1A173D1183E68C55867E55EA78610CC3183A7F60181D1751A12107225C7156B99F86846FDF5777502A201FB583202B28EB78EEF356918D2B5B7594AE364902D45C2E8691137C98CA7B2425274068D765AFF29095ED546309C2D4CD6A5DE0571E67566DB14C386A87F15379CD1190EF02806D6B8387C87C73B805E01DB128C0A86C1013FAA7CB7D46770A0835C5343C931AB8CFDF56AE4241108C55976F127334AC3E2B52360661B61532CCB641CA043AE9B3173D0133CB0E4581748B6F1AC00BA0BAE4960376782A25F36765A1A4318D73C18781C90755C657847ED6849CE1301B11A2FD75616B4F326DAD545744793A77A843520C9EB8B057FF28854193916F711902B1F8B4B9C235251FBDC8040C8A38C022557DB50CB28CC8DF99A859C2EC017C24015877D2A3572571FC783BF1E984401C11158E32A95351BE407A8AE6B5E054A33C2427F4A346761559F776671095B495074AF5CAC98D94297FB05624443CAA8151AF3A497F73203EF184CC7336650427CDFD47B10245EDDE30C3075933E431DC1B1C2A77B2073257C2AB73ABE706DE138CD54922CDB09CEFA60BA473092E43BC3E3CB951939B1C4CB2AFDCB4F8A5310FE9A790E560B25A40AC9E18D35A27238A60A126B398980BE8425C8A01B930FB336CB359F58131BBEE6AC450B8C811B2DDEA836F9D0C2C72A709E134321DCA727641A1D678A8E0CAE6BD6BBDAD8021AE3C1B6067FB1ECA42D215EC2C4297F6891567712F75047775B741713097B1271AFF026323A134DC20DEBFACE46D5B01820A9A862BA93E3AFCB5AC4C2204AF2E15787D0C857896D24DCBD6393C1FDDC12CDDA6A1F337B18D6C3CCD5283B37239A80424780399281C3FF1967B3BB6DAE499D42F511997077F38A8D63EB319342B1BC749924E467C6A2A11728826BEB52A39BA7A1A03C93C613D36A3F1F544B72A8BEC24009FDE07E677101456A2B76EC3353CB8944C339081A4B59672CD1B5446FFA6FC0B468D9FC83EBF896CE12158AFAA6812028F54B7920636784D3B3854030D05A9C19D936C6FACC5B81070CD524728A96A58A2E1207C73A4C533DDB00098141158B11DB674500781F47DB9B45F3CDE244502D377886418287C22075B2BD172606CCFA6F4914844525C113BCC7C049B3D14A2DF91B6C62E0A2EE5922DA3194DFC0C506D48ECCF5697BA31BD0839A4D3B3078CB7C2936CE1C507B0B54023585CADA6BA5657726075659DE16A6403110CE38A247CA85CE02C1DAC79FD175BCAAFA116F710516A4B73D78BFC6F9854228B6C5F035946B1F61B629F31328A65556C8F0661D58622C6021F58C1ACF154C6E78BCF563352AFB89B824513A35502F117861A34C52B1011F696A85185186BBA23B518C720763529C181D902CBBB58CFEF77CD2E72F4780979FD46126C0A4BC1965A6E070FC284B1F856852110E19C268390CA9494116EB293F1A111ABEC1AF04F706B114617F0362B3DB4B99E076287AAFB7127FE2C68904F61664D63D4FB267CE07AD5A659FB81886F8E0A9C26261A0055F48F432E9F8242C439F58B5A21EB777483B2E68B3B1118562430270340243F1E87C22CB5BE2F167DC39CF4C69B8B8E9B726256CBE605342F47E23A871BA7250BDA8997FD474B3375920522F2C511B3EA35CF459342893AA12B128CC2184E304335AC7BA04653898590A664672FE744F301651442BB341D32F36262C576A50F803B02F91105FEBCABEF7030D2A76CBEC6C2CF36283590BB44842853102D3D350801167D7A96968648C0CAB9AFD39CB7F658909283CB83CA78544929AD90069CA3E660196792A654A911CAD7C23024C90E25AA61B30A4D568C5A5C12A53565A93E910D5940EF3583856017BC25B05C4473F48584C6908C13D2B19E7A3A7992976D31A464807199AE3A6307CA55765590F6B4721632D70FA47E2C1098E36898BE3125E43C61CBB7A6C246CBA0002CF325A5D337989289BCCDA54835511DE9656287363DEE85033410AEAE16C770D1FA4C0F5DBB660530772FCC2297F59BC9DEE338CD124F0924CF7E3762D4DD0E86091649A0A08EA44DAB85DF56797F8BF46222C2DBA7DEC6374B9B2268E"_sb);
        cmp_bytes(
            k.public_key_,
            "744793A77A843520C9EB8B057FF28854193916F711902B1F8B4B9C235251FBDC8040C8A38C022557DB50CB28CC8DF99A859C2EC017C24015877D2A3572571FC783BF1E984401C11158E32A95351BE407A8AE6B5E054A33C2427F4A346761559F776671095B495074AF5CAC98D94297FB05624443CAA8151AF3A497F73203EF184CC7336650427CDFD47B10245EDDE30C3075933E431DC1B1C2A77B2073257C2AB73ABE706DE138CD54922CDB09CEFA60BA473092E43BC3E3CB951939B1C4CB2AFDCB4F8A5310FE9A790E560B25A40AC9E18D35A27238A60A126B398980BE8425C8A01B930FB336CB359F58131BBEE6AC450B8C811B2DDEA836F9D0C2C72A709E134321DCA727641A1D678A8E0CAE6BD6BBDAD8021AE3C1B6067FB1ECA42D215EC2C4297F6891567712F75047775B741713097B1271AFF026323A134DC20DEBFACE46D5B01820A9A862BA93E3AFCB5AC4C2204AF2E15787D0C857896D24DCBD6393C1FDDC12CDDA6A1F337B18D6C3CCD5283B37239A80424780399281C3FF1967B3BB6DAE499D42F511997077F38A8D63EB319342B1BC749924E467C6A2A11728826BEB52A39BA7A1A03C93C613D36A3F1F544B72A8BEC24009FDE07E677101456A2B76EC3353CB8944C339081A4B59672CD1B5446FFA6FC0B468D9FC83EBF896CE12158AFAA6812028F54B7920636784D3B3854030D05A9C19D936C6FACC5B81070CD524728A96A58A2E1207C73A4C533DDB00098141158B11DB674500781F47DB9B45F3CDE244502D377886418287C22075B2BD172606CCFA6F4914844525C113BCC7C049B3D14A2DF91B6C62E0A2EE5922DA3194DFC0C506D48ECCF5697BA31BD0839A4D3B3078CB7C2936CE1C507B0B54023585CADA6BA5657726075659DE16A6403110CE38A247CA85CE02C1DAC79FD175BCAAFA116F710516A4B73D78BFC6F9854228B6C5F035946B1F61B629F31328A65556C8F0661D58622C6021F58C1ACF154C6E78BCF563352AFB89B824513A35502F117861A34C52B1011F696A85185186BBA23B518C720763529C181D902CBBB58CFEF77CD2E72F4780979FD46126C0A4BC1965A6E070FC284B1F856852110E19C268390CA9494116EB293F1A111ABEC1AF04F706B114617F0362B3DB4B99E076287AAFB7127FE2C68904F61664D63D4FB267CE07AD5A659FB81886F8E0A9C26261A0055F48F432E9F8242C439F58B5A21EB777483B2E68B3B1118562430270340243F1E87C22CB5BE2F167DC39CF4C69B8B8E9B726256CBE605342F47E23A871BA7250BDA8997FD474B3375920522F2C511B3EA35CF459342893AA12B128CC2184E304335AC7BA04653898590A664672FE744F301651442BB341D32F36262C576A50F803B02F91105FEBCABEF7030D2A76CBEC6C2CF36283590BB44842853102D3D350801167D7A96968648C0CAB9AFD39CB7F658909283CB83CA78544929AD90069CA3E660196792A654A911CAD7C23024C90E25AA61B30A4D568C5A5C12A53565A93E910D5940EF3583856017BC25B05C4473F48584C6908C13D2B19E7A3A7992976D31A464807199AE3A6307CA55765590F6B4721632D70FA47E2C1098E36898BE3125E43C61CBB7A6C246CBA0002CF325A5D337989289BCCDA54835511DE9656287363DEE85033410AEAE1"_sb);
    }
}

void test_mldsa() {
    LOG_TEST();

    using namespace crypto;

    auto f = [](auto &&m, bytes_concept seed, bytes_concept msg, bytes_concept ctx, bytes_concept rnd, auto &&t) {
        bytes_concept skey = t[0];
        bytes_concept pkey = t[1];
        bytes_concept sig = t[2];

        m.keygen(seed);
        cmp_bytes(m.private_key_, skey);
        cmp_bytes(m.public_key_, pkey);
        cmp_bool(m.sign(rnd, skey, msg, ctx, sig));
        cmp_bool(m.verify(pkey, msg, ctx, sig));
    };

    auto seed = "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d"_sb;
    auto msg = "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8"_sb;
    auto ctx = "8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8fab"_sb;
    auto rnd = "6255563ba961772146ca0867678d56787cad77ab4fc8fcfe9e02df839c99424d"_sb;

    using triple = decltype(seed)[3];
    triple t44 = {
        "dc7bc9a2e0b6dc66823ae4fbde971c0cfc46f9d96bbfbeebb3470ae0a5a0139ff037b84e75537e0a1cf02a517acfe323ffffe11df72e4f38430e0e66a2654b2f2ef757da47649d9f63fa03f1bf6fe6bc7c62971a98a2bd9d36eb0ec43ad4e9d940df3bb5874f5c92192aa31e0535d3cf70950bba858d11a688eaf854f63ecfc520c50d624891434265d8b0680c03061040299a104082c0910c8508d1100d44a6509408292211125b90508a2688e1302dc4021280028ac302611820851237808a000ae2040421b4910bb80550a08051b2511c28428a3672a494504910201bb45161424424a75001328181942d62a850023449ca94200b296213156408924c48122100b605030208e0060200a311e1802021116483a62898029291480801083041066613200e5b360951400c53000aa08851944842e316704ab2089b92440025121b0309418209c2a0800b290a819851c4340da4424500a0105b048e603400138928a4422648002c90202d194068e2146d19278a083746e4146914006422c660d3a03013242844965014166da0284dcc462e94367100232e1c114909a2040131060a2172c2142ada000c5a260d13228a62c444e3142d013445980224d33841c0308121a621e348720b1984d2c89108b8690887714a2884d496451a9301ca2285da30859ac851dcc00820106060465262302aa224251044640b2842988011540692144251d236719bb4900b082890188e41c469e1a469032160e01409d3020c20c88c1cb23164086218476920228ccb8470089528029550533270013405888424541041d202881aa84ccac88181008d0392899ab809d9900c9a1290614065c9322d89860c123521cc4266c8360010062411028ea3b44d44023043a0285a002ed1980c4882658922441c010212907084226e12134d011902519064113364c91806c2c04589262908b63024308cda022e0c27250b367058162c5116420b4946c1208841246c99466a04434e18a86c821661922028639409c30211029520211782d43868003460c84688e0160000a32dc0a82824b640831464c81022a2086503234ac8122ea098418c2072cc308a62c665093408412682da429089328514967081226001176d5948428ab88d592051d80892e2c0889044700ac0245a020904218a59c45094441094140820460209270c441020dcc8209212015038250c456e4a1666223770dc808ca426412222441ba3618a343099844099c42952046d88146ccb242a7cd129a8d333115c62d033b6a8357cf7cd10268ab12f16fceb7975d0a28a6c4822213c9a772df084ad91a669e2040550fc5e8d0aeb10fab2375fc9625ef9cd48c19631997a1cb6455d2c6286c569c9637add0317ce990996b28e51c3f3f717fb5907bbdd53961ad3497f2c3c473cce170906ac4c624a89aa8fbe624d99385e9c9548bf05e8cafd47d2476e41b73001f813726499e88b2b3b6f596ca311657850346598994c40e34747161e4e76264deef2a3019389d1594c942301af47b7544c23ecda2df2dece81e487d8f3f58ea89cd811d7275807ff1b0369ba86470088c174a3099fdafbe5fbb4d158801053b2b435d54059e26dee76d10a7a372f06b0b88b985b32f52052387438be8dc8bc6ae7369e2da9aa5e2585f8de403d091ccb7f790d54ddb34c608b0876f2825e9113be20a2b85867a01bda53287ac780bcd8b606d2e6d7712c56ce0142d22fe6b786de544963e134fecedfafb83d763061d799096a59e30d4472e440ae1faaabdf42640ce69740ceb9cae1a9612c21931b74af3f780236123321b205b6efd6cbb134f4c73d63c0c13e660b59d5920bc33197c355853d8d1cddc7959f7bc500ac81d985016f5b89a0eec79b0d9364ead8e38577c2a6549f2d067cb09438fdb21220aec80f6e22a476f332a2a4a0b7acbeb9e078d2b5a92ae84c924f7cb19fc7df377beb6546af97aa985c747cd111a127a674b4c26d89c14485b82e3a498a12d05406febd6c4d4b8bc051ab2cb91224b078538374b794b7dd9ddf3ac2b4a671fb7b9cf5acb78622ae2709eb2db16943aa24a9c97a81077bc784d25c0ea5991d2de883798a1f0e78f3361ed6a10dded81b1d683658331534fd7c01bc0eb00dfc4c3c84f0693046ff806bb200dd7bd4c0e6abca3f2934b4814fc0e1f8be615a2dda7c8a8d06cf9ce8566b40f4a6543b25bacddc926863fc0fa2007d6d7bf6d18dc98df696bd0865bf0be4c492b8043a32def8e3595ba7da345252f38f95be10fd7fb899b498fa01b09de5d5608eabc44a721aa04c4ef1dcb86102ac5f5f79c9708dcf5c5e896edd8c2c7bde3fa83e6ffce22d66174e31657a0b6361585e669d3031952f08631ae1f16ff90b90d0aad3c6d7e1dd0a9c41ab00a6e1c4f96af9ac5b79fcf821ffc016cb059245fb78dbe6c633d965aaab5333be07195c4b74b18e4600ce783c0a914ef4281016e80a7c9aa92d0fd789879c5e6751125ecb154432311e41cebd4fab3a31e4d2ce22d0f8c67737bf8a0dd85fe1349d5079a4d5feb3fee9378ca47ae46cc58a3f02038cfd53c4cee9cc4270cebc3d115a39c831e8ed41c4dbe4051b51d7872ba0c2bb163e0085201188eaa624a6bea9400a3a1fcc355a57f15704e61fda55a5dbaea8448fa5cb2d377a07f58305ad107e844ab4806e5bf99c1f513ee1d0a2acc04549f0801742169a77971d0adbfbfe0dd2ee5d16bc461e35748d1f3f6f4598321e8c49e79e740f990359858d2729dde007fcb26fdda9aa6e2ec4bd736f2836e7e4c83440191c849f6a53c72a4f8f830d001ea3b18f3cb4a5bd3cf066032b4932cfd2e62a9b55723fa61c688c935518af6860cd649bfbf1bf5fdc1f36dcaefaa157438d1cc8d56a150161511df82631f5e88e773e4ce263f276b7b3678d4c6fc75311d411c0d01bfdb595bb70552838e1b86517c837d909e772b428599e1fe569f77ce61531fde6fd31cdce1bdee4ba467fcbfbb9feeaad99fef67d4906e036c73662ddce158d4e5d4635e5d366f79f31a19d1b3dc4a591b0df194bb06c18147f41d88d1a409becdfb67eb063d16312266fd51b521ba9115e2e5e2aeae6ec511cede13ed4132ffbe0273f6c7039b3874f058804a54809af60557a21d9b4b831d04156a7c22dcbcdfe14f62437f449cb5ef12bf4251d485496cd835c0c2bc58bd845963dfa76ecd68519c4bdaf110be7ab052876dc3407591568c956ea3bf107c90fd5853a292f59a8d4b58b5d3fddf29bdbeac36852e3c69766fe460176a801831292b8e88a74a01ecbbe09a7b4d74cfd7fd628841944d9d556dbd60c76f96f07dc53443805ee9aa09365de4fb8179252c6b099b5dd351fdefc23dbd8090596c5d208ffd2c5661d8e5612dd574fc69045c769a969e600d77cfe192f1d3ae911289355c585811491b0ccd73692ab158824ab9edf8ac8193f0b33e6138b72c6dcd5d344f807b3da92425037de5ea4eead1c795effaa145e2ecdd327606eb2609929b9474b2bb04653602555c068385e92f06f29ca613ce5b4404f01ab1805db0acaa890330d291f40692df382509302b6dc8668f2c8f2d3a44fd58dca26e9802794f73d25b3149e6d576441"_sb,
        "dc7bc9a2e0b6dc66823ae4fbde971c0cfc46f9d96bbfbeebb3470ae0a5a0139fdd6a6ce5bc76e94faa9e9250abd4cee02cf1ee46a8e99ce12d7395781fa7519021273da3365519724efbe279add6c35f92c9d42b032832f1bf29ebbecd3ec87a3af3da33c611f7f35fa35acab174024f118979e23bf2fe069269a2ec45fbc1b9c1fb0e1f05486a6a833eb48adc2960641d9af6eb8b7381b1ec55d889f26b084ddfa1c9ed9b962d342694cede83825309d9db6bd6ba7582132534861e44a04388a694242411761d34e7c085d282b723c65948a2ac764d9702bd8ed7fe9931d7d8704a39e6508844f3f84843c305594fe6e5404e08f18ed039ac6563cbaa34b0ca38320299d6256ec0f78d421f088159d49dc439cbc539a55884a3eb4efc9cf190b42f713441cb97004245d41437a39b7b77fc602fbbfd619a42363714b265173cae68fd8a1b3ca2bd30ae60c53e5604577a4a3b1f1506e697c37432dbd883553aac8d382a3d250cf5b29e4d1be2cbcd531ff0e07e89c1f7dbc8d4529aeebe55b5ce4d0214bfdec69e080bd3ef36cca6a54933f1ef2f37867c0d38fd5865b87929115808c7e2595458e993bacc6c5a3b9f5025001e9b41447708bfbaa0462efa63876c42f769908b432f5485508a393224960551d77eadfaf4411cbc49fdff46f2f155ddd6ec30867905b709888ca0f30f935fb8d7f4803cfc7a5f7790ca181d99ca21f2621d69a5c6d49c76b4969da62740a378470332b30947ab31ccdb9ba0c7b625879eec4bd81f0200ba23504a7dc3b118bc2ab1145df13af3c8cc39f577873b84911b3d85fbbf4cb19e4d36b10a938eeb78b599dc86615fd6cec6eb7b8f7afa5f6d6be19ea81630d36ccfb2f487de50d0cf46da8d3fe3512812043c0e3ef2d7231fb0b0a35a0fb283be30a1247780f30ae0294e8b6f5897383edb895595f577524df54593cdf927b4967616ee3913e4d6b29b0dbd7c33a2a45e4ef1b1954ea5d91ce37efc1302e7ce02a97395565da2a5c5d3fdb0d87684e9b1c0ad07ec33df2dfad528e2ea0966d2a47dd5ee88e77d653c0d004fab0165f0757c4da40af327e7192536c79947a80a827aa2107dacfae3debfc8fad3d6e08076d938c510a276bdf6721a1f087cb169515028ad5ce27a1047abd92809934ca63b893f71f9a34a99c0fd30310c47e9aa37394d0ab73b254d3ca69d9c5549c9479aae24264ac5ea64d3fd821c3962ec77e709f9d30bc7b65a52e48c16e80603558caca1811411c3155d1f949fc9cf9aa9385a7199e99be77a66fad7eed91258de55b2c4c83f9a050adebea5f09758f40dac4a1c394ee8d687879150d26426895ab1938e14ae11b376254c91fc6130436996f8ed43bd27be20ec9067111c116ec94cc2b06cc91a13c5d10bbd7eecea4792f17b2b77631ef145e9fb41a83eaa11c2b72a48fb90fdbd88644c4edf8ab20dce3118364b276ac1237b36c8926e346aab5a111aa0bf341c518b7bff9e9dbb8bcb4728601b3760663e67650331e6fb54ac82fc414cb8ddfc160a25311ec5272de46217fef8b992ff89754fbee351f21bb90b6c97078b510c983350681266c8fed1f0583c5151e7b8fe3b7292319699687cc6b641fdbd689428543bc0fa1facc109de65b62784c2d985ab15d77d3af12af6d03e8d1859a553688584d75ef673a1de74093ee108c761fff32c217c231b0e2953daf521429264c0963bc8a5cdeddc617a7285b934ea51ddb5cdab23bcede86be36e001bc65c65e9a1c94baff4fab8eb5f8ed42ec377423633fe00049142467c47c5d58a7202c8e9104841c1f7f380145a6a0a828c570235e507ae5868a6062f722bb98ff6be"_sb,
        "cda4a78cab6ced4ecfa25627aece5dcfba40ab7f29bcca35517b0ef81714bb1a6b6225096523a63b1f41e258d1620881bb0bc90ef179b68387001de351bfd8f142944fbb23cd16b4f56958e3179f35a17228c248636a96ac1d5fc9ecd11fd3ead2ccacac24bd6aaa4571a80321be96b25345b56810d65c87fa80e8b7f0ea1f7accdeb171753d28725ab6d7c06656b8ced06f1cfd25963c14b857c1bea064116f2530202a9c3a3e8ca75db407c6704282e950515adbe201739ed58acfcfabe7fe9b2acb62f49aaca5fd64af27890b4763042a8e30b5b120677b349f693adbbf642ecbb6c11acad9f7eaf5ea16d54b245d61091573d50421eae34b98ccfbdcc6c36e82335fec44b3761b98d982a7950de49092ab058075fabdb24aafb2cbabad4f505fe815021fd7b4ba7002ff09c9c931537ebdf06da2fa09af9c3c2beb7ee913b73d843cb7d4c98aa9008cc683233f795a9945bd6ae1c69970a699f822e89431ec46c2b7145f170afd843df09d93b130ca4477d93bd974913cd6fb75d0c78fa71bd2edc7dc027deafc11ce406c0bee7d4cdc7795bbbd3f396d5a8c28dc42fe7e41afc9dd702308dc8277d17f5dec88b34516b1a38c75cb40509dfe59af0869a15a6e2bcfccbf0b7045c0bf6dab17a96949817732ac7a7c81f7b49ed39c95f5729cb9a349ef1fd7b7bde35c108345ebb2beb36b6097a54c322dd3371500913be04912746c7a2c400bd15f0b5aafb23224100f0d1ee7300cf8e1ba86cb92bcc578b4ac4e7ffd1e47c2908e09f49227330697bdc1a9463211526ff35a3fbb1e3d9c8fcba49b07ea0891c709c92266970f384d5ecfbba21cc2c3263f6deb826272e2a39de63e9f76b84696a77041eac17988d92bd21ded53d1ad36318ac3af5a71d78d122e087238c63013889c602953086d051636b9abf8729b6a1076e382ff1c0b327514d3a5b2359b2796e7efb315d7d44473e20da51cedb2d7a958ed746e8d70573043869d36fcd454a852ebdeb69947a2413e4bffdfea2232d0dde94beef1769d4da88c824697d94f0b21ed536e9d2f284eafa41bea9b1923a1ca5a4df1a2b244e61fadb48a427e4a80617f52ca05d431d91694c47e05be5ba5362cccfa02358e6a81c7ef0dd7824c129b2680814b692cb130a8dced71cedb24e3e94ee28ba73619676d1f2767c10574fa861e7e5079c6ad057506f6b735c4821cc0657b3951d236a5fac339925cc805d2688f6371210896522acfcb846a4beb77c2e6355c714306ccc4f2cf7114d2c57b26c236f141d52fc7234aa8e44d94d2aaadeee716b2ccc023acd1cacbc7572fd4dab1e70a340471683c2ad7ac10edef3e1fc659e6d830a8447cc3efd00a16652b64cf644b068bc0d520a6f3f79bd5286d7c6f8cbf39f30ef00c2151fa4959d899556e8899ded1e2b4d460ea72e53ed9b5a98b96dd77ef3e6a5c968540128932e387f136506654a59beeaae649aa6f74eac026926a3b7b7c0e9edc56a8a150be1d2ab7f830594f2953c10f2b4c2669d471f4b22a5654402c7d0332dfb8f5d159d49314c17ef60e426beeeff28164fba15a04639bddf1433a3f4d8b871429097aa1917e791849e9e4ae84daac6a39319f92e4a70a63a7ddc919a1f179209e5c5bd15b86bac2cd393336aeb2f85f2e163baba6c16629e1e88d61b2906c8f5a971547b1990a1d58a04cf432a545e945fd638eb871a69f2c754c371d60090dc2c79cd45abd9885d0d138b544e3f0891cf601f7f1483ffd29b9377e9a33bba63cf715651e26af1d0207943ed0428ff4b59f63b6b4dc9dec62a990cc913b91096bce2f833ec625981ebea1b397777c6b2a9e689861e76a23c281986235bcb800fb28e34ce3d81677bdeaa67ef3bf86e00993a8cff23c1cf6af9348db04ab1f49817310744b012414e3997eb3866e1df6fcd1ca644da0f20bee2587f97232cd62c5fe918176a0d142e680703900a8e1315d9fad4374c9602c3b5eacf8f4e299e33064c80b65e94adc84382dd8d675ef538016a21d76761daa48877db2b5c676e8f42c4253ea86c2abed54166961638b908efd26ff20760559964c423ca556c01c9d9febbc5583e488c1bb3b6e2b0ea45885d7bb362abef21afe8743233b397f90c7e35ae8f225fb09d03f29c664e330b9cd35f733a4314b236b20f37bfe00fce9cb119910804eba636bf8777cf4eca5e8f1f1439785b21d43ce26c0363095153f316c1f9b97fea3176b116e3ca6ce83a2a456d1c915f87379a03d68dcfffe80b1cc600c020914ed582012b488775942a465ce7accf088f97a6fe85f9bc82a246ea59e9955a8418db50069186fb1bffe062fe638353c4f5c4c5328d957adf353a86dddd1ef332c537cb832ffe7731480ab134b0206beef4373a26551c401d54f623fb078d9626ad7872460f3ab10d3a278f2c5c84c7efdb64f60829a451102d74ecf807fefff5f83b2ff56f490b63cdaeeb951e66374e1b34dd218974dfca934db5b3994117435a53cc6ae318290f26e20338deea045a9f1872b4cf9f25c5eb0fbe8411f5f8be19a3724d4e2479d62a83f6fa341ea59067a68d7e2972efbc0776cb07954c246d3badd1c6bfb0b94ae25a798c4147e59520d116c2b9ee76a3f7231ef572ecd59380fd44f4a83193d8041eeff5869fdb93e72aff6598fc18e7e084130e9f23961d41a994de8d52963d101a1640301ce8afa8153796c6bcc214c6138890f8a3dce2993c5ad3cdf7e4c20c520fe0cd05b24eee01ae40ee32a811d005d1203fa22ca224cbc5deedfe2648dc350d20a0b3a6cddbe8fa262bac453e8f4335ebbaac739197523377ba3b5e122371457bdd0a636fa5def7cedb1583347695d9c49641028aa5c29d5b197668b849c2576d00d231737c07d57330057c8ba32684e04bee4c2b6adeac3a147b7cd7685b94628828d23ef7e9672710ed4b3b3a62e03e4eadeb99a877c89f5407006a68aa18ca9e05a49c6274b8bd849eb0b369ba45dda8cb16255e20796521acaa176c6624a9ffa6d6be6e57b7a7fde801db6266b8e38e78d278fb427f5e4b37a1e4d82319f634068fb8cccb2751848a40e3cf77e1f4690a44686d4654f2289b34f3813861aa59d11937905ebefd25d4ca1961dfc17273f5f63df2ba0d6b882f6da9ee0ab2674802d0ca3d17ca3e3d63e6b21e5c021dc3479bbbc6bc3461d5e7c132ba0b873c85f499796bd9dca3ba569b94c01ab6fdbaf7f31280782993260d681eada05ed85ca69b7a964eac8d9f3450873710b3c36f144ba22c243e99e4c5c74fa2473832e673eab80adc198141819304d5669a8b3bbcfd0d1070e141e26293139424358727d82838c9ea2b8d3d70d23297b7cb4b5bed6fe0b194d5a6c8d92acb8d4e4000000000000000000000000000000000000000000000000000d222c37"_sb,
    };
    triple t65 = {
        "1483236fc9f943d98417809e95405384530ed83e151e8465d34e4638f1f8d7052af11ab9ebffd68056444dcfb24f4992e6707e4a4d33ff238f673cd8a248bf6604d45a155fbd534ec09bee119b6f14baf84bcc4d3a03fc0db2b61b55156f138ae606cc03ff4d6090a4dc8630d3ed13dd6a524931ae7376367e4cc95baffd8d97230406026828414840360125756741144255428634772264841831587751357787342578833435877482354428618823051535883125455388112525024833711237111647244333331406774616666657770707851668427186855126400732348826217066327330602601401688847885162475668718571250864535386168236664584781600285443525766403387274306503880843858072450648247865254055322502021503366573867064017388126827834715540003026816356777068660688502140465422546822321061260625162131621620221755832864048588058387288206472344763484260106264004647433711748052425100620768177142123875641184304777016233640744881572435671226611877822272367658662811787816623034135155345520212065511428444637751846275447113441134168404818422261676045254163278378450512564552068205840264625622117272616384378485424333362585837208278600204050630488520152214542100045474670642144311074014048402665474835167832288623141348377636201771342454322775565213380737156322451705843242130348683135028402183773237070426480162423762426770740465032546015661022224712045680268357857201213713820752816118408522355411570452886870738860177653630410408203552124225500167332746708007880274606401843336707010570442734127168626074043448485810853148118606772546775176374454167525806401156883742113162708146061861675515720018407430220524500575527857057476405884448685745626133888070218407577252250643225653813375064553353468530550260772756767138664472651126365878171778883230831404425524140482715258552171775583617447000033003718063876104887835885621153884170226806686583323576266448575113821581113785452602585306801014663862003285835182512712143540144025325303080642343441666466406826424006222611635027171451842864725620026456327517645828125006332220214781004042460637442837853503388526866630425168671688445538246600414783242447527465864337301486512878074605141825620576040880222220834321034137350362850225847888288182277608780540466474408425664558723237773574146856815621032306366082660534153612520012343051583833344840558736113610732034865242884247367171808132736171245452276067253012538243472365332675812032376222643656770781631606627017212172434163234536588404047322723865742555485282585774227275166063364305478022711046383673075364733220621284085213742647702557800865532785418010611865084250181814743684005415406105063222037300435404375172880724351772463247335677825433206873622884245285254686468860281722236671122813433563373305224145501243683504687246207340764636833438766130163785674047512730074505803442143251750630456084268478772206361681300880675134538312230555581382001651815238350458221441758370841542830574231286063320372728401358647655157486070142558772141645065357580112115844512817481675276825504032441460421226517015101173340083722277544845004026744808466630882220575440622303370422737786644670418548374266666021523308427447073066071122185576262105862146885226361381535778007105001721660304489fe23da51d48ff5b182e876abd590dd2c62c67c11249dcb4946dde62ea38b3c3f7edf2d20f4d56b169183276af19ca6f3ced969c4ffb5addbee87c4a2a5b7c3b68b7f9b264709c57829564594ca8e4e1651165f81cd3f1259a4f3fa655da8ea6fff783713c08ca482afde8b296a40049092e6d88f695772245c4ef448a47a9999701ad5d65c9659c3451b2be0a5db4448dce6645a1aba8e4b201ca3d994fc2ae2f42e25cdfdb73f9c6868b7117be4034c96e721d38c7f7676b1c6f17230a6654f62d67b0113ef6226f3d729579924bbf665e7ee66deee58c1bb8153197c3610811a7937394de07930b5a13044e7d36a6c483556bc3c6d415dbfb31d53494c79e92d42214c0747274c2a8c5b5f9370f08eff0d27d03193ad2834ae9283cba51b35cff01bd3fd125d9c24b21da4bc610047fe4c5c422343f9f19d4674aa132de48b4b2436e9e4cdee81c1a6c410e14bfb438a7a3cbc7a1a75d033010b09d00b625350b8219c1f0073774b64b72c6d513ae433f6d27897e9b0a0d96b28d9b874324eaaf113eae0b5ec1a2acc34352d0e592abccc94f0da09066b80150e7e0d0ed78178ef74399578ac69fcd3e55a0d62c972e942f3ec8acf0cbda3d3bbd7febf6b58509d9440b4ccee78ec4fa11b7d3aee45a2a675832c238862619bee434edae1e0cea56ea7f9875aeecafc043f99711c0bf446aed1707a1c1a83a16a44c0a91d2d7163af7c553192ac87ec3aead1dcc40def004dc17b73d1f765df3b18dcb3ffec898e67fa15b71447a161a4577e1a1f3533dbcde013631bad70e55c60c4b00d3f98840cd54e86f099937f856cd45d2ad1545517375ec9e2538f9c6ad3247662a699d8afa837a6607235a80c0dba8fae6a0b8034275b05f99c3423e74d598d0af535cef8255c3136248b6db1c9a15a617199236ff62036d5fdb3b9ceeaa63524adb13f41fb10faa48e5037b4cea0c3cacdde08f26f2c11f171b468b26d6791260ea65845b48a2e29f174c4660ff27ada469334fe55c99c00cd0d3e687d95b91882388f739b78effd211059a30a9f4edd08e812ea06e16853fe628de2b77aa9036f9bcdbd2f533a5171d6699a9ecdb8767501f9d82d8446183fd576c71fcba3426d97f2ce258bfc97a48386aabe3b378ca30a7ab63aef6ae1fc3334d5fb70a4022ac7e3edc998c8b63128b45a787329d5c1045462f7a8992a3730bd69d846759b1c92e013d2d6225f374cd3ce5fba467f3da5de5393fab4d1890a34c8061fc9696970ee3e72fc9975688ca71b698f44d2b486f0954881f83c8664582a42f6756d3ab7e35de40d6559098ea6ed2c6d250b4187311b0951889d321dfce9d652d404a6c63d2350d3d40161c1eb9480b0f4552474464328fce6a4f758da47885868760e1ac1468c3cd84ddfcaf22ac10fdf5f73a3e758aa9488146d5a8b0c240c1ded13403fe4117b75619461f2befbb0ab1b33c3393c209f3b59e4a1ee0e4795c1278b5acced5a171c7100f22c64428f2bc856e143031a9947d2afdecfff2506a8626dd144136b752354cde6af43b95802c56bc86e975e7ed79e2d4ef1053920000278a4e3a98b9ccd634cc6f373d6dc97078a9ccd5e71119b05a82e15446760e496de9a25229184bff935b52e472a0e448513bfe615ea7dc5efa342a501db9512e8158a6e289733029b198e171c97ca414f02e10bf9022b680534433a6ccca66adc617413687d8ac09a9cfbdcdef84aeee5b857e19525edc5aa5c88562f72ca890a37a50a881b9b3aed4fd26a485cf9a0b0d5709cb60d9260893b93ffed510bd9ff2b97bf5db7ca5d67c63d68d3cb72bb13a9e4966c0a271c0cb92f6ba6803d3a412f9910cc2c250e9349f59efa3c94a606eab7d1fa4220e5aeeea3a6ff1f79902f623a2de6f086bb10f1446ddc3ecbd1a38b8c9fd8067b16174b25ef450336fe91c140947cb0b4047abb7ab6ecdf2d4dad9aff880b4322d90c6fafcb8abd864d573c6eea656cc8b59a4cfdb7d6b9f76697ce47c8dea6db2538aec0850705469a69b98b0a6dbc87290ede4a155886c9e2af16b4e1022a09482f03a5fccc00754bb252c86ba5e717939a2af1a2e9357eb2e6f4b39632c85b10cafe00c6e69b7a1ba4f8109251b2cd20881aa637ef1ae54501261a04c88370f8f5f1b120c72914cf385b3c18e849bbbbfd58d42274f50f8f610bcc43cf66171f76bf6f96c615b1711474bb9bdac9ba6beec366f7052d0c115c63917a2c87faeab63a3ec86f4762befd088b4b31d6f56caa4c30298debfb38247afb6babb55d8d43f02893d7596bdb0ca1a30c45ad770a93c175999b91ab3383951df261766399b1eaae58614663d370395fdd1a9f533b886df77edf6b99c1546e90aaa51895071561c320887eb50cebc708ecf0c2b3b4c33dc67d3496c69fd16bbe762fc03476528cfabd304b6c3f47bc540ce878ca646e52e2cb6ef1c27ee707a348969b1b677e2c3dbf235d7ca14d982a7070e4adad033cca242271b7c64eb2d97badefe590d4f8317f2cacefe10f25d9af0dd7aa7fa38589de30d6189a5efc1018d2ffe2f7e571c18462a5eca4ef657f9a9aaa2a15316caaa53a39eb0b0c3a3301e92d77a61c91808182a263c93eb9f6c7e3d15dc3f844846fb528707cbd58d05c48927916ce8a78665200199439bc6e7654bbcd5b326980af79779d0cf3c8497eaf6ab58ca0e1ac587f8f28297a590b8b239765aad4ad4dc6cc2f77da6497049772968aaba2f3d136172fb082e846d517292938f315b0aab218163460bdecad80a5551fbe059cd3996075b3774c764b091cfa2493616bb9aceccee4b37760de129636a978913679ad913dfc5055300f3af319bcdc7e4686d8897a3d2a1b4cc620b48cb7dccbfb39dd3a52361ee34cdfef3ccd5f269ef316bff3e57cb808e455dc10f4fa538b12e8375d4a16fb4daf68b75e092cdae178c5dbf0ff4c295358c84afecfd6e49c460702e6a514242c085704fd02709d2813f0453b69fdd4657a3c51cff3a6d7df51b30ef22df328da02d80030b9ebe5708e8de2e71012fa22bdff759d427f883052db3249add0b3c5733b98a96f4f29681d6d98eff8230af5fc61f7c083ad57eaa6e63859de78dc5098186e8b8f379f06bcc6a87c8e1fea19afe9d1bbc67363a8d0d88d740bb6da586f0543efc09a3f6126c84ebb031ef6e88374f1aa60417ec4fd1e86a715fa1f203de290a1ed08a5d1f3e91fb0d9d74190a6614524a30494a2fb3de71ea2f5e937fef1d18a14403da248935d8205055b9c8c0bd50b29f61bf57d480989057434ec20621d5061a17f4c79d51840585a33e1306b3f4fb3f0b33d03fefb0f658e783ea9de6c6a12fd096de27a1917244eba69e59b0fdf93b915c372e796eef3693613756937d37764d39d4eeb54aa885d1230ae1c25105db09eed9d5e4f9a751338211c490764611df76a129e0404e56786178283a4ad9e9f4e48b59ec6e056f09ce6c58bc4aefd484f7d90c4b19af8baa7aa20420e4c597892488b67b203fcc0c9f84"_sb,
        "1483236fc9f943d98417809e95405384530ed83e151e8465d34e4638f1f8d7058d62e19ab806490883a823176d4dc8a3c10c9960d0e948a9f7b62ca8e118de5d7a05bb18e8018b6cacb4fe7885490599939d90d004bd480b116f5d6627b6c4c1b2a1496cc3525ef9f19953ec63cdd6ebdb21d65b27c644194916aad07cc559b08cfc1282d25d7276c9e5062e0b1c4cf111c0a9dcc49bf40f5ed3c27cb4e78e39c1f068736a788e2ed4a02e9ef23eace802cd295b6eb97d533091b3293d9bad2938dfdecf2c4f9f6387b38a7fd22738a010b85949688650b6f063b6bc6350a1e84c869fb3bbcdc4bf6c0d0674d7c07f7ae78e4bbb302b6db8488b5f9164e5e264682e45e71b58fc19adf5ea892439eb352afddb63d22177aef17261909e3f87bcc7e1b1a58cd5de8f8a886a12d7137ce5bfbd2c53ecebfd1b9f2298583d767e0db5178b952f4d069d66fdedca1fbdcf8720aaaa5313c0500ecf95b9b70e7e3d58dd2b57433d3a0637df36e964b21f44f791b3af9074d6dbc9a2fc041d9e22d5e387c4081e6d4cce6ab11fc8b4f2c718eb2a19924e3f17ea1f44d0084b5d5296a97a3624e4e1f6ca05229f2888557aab577fd72f8dc328f0e4f45dd13a191920f671ace3bc29dc3195e951d0f5eeaa095a3d5f20e4e4ea1ac157261c1c514aeb6940e63053ad68383f14e923602e6b241e9813246b47f009db446fbf61246bad7ed386647d020a854cca39ecae5fa6d667cb6d433f02bc2fab9f37096f3c127741ec02a46c81022e070ae1df54623df44c5c744edd0d3bc66581b8e1348e75b5c52d0e41bc71edad5b12dda2280724b7d704bff2af04505f65ae496da86701d36bc9afb0b199442a9c5c743d97880e89c8ccb34c51890602627924316e79d4415cc1c2ed490a7a6ebb4b507181cff18bb53a6b8f816c15a2ea8667ce59edbe8f42376001e31981310ca403e08328aa97828dc3a86c260819bc8df72a3e29657ca65b7763a54067958ccd6fd73df789b306a37185c8117f0c86cf9d1c48d102eca8343f41f86f6084e2e72e6952357d7dc076a02a7cef64724ae634e35712e291a24704d2939717246371b42c11a672fe8fd31da83fc3d5de650fb2136a13a0d6229a115ea3758e3ad0810a99944275fa8fecfd2bf1d130b40473f4abf886485a1e36290db437b331db303539f98d298183509d934f1a747af29bc36bd7ca79e5d40d098ebfe61f400620b5b1afb81327342aadec634f1a77dae793d55a252d391ad155a6150ab049cba0270f07936ac21575be6fad53a0dc23f462e377f2c882391bac1c17c11d18a677c3effacc4c6a920596f8654bb4955750bcbc18744375656f0b594d825872bb161a1b7fdfe7d01e7a19e02f41ab9d02d1fed47161716172b8d68db04e57c74053dac785e9245bcc8dca48c736457edeb8a075c1c42254e87110cbe4a909421ae6aecece5d65834739be6cac51d1023ca25c322b7b3461ec65168cccf483a2668fb4527bcb312564c4097224dbc38ab397c3a7fd693b29992b9a773c43c0e9e94479f1762c91c367d9a079b13fdc38bd74f209e4d543abf8c9b14ced015599dfae94723361acbf6c1c0434dc0efaf22c61057775f17f36d76fd75d6bfce7dce922dcd7585aa33cae7a6916c4e4ac5f86e4753f8cc798c20205c8c47656fbad7799b6a53dae5dcb74cdb677fffa66cbf2873a219413714578d6da3b61aa29c494c2f084be1fa1c1cc40d1e4a424a4cec73e455062b6e28c333839570d6fc6c08402a8d39f145b97c3aacc6f24702e80f66f5d2fa1530cff2a07486b3d38d8c9994ee633c2e527af49fbe26f634c6663cf95520e04a76f33e8876826b88887c4fe8fdeb1c50f55c7e7fbc2a5077fa029db53b7cd8fa3576bbc219ae7d7b21518fd94fa187d39d63187bf9f2bf2592f1a7a35628137d82e50477ff3406dabfe558a3fd30d4e72d1f523ebf51df6c7bfd9c85325897a7949113f30c9570f3a9fbaf73658430c3b2afa43bf9d37d5410b5e416c5cf375cf9addcecf560e7d636c2d58b89d3e5a446201990effc467ffba1009ee90d0f46bd2d7018ae92cabecf62130bd7b4a077af31882a713c73572387533ea249c9a18f0599c06ee216cfc60f7498b2a75f3f8143d90a4abf8651defad600fd332ab09e3d8faefa2ec9152eaf6f2be6b78629022c0231849be4c13fa08b827ec301150fa380663f737418c8bf0700f4327f58c2256f8ba8b61176dfd1ace6a81c19033e3d678a9cb234f85a5b6372eaf1a1883f5aced3adf58b7fabfe44d986dbeda351ea9de5a841cd523336f986ab8fbbecf1f52b1e87dbb3ac457a743fae899a5bb3d10eafc4d0808b7fa98c8068093cae7a0bc2074baa701273734c28e97cd1102ffbcebb83ebb17c9200be6dbe58bc87c522e4d24254204fd2ec52c60c1225649c3dee17012c1cc0d5cda0b2f0fc4f27274e04acede68bace92e294b589be45d74c5377afeac7182f4b702b5a50b49f1b32bd476483957c664676a819fe6851f07768da82261c75d53f8f04a64291a56e008b11ae09ee73923257ec195020d958f7b6d43aba268978cb33b150a9c0decafbb36291257512cc7f2cb0b5564a0f81ef4686838cdbfe10475520e6ef69047cca864e50c86e9d91fc4eae741d4be8ad7b12952b76c3429548169c370a7a5e2db3fc809b9930952ef5af9cdccaf74fc13d0db8d55862858e47e4c6f66fda9da423b884db6ed79d012587f757f0bd974680ad8e"_sb,
        "00104431e750dbef67f52da2ab2d0f2da33294277742b69dda7d6682c86cf8235e6a61873f18abf9a2c8c7d95186b32fb8ac5dbf7b0a6cd8298b6e94ea27549035555fb126fb74b7077cb16aa7a6cda5fd8cc250516ce724d3a422daec2becceae026874ed60f98fb55bdd1be06f9eb6287fe4b53bbe28b61ff400c7b99abad4a84c72fcd25f1f544fb608bce7f0b1c6a904ade1dc712b66ec6cfe9f80ddfedda239201f80b48be0b07df03e322594449771b49a011178cff60c13136f3f25c8093244061ad0ce948380a9fcc22367fb55dd336d82a8158ec75822adbf9d1f5781e181622937c7fb9bae066c159c49cd49c3c1b7e9f71c4623a8c3bbc94ac4c68f09a1498bba49fa1c624b3e338f661823f4a794c804e97d90f1a96b55cb92b3f02b21c0b3c4bac712e72e48da18f931b8c08555b61837c62924378629e4483154b28757627deede01e075043a28b34c7d28fd3c759674afd1255b4ab844cedb00f18664ffb00e3e2b08272019a48194441dee20e6a88f8f69a93e70001b58e8595bf372d2d41a3188ec739226b08597a4bf05a16ec9d1b875d16140636a2206ff1f3a375787e9071ad81504d47f3cfb35466937bb95e4364e8f484843dc8be5ea3e097bf0d21d2a7697bd2cca815edd6998c61bcceeb06257032e351551607f0bd48da2f6c224c7fbb8b6a4c35c6c51729ebf6033561e70d13622b16ebf111ad62e91d07a617a9b8c95a9887d63fd0286c0f199d7aa02ad3d50d601bf387cd51a6479b2f7d5e79f7f9ec53c5b1a35b2f6a2b2cb2c496faa8008b760c91adaf57a4b092bffce522fe04cd1be1657c6133b3c67bd0ffa03dde43ccbcac44a136bf5c3179c9a13161148eda21496eb34f4049740ee198aa7e9451889966628a1cac91efe2666d3410e0a58942eab3eef6ad61463e9901c4c4ed5f711685edef5230fcf91a43961be2677fabbe2caea00bbb22d9e20afb1434ef25e774d2c772aac7e669fb7c311610707feecbef636ceadc57463cae9d1290f3bc5116547a075aacd37cd69881fb0d81900cb17e943c25c69e00f0f7254f2ff16876a64cb1028f914817b2d23b8c5ce4c83fad8cfb3324ee6a92741048f3414e52f4ffd823f0acd802ab3483da9a23a8e116062f32b7dc3db16020ff3c4854635bca8597ad90f6e4d6a24e42987b76e3f690f0876d3243b176c92fdb8eb254518f31d14c360d5d3e2a82b0674e1c3848daea60aca7907aa9e65a2f1ea296afdd7386a6b39b9d1e4fc604d1e485f9fc7fee942d03360deda387b8004835665548b693ae45b57538b7a9ad2e500297aa3f72bc60aa92d418562bf5e25ae9bed3ec25126fa0cabbda474559199b7b2eca783e9b031694a4dd94d1ff9307e1fdba0c06978dc1222d29dca492a78e926548cacb12b80f57664dd1fdf9d23a587b4007f58d7fad290073be76aeda66b57d3977d39f1a4692e20e90cef50b538b1a16a2dcfd1d7478776fc2235ae34b14b39e72609a7d1f1d3e46b1a141430455989029899bc2dcdc2e0f15ea48ed5c66afbe8912056c80c6089dd092df74c71ba4313084ad62a4ae736cc7fbf0a3b8211e8be1e8aab6472bfc0b93dfa17272898d997a37a929259bbed966b690e9ff0b078b4c55b76c14df3024d9c2f2cf18cea9f747fc085a178c0c89e05bacb5d246cab4e1a5ebe9ffcd1161d75ebf70c6d0ae3e939ca1510e1b31f84c09c89e6421d4dd1b786e903a60175223d6c112cbe88bae5e573604f8c9a0cf3cf0fb34e5525ae860626e3725a69c70fff25c7fd417e670121f8122e9b22f1d30db9079b9be068fb28e09fc76fe97fe29de15b519cdde5bf0cc6058eca5443ac9e405d689e322e441ec1bf46d20038ff5b69fcc234b6cff2d614ef78a16af5ee363fa685859b374880e091892d6d9ff942dc1aaf3ec6b6d7b92a4c5ad3ac329f4fa0a633a33d982491e409a47f0b347afea1ce6d9fd0326a9ab9019a26563c29619fdea7cafd1f3ab21ee0737aac0f5fc710d33fc9fa91a1e9aa74c6d77324b53d3820e8e06ee79b022d32ef9ed5d0cc5a23ebda44772b9557fdbd03c7bea00195f6920fe51c2b8356c6e118cf7cc6d7878bc3bfc7caf46762b838b08c1d3339532dce896fb7d7c6ad7e70271d42e921c14860bf78943501b4c1316a8222cbf0d16eb14be5805728b3a51b9d8bfd751d8967af2bd03fcedc2f8b9fb9031324bfbc38502dc202d77aaa6d2cc1425f1bb98554486821fb1242df02b2461cbd45a102193d3b34923de2e90b735137389372620149a195a06147ab5bc94cc73b2965dfe40180a5e3809ab968435658d3d6f9478d5961a878c4c50241c0bedd3ebb1721260fedba2a35a365ea48fad675b8adb7f7ff5e44832aa33da712a7f97db0025d3cb212123b1d1c7c0f86f3d698b84deafa8d928978aebf7bc01ca4aadad5da2ccb82cd963774b3ca65993bfebef5cb6c84ccc79b49bb7670a88a66bde1ca1bbbf76c5d303f91fcba0288ff4524b2533e1cf522f1c1e79924b48dcb0eeaf7ef4f03f644aa1fff70ed0977fc074f1d85bb1937043a711277931a2eab0be75c5b8a6dc4a973745c2f965dbc62acb151c86f4cfa2a01cb043e6c3b036185d21add6ce534647ff2d87de822f49037d6d1e302f045585129d2eb64b14437a282dac94d28e6dce6d0248d81920d5fb544e0488018de18909db9df42471b5d231f425fc656b750d4780a1e70d05ed25ed820022eed16f82c383215a46dced5349ed1b23f3f2d8ce554504b5eb3674e6c7f9f10ccd97a38b192da2c7514a051005ef305f166f9f38d3344fd2aaafa6c085f5b9e4f537121c5c065f2196965d772783f03cbae773fbb3aeb426bf06c94cd403f3ad2cfa37e22315c2f1b6cc62e84bd1ac9ebe29cc19eb80a3565a752145679951fafaf2dcb086fcc177991ba0cffd8a68d41543e01866663790b2af21fa782e83fff0a6e58e24f1abb2d4b6dbe9612a8951f23864f4fdee9e1236d0efd5d9db5b75fc018c8de8b1e53b43f34c7c2cfcbba013addf76f660e72ea910b60fb7ca8a70b465745cc5395c863c81371e29afebbd8bbc96091ca6cc424add5ab1d3db47501353ca0d1e6c991f81e43a0d4851b14a1d2dfeab85dd4e6d3962d9a85b8be9a71d2f6a9a6b296e78cb447b6f2e4bba48ce6917bf8bc40721d5bc45fc88aba3c5e4e083e2e95d0af5fefb1da797a7ba1276695101a08c73a0f35affcd6f856591bd4264e28bcb26bbb9f0a467fb926db645a69a5d18116f7c8b4a42324d5b1cc3ca22815983e7e757d2b9ee310527ba94ad47c6486ad437195a69550e4b699ff7eece71331a286ac54d88224f87fe269de2ffdbcb99bb8ee12ef5f2a4299bc0c870c85a64ba4f0fb941b3c8a1114537f7a897ef9fefc89b7975f44b15d4fba662d8a5ca2f43969190233489d08915e63dc9ff8eeedb6216833ab80f8dce090879e1f3a3e631afa9814058f0c5e587c6012eb9ae86c24be787fa14cd6beda6fbc0cdc2ea541bd2d1eb0d4e8bc42a1275958068d8a7bf75dffca5e46929717b122f852844873463c2d791c4f897d29b41a1fbf89f50b4663109462133b86616f971ed0859983f8be3019b76cba3e770e4a1fab3f6d66fd56ea47c356a8c68406e362077849b1ccce0a8d3c717b88363197c41a6006249c9ed7451e74513a97ab81879462695a69bbfe52bf99905c1e37b1c84f4c786fe8b01a4b357c168d54496bc12927403e60f68ca4e8db90ee01350e7a98f9c5302b19d5b8a3e609d66579556dd504efd6fcbb7abd90e4f8aa03cd87ac0b60d0555888cb4663a675ea8016e646f051eadd8a210f1ae334bb2767f709b7f50fa2677b5a5eb0cf43ecb863957bf12b9571a2a37d575ad10ab41399498a1d91dfae480165883d7e0647839e6d5793f460a61974d7c0b829817dedf606e8fa455d356a2ff338daff2c8c53b670e44a634af74d4c78f0474d55188b1b5bebcec175c6f34c962f1ee7f64e4e8c8d7af20249ebefd2dd3b334dbf6d792a10798ad5cdf87902a561801fc4c7d3204281dc7a8d4e27246aa5089e90e94ae8ea3c3181d9fed6d3f2d4d7fde1fefc561f0702d4635805a48590af4679ceca11b704c394879de470c0b54b089fb38a8c3e001918762f0dfafd1cc1a7d66973e888ecb9e0328f774d327017b654f279c6bec310a207e44a74e4ed5abcb6aa7f3ae82787fba8c7b9b6344043ea38b13fa4642ca713069baa83abfcf9033beb2ebc35e4c9cf2d5ec0a631f0b09898a52df3988249d406e472d5e5fdad7913186e2c33411ed1b0b241c2800b91d29960ef67a8ad9c9bd4b2546597b5c5061c05530920ce49d7be3e155d7776531802d1461d5fe974ab4505a7d7a44f81417eecf0d1b867f3ef094bae8d7de01254f07a904a3bfc2fe013ded8983c85ced3066f6c6adcfaab4e0157c85b3fb269fd4dfc7107cdeef71c33ba0f25097165c1f033f8a8fa8cc4afa9e9cd23d0f6b9240809131568108c2ff796b41f81247d9dc19befe94a87700a041c9dbc6c571aa4fd90b625039bb73d730adfafdfea647a0cebdf29c42db04391db6fa47aa984ae0327e4f3f63d3574e1e4091a6176898ea7bcc3163e3f4a4d5a6293d0e1f5b7c5d3e3073170cee3ed0000000000000000000000000000000000000000000000030c171b21"_sb,
    };
    triple t87 = {
        "903efbf16cd1f779825106f76de12df49ca4371b57117480702a1d94dd9c2042ef36c028da0fc830495d9ba90d50351ec7196f68b73c77253acdcc036cfc89ea9c666136197385c1e3eea6f5e484503f1c33d7abee2ac45073b0d8b51c649a1d23adb8b6266100c33bee32d25c4663e8b7f6df9647894dc146fabe7ac5b5fd5f14244014994c21090e5406680b06694bc46c93226dd22291c1404d1a446a18a7001c1488418028e0c4305ba4645ab28024450e2394515b988158324d09024c49a010d39001182904828628d4324842c02444904519446e1c416adbb80000a04d64a610cb48800b803111a0884482290448215896806242268a4466d2842d00014ec9c6650a82101b24215aa04d8c382a51884c1a30811cc28488c09019a50dd824091cb66851c00c844082a32848e28069a148211c300d092746e3982cd9440622c7648882495bb688c1242d83368994c08491c288e0940c5c443259802d0c250cd0482e09470802171109b16519c4300b98218ac24c00b748422444c2266542b60812148a409225c4a2610c2226da406e49086c9b9040188790cb068120000143b06591a00d1c164821866c0004060c943041484aa1466061062554888114102d5b8869e48805e3404508908464a24cd93662e034100027485ac68921830898082293c41124128d81b6450921824a4849d240312406840a812444c29051c845244588e4126ca09888da30889c36605aa86cd1888c14362e93008d894488d11491442662582682c32681a2b821c9000c83945010150e0903855c0069038051601086928668c2c4689326682088608b44812304804b386a0ab850e0004e01c64dc4380ea4066989b670984426c13052939869e3168e014926a3a24da41849141288c08051c3b06dc8a20d48b841184671182485cab2706420689bc68d01a020e2182501c3811b4380418605c1c040a49810109900e1923103c44ce18409124901d4206c41360920c220984469a1a8819b2270a42088cc3630989620d032601018914184444004849c9280d2224e84c44c88908460360cd98449c91021412671d13224e3928402230a4c846014b421e40490db38329b421012972913b62063c2911c458aa1808463066dda383290140ce1484e60c26919b0000c998122452a1b254c2281405bb08c02a9411c2420db864c98200dd8964913357210832d9148480ca70108844562864922826d0a80840a14684286294b1082d8100202189222344682062c0c176a1c986c20412542108ed1028900b521943880c212911b044891222ee2944c1b944584426e80466e192572a1c80d0816014b48104b24816120644224861026460219058c122d1c21001a3130c02432031952033644c31044d02632244686020946e3106a88008994a68408446a98326ac394504132504c948d8bc288db1291e1c68c84266c61164e20b68993140522212ea4a27003340a80c4500a29259b16709c02651b852d1b96240cb04100347041a40c6106815b06409394601a4941220622144060a3b650440089182401438804a020909b02819c324a84124ada006d1a462693044513b3010339416122815cb24114359109a38c01106d14363081482dc8c82d4b304d11c06c21966414266551a08d142042c2328502946402422ca1389044b84cd22261a1c43143a625500662538049233489098140883091c0c831431202ca26061c004ecab650a30210103461140688cb902921472d0198711c480ed426905b2261c3b44c24242ca414605c082ec19028e2346a0c21114a1844e11871d00292d806261a0502411871989891c1006103a54d480492cbc681d0368204c7112105010cb904c0424990c648932491928084d3a45090220408894552022693c670c89411d23486cc8205000144c8400d19400a1aa805d3067182288421054d8b2250102708e3486161248a4c049011926cc2a62990444a12306580b0240c298141c08801328190869022844ca1323058002e8a80200a348c9206924998208c246c6480111895611298604800481ac840cc0601a0284e1a1624ca309149a0840b34448aa040ca246490b84560c40012994524b830614028514431e1c6111b8729a0c22c11b6886440319ab464a398509ca46489062951186450460dd1364019c10c12149202068060c00008484e22047204b66024996dd4363186af293257208b576caf86d14b028a73d0c7b2781fcdf5fc02dd3d926e96d07747df7b4d5c5426073f0587600f6ff98abb97e094392d0bfc037e489a9fa9e7964dbaa46861cb55819a023475bb34b99d95411a4c6b3d131d500b5217c7ceaf0713cda8e54aac2e4da2a3e14d3bc420bec4bd0e1aa9bd9d3e3478e461e55f7519e91997aa35d62858c25d645e3442c2411beb306e9f215dc9d38900331677461067236b8e4cec7a222fdb89834203c79e1606b3a1a80f05c73bea376966e7dcdaef6ed9560aea880a221f77a3169127912df9ed9ee95b72d4fdea9ebee55fed40c1be36c3137fda7a1bf46cdbb0061b86cbc99631b00b0550ca93df5292a39ab61e4d1a16973ecb18de87de42ef234d57fb3484f8df07847cd6559e0e13e265f3203a24d79fb34889c2a1638603058a46a57fe0f8c3729ffd7cb16021e03b11b95a87fbd49b3d9aa1a961782a02cc6636b2a55de6a8a1ef7b1d8a639db9b739116300d4a85a4bcdd8658508bcf364057a06029c6e52b09167305e2a373b985abdbff12bd6aa6b189edbd545744a6579ab1c5e1055db5f97e3570ef07c06fda155eaedb36c95f65057a70ea3150a923b07343c74c0b4ae0a5e9cc1cb0c31104048846743631f49f1f89886285383a16cd88db64c44dad10eaad0112c88f7ae17f9b1f491df0eee81eb50f1d89a616be9a386b4146a2ee58997a106a88be83e2e7192a06f42cd391044185ddbf299298cfba5f127dffdf18b466fdf6d36ce7daf4f2bb89ce69e3f98a17d2cadd2a6c25c05112131c54a0cd4feb40def10a6e9c19feb1db7d4766a47d40ec3cac0e6790afc144b2060a807ee02318c09445d89501e9e61f8220555629983cf04201aded4b1b7f4862fd0732c7cd11a3763b5e34a492c8c9648275388a9ad01edd829e71cf734faef7d755597c17c8dfbbcd3d1adc706ae10625426bb71b759173f676ae295d9a73b06953ed34fef80768933819dab50283b91265f799562a0333e91ac3bd125d68abf173f8b6b6dee0635ec672f0cb44a143edf1451465072754a1412ddf1fb8fc86b8cfd5dba05c1fd47cd570809fdcce4ae335212e5d3d09579fc7b5a1121ce8525a11fa31e4afbea079b4be808350dd4df5325e214409b5f2267788ec9904aa65550bb1974fe5745d92cd159eab72d5524ee56adabbdfa38d8962749996c98e00724827ae31e388cee40f9c31895d5244a91b7eef8d9831bea769262dc43b0a8348bbcc602a062ccae3cc797029a3bc68e243fb8985d2ff1011a2e9f150b6c975e38d86ce028050d5e423717b65a09eee2f980b948e01a8df8628230434b7a4cd9cac95a8f17deebd186e96372dd9ad054cf862f1bec8d133543d4e89ab35c74634e0d07de2f1f0aa3c8c1093a6bc7ced456b0b2a6c1a7852f6a0feca54bbf5fb124be8dd1722fcd646ebfedc92a3a30762524701fa60f3076ead2daeb42621f22f900a06cdbe92d863fb61891f1b0cc27a3d73c1f82586bb87aeeb31774c5c7af01f3752850f34d12589051699a2f505bfa6db2d4e514aca84837effc71d48582752b23d8fa99e37f2715269607c209c84f11f1b3cd14f767e8c3585fecdcf1399c3ce55fd2c4b4f910fb9cdab977b56b512bea3c931e451985b95005b45db0c9dacc87d13526251f671ef836563bba62b77707653c0ca5838505bd3f5d38b863e1b4f698db9e52c95bcdf385d85f7a6ae9370c815d5732ccb72e6eb979bd0c2dd21c664debdb9a1a031759774557c06b420777cc2ade8949694e8b7162c9f23d0c1cb7d7bde1b243de3358e41263c7be1bde8fbf3ff3ec2357e51f0b15f84a627e01c1a81d65cf7eb6fe406bbb3e89c35f7ea99670ab53cf7e908e62b7b5ece31c1a42f9addd67717529efacebefb28989c19d3c311af457bc40d1adec93f6b6cbf9157d061e1fbbeb3f463c161d2a885bfd595b9f7a5fa38a1dc66aebfbb6fad905b93f523987671e60e27a2d8af08fd9a79a63f607f93e15bc9bb8659bd9713b7074d1576ccfe67725d2d7dc8ff402c93d12be9db0b70173a346e84c19c42464524bed606960c1024e159ea3952c55a97cdc8acc718310b0d72426d6298bd40c882bc984a73833b53ab0aa9f819a1cc6ee8db3d851dbbe53f5f2ecd12fc636477d5f4dff9d6b740ee9caa5f51c4805a2abd0730ee8a38e99dfc28952c94556a566051f701c6e2cd534b3d44ffe15fa004525c7c405ea08e7928abd1c1c8cc0e45134f9bd6caa02a6efffc31425a3e09de5bb616fb618bebd5c72d18993da4bab83f8d56667157b1f1a347c4a85281d93c5e3d9310bb721df9955ed2ddd7cabb25ec83f5050598f0879eb9f071203216af106622f10025657e62ba9b844c8cbaa73f8d6a37c6264105054d512ca6d242f0d0f46983e91c231ae9775800a35dfb4cd839cc6587ee89de14f7e26926052927cdf202fb3a39c1b942aa9d67ab00426a6d23acbde0b1254afd2e442ab7aa19e54e7b2d6e98b271de5e8f7ca6a447c1275313b9e45bdbbac6fc57aa9ce78b5858ec79c3a8526de42fda47a621acd26d9361f23f103d247e0fc7d10c3007b708ef2146af308709d8d2d8f8dd094cb30da11ec74b15fa802a4e3735f6ea09342f3e81edbff04486d9618295dad02e88d5dd7a84d2d9f1d5580ecd2513a0dd62be5c3901e36ce22f288fb765517cd5be077929e3669a379e6beeff8f049adfa5b4e32e80f62832706655ef5a792024faea9d7694dbf94e4c280aebb503eef07fcc59e63a2320969314a383ee0b984f11dc478c3189a3e58473f06a37d32fe88de4aada80777c8f04f8942024deec282644386677bae8dca9d848768fa726ee40752a20cde5ce62556838931fff9cf1d89e6a09da6e1bbe9ce1fa1c64555d82a305a3907ffb96ec49dfa881ce0f39558a4758dc8933a0aab59857f69af74c53c8b9b1e1ae736b28ead6a71783f81ff23b4fffe422a321c93eceb383eb7d62f3568a2fb59d8933f52fd92bdff4d219fd0931e76ad7fb8a3de09e29032f2889b53fc8f919e11643b598a366ecb9e4fc68ad03c22ef0a1eef9852aea8f0fffb4e46c372173a4302a3ea2edb5120e18a3ffe4de31b0c3596aa0ca0da4eaee609b72f6cb366eb68f45e000ae7fe7a88e04f471aa9a66dd18aa6c50b44c4855eebe530d40d799b1a2d88901cfc91d17ff748a862d2a462b5a7ee80352924ecb72232b6bcc4433e721d20f1b88d57d7e342b118c7d1ce5da4143f3ab48bc1b602b0cb9d455fc362e5a1768fffe345ccf02fda3797b358cb5bf81a69bfa7bdbc6f05b563e40fc30d0fac31aeac6208f61d638c1ea463089fe6d75cfedb4286f2b8f12b631d53bbb2f39d5d12c5ed3a45145c37ba99b16813b40a1f56c9c7229f2252a4d5d69074c2ffa8180dd7f5fc23b423420b624211e06da3017480cb90fcee458d2047d08bb4986e1ddb046a2210c9cfb4a628e1fb99698c479bd3c17ab6a49c3fe094a01f37bc366c3d2cd6de7c66e63f5e44c3af20a0f29fd7e0eb3de00a0485daea89036c7a1767a86cafa8675db365ac6326d836120d8bcbb97eb39a9fe4a7adb7c36162d4ed77dff6e8ae5fd11e41ef8557b8dc78a9a55b9619af9a775ad08adc086f4547d0f6811ffd650d596ec156c47c2a5eb25b4169517507163b9056f2f22b7753b76b62c586527bc20a627f6569db23c19befd38df3353428a638554b0e6e0f8dd1002b044906ecc49a4bf3e2d8368374d33073ac3f2deeb00eda862adb5f57c4a2a00252b3ed26dbea8beb2a31012e68ad1c053f7f5c7e2aa960a06858e3510f68a1fb4040aa2b08d1d72ca3aae909fe1beb9d10027942050099085679891aa949129f2ac3efdcb50ec66e688f5be7c005e7502411d59e29bd5c5d7712324c84baa8401d6b45fdeca36b07c655eefb3271269bab8423021f2332fe1c10e1fe91df5baac280628d5edb6d1c6f051c9240fb04168ba0d09e06259c329e17ec4165b1b3845f540465c3ee6de5158dea31e939b0f7dead94404e393be361cb0880078c69c4a403fb2b24b548887d2b5f77fc7b4cbad02d16ed6a8c55996d31de2f271a228dc52c3ff3d25874e1075f26f1cd816788de8d33e8dd1fc0a1236f906dec85a92f11caba9c85116c4088b46eb775c6f59442b5454c7b8607ea01fcb4cdada3319b38bfb15a2b6e4b7e5267ff13235a728d4b61a6dea620099e06c0d01ec588dbb4b625d9114c06d58750ecdf3d4b9a5cfa7b7fdc7933146d19bd2290f5f10615db5a3e9322d364f5b1028971e763e93069a4c85fcf78e52b543d2527cb2400b6b27cece09911933785d2eb3df8c8f08448fefaff4d4bd392688830cf0776d51e1a9637c7e38eae1ddeaef89cf17e34ef743515aafd7f33746855ec8d068b0c77c5c302a61b3b94b0ab4a9d8ee1427a91e516f2dd95e318b8985b211259405fbba92f65b31bfc7c93cf26c768143ca863f935d3c8ec9361158472d9f408709494e2b5f34fc09588551c4de8a8420dc0c09696ee9aad01194c21a1cdbcbaadf9f4de8bb3e66c7fad2b95973ec22cf1562c791c6c1debd2eec02ec572edc92f20a9758101ffdcfa094c686098514c6fb2c1e5da4d924b50422c7a011b4a8e2921f5707480dffb68e7695be9c9cb5c2fa19dcc31cdcf1a904c40d5bba8a381b812d9ae0f10679228b2d8692a91d382d8756358d97e78777c4b"_sb,
        "903efbf16cd1f779825106f76de12df49ca4371b57117480702a1d94dd9c2042bdda05359144230762a55d09aaf6961245e21b0d413dc2f39cf995327c6a1d52607bd9c3addf70d056361d8eb86c4b60fb7e0de5638e4255454cd32eb48653f6a9047247233284953da6d5f65af1b59421673f6f9e89b58d483c6a9d3fc4eac36cc3e489ca243f17dbcf0686b8b4dcc4a37078b7a8b28218777c5c223aba3123eaacd83ce2ed91ada7ee0efa23179f4457903417eda5350c4f4bd856de0bc419c91b76e7de9074c8eb4434d6055d80ac55ba276427fe3c844ec42bbd37ebc6cb142c6c1755f02f7f0c94631c987ec447060898b578144950e77cc51d9797df07025c8393ecb565c32eadd3179c696cb6ab5de99b8fcb623e8c59d836ae3d4e879cff4c4849880f0fbb293e7e637d3897d47caa894656d58434244593d72a9781ff045a405f9c8886d1c2b828467a9bc28c4e29aece6536abf539b02ab03c876d899376ccdda5c1abc4d3b2aaf3c5b3c7ad1956fcdb37f691e3e3dbb43ea967e733ec9e2d06d5a0e9fd67af3020cbae5fcd7490e44f5e2646245fb1b92c93bfd6945093246d490a1a0fcddd6d46bc4fa11137aa673d562488fa72cfb7fd210d3b3f04794415826861e87c50fd9b297f0ebe32153b959d2ba684aa978827bebf6b825c8c283388de6237ba4b51a0d47f01c57951809b9592c935c9acd64f45d08d5207ba365ca2af7908c7791a4ecb8c20efded66ea6408602935424797912e1363cb725c42deec98730fa99f17af4dbaa825159164878f5b97ffb8959160ef304e5e1a10d7f8671454b81081d7e24a75922eaac49dd67c0caac7e24d3f914ed64fe618e26860c6be09a6ba56100687b3f0a61ead9d55c984107b1db88a1901abfb93b0c3556e4a3601e08bae9babafb177d61702e0e8a357a2e760edd39cf7a3c601c022c629607bea771e408bed8c96788200f16f3f76f9fb89b4f04389d40b76ff720ce478bacd77e659359d3803bae4be439fd4a212b38e169bc1a1cf9594fedf4a33ed7da7b3e1d853d055d45c85b817805d25b59b52879b1eb7d59b723d05afbf9f62fb1384a12748b0965feaf5ccc5f45162f173836d87b25907c262aa247c198e7edfe7a472bc6553843e14c39e70dc993e566f0c339108fdf32a7c9c9186a09bd5773b3d3393caf8f8d3ccc2edb7ba08ffa76c918669560cc170f69ca41614abfe6d230ac167a8f74f6664a23179580796ec0c01269ba2fef895b36ec666e750dce0f76bb411867ec5152ef5b1a1ae2a857d791147ec9bf50d4b1e93562812787c7cd07b8ed8ccbc294ec0721775c69731b3b471ba1621cd5bdfd11d5ca1d38ead2a5b565d617a84d08ff1f4ad5bee0470d09b67c8d24c9018eb13205e6c86049b50c5de2c52345e015732cf2ce1da9e5df6cf0f54256b4d1d35e7193afaacf616e28e761d977abf2a54a3fe5d2823a275dca6360394f0a7879ab61871bb8f15c9bf1d8990dd256fb7f07c90541fb2af3c264e24c8dc24ba47f6e23c9c17ba3162cce979c063a47841a3d264cb8489082b3b1266539abf7bb6d6c277064980799793656e1f56906ba4541c19a8969cae9fb98ee76500a895df493fa7aa4d8c4cf2f6ac554aee05490c1cc888a8d9f30f477ef76ddc191794f0e92d3feade9b09b1de64ed0eba2bfc82d6bfc693a48205310d32bddbdd48333ac81db32b404163e6a835a5dcc3308aa0936f39e66cfd9173437b00bae28d6d4defc2ddad001e2a6e782bdefab164a214f36e95c307ca141a1f38d5efa943779e9d01a72100f5de76a072074286b5c6739b805eeefba5639f2ee0880265ed091e4a2dec230cf7453f4bdec313e16297338a3e3f6e03c8fb1208909a46dad667d14bcb66f9d21573efcbd3a4b2d8196c94eecc453d943c8b27d3e2bf9b7defc2d00efa3fd131bb48170a263a76366b78bbcc0d807cb0dca4daa9948c8240b537ecc28fefc3ab60d88a3486a5fc15c4bc6ec099e17d3a6b7b2761ea86980189e0e606bc0b1e971532e627ac167726902a9d44c50be24ffc34212b54dc596064e34b9821e6ea5a63892f187901691f516649e7b01748af1867a42a63bab54bf551668d0825e64773752449c64ec20842e5b8c6760d3379137eb9b5caaaf469474aa9bb3c1f1a5c257363eb27be4c7bc5c890f5d9532975051f2c4d62d14c0024289f240a6abde67c0896de2ebc84fcfe99cef7d15f79b221617d385782f60564b0b5911ee2d1be5459058a37c578d0348d1c6e5976ded66b6bd26d5ed78afc59561bc28c75fa4b5048aa59d7d7010e22293a14d27b7b6f2ed3b8e5974be2e8e46850e30737896fa0a2104ef31ecb24ae8b16fb090aaf578811a60d864711b8be1cb538f69a3af67ef47b81d50f07ddafb394373f8c8678d938e618184955d14eab88d715e1cd22e33aaa7027378c392d76f458463f28a7f365ee708eefeefddb261d0ec1f44eef0e0084dddfcd7dd4f28019d9184091c6e2ff0dcea261da0ee746ab6ea802f63c1c374675b52b3935b937eb7375ea28e3b5198c8fe2c9a677be319933d981a19505e557a2ed6e007110f0d95689ed23f62f20525e0029e4789933136b6cd3644f4d63b002a0b5942eab5ff7b858b40dc120d78bae089a65ee5c7128db3841df863f476ac15029ec0147a0596d2293d1b5f48b13071822e2e8e9f525fff083732ba87719fe92f6b264d9950458bd2c499e45af0c6179b0f116210844306ec289c478fa72f76a6ac46acc55a32c19b2827127fa1a6d6f36b1ef50ce67a458643caaf9b8a9fe3f28ebb7896520d14827f64ca7d6efd9b8599ede0d32f9748387569abb52028e042efc659aede4ef4ee4b85ffcd17455a522adf712c6675f46a3dbf341e6fc748cc19ce8306c1e3bb762f69b171446d36e63a299d0d68b88ecee3d7fa919bf402ca3ebd46fad001bc250c8177cd43aeef01d32417303b65728fd25dceb9f1289815c3132ec1e57a376f1c19d6901c398c58a3d7da3ae23c399eb71fa31a86d1cda4940b624d28ac93da1e9fac52026c3a110250b5e95f78229059aeb9703377671e47a09496f1dc333be19c537514ab5255a27838cb039cb7817d35c387f3a19e21437ee1cdd2c7ef58830284eaf677dce2d21d4b1ed54e2b2b15977a983cf939a9f5ac5598dd73e50a43cdb6bd4ca9f08b78cd9c96ced06554db1cf4a6749fd50b062c702a6a2ee9f6102d7e848254593e430ec9a659e0104602050b49b70c4f182327f3ebbc4214fa6bd034e2222ca012b3bc288413f6ece618eaf3acf1b0d9aa94a102da9b56329f4c808ac33d35af54e6d4c1d12e60734eb0289f1674255ad4faca9644c36388e65c1da898e4cd6531e89592e1e57bb2988d5788ebe1b013283dddfa346cda5b224f5f8beffac5ca521bc546aa3f1eecb254c597314657dda91727ba42929b3993c3c44ed3ce00aa1af9b00cf9eefd7530acf29c50bd0706620372424f58bfb356d28ef5a8d90403c52d62dd2f92a19b75e6c46cb4eac77a9102a6dcbb1dcea05a28688b94ed3966e9564519580803795f038255ccf0ab91762898942afa38e4bf7839b3dec19d2444d5237212e15a491d1f5636d41d0cc3751d96d856f1cd4bf2a3fe1ae8168b2475d11051eb1980c39fe1"_sb,
        "ef5e4b6a19d7e3f2610cf51caf5ec2afb1cacf9e1860c4b65a0bd6f1a5d4dec373fcaf0e72082f5d02f2cd034faaa77cb3d4d363f5b0798890396d395a6ba0025f01937d38f1a73fac801ad1e1bbe5095319ec38f7331b174f19dbfe45e5bba146cccd1664b36b74d43f5e680316c1436b943b0a24f9305a168a1700767f6b72fedd51c3072cd8f18930e14e4e5c1dbb25496e9563c21e414a52e160c4eab318e401b11b52a83ebb4a1b718be9ecc1d5b8c61c599b8e8fba752a6a25d37aca167e3f6fd46e96d657a6133851f2983f62c49e1d24e62e9de8baed342c18acbe2321d2c4df02ff30a93e31cf3adbddfc79f9f709536dab9f853482518c84d9bdd0e0fb7c0c6822ed571a73eedccc0ce7149c10f3f7bef392bf274b9fe995f771120f15744d623a1e8c4f5c6c659eb0ba0287b4db75ea1e9affbda0b343b8fa855aff45926ca62f8fc58ddd9d5c71d2e7b800941c2c74bcaf62cde9c97cfe205737fef8a2a527f954f008a5d34531a127b9fe6cc218fe713b3417d7ac0fa8e06a9385b03f1fd8b8b043c5b6266c07aac98afc7cbf554b00fe482f8218f4542b8253461b85fef3011ec2888d7faefc351f199288e76cd290490199520a2007fd714c6f6817e9034d7d51b3f27c34e94bd042b6ccf0469f14192cca7c63c885b3e1c085ef29bd8758865165fad6fe9e7fd1c516c5ab7d510ae54690eb1baee146aee248935c9d8b992469ac9f66ba6433a70e360a1cfff6f2f0168e241b1c390ff9c69ea289bbc7d66b7c3444d5dc04ee23a7d80328c8e29c2a3438969a3d6c806efd7eaf8f1874f7744410ce0c25e0b8117f6da441114d931bb847bdf21107a58a6d8565e109804bd0704fab7100126c6be6b80605c6c15226215770c5fb728fe4eae4c5c52812ed697732d725c85eb5143f91b51ead5ed9b8334e613dc70e2caa297838a027cac1d908afab311eb0c1d71079d3ee7ab448a38a7ec9d26d8cc45cb8262f6354045d757552ac8349e3eea902dc10c088ad545f3a1ad5eab50d6d6c5ce3b62302b2882e3fca681629e4589ea06f74fb397d5978287ec561167f5a972a825f779f30a9543c9ac46eec1fa258f8a92c65eb6e612f58810f708a1d5db1f84858d90f36d767e35ffb791f4828a23fbe374135a563318c9e7746af289ddb4473e332aba30eda25379af1060e1da9329fc54ced8704eb0b264503aec6d92a8b2431035238877d64150b36c791f193af3a41a9511fcdeb0213838c084f05e8024e5a3b3c196c6b49fb8d82105cb903813d39d56c96fef14ea2e40d0fa1b309df96e830b208ff582829c604f46c8c8a1d45ca15ea3cfe5d8e1267286666eb524f51af51050dce9ebad7e064dccff5c1d3ab3d15be872326bf0d02acc7e7e4e13a4224abd93b2a746c1d4fbac82bdc991c58446cd4d15888025a7c1151f25f3c6371d3a6bad5eeca0643486cc9e6dec5fccc20be05294af630bca5b5a8c5d1a3c9a94d294f273bfd922d8b66622c44e57b21e2fc48709de6ccf3400e4d8a63d7694495e4427be30af408c05585ad62b157eeac27de5fabbbc5118c5fc90869a66d31128a36b20ee40d7f3f0855c10f5f31ef8439f0128e9613693900f4a46530bd2e57522c664b5115e0a891feda1e78717b03aeac9380d4092e6e885fcb7ab783b6cb705349a4e1ebe35e7ba356e5573eb2e42ef319869f278bf98ee7ca4635a10f14c137fed389ff11ff5439c0c042e955d10c8663bc2fa082a1926c984be9918911e08e5fb6d3b74a5ad1a43bfb8e2c90aacdd4910d5d3e34f1f4d78d2b9e4189e5ac29b7712a8c348ac815224c2c61b63a42f7eac4e794dd996325c92d1bb9e8fd71b03a1c2c066a991e7b2c421a3029cf263377f805aca99b099ddd69f834637b870b869f7bc93d55dd07267aff48c752b42a175a8c4120a0241103abcdada00e6bfed3989ba8128a0d2fcc3d5b60b04893e53a95d16134835cf11005f8ba5490d9cc409336516bc15c07a8a41b9f093afe5f1d97958a8f19d05d5d73f5359bc712cf151c28700fb82bc97839eaa15d69a626365a9f744690a30472bb43e9232065b11d87a92487edfb844fe8fee5a35360665d006294516d717ed5276c8ffb70f0d677dd16d4b2ebf71a60eb90f3cf9a41e6b96ad60aa9a80ac66ed82e8984e8680e5b5128ae0af66c1c11ab26e1119c23996f34d69cd2ada61c2e3ec506f2f0037aec8ab2ad45cdcb84ea3ff0b60a1bc603026c34c38facdd90acdacd20a7f080e198d8608d09bf3ba3e9d97702c683f7c16a165c4c1a639131fd54a28f70c49123c07fc837ae812edffbc4881df63f6c8d7fb44feed04e6b87baef5ab3596bf502b673de4c1b0532b7dc595d5140f4a473e214d2831d4e892d1bbc16f7db1e712080466d3d072655daffa2d3df1fdb094caf5399b9698441bfbe3538b4b61b7084bd70789f8c2092713c716510282f87577eb29676216a037d3bef5271c797fca2abf33228d7e64387493f380efc65a0609a82b3abe4e7c2d84007c23f26fc9265e6e2219cdb069645f263ffe64f6cc5dd31b4b362a708747561cc654cbb1c0861a8c52392905a725571d0880348af36fa4b274670a9116c7dcc3de384f040f9efc2ab8a461980aa3c72414854ad3bea2feff68a6f76e3d3f445f41ea13ef6cf0322ccc58916d472c39ff042123a5ebb5c05579876ae12487fe2657ddc4dec2c90a0c18ea0c862a6d19492e0454bdd72138913ab0a8999f8c80ae97d1d369f42fc0bdbd0128a56051462ae71ab1e788e989abb4ce88e9d08b79664f8eb4d1f8c20d350da25f4aad0cde2cf106966a3889d1317e3ad9994079749226fb070c221d7d8fa14b24bfcbb263e49359f3c6dfc93462c43f88913fd067f5408991bb8d706ecbf0e93f56687fe86d401c11dbc1d3a718b175a12bfed6fc4174cbfa2a5c43d9fb807aae578700e5c90e681280f5b14dbef66ff4a51e841a6ca0f262343b41a2c05154fa260d820946881a1a75dab8cebb200b9e08e714a01cc6fd49e631b0abd304cc149ae34f5f31faece02f7cb07f8fd5c7ef9bd013b2b0256977f08f54225c5922e7e59dd4fbe0053164b18853010711bc3619c3ad510b0324b3f0358e171789da596858ab01747a94da035cad8cc85514b7032c2bc0fdb01bfcca544aef69da90d6fd6af7c51090a364698856a07e19db86c8bf71b879e99b86c4c709c918db8041e20c7502a37d5433eb57cfe30ec1ebef6625715b4e4e61f97eac6ccb167bba3c13f2ff62cb75d2eb39a89bd3fbe9b4fc36a8d33aa9b4843a0e1ecce09f503467b2dc60750c5d14c192b6e56f92e151fff00187d0f16d0a0608c30ac3c47942eaeb21f2e63423c2c9e9138f250c9f0099307e389e5de71ba8714509d9b33536def022f8edfb0277286dad0d78fa7200b5bd4b3bf9d4cf627e9c68a0afa8d1695e9c72a62ff80750266430eff90e6e9439c9553a326d84c54f977cb4f5370a19c121005e0c80a7b6605b683ea236667fa045e5f73243998490a6992693c5fef79259f52be42e6560d0e644888f16ce5a4a01498b585f90e670831c49e429898020a4c3facb76c0f120126bb6c9459087ff0b649ed5d143683be7a437e21c80ee8a5f92a7606b38655433427cddfc1277707733a3ba1c67e254b6f47747eb9b3a537dc12cde1e63c05796fdc8d6ea613d0211174d66a34520eb4d0476521a0de3d45c2598c576e7da73ba4cb9dea4504472ffeff859dc2de711532c390b0760b9cfbdad542bd5d623842340bc7ca0f13022a59c0a82d8fccf07265d24582ede1fe3abdb14914877080457be3bf8ce124d5cfcf64f6ad8696d00a7f9c8a8aff63659f1888cfd670f3ddc0ab04c8c646d61856fe3e2e479d214619f34b9994c6800dba4323978ca55b9a3116e7526f6ef753b705783f64f9942c62b53a1fc3b8e6b1237e215ca18aa54f2ada12e4cf7a6a63e21dfeaa28d7a27096e01dd1aa77a95a0c04c47b9fbbc3c31fe124bbf6f8c87bf05b4422d1d585ed4ac4db62bbfc8a52bb5fc0c162797ae44def777b25a169cfd2fe7cbe87873834e99f4f0abda6637a2a820b177eaa7a5d8506f63d1604f9e492fdc334e9fb0ae263548a2aa8607a59f741934246b316b900dbb07ccb56067c00d2c42d4428d1bf489d96912ca2e1e62d0fc5bed12103ca41190c14f7d8513dcacd7b9b141d69085fdc724b6ece8e5050208840bc90bea4a182d28d3bffbe1e1c7ec66e3d5e310a938b9b7127efcc47f407de15b059db8ca7a73e0e6d289f3781854a90613e94a88a6d7c9b803c248be7970e4be1938a6168b99e38a41123e6af0c2086d291b983630af4852d07ff9dc6a6ff461c95338cad2b13c5c61babdbde8d51112a1de211a41aea0cbbbaa7453bb9ac7076622075139ab7b4463527004ab26b675e5e3f42f1f2393d94a2a671e8c9c5ed5b1666c8ea5eb1686fd1087629b4560551f0a57f64ab7fe829a361474815fc16d6df534f69ec7ed5244bc8b6422f261d39205accc9b9a142e6e521d1f49549114d4abbe99c43175d09978e8f0d3c26839cdc73659b191531cc81481ee03959527a38547290b49449697e85b9d8a98cfe7073a126f3263b99a079c4141ae1f45ffba293fc197484a3c3c7b85b1bbe46e16b76e17cc1bad3cd487d7a10d2d01c8ed84f8d674354af11ede1dad5a0108dc644b58f5cc718d4c696c93617dcf49b114f22bfabcfcc14ec15c3c1598fd1e1d488d04f07eafa74600fe6596d682252c422aebdda3db3c31180ef83d01e457d0ec81cc177f211bba5d93839f003f4b6db6204678d084fe19425638c1de5dfa593956c83f36862ea59210c31bd2600000a811ab95a9473b07bf460be223704a736a55dff248d25fde0e3bbb2f1b1703aad3a80998bf5f36124500ad746919a11161fbc01142bb60cd9e80a56f9ebb7137cfb0543b7e99c8f657bdffd900b5d95f6b6f99aef60adc2d0c4b4dd5283deef2a432228fb521adb74faab82da64bfddc9c522aa5f4f7550021c0e827c7080b7f87e5d198dc289e6b8780c00bbc8d5997c820922d072e609155da4e2d0c4fc0653c9da4894cbc2ecf6f7dcae0b1f5b06a9f74bff02d1f3afe3e957ab6d4b4353e9d1cdbdbeb895a0aa3fe149327b5f3c17482f77b415aba9723f3c8c558e4ccf33d5092755652c1a9c54f8212fce5353944262b8f6d16993c7c7f33bf2f8c3eb6d540885961f3d013c063d5bf2be358950e77008b9f341208288e956ebbef219bd1f96b765abbb7d0d29b683afde5d63f7fc1bf907dac96bdb3e0699732b519e69e4f4bf57711a0d36ced7ab2cf37715a4eb9c37eddbb6e1d0f7b8ec5fa99bef4a4f08c5216d330536a8161a40443144b424674eee55dcdd1958ddf61298f29538c442bfd6028b4d483f36c151cb4674fce45dc901a92a481d69d4383d7553e04c4f367c171c87e868dd9a2898d136e56773af1d36351572f20b0bb49fc72bf2257887394250ba803fa584dcdec3432ba65615a48f27f975d8610d224d8156eee84857b8e57064942fa12fe416a818a8ee790b4f60808639576c715eed0c1c6333dda62cf28991a779df67f29c07a6eb744db1fedd99e2017286e0870d3d63e084bd93f13300597cb9cd714cc5291748ccf4b140d81a720cd5a3b19307a4dc48bb0934fe13393714f394891dbc00e7580cf965d2dc8f1455d11c23701faa4d26bfbaffb7a0e3563a92a0fab343600a265d84ea3be4aebe508a4e872c003180f70cc6451e206f20b21b37168b11701a7d20eb407e23359075a1b36c319d85e698df3ac9c4d992e0a1f7655ca27f67274aaf322abd7a3a9afa3905c9298d60818987977962409887f12930b2eb53dfdcfa9d3c98e7c3a961c5d712b0b2f7658a24a970a062f37fc8dcadde33374554b6b3046b28d6a2c67c7994886bb233335ebbbf42eeda2c28f477ba0baea25ef595466ff743d9019f0df3d4c7ef764678a2c629aba8a59f6731d5dbe0e0b1176ef58ea593caf4d1c9c2d2ce20463fb422a658645b01a614d7ec5b9b800f8129ed2b9de45ece64c651deefc2ffa874756271c049047806bdaa77ab023cded533a009e079d55480de7ddbb7baaab3ac3a8b5f357f5425f029de76e09716536b2cdf763cf5c1e5154fd81d1cc4d4acc1ed23594196011dae529e0ee8f11db9c3258a5789b77100e969a2dc91b791e96ca10cb17b84b63be2f2103b8e34b499b828c1af5938626e12f119955866c85879db5d9701c29348d16aeadbb7b547263f38971e00bb5f2f8059e3e4231d1c1ec5d16201c68a4af0f5bca7f7443ada85e18a9e969e7329230c5d38aece15c9386ec0f0963e736e081b1d2b75d6577b6317ebcc94af57d00c5b58ae9d95c5084e6604d34556bbfb62363cd603b3a48dd2d9eddbce3dbe67b6f4361531586163a1a5b9bec1cf03318dff91bae0edee686e939ba0a7e3f0f509163cd3e21b3a475a82b6ccd6fc0e2d4c506c74799eb8e3e601232b334ac6cbf8000000000000000000000000000b0f141d222b363e"_sb,
    };
    f(ml_dsa<44>{}, seed, msg, ctx, rnd, t44);
    f(ml_dsa<65>{}, seed, msg, ctx, rnd, t65);
    f(ml_dsa<87>{}, seed, msg, ctx, rnd, t87);
}

void test_base64() {
    LOG_TEST();

    using namespace crypto;

    auto bytes = R"(
50 44 14 1b ba 11 75 41 51 2b 94 31 44 1b c7 af
ba da 6b c5 ba 56 0c e2 d7 32 d3 b4 65 88 ae 40
68 31 2f 7c eb 50 77 97 cf f1 35 de 4a 38 3a 48
89 a3 73 da 34 4a e8 6e 8e bb 01 fd dd 90 0e 48
17 4d 8b 15 42 a0 1c 2b f8 13 8b 84 43 92 ed a4
cf b3 0a 05 79 07 eb 92 4e 6b 3c 9b cd 57 b1 6e
3b 09 5a 35 3c 38 83 cb a0 22 8f 02 a3 74 c3 c6
ed 10 1d ae d5 cf e9 f8 32 06 a4 bb 2b f5 1f a2
)"_sb;
    auto sig1 = base64::decode(
"UEQUG7oRdUFRK5QxRBvHr7raa8W6Vgzi1zLTtGWIrkBoMS9861B3l8/xNd5KODpIi"
"aNz2jRK6G6OuwH93ZAOSBdNixVCoBwr+BOLhEOS7aTPswoFeQfrkk5rPJvNV7FuOwl"
"aNTw4g8ugIo8Co3TDxu0QHa7Vz+n4Mgakuyv1H6I="sv
);
    auto sig = base64::decode<true>(
"UEQUG7oRdUFRK5QxRBvHr7raa8W6Vgzi1zLTtGWIrkBoMS9861B3l8/xNd5KODpIi"
"   aNz2jRK6G6OuwH93ZAOSBdNixVCoBwr+BOLhEOS7aTPswoFeQfrkk5rPJvNV7FuOwl"
"aNTw4g8ugIo8Co3TDxu0QHa7Vz+n4Mgakuyv1H6I="sv
);
    cmp_bytes(sig1, bytes);
    cmp_bytes(sig, bytes, true);

    auto test_url1 = [](auto &&in, auto &&out) {
        using b64u = base64url<false>;
        cmp_bytes(b64u::encode(in), out);
        cmp_bytes(b64u::decode(out), in);
    };
    auto test_url2 = [](auto &&in, auto &&out) {
        using b64u = base64url<true>;
        cmp_bytes(b64u::encode(in), out);
        cmp_bytes(b64u::decode(out), in);
    };
    auto test_url = [&](auto &&in, auto &&out) {
        test_url1(in, out);
        out.resize(divceil(out.size(), 4) * 4, '=');
        test_url2(in, out);
    };
    test_url("f"sv, "Zg"s);
    test_url("ff"sv, "ZmY"s);
    test_url("ff"sv, "ZmY"s);
    test_url("fff"sv, "ZmZm"s);
    test_url("ffff"sv, "ZmZmZg"s);
}

auto test_all() {
    test_base64();
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
    test_hkdf();
    test_pbkdf2();
    test_chacha20();
    test_chacha20_aead();
    test_scrypt();
    test_argon2();
    test_x509();
    test_pki();
    test_streebog();
    test_grasshopper();
    test_mgm();
    test_gost();
    test_jwt();
    test_hpke();
    test_mlkem();
    test_mldsa();
    test_dns();
    test_tls();
    test_email();
    return success != total;
}

#ifdef CI_TESTS
int main() {
    try {
        return test_all();
    } catch (std::exception &e) {
        std::println(std::cerr, "{}", e.what());
    } catch (...) {
        std::println(std::cerr, "unknown exception");
    }
    return 1;
}
#endif

#ifndef CI_TESTS
int main() {
    try {
        //test_all();

        //test_base64();
        // test_aes();
        //test_sha1();
        // test_sha2();
        //test_sha3();
        // test_blake2();
        // test_blake3();
        // test_sm3();
        // test_sm4();
        // test_ec();
        //test_ecdsa();
        //test_hmac();
        // test_hkdf();
        //test_pbkdf2();
        //test_chacha20();
        //test_chacha20_aead();
        // test_scrypt();
        // test_argon2();
        // test_x509();
        // test_pki();
        // test_streebog();
        // test_grasshopper();
        // test_mgm();
        // test_gost();
        //test_jwt();
        // test_hpke();
        // test_mlkem();
        test_mldsa();
        //
        //test_dns();
        //test_tls();
        //test_email();
        //test_ssh2();

        return 0;
    } catch (std::exception &e) {
        std::println(std::cerr, "{}", e.what());
    } catch (...) {
        std::println(std::cerr, "unknown exception");
    }
    return 1;
}
#endif
