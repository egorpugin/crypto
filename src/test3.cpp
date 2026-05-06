#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdh.h>
#include <botan/x448.h>
#include <D:\dev\swst\pkg\57\e6\89cb\src\sdir\src\lib\pubkey\curve448\x448\x448_internal.h>
#include <botan/hex.h>
#include <botan/pubkey.h>

#include <iostream>

int main() {
   Botan::AutoSeeded_RNG rng;

   const std::string kdf = "KDF2(SHA-256)";

   // the two parties generate ECDH keys
   const Botan::Point448 u({5});

   const Botan::X448_PrivateKey key_a(u);
   const Botan::X448_PrivateKey key_b(rng);

   // now they exchange their public values
   const auto key_apub = key_a.public_value();
   const auto key_bpub = key_b.public_value();

   // Construct key agreements and agree on a shared secret
   const Botan::PK_Key_Agreement ka_a(key_a, rng, kdf);
   const auto sA = ka_a.derive_key(32, key_bpub).bits_of();

}
