#include "isap_a_128.hpp"
#include <cassert>
#include <cstring>
#include <iostream>

// Compile it with
//
// g++ -Wall -std=c++20 -O3 -I ./include example/isap_a_128.cpp
int
main()
{
  constexpr size_t kntlen = 16; // bytes
  constexpr size_t mlen = 32;   // bytes
  constexpr size_t dlen = 32;   // bytes

  // acquire memory resources
  uint8_t* key = static_cast<uint8_t*>(std::malloc(sizeof(uint8_t) * kntlen));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(sizeof(uint8_t) * kntlen));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(sizeof(uint8_t) * kntlen));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(sizeof(uint8_t) * dlen));
  uint8_t* txt = static_cast<uint8_t*>(std::malloc(sizeof(uint8_t) * mlen));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(sizeof(uint8_t) * mlen));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(sizeof(uint8_t) * mlen));

  // generate random bytes
  isap_utils::random_data<uint8_t>(key, kntlen);
  isap_utils::random_data<uint8_t>(nonce, kntlen);
  isap_utils::random_data<uint8_t>(data, dlen);
  isap_utils::random_data<uint8_t>(txt, mlen);

  // clear memory allocations
  std::memset(tag, 0, kntlen);
  std::memset(enc, 0, mlen);
  std::memset(dec, 0, mlen);

  // authenticated encryption
  isap_a_128::encrypt(key, nonce, data, dlen, txt, enc, mlen, tag);
  // verified decryption
  bool f = isap_a_128::decrypt(key, nonce, tag, data, dlen, enc, dec, mlen);

  // ensure truth value in verification flag before consuming decrypted bytes
  assert(f);

  // check that decrypted bytes exactly match original plain text bytes
  for (size_t i = 0; i < mlen; i++) {
    assert((txt[i] ^ dec[i]) == 0);
  }

  {
    using namespace isap_utils;
    std::cout << "ISAP-A-128 AEAD" << std::endl << std::endl;
    std::cout << "Key          : " << to_hex(key, kntlen) << std::endl;
    std::cout << "Nonce        : " << to_hex(nonce, kntlen) << std::endl;
    std::cout << "Data         : " << to_hex(data, dlen) << std::endl;
    std::cout << "Text         : " << to_hex(txt, mlen) << std::endl;
    std::cout << "Ciphered     : " << to_hex(enc, mlen) << std::endl;
    std::cout << "Tag          : " << to_hex(tag, kntlen) << std::endl;
    std::cout << "Deciphered   : " << to_hex(dec, mlen) << std::endl;
  }

  // release memory allocations
  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(txt);
  std::free(enc);
  std::free(dec);

  return EXIT_SUCCESS;
}
