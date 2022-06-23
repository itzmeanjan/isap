#include "isap_a_128.hpp"
#include "isap_a_128a.hpp"
#include "isap_k_128.hpp"
#include "isap_k_128a.hpp"

// Thin C wrapper on top of underlying C++ implementation of ISAP authenticated
// encryption with associated data ( AEAD ) functions, which can be used for
// producing shared library object with C-ABI & used from other languages such
// as Rust, Python

// Function prototype
extern "C"
{
  void isap_a_128a_encrypt(const uint8_t* const __restrict,
                           const uint8_t* const __restrict,
                           const uint8_t* const __restrict,
                           const size_t,
                           const uint8_t* const __restrict,
                           uint8_t* const __restrict,
                           const size_t,
                           uint8_t* const __restrict);

  bool isap_a_128a_decrypt(const uint8_t* const __restrict,
                           const uint8_t* const __restrict,
                           const uint8_t* const __restrict,
                           const uint8_t* const __restrict,
                           const size_t,
                           const uint8_t* const __restrict,
                           uint8_t* const __restrict,
                           const size_t);

  void isap_a_128_encrypt(const uint8_t* const __restrict,
                          const uint8_t* const __restrict,
                          const uint8_t* const __restrict,
                          const size_t,
                          const uint8_t* const __restrict,
                          uint8_t* const __restrict,
                          const size_t,
                          uint8_t* const __restrict);

  bool isap_a_128_decrypt(const uint8_t* const __restrict,
                          const uint8_t* const __restrict,
                          const uint8_t* const __restrict,
                          const uint8_t* const __restrict,
                          const size_t,
                          const uint8_t* const __restrict,
                          uint8_t* const __restrict,
                          const size_t);

  void isap_k_128a_encrypt(const uint8_t* const __restrict,
                           const uint8_t* const __restrict,
                           const uint8_t* const __restrict,
                           const size_t,
                           const uint8_t* const __restrict,
                           uint8_t* const __restrict,
                           const size_t,
                           uint8_t* const __restrict);

  bool isap_k_128a_decrypt(const uint8_t* const __restrict,
                           const uint8_t* const __restrict,
                           const uint8_t* const __restrict,
                           const uint8_t* const __restrict,
                           const size_t,
                           const uint8_t* const __restrict,
                           uint8_t* const __restrict,
                           const size_t);

  void isap_k_128_encrypt(const uint8_t* const __restrict,
                          const uint8_t* const __restrict,
                          const uint8_t* const __restrict,
                          const size_t,
                          const uint8_t* const __restrict,
                          uint8_t* const __restrict,
                          const size_t,
                          uint8_t* const __restrict);

  bool isap_k_128_decrypt(const uint8_t* const __restrict,
                          const uint8_t* const __restrict,
                          const uint8_t* const __restrict,
                          const uint8_t* const __restrict,
                          const size_t,
                          const uint8_t* const __restrict,
                          uint8_t* const __restrict,
                          const size_t);
}

// Function implementation
extern "C"
{
  // Given 16 -bytes secret key, 16 -bytes nonce, N -bytes plain text & M -bytes
  // associated data, this routine computes N -bytes cipher text & 16 -bytes
  // authentication tag, using ISAP-A-128A encryption algorithm | N, M >= 0
  void isap_a_128a_encrypt(const uint8_t* const __restrict key,
                           const uint8_t* const __restrict nonce,
                           const uint8_t* const __restrict data,
                           const size_t d_len,
                           const uint8_t* const __restrict txt,
                           uint8_t* const __restrict enc,
                           const size_t ct_len,
                           uint8_t* const __restrict tag)
  {
    isap_a_128a::encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
  }

  // Given 16 -bytes secret key, 16 -bytes nonce, 16 -bytes authentication tag,
  // N -bytes cipher text & M -bytes associated data, this routine computes N
  // -bytes deciphered text & a boolean verification flag, using
  // ISAP-A-128A decryption algorithm | N, M >= 0
  //
  // Before consuming decrypted bytes ensure presence of truth value in returned
  // boolean flag !
  bool isap_a_128a_decrypt(const uint8_t* const __restrict key,
                           const uint8_t* const __restrict nonce,
                           const uint8_t* const __restrict tag,
                           const uint8_t* const __restrict data,
                           const size_t d_len,
                           const uint8_t* const __restrict enc,
                           uint8_t* const __restrict dec,
                           const size_t ct_len)
  {
    using namespace isap_a_128a;
    return decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);
  }

  // Given 16 -bytes secret key, 16 -bytes nonce, N -bytes plain text & M -bytes
  // associated data, this routine computes N -bytes cipher text & 16 -bytes
  // authentication tag, using ISAP-A-128 encryption algorithm | N, M >= 0
  void isap_a_128_encrypt(const uint8_t* const __restrict key,
                          const uint8_t* const __restrict nonce,
                          const uint8_t* const __restrict data,
                          const size_t d_len,
                          const uint8_t* const __restrict txt,
                          uint8_t* const __restrict enc,
                          const size_t ct_len,
                          uint8_t* const __restrict tag)
  {
    isap_a_128::encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
  }

  // Given 16 -bytes secret key, 16 -bytes nonce, 16 -bytes authentication tag,
  // N -bytes cipher text & M -bytes associated data, this routine computes N
  // -bytes deciphered text & a boolean verification flag, using
  // ISAP-A-128 decryption algorithm | N, M >= 0
  //
  // Before consuming decrypted bytes ensure presence of truth value in returned
  // boolean flag !
  bool isap_a_128_decrypt(const uint8_t* const __restrict key,
                          const uint8_t* const __restrict nonce,
                          const uint8_t* const __restrict tag,
                          const uint8_t* const __restrict data,
                          const size_t d_len,
                          const uint8_t* const __restrict enc,
                          uint8_t* const __restrict dec,
                          const size_t ct_len)
  {
    using namespace isap_a_128;
    return decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);
  }

  // Given 16 -bytes secret key, 16 -bytes nonce, N -bytes plain text & M -bytes
  // associated data, this routine computes N -bytes cipher text & 16 -bytes
  // authentication tag, using ISAP-K-128A encryption algorithm | N, M >= 0
  void isap_k_128a_encrypt(const uint8_t* const __restrict key,
                           const uint8_t* const __restrict nonce,
                           const uint8_t* const __restrict data,
                           const size_t d_len,
                           const uint8_t* const __restrict txt,
                           uint8_t* const __restrict enc,
                           const size_t ct_len,
                           uint8_t* const __restrict tag)
  {
    isap_k_128a::encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
  }

  // Given 16 -bytes secret key, 16 -bytes nonce, 16 -bytes authentication tag,
  // N -bytes cipher text & M -bytes associated data, this routine computes N
  // -bytes deciphered text & a boolean verification flag, using
  // ISAP-K-128A decryption algorithm | N, M >= 0
  //
  // Before consuming decrypted bytes ensure presence of truth value in returned
  // boolean flag !
  bool isap_k_128a_decrypt(const uint8_t* const __restrict key,
                           const uint8_t* const __restrict nonce,
                           const uint8_t* const __restrict tag,
                           const uint8_t* const __restrict data,
                           const size_t d_len,
                           const uint8_t* const __restrict enc,
                           uint8_t* const __restrict dec,
                           const size_t ct_len)
  {
    using namespace isap_k_128a;
    return decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);
  }

  // Given 16 -bytes secret key, 16 -bytes nonce, N -bytes plain text & M -bytes
  // associated data, this routine computes N -bytes cipher text & 16 -bytes
  // authentication tag, using ISAP-K-128 encryption algorithm | N, M >= 0
  void isap_k_128_encrypt(const uint8_t* const __restrict key,
                          const uint8_t* const __restrict nonce,
                          const uint8_t* const __restrict data,
                          const size_t d_len,
                          const uint8_t* const __restrict txt,
                          uint8_t* const __restrict enc,
                          const size_t ct_len,
                          uint8_t* const __restrict tag)
  {
    isap_k_128::encrypt(key, nonce, data, d_len, txt, enc, ct_len, tag);
  }

  // Given 16 -bytes secret key, 16 -bytes nonce, 16 -bytes authentication tag,
  // N -bytes cipher text & M -bytes associated data, this routine computes N
  // -bytes deciphered text & a boolean verification flag, using
  // ISAP-K-128 decryption algorithm | N, M >= 0
  //
  // Before consuming decrypted bytes ensure presence of truth value in returned
  // boolean flag !
  bool isap_k_128_decrypt(const uint8_t* const __restrict key,
                          const uint8_t* const __restrict nonce,
                          const uint8_t* const __restrict tag,
                          const uint8_t* const __restrict data,
                          const size_t d_len,
                          const uint8_t* const __restrict enc,
                          uint8_t* const __restrict dec,
                          const size_t ct_len)
  {
    using namespace isap_k_128;
    return decrypt(key, nonce, tag, data, d_len, enc, dec, ct_len);
  }
}
