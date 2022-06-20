#pragma once
#include "common.hpp"

// ISAP authenticated encryption with associated data ( AEAD )
namespace isap {

// Given 16 -bytes secret key, 16 -bytes public message nonce, N ( >=0 ) -bytes
// associated data, M ( >=0 ) -bytes plain text, this routine computes M -bytes
// cipher text along with 16 -bytes authentication tag, using any of
// these four algorithms {Isap-A-128a, Isap-A-128, Isap-K-128a, Isap-K-128}.
//
// Which specific algorithm from ISAP specification to be used, depends on
// choosen template parameters. See table 2.2 of ISAP specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
//
// Encryption algorithm follows generic pseudocode described in Algorithm 1, in
// above linked specification
template<const isap_common::perm_t p,
         const size_t s_b,
         const size_t s_k,
         const size_t s_e,
         const size_t s_h>
inline static void
encrypt(const uint8_t* const __restrict key,
        const uint8_t* const __restrict nonce,
        const uint8_t* const __restrict data,
        const size_t dlen,
        const uint8_t* const __restrict msg,
        uint8_t* const __restrict cipher,
        const size_t mlen,
        uint8_t* const __restrict tag)
{
  using namespace isap_common;

  enc<p, s_b, s_k, s_e, s_h>(key, nonce, msg, cipher, mlen);
  mac<p, s_b, s_k, s_e, s_h>(key, nonce, data, dlen, cipher, mlen, tag);
}

// Given 16 -bytes secret key, 16 -bytes public message nonce, 16 -bytes
// authentication tag, N ( >=0 ) -bytes associated data, M ( >=0 ) -bytes cipher
// text, this routine decrypts M -bytes plain text along with producing a
// boolean verification flag, using any of these four decryption algorithms
// {Isap-A-128a, Isap-A-128, Isap-K-128a, Isap-K-128}.
//
// Which specific algorithm from ISAP specification to be used, depends on
// choosen template parameters. See table 2.2 of ISAP specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
//
// Decryption algorithm follows generic pseudocode described in Algorithm 2, in
// above linked specification.
//
// Note, before consuming decrypted bytes, ensure that boolean verification flag
// holds truth value.
template<const isap_common::perm_t p,
         const size_t s_b,
         const size_t s_k,
         const size_t s_e,
         const size_t s_h>
inline static bool
decrypt(const uint8_t* const __restrict key,
        const uint8_t* const __restrict nonce,
        const uint8_t* const __restrict tag,
        const uint8_t* const __restrict data,
        const size_t dlen,
        const uint8_t* const __restrict cipher,
        uint8_t* const __restrict msg,
        const size_t mlen)
{
  using namespace isap_common;
  uint8_t tag_[16];

  mac<p, s_b, s_k, s_e, s_h>(key, nonce, data, dlen, cipher, mlen, tag_);

  bool flg = false;
  for (size_t i = 0; i < 16; i++) {
    flg |= static_cast<bool>(tag[i] ^ tag_[i]);
  }

  if (flg) {
    return !flg;
  }

  enc<p, s_b, s_k, s_e, s_h>(key, nonce, cipher, msg, mlen);
  return !flg;
}

}
