#pragma once
#include "aead.hpp"
#include "common.hpp"

// ISAP-K-128 authenticated encryption with associated data ( AEAD )
namespace isap_k_128 {

// Given 16 -bytes secret key, 16 -bytes public message nonce, N ( >=0 ) -bytes
// associated data, M ( >=0 ) -bytes plain text, this routine computes M -bytes
// cipher text along with 16 -bytes authentication tag, using Isap-K-128
// algorithm
//
// See
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
inline static void
encrypt(const uint8_t* const __restrict key,
        const uint8_t* const __restrict nonce,
        const uint8_t* const __restrict data,
        const size_t dlen,
        const uint8_t* const __restrict msg,
        uint8_t* const __restrict enc,
        const size_t mlen,
        uint8_t* const __restrict tag)
{
  isap::encrypt<isap_common::perm_t::KECCAK, 12, 12, 12, 20>(
    key, nonce, data, dlen, msg, enc, mlen, tag);
}

// Given 16 -bytes secret key, 16 -bytes public message nonce, 16 -bytes
// authentication tag, N ( >=0 ) -bytes associated data, M ( >=0 ) -bytes cipher
// text, this routine decrypts M -bytes plain text along with producing a
// boolean verification flag, using Isap-K-128 algorithm
//
// See
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
inline static bool
decrypt(const uint8_t* const __restrict key,
        const uint8_t* const __restrict nonce,
        const uint8_t* const __restrict tag,
        const uint8_t* const __restrict data,
        const size_t dlen,
        const uint8_t* const __restrict enc,
        uint8_t* const __restrict msg,
        const size_t mlen)
{
  return isap::decrypt<isap_common::perm_t::KECCAK, 12, 12, 12, 20>(
    key, nonce, tag, data, dlen, enc, msg, mlen);
}

}
