#pragma once
#include "ascon.hpp"
#include "keccak.hpp"
#include <algorithm>

// ISAP AEAD common functions
namespace isap_common {

// Which permutation is being used for AEAD scheme
enum perm_t
{
  ASCON, // Ascon-p used in ISAP-A-128{A}
  KECCAK // Keccak-p[400] used in ISAP-K-128{A}
};

// Generate session key for encryption/ authentication operation
enum rk_flag_t
{
  ENC, // encryption mode
  MAC  // authentication mode
};

// Ascon-p, Keccak-p[400] permutation's state byte length,
// see column `n` of table 2.2 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
constexpr size_t PERM_STATE_LEN[] = { 40, 50 };

// Byte length of secret key, nonce & authentication tag, see table 2.1 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
constexpr size_t knt_len = 16;

// Generates session key `Ke` for encryption & `Ka` for authentication, given
// 128 -bit secret key, 128 -bit string Y & a flag denoting encryption/
// authentication mode
//
// Read section 2.1 of ISAP specification ( linked below ), then see pseudocode
// described in algorithm 4 ( named `ISAP_Rk` )
//
// ISAP specification:
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
template<const perm_t p,
         const rk_flag_t f,
         const size_t s_b,
         const size_t s_k,
         const size_t s_e,
         const size_t s_h>
inline static void
rekeying(const uint8_t* const __restrict key,
         const uint8_t* const __restrict y,
         uint8_t* const __restrict skey)
{
  constexpr size_t slen = PERM_STATE_LEN[p];
  constexpr size_t rate = slen - (knt_len << 1);

  constexpr size_t Z[] = { slen - knt_len, knt_len };
  constexpr size_t z = Z[f];

  // See table 2.3 of ISAP specification
  constexpr uint8_t IV_KA[8] = { 0x02, knt_len << 3, rate << 3, 0x01,
                                 s_h,  s_b,          s_e,       s_k };

  // See table 2.3 of ISAP specification
  constexpr uint8_t IV_KE[8] = { 0x03, knt_len << 3, rate << 3, 0x01,
                                 s_h,  s_b,          s_e,       s_k };

  if constexpr (p == ASCON) {
    // --- begin initialization ---

    uint64_t state[5];

    state[0] = (static_cast<uint64_t>(key[0]) << 56) |
               (static_cast<uint64_t>(key[1]) << 48) |
               (static_cast<uint64_t>(key[2]) << 40) |
               (static_cast<uint64_t>(key[3]) << 32) |
               (static_cast<uint64_t>(key[4]) << 24) |
               (static_cast<uint64_t>(key[5]) << 16) |
               (static_cast<uint64_t>(key[6]) << 8) |
               (static_cast<uint64_t>(key[7]) << 0);

    state[1] = (static_cast<uint64_t>(key[8]) << 56) |
               (static_cast<uint64_t>(key[9]) << 48) |
               (static_cast<uint64_t>(key[10]) << 40) |
               (static_cast<uint64_t>(key[11]) << 32) |
               (static_cast<uint64_t>(key[12]) << 24) |
               (static_cast<uint64_t>(key[13]) << 16) |
               (static_cast<uint64_t>(key[14]) << 8) |
               (static_cast<uint64_t>(key[15]) << 0);

    if constexpr (f == ENC) {
      state[2] = (static_cast<uint64_t>(IV_KE[0]) << 56) |
                 (static_cast<uint64_t>(IV_KE[1]) << 48) |
                 (static_cast<uint64_t>(IV_KE[2]) << 40) |
                 (static_cast<uint64_t>(IV_KE[3]) << 32) |
                 (static_cast<uint64_t>(IV_KE[4]) << 24) |
                 (static_cast<uint64_t>(IV_KE[5]) << 16) |
                 (static_cast<uint64_t>(IV_KE[6]) << 8) |
                 (static_cast<uint64_t>(IV_KE[7]) << 0);
    } else if constexpr (f == MAC) {
      state[2] = (static_cast<uint64_t>(IV_KA[0]) << 56) |
                 (static_cast<uint64_t>(IV_KA[1]) << 48) |
                 (static_cast<uint64_t>(IV_KA[2]) << 40) |
                 (static_cast<uint64_t>(IV_KA[3]) << 32) |
                 (static_cast<uint64_t>(IV_KA[4]) << 24) |
                 (static_cast<uint64_t>(IV_KA[5]) << 16) |
                 (static_cast<uint64_t>(IV_KA[6]) << 8) |
                 (static_cast<uint64_t>(IV_KA[7]) << 0);
    }

    state[3] = 0ul;
    state[4] = 0ul;

    ascon::permute<s_k>(state);

    // --- end initialization ---

    // --- begin absorption ---

    constexpr size_t bits = (knt_len << 3) - 1;

    for (size_t i = 0; i < bits; i++) {
      const size_t off = i >> 3;       // byte offset
      const size_t bpos = 7 - (i & 7); // bit position in selected byte

      const uint8_t bit = (y[off] >> bpos) & 0b1;
      state[0] ^= static_cast<uint64_t>(bit) << 63;

      ascon::permute<s_b>(state);
    }

    const uint8_t bit = y[15] & 0b1;
    state[0] ^= static_cast<uint64_t>(bit) << 63;

    ascon::permute<s_k>(state);

    // --- end absorption ---

    // --- begin squeezing ---

    for (size_t i = 0; i < z; i++) {
      const size_t soff = i >> 3;
      const size_t boff = (7 - (i & 7)) << 3;

      skey[i] = static_cast<uint8_t>(state[soff] >> boff);
    }

    // --- end squeezing ---

  } else if constexpr (p == KECCAK) {
    // --- begin initialization ---

    uint16_t state[25] = {};

    for (size_t i = 0; i < 8; i++) {
      const size_t koff = i << 1;

      state[i] = (static_cast<uint16_t>(key[koff ^ 1]) << 8) |
                 (static_cast<uint16_t>(key[koff ^ 0]) << 0);
    }

    if constexpr (f == ENC) {
      constexpr size_t soff = 8;

      for (size_t i = 0; i < 4; i++) {
        const size_t ivoff = i << 1;

        state[soff + i] = (static_cast<uint16_t>(IV_KE[ivoff ^ 1]) << 8) |
                          (static_cast<uint16_t>(IV_KE[ivoff ^ 0]) << 0);
      }
    } else if constexpr (f == MAC) {
      constexpr size_t soff = 8;

      for (size_t i = 0; i < 4; i++) {
        const size_t ivoff = i << 1;

        state[soff + i] = (static_cast<uint16_t>(IV_KA[ivoff ^ 1]) << 8) |
                          (static_cast<uint16_t>(IV_KA[ivoff ^ 0]) << 0);
      }
    }

    keccak::permute<s_k>(state);

    // --- end initialization ---

    // --- begin absorption ---

    constexpr size_t bits = (knt_len << 3) - 1;

    for (size_t i = 0; i < bits; i++) {
      const size_t off = i >> 3;       // byte offset
      const size_t bpos = 7 - (i & 7); // bit position in selected byte

      const uint8_t bit = (y[off] >> bpos) & 0b1;
      state[0] ^= static_cast<uint16_t>(bit) << 7;

      keccak::permute<s_b>(state);
    }

    const uint8_t bit = y[15] & 0b1;
    state[0] ^= static_cast<uint16_t>(bit) << 7;

    keccak::permute<s_k>(state);

    // --- end absorption ---

    // --- begin squeezing ---

    for (size_t i = 0; i < z; i++) {
      const size_t soff = i >> 1;
      const size_t boff = (i & 1) << 3;

      skey[i] = static_cast<uint8_t>(state[soff] >> boff);
    }

    // --- end squeezing ---
  }
}

// Encrypts/ decrypts N -many message bytes ( producing equal many encrypted/
// decrypted bytes as output ), using keyed sponge construction in streaming
// mode, when 128 -bit secret key, 128 -bit public message nonce is provided
//
// Read section 2.2 of ISAP specification ( linked below ), then see pseudocode
// described in algorithm 3 ( named `ISAP_Enc` )
//
// ISAP specification:
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
template<const perm_t p,
         const size_t s_b,
         const size_t s_k,
         const size_t s_e,
         const size_t s_h>
inline static void
enc(const uint8_t* const __restrict key,
    const uint8_t* const __restrict nonce,
    const uint8_t* const __restrict msg,
    uint8_t* const __restrict out,
    const size_t mlen)
{
  constexpr size_t slen = PERM_STATE_LEN[p];
  constexpr size_t rate = slen - (knt_len << 1);

  if constexpr (p == ASCON) {
    // --- begin initialization ---

    constexpr size_t z = slen - knt_len;

    uint8_t skey[z];
    rekeying<p, ENC, s_b, s_k, s_e, s_h>(key, nonce, skey);

    uint64_t state[5];

    state[0] = (static_cast<uint64_t>(skey[0]) << 56) |
               (static_cast<uint64_t>(skey[1]) << 48) |
               (static_cast<uint64_t>(skey[2]) << 40) |
               (static_cast<uint64_t>(skey[3]) << 32) |
               (static_cast<uint64_t>(skey[4]) << 24) |
               (static_cast<uint64_t>(skey[5]) << 16) |
               (static_cast<uint64_t>(skey[6]) << 8) |
               (static_cast<uint64_t>(skey[7]) << 0);

    state[1] = (static_cast<uint64_t>(skey[8]) << 56) |
               (static_cast<uint64_t>(skey[9]) << 48) |
               (static_cast<uint64_t>(skey[10]) << 40) |
               (static_cast<uint64_t>(skey[11]) << 32) |
               (static_cast<uint64_t>(skey[12]) << 24) |
               (static_cast<uint64_t>(skey[13]) << 16) |
               (static_cast<uint64_t>(skey[14]) << 8) |
               (static_cast<uint64_t>(skey[15]) << 0);

    state[2] = (static_cast<uint64_t>(skey[16]) << 56) |
               (static_cast<uint64_t>(skey[17]) << 48) |
               (static_cast<uint64_t>(skey[18]) << 40) |
               (static_cast<uint64_t>(skey[19]) << 32) |
               (static_cast<uint64_t>(skey[20]) << 24) |
               (static_cast<uint64_t>(skey[21]) << 16) |
               (static_cast<uint64_t>(skey[22]) << 8) |
               (static_cast<uint64_t>(skey[23]) << 0);

    state[3] = (static_cast<uint64_t>(nonce[0]) << 56) |
               (static_cast<uint64_t>(nonce[1]) << 48) |
               (static_cast<uint64_t>(nonce[2]) << 40) |
               (static_cast<uint64_t>(nonce[3]) << 32) |
               (static_cast<uint64_t>(nonce[4]) << 24) |
               (static_cast<uint64_t>(nonce[5]) << 16) |
               (static_cast<uint64_t>(nonce[6]) << 8) |
               (static_cast<uint64_t>(nonce[7]) << 0);

    state[4] = (static_cast<uint64_t>(nonce[8]) << 56) |
               (static_cast<uint64_t>(nonce[9]) << 48) |
               (static_cast<uint64_t>(nonce[10]) << 40) |
               (static_cast<uint64_t>(nonce[11]) << 32) |
               (static_cast<uint64_t>(nonce[12]) << 24) |
               (static_cast<uint64_t>(nonce[13]) << 16) |
               (static_cast<uint64_t>(nonce[14]) << 8) |
               (static_cast<uint64_t>(nonce[15]) << 0);

    // --- end initialization ---

    // --- begin squeezing ---

    for (size_t off = 0; off < mlen; off += rate) {
      ascon::permute<s_e>(state);

      const size_t elen = std::min(rate, mlen - off);
      for (size_t j = 0; j < elen; j++) {
        const size_t boff = (7 - j) << 3;
        const uint8_t b = static_cast<uint8_t>(state[0] >> boff);

        out[off + j] = msg[off + j] ^ b;
      }
    }

    // --- end squeezing ---

  } else if (p == KECCAK) {
    // --- begin initialization ---

    constexpr size_t z = slen - knt_len;

    uint8_t skey[z];
    rekeying<p, ENC, s_b, s_k, s_e, s_h>(key, nonce, skey);

    uint16_t state[25];

    for (size_t i = 0; i < z; i += 2) {
      const size_t soff = i >> 1;

      state[soff] = (static_cast<uint16_t>(skey[i + 1]) << 8) |
                    (static_cast<uint16_t>(skey[i + 0]) << 0);
    }

    constexpr size_t soff = z >> 1;
    for (size_t i = 0; i < 8; i++) {
      const size_t noff = i << 1;

      state[soff + i] = (static_cast<uint16_t>(nonce[noff ^ 1]) << 8) |
                        (static_cast<uint16_t>(nonce[noff ^ 0]) << 0);
    }

    // --- end initialization ---

    // --- begin squeezing ---

    for (size_t off = 0; off < mlen; off += rate) {
      keccak::permute<s_e>(state);

      const size_t elen = std::min(rate, mlen - off);
      for (size_t j = 0; j < elen; j++) {
        const size_t soff = j >> 1;
        const size_t boff = (j & 1) << 3;

        const uint8_t b = static_cast<uint8_t>(state[soff] >> boff);

        out[off + j] = msg[off + j] ^ b;
      }
    }

    // --- end squeezing ---
  }
}

// Computes 128 -bit suffix-MAC ( message authentication code ), using sponge
// based hash function, used for message authentication purpose, given 128 -bit
// secret key, 128 -bit public message nonce, N -bytes associated data & M
// -bytes cipher text
//
// Read section 2.3 of ISAP specification ( linked below ), then see pseudocode
// described in algorithm 5 ( named `ISAP_Mac` )
//
// ISAP specification:
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
template<const perm_t p,
         const size_t s_b,
         const size_t s_k,
         const size_t s_e,
         const size_t s_h>
inline static void
mac(const uint8_t* const __restrict key,
    const uint8_t* const __restrict nonce,
    const uint8_t* const __restrict data,
    const size_t dlen,
    const uint8_t* const __restrict cipher,
    const size_t clen,
    uint8_t* const __restrict tag)
{
  constexpr size_t slen = PERM_STATE_LEN[p];
  constexpr size_t rate = slen - (knt_len << 1);
  constexpr uint8_t seperator = 0b10000000;

  // See table 2.3 of ISAP specification
  constexpr uint8_t IV_A[8] = { 0x01, knt_len << 3, rate << 3, 0x01,
                                s_h,  s_b,          s_e,       s_k };

  if constexpr (p == ASCON) {
    // --- begin initialization ---

    uint64_t state[5];

    state[0] = (static_cast<uint64_t>(nonce[0]) << 56) |
               (static_cast<uint64_t>(nonce[1]) << 48) |
               (static_cast<uint64_t>(nonce[2]) << 40) |
               (static_cast<uint64_t>(nonce[3]) << 32) |
               (static_cast<uint64_t>(nonce[4]) << 24) |
               (static_cast<uint64_t>(nonce[5]) << 16) |
               (static_cast<uint64_t>(nonce[6]) << 8) |
               (static_cast<uint64_t>(nonce[7]) << 0);

    state[1] = (static_cast<uint64_t>(nonce[8]) << 56) |
               (static_cast<uint64_t>(nonce[9]) << 48) |
               (static_cast<uint64_t>(nonce[10]) << 40) |
               (static_cast<uint64_t>(nonce[11]) << 32) |
               (static_cast<uint64_t>(nonce[12]) << 24) |
               (static_cast<uint64_t>(nonce[13]) << 16) |
               (static_cast<uint64_t>(nonce[14]) << 8) |
               (static_cast<uint64_t>(nonce[15]) << 0);

    state[2] = (static_cast<uint64_t>(IV_A[0]) << 56) |
               (static_cast<uint64_t>(IV_A[1]) << 48) |
               (static_cast<uint64_t>(IV_A[2]) << 40) |
               (static_cast<uint64_t>(IV_A[3]) << 32) |
               (static_cast<uint64_t>(IV_A[4]) << 24) |
               (static_cast<uint64_t>(IV_A[5]) << 16) |
               (static_cast<uint64_t>(IV_A[6]) << 8) |
               (static_cast<uint64_t>(IV_A[7]) << 0);

    state[3] = 0ul;
    state[4] = 0ul;

    ascon::permute<s_h>(state);

    // --- end initialization ---

    // --- begin absorbing associated data ---
    {
      const size_t blk_cnt = dlen / rate;
      const size_t rm_bytes = dlen % rate;

      for (size_t i = 0; i < blk_cnt; i++) {
        const size_t off = i * rate;
        const uint64_t w = (static_cast<uint64_t>(data[off + 0]) << 56) |
                           (static_cast<uint64_t>(data[off + 1]) << 48) |
                           (static_cast<uint64_t>(data[off + 2]) << 40) |
                           (static_cast<uint64_t>(data[off + 3]) << 32) |
                           (static_cast<uint64_t>(data[off + 4]) << 24) |
                           (static_cast<uint64_t>(data[off + 5]) << 16) |
                           (static_cast<uint64_t>(data[off + 6]) << 8) |
                           (static_cast<uint64_t>(data[off + 7]) << 0);

        state[0] ^= w;
        ascon::permute<s_h>(state);
      }

      const size_t off = blk_cnt * rate;
      uint64_t w = static_cast<uint64_t>(seperator) << ((7 - rm_bytes) << 3);

      for (size_t i = 0; i < rm_bytes; i++) {
        w |= static_cast<uint64_t>(data[off + i]) << ((7 - i) << 3);
      }

      state[0] ^= w;
      ascon::permute<s_h>(state);

      state[4] ^= 0b1; // seperator between associated data & cipher text
    }
    // --- end absorbing associated data ---

    // --- begin absorbing cipher text ---
    {
      const size_t blk_cnt = clen / rate;
      const size_t rm_bytes = clen % rate;

      for (size_t i = 0; i < blk_cnt; i++) {
        const size_t off = i * rate;
        const uint64_t w = (static_cast<uint64_t>(cipher[off + 0]) << 56) |
                           (static_cast<uint64_t>(cipher[off + 1]) << 48) |
                           (static_cast<uint64_t>(cipher[off + 2]) << 40) |
                           (static_cast<uint64_t>(cipher[off + 3]) << 32) |
                           (static_cast<uint64_t>(cipher[off + 4]) << 24) |
                           (static_cast<uint64_t>(cipher[off + 5]) << 16) |
                           (static_cast<uint64_t>(cipher[off + 6]) << 8) |
                           (static_cast<uint64_t>(cipher[off + 7]) << 0);

        state[0] ^= w;
        ascon::permute<s_h>(state);
      }

      const size_t off = blk_cnt * rate;
      uint64_t w = static_cast<uint64_t>(seperator) << ((7 - rm_bytes) << 3);

      for (size_t i = 0; i < rm_bytes; i++) {
        w |= static_cast<uint64_t>(cipher[off + i]) << ((7 - i) << 3);
      }

      state[0] ^= w;
      ascon::permute<s_h>(state);
    }
    // --- end absorbing cipher text ---

    // --- begin squeezing tag ---

    uint8_t y[knt_len];
    uint8_t skey[knt_len];

    y[0] = static_cast<uint8_t>(state[0] >> 56);
    y[1] = static_cast<uint8_t>(state[0] >> 48);
    y[2] = static_cast<uint8_t>(state[0] >> 40);
    y[3] = static_cast<uint8_t>(state[0] >> 32);
    y[4] = static_cast<uint8_t>(state[0] >> 24);
    y[5] = static_cast<uint8_t>(state[0] >> 16);
    y[6] = static_cast<uint8_t>(state[0] >> 8);
    y[7] = static_cast<uint8_t>(state[0] >> 0);

    y[8] = static_cast<uint8_t>(state[1] >> 56);
    y[9] = static_cast<uint8_t>(state[1] >> 48);
    y[10] = static_cast<uint8_t>(state[1] >> 40);
    y[11] = static_cast<uint8_t>(state[1] >> 32);
    y[12] = static_cast<uint8_t>(state[1] >> 24);
    y[13] = static_cast<uint8_t>(state[1] >> 16);
    y[14] = static_cast<uint8_t>(state[1] >> 8);
    y[15] = static_cast<uint8_t>(state[1] >> 0);

    rekeying<p, MAC, s_b, s_k, s_e, s_h>(key, y, skey);

    state[0] = (static_cast<uint64_t>(skey[0]) << 56) |
               (static_cast<uint64_t>(skey[1]) << 48) |
               (static_cast<uint64_t>(skey[2]) << 40) |
               (static_cast<uint64_t>(skey[3]) << 32) |
               (static_cast<uint64_t>(skey[4]) << 24) |
               (static_cast<uint64_t>(skey[5]) << 16) |
               (static_cast<uint64_t>(skey[6]) << 8) |
               (static_cast<uint64_t>(skey[7]) << 0);

    state[1] = (static_cast<uint64_t>(skey[8]) << 56) |
               (static_cast<uint64_t>(skey[9]) << 48) |
               (static_cast<uint64_t>(skey[10]) << 40) |
               (static_cast<uint64_t>(skey[11]) << 32) |
               (static_cast<uint64_t>(skey[12]) << 24) |
               (static_cast<uint64_t>(skey[13]) << 16) |
               (static_cast<uint64_t>(skey[14]) << 8) |
               (static_cast<uint64_t>(skey[15]) << 0);

    ascon::permute<s_h>(state);

    tag[0] = static_cast<uint8_t>(state[0] >> 56);
    tag[1] = static_cast<uint8_t>(state[0] >> 48);
    tag[2] = static_cast<uint8_t>(state[0] >> 40);
    tag[3] = static_cast<uint8_t>(state[0] >> 32);
    tag[4] = static_cast<uint8_t>(state[0] >> 24);
    tag[5] = static_cast<uint8_t>(state[0] >> 16);
    tag[6] = static_cast<uint8_t>(state[0] >> 8);
    tag[7] = static_cast<uint8_t>(state[0] >> 0);

    tag[8] = static_cast<uint8_t>(state[1] >> 56);
    tag[9] = static_cast<uint8_t>(state[1] >> 48);
    tag[10] = static_cast<uint8_t>(state[1] >> 40);
    tag[11] = static_cast<uint8_t>(state[1] >> 32);
    tag[12] = static_cast<uint8_t>(state[1] >> 24);
    tag[13] = static_cast<uint8_t>(state[1] >> 16);
    tag[14] = static_cast<uint8_t>(state[1] >> 8);
    tag[15] = static_cast<uint8_t>(state[1] >> 0);

    // --- end squeezing tag ---

  } else if (p == KECCAK) {
    // --- begin initialization ---

    uint16_t state[25] = {};

    for (size_t i = 0; i < 8; i++) {
      const size_t noff = i << 1;

      state[i] = (static_cast<uint16_t>(nonce[noff ^ 1]) << 8) |
                 (static_cast<uint16_t>(nonce[noff ^ 0]) << 0);
    }

    constexpr size_t soff = 8;
    for (size_t i = 0; i < 4; i++) {
      const size_t ivoff = i << 1;

      state[soff + i] = (static_cast<uint16_t>(IV_A[ivoff ^ 1]) << 8) |
                        (static_cast<uint16_t>(IV_A[ivoff ^ 0]) << 0);
    }

    keccak::permute<s_h>(state);

    // --- end initialization ---

    // --- begin absorbing associated data ---
    {
      const size_t blk_cnt = dlen / rate;
      const size_t rm_bytes = dlen % rate;

      for (size_t i = 0; i < blk_cnt; i++) {
        const size_t off = i * rate;

        for (size_t j = 0; j < rate; j += 2) {
          const size_t soff = j >> 1;
          const uint16_t w = (static_cast<uint16_t>(data[off + j + 1]) << 8) |
                             (static_cast<uint16_t>(data[off + j + 0]) << 0);

          state[soff] ^= w;
        }

        keccak::permute<s_h>(state);
      }

      const size_t off = blk_cnt * rate;

      for (size_t i = 0; i < rm_bytes; i++) {
        const size_t soff = i >> 1;
        const size_t boff = (i & 1) << 3;

        const uint16_t w = static_cast<uint16_t>(data[off + i]) << boff;

        state[soff] ^= w;
      }

      const size_t soff = rm_bytes >> 1;
      const size_t boff = (rm_bytes & 1) << 3;

      const uint16_t w = static_cast<uint16_t>(seperator) << boff;

      state[soff] ^= w;
      keccak::permute<s_h>(state);

      state[24] ^= 0b1 << 8; // seperator between associated data & cipher text
    }
    // --- end absorbing associated data ---

    // --- begin absorbing cipher text ---
    {
      const size_t blk_cnt = clen / rate;
      const size_t rm_bytes = clen % rate;

      for (size_t i = 0; i < blk_cnt; i++) {
        const size_t off = i * rate;

        for (size_t j = 0; j < rate; j += 2) {
          const size_t soff = j >> 1;
          const uint16_t w = (static_cast<uint16_t>(cipher[off + j + 1]) << 8) |
                             (static_cast<uint16_t>(cipher[off + j + 0]) << 0);

          state[soff] ^= w;
        }

        keccak::permute<s_h>(state);
      }

      const size_t off = blk_cnt * rate;

      for (size_t i = 0; i < rm_bytes; i++) {
        const size_t soff = i >> 1;
        const size_t boff = (i & 1) << 3;

        const uint16_t w = static_cast<uint16_t>(cipher[off + i]) << boff;

        state[soff] ^= w;
      }

      const size_t soff = rm_bytes >> 1;
      const size_t boff = (rm_bytes & 1) << 3;

      const uint16_t w = static_cast<uint16_t>(seperator) << boff;

      state[soff] ^= w;
      keccak::permute<s_h>(state);
    }
    // --- end absorbing cipher text ---

    // --- begin squeezing tag ---

    uint8_t y[knt_len];
    uint8_t skey[knt_len];

    for (size_t i = 0; i < knt_len; i++) {
      y[i] = static_cast<uint8_t>(state[i >> 1] >> ((i & 1) << 3));
    }

    rekeying<p, MAC, s_b, s_k, s_e, s_h>(key, y, skey);

    for (size_t i = 0; i < 8; i++) {
      const size_t skoff = i << 1;

      state[i] = (static_cast<uint16_t>(skey[skoff ^ 1]) << 8) |
                 (static_cast<uint16_t>(skey[skoff ^ 0]) << 0);
    }

    keccak::permute<s_h>(state);

    for (size_t i = 0; i < knt_len; i++) {
      tag[i] = static_cast<uint8_t>(state[i >> 1] >> ((i & 1) << 3));
    }

    // --- end squeezing tag ---
  }
}

}
