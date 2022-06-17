#pragma once
#include "ascon.hpp"

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

// Initial value `IVa` of ISAP-A-128A, see table 2.3 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
constexpr uint8_t IV_A[8] = { 0x01, 0x80, 0x40, 0x01, 0x0c, 0x01, 0x06, 0x0c };

// Initial value `IVka` of ISAP-A-128A, see table 2.3 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
constexpr uint8_t IV_KA[8] = { 0x02, 0x80, 0x40, 0x01, 0x0c, 0x01, 0x06, 0x0c };

// Initial value `IVke` of ISAP-A-128A, see table 2.3 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
constexpr uint8_t IV_KE[8] = { 0x03, 0x80, 0x40, 0x01, 0x0c, 0x01, 0x06, 0x0c };

// Generates session key `Ke` for encryption & `Ka` for authentication, given
// 128 -bit secret key, 128 -bit string Y & a flag denoting encryption/
// authentication mode
//
// Read section 2.1 of ISAP specification ( linked below ), then see pseudocode
// described in algorithm 4 ( named `ISAP_Rk` )
//
// ISAP specification:
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
template<const perm_t p, const rk_flag_t f, const size_t s_b, const size_t s_k>
inline static void
rekeying(const uint8_t* const __restrict key,
         const uint8_t* const __restrict y,
         uint8_t* const __restrict skey)
{
  constexpr size_t slen = PERM_STATE_LEN[p];

  constexpr size_t Z[] = { slen - knt_len, knt_len };
  constexpr size_t z = Z[f];

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
      const size_t off = i >> 3; // byte offset
      const size_t bpos = i & 7; // bit position in selected byte

      const uint8_t bit = (y[off] >> bpos) & 0b1;
      state[0] ^= static_cast<uint64_t>(bit) << 56;

      ascon::permute<s_b>(state);
    }

    const uint8_t bit = (y[15] >> 7) & 0b1;
    state[0] ^= static_cast<uint64_t>(bit) << 56;

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
    // not implemented yet !
  }
}

}
