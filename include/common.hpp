#pragma once
#include "ascon.hpp"
#include "keccak.hpp"
#include "utils.hpp"
#include <algorithm>
#include <cstring>
#include <iterator>

// ISAP AEAD common functions
namespace isap_common {

// Which permutation is being used for AEAD scheme
enum class perm_t : uint32_t
{
  ASCON, // Ascon-p used in ISAP-A-128{A}
  KECCAK // Keccak-p[400] used in ISAP-K-128{A}
};

// Generate session key for encryption/ authentication operation
enum class rk_flag_t : uint32_t
{
  ENC, // encryption mode
  MAC  // authentication mode
};

// Ascon-p, Keccak-p[400] permutation's state byte length,
// see column `n` of table 2.2 of
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
constexpr size_t PERM_STATE_LEN[]{ 40, 50 };

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
  constexpr size_t slen = PERM_STATE_LEN[static_cast<uint32_t>(p)];
  constexpr size_t rate = slen - (knt_len << 1);

  constexpr size_t Z[]{ slen - knt_len, knt_len };
  constexpr size_t z = Z[static_cast<size_t>(f)];

  // See table 2.3 of ISAP specification
  constexpr uint8_t IV_KA[8]{ 0x02, knt_len << 3, rate << 3, 0x01,
                              s_h,  s_b,          s_e,       s_k };

  // See table 2.3 of ISAP specification
  constexpr uint8_t IV_KE[8]{ 0x03, knt_len << 3, rate << 3, 0x01,
                              s_h,  s_b,          s_e,       s_k };

  if constexpr (p == perm_t::ASCON) {
    // --- begin initialization ---

    uint64_t state[5]{};

    isap_utils::copy_bytes_to_be_u64(key, knt_len, state);

    if constexpr (f == rk_flag_t::ENC) {
      isap_utils::copy_bytes_to_be_u64(IV_KE, sizeof(IV_KE), state + 2);
    } else {
      isap_utils::copy_bytes_to_be_u64(IV_KA, sizeof(IV_KA), state + 2);
    }

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
    isap_utils::copy_be_u64_to_bytes(state, skey, z);
    // --- end squeezing ---

  } else {
    // --- begin initialization ---

    uint16_t state[25]{};

    isap_utils::copy_bytes_to_le_u16(key, knt_len, state);

    if constexpr (f == rk_flag_t::ENC) {
      isap_utils::copy_bytes_to_le_u16(IV_KE, sizeof(IV_KE), state + 8);
    } else {
      isap_utils::copy_bytes_to_le_u16(IV_KA, sizeof(IV_KA), state + 8);
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
    isap_utils::copy_le_u16_to_bytes(state, skey, z);
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
  constexpr size_t slen = PERM_STATE_LEN[static_cast<uint32_t>(p)];
  constexpr size_t rate = slen - (knt_len << 1);

  if constexpr (p == perm_t::ASCON) {
    // --- begin initialization ---

    constexpr size_t z = slen - knt_len;
    uint8_t skey[z];
    rekeying<p, rk_flag_t::ENC, s_b, s_k, s_e, s_h>(key, nonce, skey);

    uint64_t state[5];

    isap_utils::copy_bytes_to_be_u64(skey, z, state);
    isap_utils::copy_bytes_to_be_u64(nonce, knt_len, state + (z / 8));

    // --- end initialization ---

    // --- begin squeezing ---

    size_t off = 0;
    while (off < mlen) {
      ascon::permute<s_e>(state);

      const size_t elen = std::min(rate, mlen - off);

      uint64_t mword = 0;
      isap_utils::copy_bytes_to_be_u64(msg + off, elen, &mword);

      const uint64_t eword = mword ^ state[0];
      isap_utils::copy_be_u64_to_bytes(&eword, out + off, elen);

      off += elen;
    }

    // --- end squeezing ---

  } else {
    // --- begin initialization ---

    constexpr size_t z = slen - knt_len;
    uint8_t skey[z];
    rekeying<p, rk_flag_t::ENC, s_b, s_k, s_e, s_h>(key, nonce, skey);

    uint16_t state[25];

    isap_utils::copy_bytes_to_le_u16(skey, z, state);
    isap_utils::copy_bytes_to_le_u16(nonce, knt_len, state + (z / 2));

    // --- end initialization ---

    // --- begin squeezing ---

    uint64_t buf0[(rate + 7) / 8];
    uint64_t buf1[(rate + 7) / 8];

    size_t off = 0;
    while (off < mlen) {
      keccak::permute<s_e>(state);

      const size_t elen = std::min(rate, mlen - off);

      std::memset(buf0, 0, sizeof(buf0));
      isap_utils::copy_bytes_to_le_u64(msg + off, elen, buf0);

      std::memset(buf1, 0, sizeof(buf1));
      isap_utils::copy_le_u16_to_le_u64(state, elen, buf1);

      for (size_t i = 0; i < (rate + 7) / 8; i++) {
        buf1[i] ^= buf0[i];
      }

      isap_utils::copy_le_u64_to_bytes(buf1, out + off, elen);
      off += elen;
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
  constexpr size_t slen = PERM_STATE_LEN[static_cast<uint32_t>(p)];
  constexpr size_t rate = slen - (knt_len << 1);
  constexpr uint8_t seperator = 0b10000000;

  // See table 2.3 of ISAP specification
  constexpr uint8_t IV_A[8]{ 0x01, knt_len << 3, rate << 3, 0x01,
                             s_h,  s_b,          s_e,       s_k };

  if constexpr (p == perm_t::ASCON) {
    // --- begin initialization ---

    uint64_t state[5]{};

    isap_utils::copy_bytes_to_be_u64(nonce, knt_len, state);
    isap_utils::copy_bytes_to_be_u64(IV_A, sizeof(IV_A), state + 2);

    ascon::permute<s_h>(state);

    // --- end initialization ---

    // --- begin absorbing associated data ---
    {
      const size_t blk_cnt = dlen / rate;
      const size_t rm_bytes = dlen % rate;

      for (size_t i = 0; i < blk_cnt; i++) {
        const size_t off = i * rate;

        uint64_t word;
        isap_utils::copy_bytes_to_be_u64(data + off, rate, &word);

        state[0] ^= word;
        ascon::permute<s_h>(state);
      }

      const size_t off = blk_cnt * rate;

      uint64_t word = 0;
      isap_utils::copy_bytes_to_be_u64(data + off, rm_bytes, &word);
      word |= static_cast<uint64_t>(seperator) << ((7 - rm_bytes) * 8);

      state[0] ^= word;
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

        uint64_t word;
        isap_utils::copy_bytes_to_be_u64(cipher + off, rate, &word);

        state[0] ^= word;
        ascon::permute<s_h>(state);
      }

      const size_t off = blk_cnt * rate;

      uint64_t word = 0;
      isap_utils::copy_bytes_to_be_u64(cipher + off, rm_bytes, &word);
      word |= static_cast<uint64_t>(seperator) << ((7 - rm_bytes) * 8);

      state[0] ^= word;
      ascon::permute<s_h>(state);
    }
    // --- end absorbing cipher text ---

    // --- begin squeezing tag ---

    uint8_t y[knt_len];
    uint8_t skey[knt_len];

    isap_utils::copy_be_u64_to_bytes(state, y, knt_len);
    rekeying<p, rk_flag_t::MAC, s_b, s_k, s_e, s_h>(key, y, skey);
    isap_utils::copy_bytes_to_be_u64(skey, knt_len, state);

    ascon::permute<s_h>(state);

    isap_utils::copy_be_u64_to_bytes(state, tag, knt_len);

    // --- end squeezing tag ---

  } else {
    // --- begin initialization ---

    uint16_t state[25]{};

    isap_utils::copy_bytes_to_le_u16(nonce, knt_len, state);
    isap_utils::copy_bytes_to_le_u16(IV_A, sizeof(IV_A), state + 8);

    keccak::permute<s_h>(state);

    // --- end initialization ---

    // --- begin absorbing associated data ---
    {
      uint64_t buf0[(rate + 7) / 8];
      uint64_t buf1[(rate + 7) / 8];

      size_t off = 0;
      while (off < dlen) {
        const size_t elen = std::min(rate, dlen - off);

        std::memset(buf0, 0, sizeof(buf0));
        isap_utils::copy_bytes_to_le_u64(data + off, elen, buf0);
        isap_utils::copy_le_u16_to_le_u64(state, sizeof(buf1), buf1);

        for (size_t i = 0; i < (rate + 7) / 8; i++) {
          buf1[i] ^= buf0[i];
        }

        isap_utils::copy_le_u64_to_le_u16(buf1, state, sizeof(buf1));
        off += elen;

        if (elen == rate) {
          keccak::permute<s_h>(state);
        }
      }

      const size_t rm_bytes = dlen % rate;
      const size_t soff = rm_bytes >> 1;
      const size_t boff = (rm_bytes & 1) * 8;

      const uint16_t w = static_cast<uint16_t>(seperator) << boff;
      state[soff] ^= w;

      keccak::permute<s_h>(state);

      state[24] ^= 0b1 << 8; // seperator between associated data & cipher text
    }
    // --- end absorbing associated data ---

    // --- begin absorbing cipher text ---
    {
      uint64_t buf0[(rate + 7) / 8];
      uint64_t buf1[(rate + 7) / 8];

      size_t off = 0;
      while (off < clen) {
        const size_t elen = std::min(rate, clen - off);

        std::memset(buf0, 0, sizeof(buf0));
        isap_utils::copy_bytes_to_le_u64(cipher + off, elen, buf0);
        isap_utils::copy_le_u16_to_le_u64(state, sizeof(buf1), buf1);

        for (size_t i = 0; i < (rate + 7) / 8; i++) {
          buf1[i] ^= buf0[i];
        }

        isap_utils::copy_le_u64_to_le_u16(buf1, state, sizeof(buf1));
        off += elen;

        if (elen == rate) {
          keccak::permute<s_h>(state);
        }
      }

      const size_t rm_bytes = clen % rate;
      const size_t soff = rm_bytes >> 1;
      const size_t boff = (rm_bytes & 1) * 8;

      const uint16_t w = static_cast<uint16_t>(seperator) << boff;
      state[soff] ^= w;

      keccak::permute<s_h>(state);
    }
    // --- end absorbing cipher text ---

    // --- begin squeezing tag ---

    uint8_t y[knt_len];
    uint8_t skey[knt_len];

    isap_utils::copy_le_u16_to_bytes(state, y, knt_len);
    rekeying<p, rk_flag_t::MAC, s_b, s_k, s_e, s_h>(key, y, skey);
    isap_utils::copy_bytes_to_le_u16(skey, knt_len, state);

    keccak::permute<s_h>(state);

    isap_utils::copy_le_u16_to_bytes(state, tag, knt_len);

    // --- end squeezing tag ---
  }
}

}
